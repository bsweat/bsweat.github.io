/**
 * PhishLens — Client-side analyzer v1.2
 * Runs entirely in the browser. No backend required.
 *
 * Scoring philosophy: one confirmed red flag = NOT TRUSTED.
 * False negatives (missing real phishing) are far more dangerous
 * than false positives for a security audience.
 */

'use strict';

// ── Brand / TLD databases ─────────────────────────────────────────────────────

const TOP_BRANDS = [
  'google','facebook','amazon','apple','microsoft','paypal','netflix',
  'instagram','twitter','linkedin','github','youtube','reddit','ebay',
  'dropbox','chase','bankofamerica','wellsfargo','citibank','coinbase',
  'binance','stripe','shopify','wordpress','gmail','yahoo','outlook',
  'steam','twitch','discord','zoom','salesforce','adobe','snapchat',
  'tiktok','spotify','airbnb','uber','doordash','robinhood','schwab',
  'fidelity','usbank','capitalone','americanexpress','icloud','onedrive',
  'att','verizon','tmobile','comcast','xfinity','fedex','ups','dhl','usps',
];

const HOMOGLYPH_MAP = {
  '@':'a','4':'a','а':'a',
  '3':'e','е':'e',
  '1':'i','l':'i','|':'i','!':'i',
  '0':'o','о':'o','ο':'o',
  '5':'s','$':'s',
  '9':'g','6':'b','8':'b','+':'t','7':'t',
};

const SUSPICIOUS_TLDS = new Set([
  'tk','ml','ga','cf','gq','pw','top','click','xyz','info',
  'biz','work','loan','win','accountant','science','download',
  'racing','review','party','trade','webcam','date','faith',
]);

const DKIM_SELECTORS = [
  'default','google','mail','email','dkim','selector1','selector2',
  'k1','s1','s2','mandrill','sendgrid','amazonses',
];

const SUSPICIOUS_PATH_KEYWORDS = [
  'login','signin','sign-in','verify','verification','account','secure',
  'update','confirm','banking','password','credential','webscr','checkout',
  'authenticate','validation','recover','suspended','unlock','limited',
];

// ── Levenshtein + homoglyph normalisation ─────────────────────────────────────

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const prev = Array.from({length: n + 1}, (_, i) => i);
  const curr = new Array(n + 1);
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] = a[i-1] === b[j-1] ? prev[j-1] : 1 + Math.min(prev[j], curr[j-1], prev[j-1]);
    }
    prev.splice(0, n + 1, ...curr);
  }
  return prev[n];
}

function normalizeHomoglyphs(text) {
  return [...text.toLowerCase()].map(c => HOMOGLYPH_MAP[c] ?? c).join('');
}

async function dohQuery(name, type) {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { Accept: 'application/dns-json' } }
    );
    if (!r.ok) return [];
    const data = await r.json();
    return (data.Answer || []).map(a =>
      (a.data || '').replace(/^"+|"+$/g, '').replace(/"\s+"/g, '')
    );
  } catch { return []; }
}

// ── Check 1: URL Structure (pure JS, no network) ──────────────────────────────

function checkURLStructure(url) {
  const label = 'URL Structure';
  try {
    const parsed    = new URL(url);
    const hostname  = parsed.hostname;
    const pathFull  = (parsed.pathname + parsed.search).toLowerCase();
    const hostParts = hostname.split('.');

    const hasAtSign          = url.includes('@');
    const isIPAddress        = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    const subdomainCount     = Math.max(0, hostParts.length - 2);
    const excessiveSubdomain = subdomainCount >= 3;
    const suspiciousPath     = SUSPICIOUS_PATH_KEYWORDS.some(kw => pathFull.includes(kw));
    const veryLongURL        = url.length > 100;
    const hasDoubleSlash     = parsed.pathname.includes('//');
    const hexEncoded         = /%[0-9a-f]{2}/i.test(url) && url.split('%').length > 4;

    const flags = [];
    if (hasAtSign)          flags.push('@ symbol in URL — likely credential harvesting');
    if (isIPAddress)        flags.push('IP address instead of domain name');
    if (excessiveSubdomain) flags.push(`${subdomainCount} subdomain levels (e.g. secure.paypal.com.evil.xyz)`);
    if (suspiciousPath)     flags.push('path contains authentication/login keywords');
    if (veryLongURL)        flags.push(`unusually long URL (${url.length} chars)`);
    if (hexEncoded)         flags.push('heavy URL encoding — possible obfuscation');

    let status;
    if (hasAtSign || isIPAddress)                    status = 'critical';
    else if (excessiveSubdomain && suspiciousPath)   status = 'danger';
    else if (excessiveSubdomain || suspiciousPath)   status = 'warning';
    else if (veryLongURL || hexEncoded)              status = 'warning';
    else                                             status = 'safe';

    return {
      status, label,
      summary: flags.length ? flags[0] + (flags.length > 1 ? ` (+${flags.length - 1} more)` : '') : 'URL structure looks normal',
      flags, has_at_sign: hasAtSign, is_ip_address: isIPAddress,
      suspicious_path: suspiciousPath, excessive_subdomains: excessiveSubdomain,
      very_long_url: veryLongURL, subdomain_count: subdomainCount, url_length: url.length,
    };
  } catch (e) {
    return { status: 'error', label, summary: `Could not parse URL: ${e.message}` };
  }
}

// ── Check 2: Domain Age (RDAP) ────────────────────────────────────────────────

async function checkDomainAge(domain) {
  const label = 'Domain Age';
  try {
    const resp = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { Accept: 'application/json' },
    });
    if (resp.status === 404) {
      return { status: 'danger', label, summary: 'Domain not found in RDAP — may be brand new or use private WHOIS', ageDays: null };
    }
    if (!resp.ok) throw new Error(`RDAP ${resp.status}`);
    const data = await resp.json();

    let registered = null, expires = null;
    for (const evt of (data.events || [])) {
      const action = (evt.eventAction || '').toLowerCase();
      if (action.includes('registr')) registered = evt.eventDate;
      else if (action.includes('expir'))  expires = evt.eventDate;
    }

    let ageDays = null;
    if (registered) ageDays = Math.floor((Date.now() - new Date(registered).getTime()) / 86400000);

    let status, summary;
    if (ageDays == null)   { status = 'warning';  summary = 'Registration date unavailable'; }
    else if (ageDays < 7)  { status = 'critical'; summary = `${ageDays} day(s) old — registered this week`; }
    else if (ageDays < 30) { status = 'danger';   summary = `${ageDays} days old — very recently registered`; }
    else if (ageDays < 90) { status = 'warning';  summary = `${ageDays} days old — registered < 3 months ago`; }
    else if (ageDays < 180){ status = 'warning';  summary = `${ageDays} days old — under 6 months old`; }
    else if (ageDays < 365){ status = 'warning';  summary = `${ageDays} days old — under 1 year old`; }
    else {
      const yrs = Math.floor(ageDays / 365);
      status = 'safe'; summary = `${ageDays} days old (~${yrs} year${yrs !== 1 ? 's' : ''})`;
    }

    return { status, label, summary, ageDays, registered, expires };
  } catch (e) {
    return { status: 'error', label, summary: `RDAP lookup failed: ${e.message}` };
  }
}

// ── Check 3: HTTPS / SSL ──────────────────────────────────────────────────────

async function checkSSL(url, domain) {
  const label = 'HTTPS / SSL';
  if (!url.startsWith('https://')) {
    return { status: 'danger', label, summary: 'No HTTPS — traffic transmitted in plaintext (HTTP)', valid: false };
  }
  try {
    await fetch(`https://${domain}`, { method: 'HEAD', redirect: 'follow' });
    return { status: 'safe', label, summary: 'HTTPS active — encrypted with a browser-trusted certificate', valid: true };
  } catch (e) {
    const msg = (e.message || '').toLowerCase();
    if (msg.includes('ssl') || msg.includes('cert') || msg.includes('tls')) {
      return { status: 'critical', label, summary: 'SSL certificate error — browser rejected the certificate', valid: false };
    }
    return { status: 'safe', label, summary: 'HTTPS used — connection is encrypted', valid: true };
  }
}

// ── Check 4: Redirect Chain ───────────────────────────────────────────────────

async function checkRedirects(url) {
  const label = 'Redirect Chain';
  try {
    const resp = await fetch(url, {
      method: 'GET', redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PhishLens/1.0)' },
    });
    const finalUrl    = resp.url || url;
    const redirected  = resp.redirected || (finalUrl !== url);
    const origDomain  = new URL(url).hostname;
    const finalDomain = (() => { try { return new URL(finalUrl).hostname; } catch { return origDomain; } })();
    const crossDomain = origDomain !== finalDomain;

    let status, summary;
    if (!redirected)      { status = 'safe';    summary = 'No redirects — direct link'; }
    else if (crossDomain) { status = 'warning'; summary = `Redirects to a different domain: ${finalDomain}`; }
    else                  { status = 'safe';    summary = 'Redirects within the same domain'; }

    return { status, label, summary, redirected, final_url: finalUrl, final_domain: finalDomain, cross_domain: crossDomain };
  } catch (e) {
    // CORS or network failure — don't penalise, just note it
    return { status: 'skipped', label, summary: 'Could not follow redirects from browser context (CORS)' };
  }
}

// ── Check 5: Lookalike / Typosquatting ────────────────────────────────────────

function checkLookalike(domain) {
  const label = 'Lookalike Detection';
  const parts = domain.toLowerCase().split('.');
  const tld   = parts.at(-1) || '';
  const base  = parts.length >= 2 ? parts.at(-2) : parts[0];

  const normalized    = normalizeHomoglyphs(base);
  const hasHomoglyphs  = normalized !== base;
  const hasNumberSub   = /\d/.test(base);
  const isPunycode     = domain.includes('xn--');
  const suspiciousTld  = SUSPICIOUS_TLDS.has(tld);

  let bestBrand = null, bestScore = 0, bestDist = 0;
  for (const brand of TOP_BRANDS) {
    if (base === brand) {
      return {
        status: 'safe', label,
        summary: `Exact match for '${brand}' — appears legitimate`,
        is_lookalike: false, best_match: null, similarity_score: 100,
        has_homoglyphs: false, has_number_substitution: hasNumberSub,
        is_punycode: isPunycode, suspicious_tld: suspiciousTld, tld, indicators: [],
      };
    }
    const dist  = Math.min(levenshtein(base, brand), levenshtein(normalized, brand));
    const maxLen = Math.max(brand.length, base.length);
    const score  = (1 - dist / maxLen) * 100;
    if (score > bestScore) { bestScore = score; bestBrand = brand; bestDist = dist; }
  }

  const isLookalike = bestScore >= 75 && bestBrand !== null && bestBrand !== base;
  const indicators  = [];
  if (isLookalike)                 indicators.push(`${bestScore.toFixed(0)}% match to '${bestBrand}.com'`);
  if (hasHomoglyphs)               indicators.push('lookalike/homoglyph characters (e.g. 0→o, 1→l)');
  if (hasNumberSub && isLookalike) indicators.push('digit substitution detected');
  if (isPunycode)                  indicators.push('punycode / IDN encoding');
  if (suspiciousTld)               indicators.push(`high-risk free TLD (.${tld})`);

  let status;
  if      (isLookalike && hasHomoglyphs)              status = 'critical';
  else if (isLookalike)                               status = 'danger';
  else if (hasHomoglyphs || isPunycode)               status = 'danger';
  else if (suspiciousTld)                             status = 'warning';
  else                                                status = 'safe';

  return {
    status, label,
    summary: indicators.length ? indicators.join('; ') : 'No brand impersonation detected',
    is_lookalike: isLookalike,
    best_match: isLookalike ? bestBrand : null,
    similarity_score: Math.round(bestScore * 10) / 10,
    edit_distance: isLookalike ? bestDist : null,
    has_homoglyphs: hasHomoglyphs,
    has_number_substitution: hasNumberSub,
    is_punycode: isPunycode,
    suspicious_tld: suspiciousTld,
    tld, indicators,
  };
}

// ── Check 6: DNS Security (SPF / DKIM / DMARC via DoH) ───────────────────────

async function checkDNS(domain) {
  const label = 'DNS Security (SPF/DKIM/DMARC)';
  const [txtRecords, dmarcRecords] = await Promise.all([
    dohQuery(domain, 'TXT'),
    dohQuery(`_dmarc.${domain}`, 'TXT'),
  ]);

  const spfRecs = txtRecords.filter(r => r.startsWith('v=spf1'));
  const spf = {
    found: spfRecs.length > 0, record: spfRecs[0] || null,
    strict: spfRecs.some(r => r.includes('-all')),
    softfail: spfRecs.some(r => r.includes('~all')),
  };

  const dmarcHits = dmarcRecords.filter(r => r.includes('v=DMARC1'));
  let policy = 'none';
  if (dmarcHits.length) {
    const rec = dmarcHits[0];
    if (rec.includes('p=reject'))      policy = 'reject';
    else if (rec.includes('p=quarantine')) policy = 'quarantine';
  }
  const dmarc = { found: dmarcHits.length > 0, record: dmarcHits[0] || null, policy };

  // DKIM — check 6 most common selectors in parallel
  const dkimResults = await Promise.all(
    DKIM_SELECTORS.slice(0, 6).map(sel =>
      dohQuery(`${sel}._domainkey.${domain}`, 'TXT').then(recs => ({
        sel, found: recs.some(r => r.includes('v=DKIM1') || (r.includes('p=') && r.length > 20)),
      }))
    )
  );
  const dkimHit = dkimResults.find(r => r.found);
  const dkim    = { found: !!dkimHit, selector: dkimHit?.sel || null };

  const flags = [];
  if (!spf.found)                        flags.push('no SPF record');
  else if (!spf.strict && !spf.softfail) flags.push('SPF missing enforcement policy (-all / ~all)');
  if (!dmarc.found)                      flags.push('no DMARC record');
  else if (dmarc.policy === 'none')      flags.push("DMARC policy set to 'none' — no enforcement");
  if (!dkim.found)                       flags.push('no DKIM key found on common selectors');

  const status  = flags.length === 0 ? 'safe' : flags.length >= 3 ? 'danger' : 'warning';
  const summary = flags.length === 0
    ? 'SPF ✓  DKIM ✓  DMARC ✓ — strong email authentication'
    : flags.join('; ');

  return { status, label, summary, spf, dmarc, dkim, flags };
}

// ── Check 7: VirusTotal ───────────────────────────────────────────────────────

async function checkVirusTotal(url, apiKey) {
  const label = 'VirusTotal';
  if (!apiKey) {
    return { status: 'skipped', label, summary: 'No API key — add yours in ⚙ Settings (free at virustotal.com)' };
  }
  try {
    const urlId = btoa(url).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    const resp  = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
    });
    if (resp.status === 404) {
      await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodeURIComponent(url)}`,
      });
      return { status: 'warning', label, summary: 'URL submitted for scanning — check back in ~60s' };
    }
    if (resp.status === 401) return { status: 'error', label, summary: 'Invalid VirusTotal API key' };
    if (resp.status === 429) return { status: 'warning', label, summary: 'VT rate limit hit — free tier: 4 req/min' };
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const data  = await resp.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const mal = stats.malicious || 0, sus = stats.suspicious || 0,
          har = stats.harmless  || 0, und = stats.undetected || 0;
    const total = mal + sus + har + und;

    let status, summary;
    if      (mal >= 5)  { status = 'critical'; summary = `${mal}/${total} engines flagged as MALICIOUS`; }
    else if (mal >= 2)  { status = 'danger';   summary = `${mal}/${total} engines flagged as malicious`; }
    else if (mal === 1) { status = 'warning';  summary = `1/${total} engine flagged — treat with caution`; }
    else if (sus > 0)   { status = 'warning';  summary = `${sus}/${total} engines flagged as suspicious`; }
    else                { status = 'safe';     summary = `0/${total} engines — no known threats`; }

    return { status, label, summary, malicious: mal, suspicious: sus, harmless: har, undetected: und, total_engines: total };
  } catch (e) {
    return { status: 'error', label, summary: `VirusTotal check failed: ${e.message}` };
  }
}

// ── Risk scoring ──────────────────────────────────────────────────────────────
// Conservative by design: one confirmed red flag = NOT TRUSTED.

function calcRiskScore(checks) {
  let s = 0;
  const { url_analysis: ua={}, domain_age: da={}, ssl={}, lookalike: la={},
          virustotal: vt={}, dns={}, redirects: rd={} } = checks;

  // URL structure (0-40) — highest weight, pure signals
  if (ua.has_at_sign)            s += 25;
  if (ua.is_ip_address)          s += 28;
  if (ua.excessive_subdomains && ua.suspicious_path) s += 18;
  else if (ua.excessive_subdomains) s += 12;
  else if (ua.suspicious_path)   s += 10;
  if (ua.very_long_url)          s += 6;

  // Domain age (0-30)
  const age = da.ageDays;
  if (age == null)    s += 14;
  else if (age < 7)   s += 30;
  else if (age < 30)  s += 25;
  else if (age < 90)  s += 16;
  else if (age < 180) s += 10;
  else if (age < 365) s += 5;

  // SSL (0-22)
  if (ssl.status === 'critical') s += 22;
  else if (ssl.status === 'danger') s += 18;

  // Lookalike (0-40)
  if (la.is_lookalike)          s += 28;
  if (la.has_homoglyphs)        s += 18;
  if (la.suspicious_tld)        s += 10;
  if (la.is_punycode)           s += 14;
  if (la.has_number_substitution && la.is_lookalike) s += 8;

  // VirusTotal (0-40 — most authoritative signal)
  if (!['skipped','error',undefined,null].includes(vt.status)) {
    const m = vt.malicious || 0;
    if      (m >= 5) s += 40;
    else if (m >= 2) s += 32;
    else if (m === 1)s += 18;
    else if ((vt.suspicious || 0) > 0) s += 10;
  }

  // DNS (0-14)
  if (!dns.spf?.found)   s += 7;
  if (!dns.dmarc?.found) s += 7;

  // Redirects (0-14)
  if (rd.cross_domain) s += 14;

  let raw = Math.min(s, 100);

  // ── HARD FLOORS ──
  // Any single critical check → score cannot be below 72 (HIGH/CRITICAL territory)
  // Any single danger check → score cannot be below 48 (NOT TRUSTED)
  // Any two warnings → score cannot be below 30 (CAUTION)
  const statuses = Object.values(checks).map(c => c?.status).filter(Boolean);
  const hasCrit   = statuses.includes('critical');
  const dangerCt  = statuses.filter(s => s === 'danger').length;
  const warnCt    = statuses.filter(s => s === 'warning').length;

  if      (hasCrit)       raw = Math.max(raw, 72);
  else if (dangerCt >= 2) raw = Math.max(raw, 62);
  else if (dangerCt >= 1) raw = Math.max(raw, 48);
  else if (warnCt >= 3)   raw = Math.max(raw, 38);
  else if (warnCt >= 2)   raw = Math.max(raw, 28);
  else if (warnCt >= 1)   raw = Math.max(raw, 18);

  return Math.min(raw, 100);
}

function getRiskLevel(score) {
  if (score >= 70) return 'DANGEROUS';
  if (score >= 45) return 'NOT TRUSTED';
  if (score >= 20) return 'CAUTION';
  return 'LIKELY SAFE';
}

// ── Report generator (used by both popup and web app) ─────────────────────────

function generateSecurityReport(url, checks, score, level) {
  const now  = new Date().toUTCString();
  const lines = [
    '════════════════════════════════════════════',
    '  PHISHLENS THREAT REPORT',
    '════════════════════════════════════════════',
    '',
    `  URL:        ${url}`,
    `  Risk Score: ${score}/100`,
    `  Risk Level: ${level}`,
    `  Reported:   ${now}`,
    '',
    '────────────────────────────────────────────',
    '  ANALYSIS RESULTS',
    '────────────────────────────────────────────',
    '',
  ];

  const ORDER = ['url_analysis','domain_age','ssl','redirects','lookalike','dns','virustotal','email_header'];
  const allKeys = [...new Set([...ORDER, ...Object.keys(checks)])];

  for (const key of allKeys) {
    const c = checks[key];
    if (!c || !c.label) continue;
    const icon = { safe:'✓', warning:'⚠', danger:'✕', critical:'✕✕', skipped:'–', error:'?' }[c.status] || '?';
    lines.push(`  [${icon}] ${c.label}`);
    lines.push(`      ${c.summary}`);
    lines.push('');
  }

  lines.push('────────────────────────────────────────────');
  lines.push('  Recommendation:');
  if (score >= 70) {
    lines.push('  DO NOT visit this URL. High probability of phishing or malware.');
  } else if (score >= 45) {
    lines.push('  Do not visit. Multiple threat indicators detected.');
  } else if (score >= 20) {
    lines.push('  Treat with caution. Verify the source before proceeding.');
  } else {
    lines.push('  No significant threats detected. Standard precautions advised.');
  }
  lines.push('');
  lines.push('  Generated by PhishLens — https://bsweat.github.io/phishlens');
  lines.push('════════════════════════════════════════════');

  return lines.join('\n');
}
