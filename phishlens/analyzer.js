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
  '1':'l','|':'i','!':'i',
  '0':'o','о':'o','ο':'o',
  '5':'s','$':'s',
  '9':'g','6':'b','8':'b','+':'t','7':'t',
};

const SUSPICIOUS_TLDS = new Set([
  'tk','ml','ga','cf','gq','pw','top','click','xyz','info',
  'biz','work','loan','win','accountant','science','download',
  'racing','review','party','trade','webcam','date','faith',
]);

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
    const r = await timedFetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { Accept: 'application/dns-json' } }
    );
    if (!r.ok) throw new Error(`DNS lookup returned HTTP ${r.status}`);
    const data = await r.json();
    if (![0,3].includes(data.Status)) throw new Error(`DNS lookup failed (status ${data.Status})`);
    return (data.Answer || []).filter(a => a.type === 16).map(a =>
      (a.data || '').replace(/^"+|"+$/g, '').replace(/"\s+"/g, '')
    );
  } catch (error) { throw new Error(`DNS lookup unavailable: ${error.message}`); }
}

async function timedFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try { return await fetch(url, {...options, signal:controller.signal}); }
  finally { clearTimeout(timer); }
}

// ── Check 1: URL Structure (pure JS, no network) ──────────────────────────────

function checkURLStructureBase(url) {
  const label = 'URL Structure';
  try {
    const parsed    = new URL(url);
    const hostname  = parsed.hostname;
    const pathFull  = (parsed.pathname + parsed.search).toLowerCase();
    const hostParts = hostname.split('.');

    const hasAtSign          = !!(parsed.username || parsed.password);
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
  domain = domainParts(domain, false).registered;
  if (isIPHost(domain)) return {status:'skipped',label,summary:'IP addresses do not have a domain registration age'};
  try {
    const resp = await timedFetch(`https://rdap.org/domain/${domain}`, {
      headers: { Accept: 'application/json' },
    });
    if (resp.status === 404) {
      return { status: 'skipped', label, summary: 'No RDAP record found — registration age could not be verified', ageDays: null };
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

    return { status, label, summary, ageDays, registered, expires, domain, registrar: (data.entities || []).filter(e => e.roles?.includes('registrar')).flatMap(e => e.vcardArray?.[1] || []).find(v => v[0] === 'fn')?.[3] || null, registration_status: data.status || [] };
  } catch (e) {
    return { status: 'error', label, summary: `RDAP lookup failed: ${e.message}` };
  }
}

// ── Check 3: HTTPS / SSL ──────────────────────────────────────────────────────

// ── Check 5: Lookalike / Typosquatting ────────────────────────────────────────

function checkLookalikeBase(domain) {
  const label = 'Lookalike Detection';
  const parts = domainParts(domain).registered.split('.');
  const tld   = parts.at(-1) || '';
  const base = domainParts(domain).label;

  const normalized    = normalizeHomoglyphs(base);
  const substituted = normalized !== base;
  const hasNumberSub   = /\d/.test(base);
  const isPunycode     = domain.includes('xn--');
  const suspiciousTld  = SUSPICIOUS_TLDS.has(tld);

  let bestBrand = null, bestScore = 0, bestDist = 0;
  for (const brand of TOP_BRANDS) {
    if (domainParts(domain).registered === `${brand}.com`) {
      return {
        status: 'safe', label,
        summary: `Matches the known '${brand}.com' domain`,
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

  const embeddedBrand = TOP_BRANDS.find(brand => base !== brand && (base.startsWith(brand + '-') || base.endsWith('-' + brand)));
  if (embeddedBrand) { bestBrand = embeddedBrand; bestScore = 90; }
  const isLookalike = (bestScore >= 75 && bestBrand !== null && bestBrand !== base) || TOP_BRANDS.includes(base);
  const hasHomoglyphs = substituted && (isLookalike || /[а-еоο|!@$+]/i.test(base));
  const indicators  = [];
  if (isLookalike)                 indicators.push(`${bestScore.toFixed(0)}% match to '${bestBrand}.com'`);
  if (hasHomoglyphs)               indicators.push('lookalike/homoglyph characters (e.g. 0→o, 1→l)');
  if (hasNumberSub && isLookalike) indicators.push('digit substitution detected');
  if (isPunycode)                  indicators.push('punycode / IDN encoding');
  if (suspiciousTld)               indicators.push(`TLD risk indicator (.${tld})`);

  let status;
  if      (isLookalike && hasHomoglyphs)              status = 'critical';
  else if (isLookalike)                               status = 'danger';
  else if (hasHomoglyphs)                            status = 'danger';
  else if (isPunycode)                                status = 'warning';
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
  domain = domainParts(domain, false).registered;
  const label = 'Email DNS policies';
  if(isIPHost(domain)) return {status:'skipped',label,summary:'Email DNS policies apply to domain names, not IP literals'};
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

  // DKIM keys require the signing domain and selector from a real email.
  // Guessing selector names cannot establish that DKIM is absent.
  const dkim = { found: null, selector: null, status: 'unverified' };

  const flags = [];
  if (!spf.found)                        flags.push('no SPF record');
  else if (!spf.strict && !spf.softfail) flags.push('SPF missing enforcement policy (-all / ~all)');
  if (!dmarc.found)                      flags.push('no DMARC record');
  else if (dmarc.policy === 'none')      flags.push("DMARC policy set to 'none' — no enforcement");

  const status  = flags.length === 0 ? 'safe' : flags.length >= 2 ? 'danger' : 'warning';
  const summary = flags.length === 0
    ? 'SPF and DMARC policies found — DKIM needs an email signature to check'
    : flags.join('; ');

  return { status, label, summary, spf, dmarc, dkim, flags };
}

// ── Check 7: VirusTotal ───────────────────────────────────────────────────────

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
  if (age == null)    s += 0;
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
  if (checks.email_header && dns.spf && !dns.spf.found) s += 7;
  if (checks.email_header && dns.dmarc && !dns.dmarc.found) s += 7;

  // Redirects (0-14)
  if (rd.cross_domain && rd.source !== 'VirusTotal historical report') s += 8;
  if (checks.url_analysis?.executable_download) s += 12;
  if (checks.url_analysis?.deceptive_subdomain) s += 20;

  let raw = Math.min(s, 100);

  // ── HARD FLOORS ──
  // Any single critical check → score cannot be below 72 (HIGH/CRITICAL territory)
  // Any single danger check → score cannot be below 48 (NOT TRUSTED)
  // Any two warnings → score cannot be below 30 (CAUTION)
  const statuses = Object.entries(checks).filter(([name]) => name !== 'dns' || checks.email_header).map(([,c]) => c?.status).filter(Boolean);
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
  return 'LOW RISK';
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
