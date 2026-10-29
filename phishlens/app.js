/* ─── PhishLens — Web App (fully client-side) ───────────────────────────────
   Reads analyzer.js functions. No backend required.
   Auto-scans if URL passed as ?url= query param (used by extension "Full Analysis" link).
   ─────────────────────────────────────────────────────────────────────────── */

'use strict';


// ── State ─────────────────────────────────────────────────────────────────────
let currentMode  = 'url';
let lastReport   = null;
let lastChecks   = {};
let lastScore    = 0;
let lastLevel    = '';
let lastURL      = '';

// ── DOM refs ──────────────────────────────────────────────────────────────────
const urlInput        = document.getElementById('url-input');
const emailInput      = document.getElementById('email-input');
const urlWrapper      = document.getElementById('url-wrapper');
const emailWrapper    = document.getElementById('email-wrapper');
const urlClear        = document.getElementById('url-clear');
const vtToggle        = document.getElementById('vt-toggle');
const vtKeyArea       = document.getElementById('vt-key-area');
const vtKeyInput      = document.getElementById('vt-key');
document.getElementById('email-file').addEventListener('change',async event=>{
  const file=event.target.files?.[0];if(!file)return;
  if(file.size>5*1024*1024){document.getElementById('file-status').textContent='Choose an email under 5 MB.';return;}
  try{emailInput.value=(await file.text()).split(/\r?\n\r?\n/)[0];document.getElementById('file-status').textContent='Headers loaded locally. Run analysis when ready.';}
  catch{document.getElementById('file-status').textContent='Could not read that file.';}
});
const scanBtn         = document.getElementById('scan-btn');
const terminal        = document.getElementById('terminal');
const terminalBody    = document.getElementById('terminal-body');
const results         = document.getElementById('results');
const checksGrid      = document.getElementById('checks-grid');
const gaugeArc        = document.getElementById('gauge-arc');
const gaugeNumber     = document.getElementById('gauge-number');
const gaugeLevel      = document.getElementById('gauge-level');
const riskTargetUrl   = document.getElementById('risk-target-url');
const riskFlags       = document.getElementById('risk-flags');
const copyReportBtn   = document.getElementById('copy-report-btn');
const verdictBanner   = document.getElementById('verdict-banner');
const verdictText     = document.getElementById('verdict-text');

// ── Mode tabs ─────────────────────────────────────────────────────────────────
document.querySelectorAll('.mode-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.mode-tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected','false'); });
    tab.classList.add('active'); tab.setAttribute('aria-selected','true');
    currentMode = tab.dataset.mode;
    urlWrapper.classList.toggle('hidden',   currentMode !== 'url');
    emailWrapper.classList.toggle('hidden', currentMode !== 'email');
    document.getElementById('email-import').classList.toggle('hidden',currentMode!=='email');
  });
});

// ── URL clear ─────────────────────────────────────────────────────────────────
urlInput.addEventListener('input', () => { urlInput.setCustomValidity(''); urlClear.classList.toggle('hidden', !urlInput.value); });
urlClear.addEventListener('click', () => { urlInput.value = ''; urlInput.focus(); urlClear.classList.add('hidden'); });

// ── VT key toggle ─────────────────────────────────────────────────────────────
vtToggle.addEventListener('click', () => {
  const open = vtKeyArea.classList.toggle('hidden');
  vtToggle.setAttribute('aria-expanded', String(!open));
});


vtKeyInput.addEventListener('input', () => VT_CACHE.clear());

// ── Example chips ─────────────────────────────────────────────────────────────
document.querySelectorAll('.example-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    currentMode = 'url';
    document.querySelectorAll('.mode-tab').forEach(t => {
      const isUrl = t.dataset.mode === 'url';
      t.classList.toggle('active', isUrl);
      t.setAttribute('aria-selected', String(isUrl));
    });
    urlWrapper.classList.remove('hidden'); emailWrapper.classList.add('hidden');document.getElementById('email-import').classList.add('hidden');
    urlInput.value = chip.dataset.url; urlClear.classList.remove('hidden'); urlInput.focus();
  });
});

// ── Enter triggers scan ───────────────────────────────────────────────────────
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

// ── Copy report ───────────────────────────────────────────────────────────────
copyReportBtn.addEventListener('click', () => {
  if (!lastReport) return;
  navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2)).then(() => {
    copyReportBtn.textContent = 'Copied!';
    copyReportBtn.classList.add('copied');
    setTimeout(() => { copyReportBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none"><rect x="5" y="5" width="9" height="9" rx="1.5" stroke="currentColor" stroke-width="1.5"/><path d="M11 5V3.5A1.5 1.5 0 0 0 9.5 2h-6A1.5 1.5 0 0 0 2 3.5v6A1.5 1.5 0 0 0 3.5 11H5" stroke="currentColor" stroke-width="1.5"/></svg> Copy Report`; copyReportBtn.classList.remove('copied'); }, 2000);
  });
});

// ── Scan button ───────────────────────────────────────────────────────────────
scanBtn.addEventListener('click', startScan);

async function startScan() {
  if (scanBtn.disabled) return;
  const input = currentMode === 'url' ? normalizeInput(urlInput.value) : emailInput.value.trim();
  if (!input) { shake(currentMode === 'url' ? urlWrapper : emailWrapper); return; }

  const vtKey = vtKeyInput.value.trim();

  // Normalise URL
  let url = input;
  if (currentMode === 'url') {
    try {
      const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`);
      if (!['http:', 'https:'].includes(parsed.protocol) || (!parsed.hostname.includes('.') && !isIPHost(parsed.hostname))) throw new Error('Enter a valid HTTP or HTTPS URL.');
      url = parsed.href;
    } catch { urlInput.setCustomValidity('Enter a valid HTTP or HTTPS URL.'); urlInput.reportValidity(); return; }
  }
  urlInput.setCustomValidity('');
  const domain = (() => { try { return new URL(url).hostname; } catch { return input; } })();

  // Reset state
  lastChecks = {}; lastReport = null; lastURL = url;
  document.getElementById('coverage-note').textContent='';
  document.getElementById('report-links').replaceChildren();
  scanBtn.disabled = true;
  scanBtn.classList.add('scanning');
  terminal.classList.remove('hidden');
  results.classList.add('hidden');
  if (verdictBanner) verdictBanner.classList.add('hidden');
  terminalBody.innerHTML = '';
  checksGrid.innerHTML   = '';
  riskFlags.innerHTML    = '';
  gaugeArc.style.strokeDashoffset = '376.99';
  gaugeArc.style.stroke = 'var(--primary)';
  gaugeNumber.textContent = '--';
  gaugeLevel.textContent  = 'SCANNING';
  gaugeNumber.style.color = '';
  gaugeLevel.style.color  = '';

  tLog('$',currentMode==='email'?'Email headers (parsed locally)':input,'dim');
  if(currentMode==='url')tLog('[*]',`Domain: ${domain}`,'dim');
  tLog('[*]', 'Running checks in parallel...', 'dim');

  riskTargetUrl.textContent = url;
  riskTargetUrl.title       = url;

  // Pre-populate loading cards for URL mode
  const urlCheckNames = ['url_analysis','domain_age','ssl','redirects','lookalike','dns','infrastructure','virustotal','vt_domain'];
  const emailCheckNames = ['email_header','dkim_key','domain_age','lookalike','dns','infrastructure','vt_domain'];
  const checkNames = currentMode === 'url' ? urlCheckNames : emailCheckNames;
  for (const name of checkNames) renderCard(name, { status:'loading', label: CHECK_META[name]?.label || name, summary:'Analyzing...' });
  results.classList.remove('hidden');

  try {
    if (currentMode === 'url') {
      await runURLChecks(url, domain, vtKey);
    } else {
      await runEmailChecks(input, vtKey);
    }
  } finally {
    scanBtn.disabled = false;
    scanBtn.classList.remove('scanning');
  }
}

// ── URL analysis ──────────────────────────────────────────────────────────────
async function runURLChecks(url, domain, vtKey) {
  const checkMap = {
    url_analysis: () => Promise.resolve(checkURLStructure(url)),
    domain_age:   () => checkDomainAge(domain),
    ssl:          () => checkSSL(url, domain),
    redirects:    () => checkRedirects(url),
    lookalike:    () => Promise.resolve(checkLookalike(domain)),
    dns:          () => checkDNS(domain),
    infrastructure: () => checkInfrastructure(domain),
    vt_domain: () => checkVTDomain(domain, vtKey),
    virustotal:   () => checkVirusTotal(url, vtKey),
  };

  await Promise.all(
    Object.entries(checkMap).map(([name, fn]) =>
      Promise.resolve().then(fn)
        .then(result => { lastChecks[name] = result; onCheckDone(name, result); })
        .catch(err   => {
          const r = { status:'error', label: CHECK_META[name]?.label||name, summary: err.message };
          lastChecks[name] = r; onCheckDone(name, r);
        })
    )
  );

  finalise();
}

// ── Email header analysis ─────────────────────────────────────────────────────
async function runEmailChecks(rawHeaders, vtKey) {
  // Parse headers client-side
  const headerResult = parseEmailHeadersJS(rawHeaders);
  lastChecks['email_header'] = headerResult;
  onCheckDone('email_header', headerResult);

  const keyResult = await checkDKIM(rawHeaders);
  lastChecks.dkim_key=keyResult; onCheckDone('dkim_key',keyResult);
  const domain = headerResult.from_domain;
  lastURL = domain ? `Email from ${domain}` : 'Email headers';
  riskTargetUrl.textContent = lastURL; riskTargetUrl.title = lastURL;
  if (domain) {
    const checkMap = {
      domain_age:  () => checkDomainAge(domain),
      lookalike:   () => Promise.resolve(checkLookalike(domain)),
      dns:         () => checkDNS(domain),
      infrastructure: () => checkInfrastructure(domain),
      vt_domain: () => checkVTDomain(domain,vtKey),
    };
    await Promise.all(
      Object.entries(checkMap).map(([name, fn]) =>
        Promise.resolve().then(fn).then(r => { lastChecks[name]=r; onCheckDone(name,r); }).catch(err => {
          const r = { status:'error', label: CHECK_META[name]?.label||name, summary: err.message };
          lastChecks[name]=r; onCheckDone(name,r);
        })
      )
    );
  } else {
    for (const name of ['domain_age','lookalike','dns','infrastructure','vt_domain']) {
      const result = {status:'skipped', label:CHECK_META[name].label, summary:'No sender domain in the headers — check unavailable'};
      lastChecks[name] = result; onCheckDone(name,result);
    }
  }
  finalise();
}

// ── Basic client-side email header parser ─────────────────────────────────────
function parseEmailHeadersJS(raw) {
  raw = raw.split(/\r?\n\r?\n/)[0].replace(/\r?\n[ \t]+/g, ' ');
  const label = 'Email Header Analysis';
  const get   = key => { const m = new RegExp(`^${key}:\\s*(.+)`, 'im').exec(raw); return m?.[1]?.trim()||''; };

  const from        = get('From');
  const replyTo     = get('Reply-To');
  const returnPath  = get('Return-Path');
  const subject     = get('Subject');
  const authResults = get('Authentication-Results');

  const emailRe   = /[\w.+\-]+@([\w.\-]+\.[a-zA-Z]{2,})/;
  const fromMatch = emailRe.exec(from);
  const fromDomain = fromMatch?.[1]?.toLowerCase() || null;

  const flags = [];
  if (!fromDomain) flags.push('Sender domain missing or invalid');
  if (!authResults) flags.push('Authentication results unavailable');
  const si    = [];

  // Display-name spoof
  const dispMatch = /^"?([^"<]{3,})"?\s*</i.exec(from);
  if (dispMatch && fromDomain) {
    const dn = dispMatch[1].toLowerCase();
    for (const brand of ['paypal','amazon','google','microsoft','apple','bank','security','irs','fedex','ups']) {
      if (dn.includes(brand) && !(fromDomain === `${brand}.com` || fromDomain.endsWith(`.${brand}.com`))) {
        flags.push(`Display-name spoof: "${dispMatch[1].trim()}" from ${fromDomain}`); si.push('display_name_spoof'); break;
      }
    }
  }

  // Reply-To mismatch
  const rtMatch = emailRe.exec(replyTo);
  if (rtMatch && fromDomain && domainParts(rtMatch[1]).registered !== domainParts(fromDomain).registered) {
    flags.push(`Reply-To domain (${rtMatch[1]}) differs from From domain`); si.push('reply_to_mismatch');
  }

  // Auth results
  const spfFail  = /spf\s*=\s*fail\b/i.test(authResults);
  const dkimFail = /dkim\s*=\s*fail\b/i.test(authResults);
  const dmarcFail= /dmarc\s*=\s*fail\b/i.test(authResults);
  if (spfFail)  { flags.push('SPF FAILED — sender not authorised'); si.push('spf_fail'); }
  if (dkimFail) { flags.push('DKIM failure reported in supplied headers'); si.push('dkim_fail'); }
  if (dmarcFail){ flags.push('DMARC FAILED'); si.push('dmarc_fail'); }

  // Urgency keywords in subject
  const urgency = ['urgent','verify','suspended','action required','confirm','locked','unusual activity','compromised'];
  const hits    = urgency.filter(kw => subject.toLowerCase().includes(kw));
  if (hits.length) flags.push(`Urgency language in subject: ${hits.slice(0,2).join(', ')}`);

  const critSi = si.filter(s => ['display_name_spoof','spf_fail','dkim_fail','dmarc_fail'].includes(s));
  const status  = critSi.length >= 2 ? 'critical' : critSi.length ? 'danger' : flags.length ? 'warning' : 'safe';

  return {
    status, label,
    summary: flags[0] || 'No suspicious indicators in headers',
    from_raw: from, from_domain: fromDomain,
    reply_to: replyTo || null, return_path: returnPath || null,
    subject, auth_results: { spf: /spf\s*=\s*pass\b/i.test(authResults)?'pass':spfFail?'fail':'unknown', dkim: /dkim\s*=\s*pass\b/i.test(authResults)?'pass':dkimFail?'fail':'unknown', dmarc: /dmarc\s*=\s*pass\b/i.test(authResults)?'pass':dmarcFail?'fail':'unknown' },
    flags, suspicious_indicators: si,
    received_hops: [...raw.matchAll(/^Received:\s*(.+)$/gim)].map(m=>m[1]).slice(0,15),
    message_id:get('Message-ID'), date:get('Date'),
    signing_domains:[...raw.matchAll(/^DKIM-Signature:\s*(.+)$/gim)].map(m=>/(?:^|;)\s*d=([^;\s]+)/i.exec(m[1])?.[1]).filter(Boolean),
    source:'Supplied email headers; authentication results are reported, not independently verified',
  };
}

// ── Called when each check resolves ──────────────────────────────────────────
function onCheckDone(name, result) {
  const icon  = { info:'[i]', safe:'[✓]', warning:'[!]', danger:'[!]', critical:'[✗]', skipped:'[~]', error:'[?]' }[result.status] || '[?]';
  const cls   = { safe:'ok', warning:'warn', danger:'bad', critical:'crit' }[result.status] || '';
  const badge = { info:'info', safe:'safe', warning:'warning', danger:'danger', critical:'critical', skipped:'skipped' }[result.status] || '';
  tLog(icon, `${(result.label||name).padEnd(30)}${result.summary||''}`, null, cls, badge);
  renderCard(name, result);
}

function finalise() {
  if (!lastChecks.email_header) {
    const redirects=historicalRedirects(lastURL,lastChecks.virustotal||{});
    if(redirects){lastChecks.redirects=redirects;renderCard('redirects',redirects);}
    if(new URL(lastURL).protocol==='https:'){
      const cert=historicalCertificate(lastChecks.vt_domain||{});
      if(cert){lastChecks.ssl=cert;renderCard('ssl',cert);}
    }
  }
  tLog('[✓]', 'Analysis complete.', null, 'ok');

  lastScore  = calcRiskScore(lastChecks);
  lastLevel  = getRiskLevel(lastScore);
  const unavailable = Object.values(lastChecks).filter(c => ['skipped','error','info'].includes(c.status)).length;
  if (lastScore < 20 && unavailable) lastLevel = 'LIMITED CHECKS';
  lastReport = { url: lastURL, scanned_at:new Date().toISOString(), risk_score: lastScore, risk_level: lastLevel, checks: lastChecks };
  const checks=Object.values(lastChecks), completed=checks.filter(c=>!['skipped','error','loading'].includes(c.status)).length;
  document.getElementById('coverage-note').textContent=`${completed}/${checks.length} checks returned findings or context. Score measures detected signals; unavailable checks and historical reports cannot establish safety.`;
  const host=lastChecks.email_header?.from_domain || (()=>{try{return new URL(lastURL).hostname;}catch{return '';}})();
  const links=document.getElementById('report-links'); links.replaceChildren();
  if(host){ const link=document.createElement('a'); link.href='https://www.virustotal.com/gui/domain/'+encodeURIComponent(host);link.target='_blank';link.rel='noopener noreferrer';link.textContent='Open domain report on VirusTotal ↗'; links.appendChild(link); }

  animateGauge(lastScore, lastLevel);
  showVerdictBanner(lastScore, lastLevel);

  // Surface top flags in overview
  const topFlags = Object.values(lastChecks)
    .filter(c => ['danger','critical'].includes(c?.status))
    .map(c => ({ color: c.status === 'critical' ? '#ff1155' : '#ff4f4f', text: c.summary }));
  riskFlags.innerHTML = topFlags.slice(0, 4).map(f =>
    `<div class="risk-flag-item"><span class="dot" style="background:${f.color}"></span><span>${escHtml(f.text)}</span></div>`
  ).join('');
}

// ── Verdict banner ────────────────────────────────────────────────────────────
function showVerdictBanner(score, level) {
  if (!verdictBanner) return;
  if (score < 20) { verdictBanner.classList.add('hidden'); return; }

  verdictBanner.classList.remove('hidden');
  verdictBanner.className = 'verdict-banner';

  if (score >= 70) {
    verdictBanner.classList.add('verdict-dangerous');
    verdictBanner.innerHTML = `<span class="verdict-icon">✕</span><span><strong>DANGEROUS</strong> — High probability of phishing or malware. Avoid this ${lastURL.startsWith('Email ') ? 'message' : 'URL'}.</span>`;
  } else if (score >= 45) {
    verdictBanner.classList.add('verdict-high');
    verdictBanner.innerHTML = `<span class="verdict-icon">✕</span><span><strong>NOT TRUSTED</strong> — Multiple threat indicators detected. Do not proceed.</span>`;
  } else {
    verdictBanner.classList.add('verdict-caution');
    verdictBanner.innerHTML = `<span class="verdict-icon">⚠</span><span><strong>CAUTION</strong> — Treat with suspicion. Verify the source before clicking.</span>`;
  }
}

// ── Gauge animation ───────────────────────────────────────────────────────────
const GAUGE_ARC = 376.99;
function animateGauge(score, level) {
  const offset = GAUGE_ARC - (score / 100) * GAUGE_ARC;
  const color  = gaugeColor(score);
  gaugeArc.style.strokeDashoffset = offset;
  gaugeArc.style.stroke = color;
  gaugeLevel.textContent = level;
  gaugeLevel.style.color = color;

  const start = parseInt(gaugeNumber.textContent) || 0;
  const dur = 1400, t0 = Date.now();
  (function tick() {
    const p  = Math.min((Date.now() - t0) / dur, 1);
    const ep = 1 - Math.pow(1 - p, 3);
    gaugeNumber.textContent = Math.round(start + (score - start) * ep);
    gaugeNumber.style.color = color;
    if (p < 1) requestAnimationFrame(tick);
  })();
}

function gaugeColor(s) {
  if (s >= 70) return 'var(--critical)';
  if (s >= 45) return 'var(--danger)';
  if (s >= 20) return 'var(--warn)';
  return 'var(--primary)';
}

// ── Card renderer ─────────────────────────────────────────────────────────────
const CHECK_META = {
  infrastructure:{label:'DNS / Hosting',icon:'🌐'},
  dkim_key:{label:'DKIM signing key',icon:'🔑'},
  vt_domain:{label:'VirusTotal Domain',icon:'☣'},
  url_analysis: { label:'URL Structure',           icon:'🔗' },
  domain_age:   { label:'Domain Age',              icon:'📅' },
  ssl:          { label:'HTTPS / SSL',             icon:'🔒' },
  redirects:    { label:'Redirect Chain',          icon:'↪'  },
  lookalike:    { label:'Lookalike Detection',     icon:'👁'  },
  dns:          { label:'DNS Security',            icon:'🛡'  },
  virustotal:   { label:'VirusTotal',              icon:'☣'  },
  email_header: { label:'Email Header Analysis',   icon:'📧' },
};

function renderCard(name, result) {
  const meta    = CHECK_META[name] || { label:name, icon:'🔍' };
  const status  = result.status || 'loading';
  const label   = result.label  || meta.label;
  const summary = result.summary || '...';
  const isLoad  = status === 'loading';
  const details = ['loading','skipped','error'].includes(status) ? '' : buildDetails(name, result);

  const html = `
    <div class="check-card status-${status}${isLoad?' loading':''}" id="card-${name}">
      <div class="check-header">
        <span class="check-icon">${meta.icon}</span>
        <span class="check-label">${escHtml(label)}</span>
        <span class="check-badge ${status}">${statusBadgeLabel(status)}</span>
      </div>
      <p class="check-summary${['skipped','error'].includes(status)?' dim':''}">${escHtml(summary)}</p>
      ${details ? `
        <button class="check-details-toggle" onclick="toggleDetails(this)">
          <span class="arrow">▶</span> Details
        </button>
        <div class="check-details">${details}</div>
      ` : ''}
    </div>`;

  const existing = document.getElementById(`card-${name}`);
  if (existing) existing.outerHTML = html;
  else          checksGrid.insertAdjacentHTML('beforeend', html);
  const rank = {critical:0, danger:1, warning:2, safe:3, info:4, skipped:5, error:5, loading:6};
  [...checksGrid.children].sort((a,b) => {
    const status = el => [...el.classList].find(c => c.startsWith('status-'))?.slice(7) || 'loading';
    return (rank[status(a)] ?? 5) - (rank[status(b)] ?? 5);
  }).forEach(card => checksGrid.appendChild(card));
}

function buildDetails(name, r) {
  const rows = [];
  const dr = (key, val, cls='') =>
    val != null && val !== ''
      ? `<div class="detail-row"><span class="detail-key">${key}</span><span class="detail-val ${cls}">${escHtml(String(val))}</span></div>`
      : '';

  rows.push(dr('Source',r.source));
  rows.push(dr('Observed',r.observed_at));
  if (name === 'url_analysis') {
    rows.push(dr('Hostname',r.hostname));rows.push(dr('Actual site',r.registered_domain));rows.push(dr('Public suffix',r.public_suffix));rows.push(dr('Subdomain',r.subdomain));rows.push(dr('Port',r.port));
    if(r.flags?.length)rows.push(dr('Signals',r.flags.join(' · ')));
    for(const item of r.embedded_urls||[])rows.push(dr('Embedded '+item.parameter,item.url));
    rows.push(dr('IP address', r.is_ip_address ? 'YES' : 'No', r.is_ip_address ? 'bad' : ''));
    rows.push(dr('@ in URL', r.has_at_sign ? 'YES' : 'No', r.has_at_sign ? 'bad' : ''));
    rows.push(dr('Subdomains', r.subdomain_count != null ? String(r.subdomain_count) : null, r.excessive_subdomains ? 'bad' : ''));
    rows.push(dr('Suspicious path', r.suspicious_path ? 'YES' : 'No', r.suspicious_path ? 'warn' : ''));
    rows.push(dr('URL length', r.url_length ? `${r.url_length} chars` : null, r.very_long_url ? 'warn' : ''));
  }
  if (name === 'domain_age') {
    rows.push(dr('Domain',r.domain));rows.push(dr('Registrar',r.registrar));rows.push(dr('Status',r.registration_status?.join(', ')));
    rows.push(dr('Registered', r.registered ? r.registered.slice(0,10) : 'Unknown'));
    rows.push(dr('Expires',    r.expires    ? r.expires.slice(0,10)    : 'Unknown'));
    rows.push(dr('Age', r.ageDays != null ? `${r.ageDays} days` : 'Unknown', r.ageDays == null ? '' : r.ageDays < 90 ? 'bad' : 'good'));
  }
  if (name === 'ssl') {
    rows.push(dr('Protocol',r.protocol));rows.push(dr('Live certificate','Unverified'));
    rows.push(dr('Issuer (stored)',r.issuer));rows.push(dr('Subject (stored)',r.subject));rows.push(dr('Valid from (stored)',r.not_before));rows.push(dr('Valid until (stored)',r.not_after));
  }
  if (name === 'redirects') {
    if(r.redirected!=null)rows.push(dr('Redirected (stored)',r.redirected?'Yes':'No'));
    for(const item of r.embedded_urls||[])rows.push(dr('Embedded '+item.parameter,item.url));
    for(const [i,hop] of (r.redirect_chain||[]).entries())rows.push(dr('Hop '+(i+1),hop));
    rows.push(dr('Cross-domain', r.cross_domain==null?'Unverified':r.cross_domain?'YES':'No', r.cross_domain ? 'warn' : ''));
    rows.push(dr('Final URL',    r.final_url));
  }
  if (name === 'lookalike') {
    rows.push(dr('Best match',   r.best_match ? `${r.best_match}.com` : 'None', r.best_match ? 'warn' : 'good'));
    rows.push(dr('Similarity',   r.similarity_score != null ? `${r.similarity_score}%` : null));
    rows.push(dr('Homoglyphs',   r.has_homoglyphs ? 'YES' : 'No', r.has_homoglyphs ? 'bad' : ''));
    rows.push(dr('Number sub',   r.has_number_substitution ? 'YES' : 'No'));
    rows.push(dr('Punycode',     r.is_punycode ? 'YES' : 'No',    r.is_punycode ? 'bad' : ''));
    rows.push(dr('TLD',          r.tld, r.suspicious_tld ? 'bad' : ''));
  }
  if (name === 'dns') {
    rows.push(dr('SPF',   r.spf?.found   ? (r.spf.record||'Found') : 'MISSING', r.spf?.found ? '' : 'bad'));
    rows.push(dr('DMARC', r.dmarc?.found ? `Policy: ${r.dmarc.policy||'?'}` : 'MISSING', !r.dmarc?.found ? 'bad' : r.dmarc?.policy==='none' ? 'warn' : 'good'));
    rows.push(dr('DKIM',  r.dkim?.found ? `Selector: ${r.dkim.selector}` : 'Unverified — requires s= and d= from an email DKIM-Signature', r.dkim?.found ? 'good' : ''));
  }
  if (name === 'infrastructure') {
    rows.push(dr('Host',r.hostname));rows.push(dr('Domain',r.registered_domain));
    for(const [type,values] of Object.entries(r.records||{}))rows.push(dr(type,values.join(' · ')||'No record returned'));
    rows.push(dr('DNSSEC',r.dnssec_authenticated?'Resolver authenticated the response':'Not confirmed (not a threat by itself)'));rows.push(dr('Lookup errors',r.errors?.join(' · ')));
  }
  if(name==='dkim_key') for(const key of r.keys||[])rows.push(dr(key.selector||'Signature', (key.domain||'')+' — '+key.summary));
  if (name === 'virustotal' || name === 'vt_domain') {
    rows.push(dr('Categories',r.categories?.join(', ')));rows.push(dr('Flagged engines',r.flagged_engines?.join(' · ')));rows.push(dr('Final URL (stored)',r.final_url));rows.push(dr('Page title (stored)',r.title));
    rows.push(dr('Malicious',  r.malicious  != null ? `${r.malicious} / ${r.total_engines}` : null, r.malicious > 0 ? 'bad' : 'good'));
    rows.push(dr('Suspicious', r.suspicious != null ? String(r.suspicious) : null));
    rows.push(dr('Harmless',   r.harmless   != null ? String(r.harmless)   : null, r.harmless > 0 ? 'good' : ''));
  }
  if (name === 'email_header') {
    rows.push(dr('Message ID',r.message_id)); rows.push(dr('Date',r.date));rows.push(dr('Signing domains',r.signing_domains?.join(', ')));
    for(const [i,hop] of (r.received_hops||[]).entries())rows.push(dr('Received '+(i+1),hop));
    rows.push(dr('From',       r.from_raw));
    rows.push(dr('Domain',     r.from_domain));
    rows.push(dr('Reply-To',   r.reply_to));
    rows.push(dr('Subject',    r.subject?.slice(0,60)));
    rows.push(dr('SPF',        r.auth_results?.spf,   r.auth_results?.spf==='fail' ? 'bad' : r.auth_results?.spf==='pass' ? 'good' : ''));
    rows.push(dr('DKIM',       r.auth_results?.dkim,  r.auth_results?.dkim==='fail' ? 'bad' : ''));
    rows.push(dr('DMARC',      r.auth_results?.dmarc, r.auth_results?.dmarc==='fail' ? 'bad' : ''));
    if (r.flags?.length) rows.push(`<div class="detail-row"><span class="detail-key">Flags</span><span class="detail-val bad">${escHtml(r.flags.join(' · '))}</span></div>`);
  }
  return rows.filter(Boolean).join('');
}

// ── Terminal helpers ──────────────────────────────────────────────────────────
function tLog(icon, text, dimClass=null, iconCls='', badge='') {
  const line = document.createElement('div');
  line.className = 't-line';
  line.innerHTML = `
    <span class="t-icon ${iconCls}">${escHtml(icon)}</span>
    <span class="t-text${dimClass==='dim'?' dim':''}">${escHtml(text)}</span>
    ${badge ? `<span class="t-badge ${badge}">${badge.toUpperCase()}</span>` : ''}`;
  terminalBody.appendChild(line);
  terminalBody.scrollTop = terminalBody.scrollHeight;
}

// ── Misc helpers ──────────────────────────────────────────────────────────────
function statusBadgeLabel(s) {
  return { info:'INFO', safe:'SAFE', warning:'WARNING', danger:'DANGER', critical:'CRITICAL',
           skipped:'SKIPPED', error:'ERROR', loading:'LOADING' }[s] || s.toUpperCase();
}
function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function shake(el) {
  el.style.animation = 'none'; el.offsetHeight;
  el.style.animation = 'shake 0.35s ease';
  setTimeout(() => el.style.animation = '', 400);
}
function toggleDetails(btn) {
  btn.classList.toggle('open');
  const d = btn.nextElementSibling; d.classList.toggle('visible');
  btn.querySelector('.arrow').textContent = d.classList.contains('visible') ? '▼' : '▶';
}

// Shake keyframe
const _ks = document.createElement('style');
_ks.textContent = `@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-6px)}40%{transform:translateX(6px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}}`;
document.head.appendChild(_ks);

// ── Auto-scan from ?url= query param (used by extension "Full Analysis" link) ─
window.addEventListener('load', () => {
  const params = new URLSearchParams(window.location.search);
  const autoURL = params.get('url') ||
    (location.hash.startsWith('#url=') ? new URLSearchParams(location.hash.slice(1)).get('url') : null);

  if (autoURL) {
    currentMode = 'url';
    urlInput.value = autoURL;
    urlClear.classList.remove('hidden');
    // Small delay so page renders first
    setTimeout(startScan, 300);
  }
});