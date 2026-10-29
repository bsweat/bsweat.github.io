/* Browser-only analysis. No backend, public CORS proxy, or target-page execution. */
'use strict';
const SUFFIX_SETS = {
  icann: new Set(SUFFIX_RULES.icann),
  all: new Set([...SUFFIX_RULES.icann, ...SUFFIX_RULES.private]),
};
function isIPHost(host) { return /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':'); }
function domainParts(host, includePrivate = true) {
  host = host.toLowerCase().replace(/\.$/, '');
  if (isIPHost(host)) return {hostname:host, registered:host, suffix:'', subdomain:'', label:host, ip:true};
  const labels=host.split('.'), rules=includePrivate ? SUFFIX_SETS.all : SUFFIX_SETS.icann;
  let length=1;
  for(let i=0;i<labels.length;i++) {
    const candidate=labels.slice(i).join('.');
    if(rules.has('!'+candidate)){length=labels.length-i-1;break;}
    if(rules.has(candidate)) length=Math.max(length,labels.length-i);
    if(i>0 && rules.has('*.'+candidate)) length=Math.max(length,labels.length-i+1);
  }
  const registered=labels.slice(-length-1).join('.');
  return {hostname:host,registered,suffix:labels.slice(-length).join('.'),subdomain:labels.slice(0,-length-1).join('.'),label:labels.at(-length-1)||labels[0],ip:false};
}
function normalizeInput(input) {
  return input.trim().replace(/^hxxps:/i,'https:').replace(/^hxxp:/i,'http:').replace(/\[\.\]|\(\.\)/g,'.');
}
function embeddedURLs(url) {
  const parsed=new URL(url), found=[];
  for(const [key,raw] of parsed.searchParams) {
    if(!/^(url|u|q|target|dest|destination|redirect|redirect_uri|redirect_url|continue|next|return|returnurl|return_url|r)$/i.test(key))continue;
    let value=raw;
    for(let depth=0;depth<3;depth++) {
      try {const child=new URL(value);if(['https:','http:'].includes(child.protocol)){found.push({parameter:key,url:child.href,domain:domainParts(child.hostname).registered});break;}} catch {}
      try {const decoded=decodeURIComponent(value);if(decoded===value)break;value=decoded;}catch{break;}
    }
  }
  return found.slice(0,10);
}
function checkURLStructure(url) {
  const r=checkURLStructureBase(url);if(r.status==='error')return r;
  const u=new URL(url),p=domainParts(u.hostname),flags=[...(r.flags||[])];
  r.hostname=u.hostname;r.registered_domain=p.registered;r.public_suffix=p.suffix;r.subdomain=p.subdomain;
  r.is_ip_address=p.ip;r.subdomain_count=p.subdomain?p.subdomain.split('.').length:0;
  r.excessive_subdomains=r.subdomain_count>=3;
  r.port=u.port || (u.protocol==='https:'?'443':'80');
  r.embedded_urls=embeddedURLs(url);
  r.deceptive_subdomain=!!p.subdomain && TOP_BRANDS.some(b=>p.subdomain.split('.').includes(b) && p.registered!==b+'.com');
  r.executable_download=/\.(exe|scr|msi|bat|cmd|ps1|vbs|hta|js|jar|lnk|iso|img)(?:$|[?#])/i.test(u.pathname);
  r.unusual_port=!!u.port && !['80','443'].includes(u.port);
  r.shortener=['bit.ly','t.co','tinyurl.com','is.gd','cutt.ly','shorturl.at','rb.gy','ow.ly','buff.ly'].includes(p.registered);
  if(p.ip && !flags.some(f=>f.includes('IP address')))flags.push('IP address used instead of a domain');
  if(r.deceptive_subdomain)flags.push('Brand name in subdomain; actual site is '+p.registered);
  if(r.executable_download)flags.push('Link points to an executable or script download');
  if(r.unusual_port)flags.push('Unusual port: '+u.port);
  if(r.shortener)flags.push('Shortened URL hides the destination');
  if(r.embedded_urls.length)flags.push('Embedded destination: '+r.embedded_urls.map(e=>e.domain).join(', '));
  r.flags=flags;
  if(r.has_at_sign||p.ip)r.status='critical';
  else if(r.deceptive_subdomain||r.executable_download)r.status='danger';
  else if(r.unusual_port||r.shortener||r.embedded_urls.length)r.status=r.status==='safe'?'warning':r.status;
  r.summary=flags.length?flags.join('; '):'No suspicious URL structure detected';
  r.source='Local URL analysis';return r;
}
function checkLookalike(host) {
  if(isIPHost(host))return {status:'skipped',label:'Lookalike Detection',summary:'Brand similarity applies to domain names, not IP addresses'};
  const known = new Set(['google.co.uk','google.de','google.fr','google.ca','amazon.co.uk','amazon.de','amazon.co.jp','paypal.co.uk']);
  const registered=domainParts(host).registered;
  if(known.has(registered))return {status:'safe',label:'Lookalike Detection',summary:'Matches a known brand domain: '+registered,registered_domain:registered,is_lookalike:false};
  const r=checkLookalikeBase(host);r.registered_domain=registered;
  return r;
}
function checkSSL(url) {
  const https=new URL(url).protocol==='https:';
  return {status:https?'info':'danger',label:'HTTPS / certificate',summary:https?'HTTPS specified. Browser-only scans cannot inspect the live certificate; a VirusTotal domain report may supply a dated observation.':'HTTP link — the initial connection is not encrypted',valid:null,protocol:https?'HTTPS':'HTTP',source:'URL scheme only'};
}
function checkRedirects(url) {
  const embedded=embeddedURLs(url);
  return {status:embedded.length?'warning':'info',label:'Redirects / embedded links',summary:embedded.length?'Destination embedded in the URL — not a verified redirect':'Live redirects cannot be traced here. VirusTotal may provide a previously observed chain.',embedded_urls:embedded,source:'Local URL analysis'};
}
async function queryDNS(name,type) {
  const r=await timedFetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,{headers:{Accept:'application/dns-json'},credentials:'omit',referrerPolicy:'no-referrer'});
  if(!r.ok)throw Error('DNS HTTP '+r.status);
  const data=await r.json();if(![0,3].includes(data.Status))throw Error('DNS status '+data.Status);
  return {answers:(data.Answer||[]).filter(a=>a.type===({A:1,AAAA:28,MX:15,NS:2,CAA:257,TXT:16}[type])),authenticated:!!data.AD,nxdomain:data.Status===3};
}
async function checkInfrastructure(host) {
  const label='DNS / hosting';if(isIPHost(host))return {status:'info',label,summary:'IP-literal target — no domain DNS lookup',hostname:host};
  const registered=domainParts(host,false).registered;
  const types=['A','AAAA','MX','NS','CAA'];
  const settled=await Promise.allSettled(types.map(type=>queryDNS(['A','AAAA'].includes(type)?host:registered,type)));
  const records={},errors=[];let authenticated=false,nxdomain=false;
  settled.forEach((r,i)=>{if(r.status==='fulfilled'){records[types[i]]=r.value.answers.map(a=>a.data);authenticated ||= r.value.authenticated;if(i<2)nxdomain ||= r.value.nxdomain;}else errors.push(types[i]+': '+r.reason.message);});
  if(!Object.keys(records).length)return {status:'error',label,summary:'DNS infrastructure lookups unavailable',errors,source:'Cloudflare DNS-over-HTTPS'};
  const addresses=[...(records.A||[]),...(records.AAAA||[])];
  const privateAddresses=addresses.filter(isNonPublicAddress);
  return {status:privateAddresses.length?'danger':nxdomain?'warning':'info',label,summary:privateAddresses.length?'DNS resolves to a private or special-use address':nxdomain?'Domain does not exist in DNS':addresses.length?`${addresses.length} address(es) found; ${authenticated?'DNSSEC-authenticated response':'DNSSEC authentication not confirmed'}`:'No address records confirmed',records,errors,dnssec_authenticated:authenticated,hostname:host,registered_domain:registered,private_addresses:privateAddresses,source:'Cloudflare DNS-over-HTTPS'};
}
function isNonPublicAddress(address) {
  const x=address.toLowerCase();if(x.includes(':'))return x==='::'||x==='::1'||/^(fc|fd|fe8|fe9|fea|feb|ff)/.test(x)||x.startsWith('2001:db8:')||x.startsWith('::ffff:');
  const n=x.split('.').map(Number);return n[0]===0||n[0]===10||n[0]===127||n[0]>=224||(n[0]===169&&n[1]===254)||(n[0]===172&&n[1]>=16&&n[1]<=31)||(n[0]===192&&[0,168].includes(n[1]))||(n[0]===100&&n[1]>=64&&n[1]<=127)||(n[0]===198&&[18,19].includes(n[1]));
}
async function checkDKIM(raw) {
  const label='DKIM signing key';const unfolded=raw.replace(/\r?\n[ \t]+/g,' ');
  const signatures=[...unfolded.matchAll(/^DKIM-Signature:\s*(.+)$/gim)].slice(0,4);
  if(!signatures.length)return {status:'skipped',label,summary:'No DKIM-Signature header supplied'};
  const keys=[];
  for(const signature of signatures) {
    const tags=Object.fromEntries(signature[1].split(';').map(v=>{const i=v.indexOf('=');return i<0?[]:[v.slice(0,i).trim().toLowerCase(),v.slice(i+1).trim()];}).filter(p=>p.length===2));
    if(!tags.s||!tags.d||!/^[-a-z0-9_.]+$/i.test(tags.s)||!/^[-a-z0-9.]+$/i.test(tags.d)){keys.push({status:'warning',summary:'Invalid selector or signing domain'});continue;}
    try {const records=await dohQuery(`${tags.s}._domainkey.${tags.d}`,'TXT');const key=records.find(r=>/(?:^|;)\s*p\s*=\s*[A-Za-z0-9+/]{16,}/i.test(r));keys.push({status:key?'info':'warning',domain:tags.d,selector:tags.s,found:!!key,summary:key?'Public key found; signature not cryptographically verified':'No active public key found for the supplied selector'});}catch(e){keys.push({status:'error',domain:tags.d,selector:tags.s,summary:e.message});}
  }
  return {status:keys.some(k=>k.status==='warning')?'warning':keys.every(k=>k.status==='error')?'error':'info',label,summary:keys.map(k=>`${k.domain||'Signature'}: ${k.summary}`).join('; '),keys,source:'Selector from supplied header; DNS lookup only'};
}
const VT_CACHE=new Map();
async function vtGet(path,key) {
  const cacheKey=key+'|'+path,cached=VT_CACHE.get(cacheKey);if(cached&&Date.now()-cached.time<300000)return cached.value;
  const response=await timedFetch('https://www.virustotal.com/api/v3/'+path,{headers:{'x-apikey':key},credentials:'omit',referrerPolicy:'no-referrer'});
  const value={status:response.status,ok:response.ok,attributes:response.ok?(await response.json()).data?.attributes||{}:null};
  if(response.ok)VT_CACHE.set(cacheKey,{time:Date.now(),value});return value;
}
function vtFailure(r,label) {
  return {status:'skipped',label,summary:r.status===401?'VirusTotal rejected the API key':r.status===403?'VirusTotal denied this request (key permissions or account restrictions)':r.status===404?'No existing VirusTotal report. This tool does not automatically submit URLs.':r.status===429?'VirusTotal quota reached — wait before scanning again':`VirusTotal HTTP ${r.status}`,http_status:r.status};
}
function vtStats(a,label) {
  const stats=a.last_analysis_stats||{},m=stats.malicious||0,s=stats.suspicious||0,total=Object.values(stats).reduce((sum,n)=>sum+(Number(n)||0),0);
  return {status:!total?'skipped':m>=5?'critical':m>=2?'danger':m||s?'warning':'safe',label,summary:!total?'No engine results available':`${m} malicious, ${s} suspicious / ${total} engines (stored report)`,malicious:m,suspicious:s,harmless:stats.harmless||0,undetected:stats.undetected||0,total_engines:total,observed_at:a.last_analysis_date?new Date(a.last_analysis_date*1000).toISOString():null,flagged_engines:Object.entries(a.last_analysis_results||{}).filter(([,r])=>['malicious','suspicious'].includes(r.category)).map(([name,r])=>name+': '+r.result).slice(0,15),source:'VirusTotal historical report'};
}
async function checkVirusTotal(url,key) {
  const label='VirusTotal URL';if(!key)return {status:'skipped',label,summary:'No API key — expand VirusTotal API Key above'};
  try {const id=btoa(String.fromCharCode(...new TextEncoder().encode(url))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');const r=await vtGet('urls/'+id,key);if(!r.ok)return vtFailure(r,label);const a=r.attributes;return {...vtStats(a,label),final_url:a.last_final_url||null,redirect_chain:a.redirection_chain||[],http_status:a.last_http_response_code,title:a.title||null,categories:[...new Set(Object.values(a.categories||{}))],report_url:'https://www.virustotal.com/gui/url/'+id};}catch{return {status:'skipped',label,summary:'VirusTotal could not be read in this browser (CORS, network, or timeout). Use the manual report link below.'};}
}
async function checkVTDomain(host,key) {
  const label='VirusTotal domain';if(!key)return {status:'skipped',label,summary:'Add a VirusTotal API key for domain reputation and stored certificate data'};
  if(isIPHost(host))return {status:'skipped',label,summary:'Domain report is unavailable for an IP-literal target'};
  try {const r=await vtGet('domains/'+encodeURIComponent(host),key);if(!r.ok)return vtFailure(r,label);const a=r.attributes;return {...vtStats(a,label),certificate:a.last_https_certificate||null,certificate_observed_at:a.last_https_certificate_date?new Date(a.last_https_certificate_date*1000).toISOString():null,registrar:a.registrar||null,categories:[...new Set(Object.values(a.categories||{}))]};}catch{return {status:'skipped',label,summary:'VirusTotal domain report unavailable in this browser (CORS, network, or timeout)'};}
}
function historicalRedirects(url,vt) {
  if(!vt.observed_at||(!vt.final_url&&!vt.redirect_chain?.length))return null;
  const chain=[url,...(vt.redirect_chain||[]),vt.final_url].filter(Boolean).filter((v,i,a)=>i===0||v!==a[i-1]);
  const final=chain.at(-1);let cross=false;try{cross=domainParts(new URL(final).hostname).registered!==domainParts(new URL(url).hostname).registered;}catch{return null;}
  return {status:cross?'warning':'info',label:'Redirects / embedded links',summary:cross?'VirusTotal previously observed a redirect to a different site':'VirusTotal stored destination available — not a live redirect test',final_url:final,redirect_chain:chain,cross_domain:cross,redirected:chain.length>1,observed_at:vt.observed_at,source:'VirusTotal historical report',embedded_urls:embeddedURLs(url)};
}
function historicalCertificate(domainReport) {
  const c=domainReport.certificate;if(!c)return null;
  return {status:'info',label:'HTTPS / certificate',summary:'Certificate previously observed by VirusTotal — live trust and current certificate are unverified',valid:null,protocol:'HTTPS',issuer:c.issuer?.O||c.issuer?.CN||null,subject:c.subject?.CN||null,not_before:c.validity?.not_before||null,not_after:c.validity?.not_after||null,observed_at:domainReport.certificate_observed_at,source:'VirusTotal historical report'};
}
