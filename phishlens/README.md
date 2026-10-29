# PhishLens — static GitHub Pages edition

No backend, server account, package installation, or build is needed. Open index.html locally, or place the deployment files in your existing GitHub Pages phishlens/ folder.

## Deployment

Extract phishlens-github-pages.zip into the website's phishlens/ folder, replacing matching files. Keep these files together:

- index.html
- style.css
- app.js
- analyzer.js
- browser-checks.js
- public-suffix.js
- public_suffix_list.dat (upstream source and license notice)
- threat-examples.json and THREAT-FEED-LICENSE.txt (example provenance and feed license)

The ZIP contains no API key, tests, screenshots, or development scripts.

## What it checks

- URL structure: credentials in the authority, IP literals including IPv6, misleading brand subdomains, executable/script downloads, nonstandard ports, shorteners, long/encoded links, and embedded destination parameters. Defanged hxxp and [.] inputs are normalized locally.
- Actual domain boundaries using a bundled Public Suffix List, including private hosting suffixes, wildcard rules and exceptions. Registration lookups use the ICANN registration domain.
- Brand similarity and substitutions, with a small curated list of known brand domains. Similarity is a heuristic, not ownership verification.
- Registration age, registration/expiry dates, registrar and statuses from RDAP where accessible.
- DNS A, AAAA, MX, NS and CAA records; DNSSEC AD status reported by the resolver; private/special-use address signals. DNSSEC being unconfirmed does not add risk.
- SPF and DMARC policy context. Missing mail policies do not by themselves raise a web URL's risk score.
- Email Authentication-Results as reported in supplied headers, display-name spoof signals, Reply-To domain mismatch, subject urgency, Received hops, Message-ID, signing domains, and selector-specific DKIM public-key lookup. Load .eml/.txt files locally (5 MB maximum); only headers are loaded into the input.
- Optional VirusTotal URL and domain reputation, engine names/results, report observation dates, categories, stored final destination/redirect chain and stored certificate issuer, subject and validity dates.
- Sorted results, source details, coverage explanation, manual VirusTotal report link and JSON report copying.

## Data flow and key handling

URL parsing, suffix matching, lookalike checks and header parsing run locally. No suspicious target page is fetched, embedded, opened or executed by the scanner.

Cloudflare DNS-over-HTTPS receives queried hostnames and DKIM selector names. rdap.org and its registry redirects receive the registration domain. With an API key, VirusTotal receives the supplied URL and hostname for existing report retrieval. Full email headers are not uploaded. Links to manual reports open only when clicked.

The API key remains in the current tab's password field and in-memory report cache; it is not included in source, ZIP files, exported reports, localStorage or sessionStorage. Reports are cached for 5 minutes, keyed by the current API key; editing the key clears the cache. Each uncached URL scan uses up to two VirusTotal requests, and each email scan uses one. Quota and authorization failures are displayed without inventing safe results. Unknown URLs are not automatically submitted for scanning.

## Browser limits

GitHub Pages cannot perform arbitrary live TLS certificate inspection or live redirect tracing. HTTPS scheme inspection is distinguished from certificate verification. VirusTotal redirect/certificate evidence is explicitly historical and dated; it does not establish current trust, hostname validation, revocation or current reachability. No public CORS proxy is used.

DKIM key presence does not verify a signature. Supplied Authentication-Results can be forged and are not independently authenticated. Missing/retired selectors do not establish that a domain has no DKIM. The tool does not download attachments or inspect target-page HTML.

The score represents detected heuristics, not a probability or guarantee. INFO and unavailable checks do not add risk. Historical reputation engines can disagree, including on legitimate sites. Check the engine names, dates and supporting evidence.

## Verification and maintenance

Run `node --test analyzer.test.cjs` for the regression suite. Node is used only for development tests; visitors do not need it.

The static edition was tested with live browser RDAP, Cloudflare DNS and authenticated VirusTotal URL/domain reports. Mobile rendering was checked at 390 px. No credential is included in the test fixtures.

public_suffix_list.dat is an official snapshot from https://publicsuffix.org/list/public_suffix_list.dat. Its Mozilla Public License 2.0 notice is retained in that file; public-suffix.js is the normalized rule representation. Refresh the vendored list periodically as domain registry rules change.

References:
- https://publicsuffix.org/list/
- https://docs.virustotal.com/reference/url-object
- https://docs.virustotal.com/reference/domains-object
- https://www.rfc-editor.org/rfc/rfc6376.html

## Dated examples

The example library contains two safe reference domains (Google and Wikipedia), a legitimate Google sign-in URL whose login-related path may trigger caution, and five real feed-listed phishing URLs. Labels are reference context, not forced scanner verdicts. Phishing examples are sourced from the CC0 Phishunt rolling 24-hour feed, updated 2026-10-29T13:02:48Z. `threat-examples.json` preserves the exact source commit, per-entry observation times and upstream signals; `THREAT-FEED-LICENSE.txt` retains the feed license. Sites were not opened to verify reachability, and feed-listed active status can change. Threat examples are defanged in display and implemented as input-fill buttons, not navigation links.
