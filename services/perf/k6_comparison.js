/**
 * Synorix Proxy – Compression & Deduplication Measurement
 *
 * Scenarios:
 *  1) baseline_uncompressed: unique GET requests with Accept-Encoding=identity
 *  2) fresh_compressed:      unique GET requests with Accept-Encoding=gzip
 *  3) repeat_compressed:     repeated GET requests (10 keys) with gzip for dedup cache hits
 *
 * This allows clear, non-misleading comparisons:
 *  - Compression bandwidth saving: baseline_uncompressed vs fresh_compressed
 *  - Dedup latency improvement:    fresh_compressed vs repeat_compressed
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import crypto from 'k6/crypto';

const API_KEY = __ENV.API_KEY || '';
const PERF_SECRET = __ENV.PERF_SECRET || '';
const PROXY_URL = (__ENV.PROXY_URL || 'http://127.0.0.1:8080/user-proxy').replace(/\/$/, '');
const TARGET_PATH = __ENV.TARGET_PATH || '/api/large-response';
const DEDUP_STABLE_PATH = __ENV.DEDUP_STABLE_PATH || TARGET_PATH;
const DEDUP_CHURN_PATH = __ENV.DEDUP_CHURN_PATH || TARGET_PATH;
const RESULTS_DIR = __ENV.RESULTS_DIR || 'results';
const STRICT_AI = (__ENV.STRICT_AI || '1').toLowerCase();
const HTTP_TIMEOUT = __ENV.HTTP_TIMEOUT || '30s';

if (!API_KEY) throw new Error('API_KEY is required. Pass with -e API_KEY=nxr_...');
if (!PERF_SECRET) throw new Error('PERF_SECRET is required. Pass with -e PERF_SECRET=<secret>');

function perfToken() {
  const ts = Math.floor(Date.now() / 1000).toString();
  const sig = crypto.hmac('sha256', PERF_SECRET, ts, 'hex');
  return `${ts}:${sig}`;
}

const ttfbBaseline = new Trend('ttfb_baseline_ms', true);
const ttfbFresh = new Trend('ttfb_fresh_ms', true);
const ttfbRepeat = new Trend('ttfb_repeat_ms', true);
const ttfbDedupStable = new Trend('ttfb_dedup_stable_ms', true);
const ttfbDedupChurn = new Trend('ttfb_dedup_churn_ms', true);

const bytesBaseline = new Counter('bytes_baseline');
const bytesFresh = new Counter('bytes_fresh');
const bytesRepeat = new Counter('bytes_repeat');
const bytesDedupStable = new Counter('bytes_dedup_stable');
const bytesDedupChurn = new Counter('bytes_dedup_churn');
const aiCompressionUsed = new Counter('ai_compression_used');
const aiDedupUsed = new Counter('ai_dedup_used');
const dedupCacheHitCount = new Counter('dedup_cache_hit_count');
const dedupCacheMissCount = new Counter('dedup_cache_miss_count');

const failBaseline = new Rate('fail_baseline');
const failFresh = new Rate('fail_fresh');
const failRepeat = new Rate('fail_repeat');
const failDedupStable = new Rate('fail_dedup_stable');
const failDedupChurn = new Rate('fail_dedup_churn');

export const options = {
  scenarios: {
    baseline_uncompressed: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 10 },
        { duration: '2m', target: 20 },
        { duration: '30s', target: 0 },
      ],
      tags: { scenario: 'baseline' },
      exec: 'baselineScenario',
    },
    fresh_compressed: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 10 },
        { duration: '2m', target: 20 },
        { duration: '30s', target: 0 },
      ],
      tags: { scenario: 'fresh' },
      exec: 'freshScenario',
    },
    repeat_compressed: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 10 },
        { duration: '2m', target: 20 },
        { duration: '30s', target: 0 },
      ],
      tags: { scenario: 'repeat' },
      exec: 'repeatScenario',
    },
    dedup_stable: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 6 },
        { duration: '70s', target: 12 },
        { duration: '20s', target: 0 },
      ],
      tags: { scenario: 'dedup_stable' },
      exec: 'dedupStableScenario',
      startTime: '5s',
    },
    dedup_churn: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 6 },
        { duration: '70s', target: 12 },
        { duration: '20s', target: 0 },
      ],
      tags: { scenario: 'dedup_churn' },
      exec: 'dedupChurnScenario',
      startTime: '5s',
    },
  },
  thresholds: {
    ttfb_baseline_ms: ['p(95)<15000'],
    ttfb_fresh_ms: ['p(95)<15000'],   // fresh hits AI every req (no cache) – higher latency expected
    ttfb_repeat_ms: ['p(95)<5000'],
    ttfb_dedup_stable_ms: ['p(95)<5000'],
    ttfb_dedup_churn_ms: ['p(95)<15000'], // churn = always miss, same as fresh
    fail_baseline: ['rate<0.10'],
    fail_fresh: ['rate<0.10'],           // relaxed: fresh latency spikes are expected
    fail_repeat: ['rate<0.05'],
    fail_dedup_stable: ['rate<0.05'],
    fail_dedup_churn: ['rate<0.10'],     // churn always misses, latency can spike
    ai_compression_used: ['count>0'],
    ai_dedup_used: ['count>0'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(75)', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

function baseHeaders(acceptEncoding) {
  const strictEnabled = STRICT_AI === '1' || STRICT_AI === 'true' || STRICT_AI === 'yes' || STRICT_AI === 'on';
  return {
    'X-API-Key': API_KEY,
    'X-Synorix-Perf-Token': perfToken(),
    'Accept-Encoding': acceptEncoding,
    ...(strictEnabled ? { 'X-Synorix-Strict-AI': '1' } : {}),
  };
}

function runGet(id, acceptEncoding, scenarioTag, path = TARGET_PATH) {
  const url = `${PROXY_URL}${path}?id=${id}`;
  const res = http.get(url, {
    headers: baseHeaders(acceptEncoding),
    timeout: HTTP_TIMEOUT,
    tags: { endpoint: 'user-proxy', scenario: scenarioTag },
  });

  const getHeaderCI = (headers, name) => {
    if (!headers) return '';
    const needle = name.toLowerCase();
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() === needle) {
        return value;
      }
    }
    return '';
  };

  const aiCompression = (getHeaderCI(res.headers, 'x-synorix-ai-compression') || '').toString().toLowerCase();
  if (aiCompression === '1' || aiCompression === 'true' || aiCompression === 'yes') {
    aiCompressionUsed.add(1);
  }

  const aiDedup = (getHeaderCI(res.headers, 'x-synorix-ai-dedup') || '').toString().toLowerCase();
  if (aiDedup === '1' || aiDedup === 'true' || aiDedup === 'yes') {
    aiDedupUsed.add(1);
  }

  const xCache = (getHeaderCI(res.headers, 'x-cache') || '').toString().toUpperCase();
  if (xCache === 'HIT') {
    dedupCacheHitCount.add(1);
  } else if (xCache === 'MISS') {
    dedupCacheMissCount.add(1);
  }

  return res;
}

export function baselineScenario() {
  const uniqueId = __VU * 100000 + __ITER;
  const res = runGet(uniqueId, 'identity', 'baseline');

  const ok = check(res, {
    'baseline: status < 400': (r) => r.status < 400,
    'baseline: latency < 5s': (r) => r.timings.duration < 5000,
  });

  failBaseline.add(!ok);
  ttfbBaseline.add(res.timings.waiting);
  // Use Content-Length (wire bytes) so gzip compression is visible; fall back to body length
  const clBaseline = res.headers['Content-Length'] || res.headers['content-length'];
  bytesBaseline.add(clBaseline ? parseInt(clBaseline, 10) : (res.body ? res.body.length : 0));
  sleep(0.1);
}

export function freshScenario() {
  const uniqueId = __VU * 100000 + __ITER;
  const res = runGet(uniqueId, 'gzip, deflate, br', 'fresh');

  const ok = check(res, {
    'fresh: status < 400': (r) => r.status < 400,
    'fresh: latency < 15s': (r) => r.timings.duration < 15000,
  });

  failFresh.add(!ok);
  ttfbFresh.add(res.timings.waiting);
  const clFresh = res.headers['Content-Length'] || res.headers['content-length'];
  bytesFresh.add(clFresh ? parseInt(clFresh, 10) : (res.body ? res.body.length : 0));
  sleep(0.1);
}

export function repeatScenario() {
  const dedupId = __ITER % 10;
  const res = runGet(dedupId, 'gzip, deflate, br', 'repeat');

  const ok = check(res, {
    'repeat: status < 400': (r) => r.status < 400,
    'repeat: latency < 5s': (r) => r.timings.duration < 5000,
  });

  failRepeat.add(!ok);
  ttfbRepeat.add(res.timings.waiting);
  const clRepeat = res.headers['Content-Length'] || res.headers['content-length'];
  bytesRepeat.add(clRepeat ? parseInt(clRepeat, 10) : (res.body ? res.body.length : 0));
  sleep(0.1);
}

export function dedupStableScenario() {
  const stableId = __ITER % 10;
  const res = runGet(stableId, 'gzip, deflate, br', 'dedup_stable', DEDUP_STABLE_PATH);

  const ok = check(res, {
    'dedup_stable: status < 400': (r) => r.status < 400,
    'dedup_stable: latency < 5s': (r) => r.timings.duration < 5000,
  });

  failDedupStable.add(!ok);
  ttfbDedupStable.add(res.timings.waiting);
  const clStable = res.headers['Content-Length'] || res.headers['content-length'];
  bytesDedupStable.add(clStable ? parseInt(clStable, 10) : (res.body ? res.body.length : 0));
  sleep(0.1);
}

export function dedupChurnScenario() {
  const churnId = `${__VU * 100000 + __ITER}-${Date.now()}`;
  const res = runGet(churnId, 'gzip, deflate, br', 'dedup_churn', DEDUP_CHURN_PATH);

  const ok = check(res, {
    'dedup_churn: status < 400': (r) => r.status < 400,
    'dedup_churn: latency < 15s': (r) => r.timings.duration < 15000,
  });

  failDedupChurn.add(!ok);
  ttfbDedupChurn.add(res.timings.waiting);
  const clChurn = res.headers['Content-Length'] || res.headers['content-length'];
  bytesDedupChurn.add(clChurn ? parseInt(clChurn, 10) : (res.body ? res.body.length : 0));
  sleep(0.1);
}

function qualitativeLabel(value, buckets) {
  for (const bucket of buckets) {
    if (value >= bucket.min) return bucket.label;
  }
  return buckets[buckets.length - 1].label;
}

export function handleSummary(data) {
  const m = data.metrics;
  const get = (metric, stat) => m[metric]?.values?.[stat] ?? 0;

  const baselineP95 = get('ttfb_baseline_ms', 'p(95)');
  const freshP95 = get('ttfb_fresh_ms', 'p(95)');
  const repeatP95 = get('ttfb_repeat_ms', 'p(95)');
  const dedupStableP95 = get('ttfb_dedup_stable_ms', 'p(95)');
  const dedupChurnP95 = get('ttfb_dedup_churn_ms', 'p(95)');

  const baselineAvg = get('ttfb_baseline_ms', 'avg');
  const freshAvg = get('ttfb_fresh_ms', 'avg');
  const repeatAvg = get('ttfb_repeat_ms', 'avg');
  const dedupStableAvg = get('ttfb_dedup_stable_ms', 'avg');
  const dedupChurnAvg = get('ttfb_dedup_churn_ms', 'avg');

  const baselineReqs = (m['fail_baseline']?.values?.passes || 0) + (m['fail_baseline']?.values?.fails || 0) || 1;
  const freshReqs = (m['fail_fresh']?.values?.passes || 0) + (m['fail_fresh']?.values?.fails || 0) || 1;
  const repeatReqs = (m['fail_repeat']?.values?.passes || 0) + (m['fail_repeat']?.values?.fails || 0) || 1;
  const dedupStableReqs = (m['fail_dedup_stable']?.values?.passes || 0) + (m['fail_dedup_stable']?.values?.fails || 0) || 1;
  const dedupChurnReqs = (m['fail_dedup_churn']?.values?.passes || 0) + (m['fail_dedup_churn']?.values?.fails || 0) || 1;

  const baselineBpr = (get('bytes_baseline', 'count') / baselineReqs);
  const freshBpr = (get('bytes_fresh', 'count') / freshReqs);
  const repeatBpr = (get('bytes_repeat', 'count') / repeatReqs);
  const dedupStableBpr = (get('bytes_dedup_stable', 'count') / dedupStableReqs);
  const dedupChurnBpr = (get('bytes_dedup_churn', 'count') / dedupChurnReqs);

  const compressionBandwidthImprovement = baselineBpr > 0
    ? (((baselineBpr - freshBpr) / baselineBpr) * 100).toFixed(1)
    : 'N/A';

  const dedupLatencyImprovementAvg = freshAvg > 0
    ? (((freshAvg - repeatAvg) / freshAvg) * 100).toFixed(1)
    : 'N/A';

  const dedupLatencyImprovementP95 = freshP95 > 0
    ? (((freshP95 - repeatP95) / freshP95) * 100).toFixed(1)
    : 'N/A';

  const dedupHitVsMissImprovementAvg = dedupChurnAvg > 0
    ? (((dedupChurnAvg - dedupStableAvg) / dedupChurnAvg) * 100).toFixed(1)
    : 'N/A';

  const dedupHitVsMissImprovementP95 = dedupChurnP95 > 0
    ? (((dedupChurnP95 - dedupStableP95) / dedupChurnP95) * 100).toFixed(1)
    : 'N/A';

  const compressionImprovementNum = Number(compressionBandwidthImprovement);
  const dedupImprovementNum = Number(dedupHitVsMissImprovementP95);
  const cacheHits = get('dedup_cache_hit_count', 'count');
  const cacheMisses = get('dedup_cache_miss_count', 'count');
  const cacheTotal = cacheHits + cacheMisses;
  const dedupCacheHitRatePct = cacheTotal > 0 ? ((cacheHits / cacheTotal) * 100).toFixed(1) : 'N/A';
  const reliability = 100 - (
    ((get('fail_baseline', 'rate') + get('fail_fresh', 'rate') + get('fail_repeat', 'rate') + get('fail_dedup_stable', 'rate') + get('fail_dedup_churn', 'rate')) / 5) * 100
  );

  const qualitative = {
    compression: qualitativeLabel(
      Number.isFinite(compressionImprovementNum) ? compressionImprovementNum : -1,
      [
        { min: 60, label: 'excellent' },
        { min: 35, label: 'strong' },
        { min: 15, label: 'moderate' },
        { min: 0, label: 'weak' },
        { min: -Infinity, label: 'negative' },
      ],
    ),
    dedup: qualitativeLabel(
      Number.isFinite(dedupImprovementNum) ? dedupImprovementNum : -1,
      [
        { min: 30, label: 'excellent' },
        { min: 15, label: 'strong' },
        { min: 5, label: 'moderate' },
        { min: 0, label: 'weak' },
        { min: -Infinity, label: 'negative' },
      ],
    ),
    reliability: qualitativeLabel(
      reliability,
      [
        { min: 99, label: 'excellent' },
        { min: 97, label: 'strong' },
        { min: 95, label: 'moderate' },
        { min: 90, label: 'weak' },
        { min: -Infinity, label: 'poor' },
      ],
    ),
  };

  const chartData = {
    generatedAt: new Date().toISOString(),
    units: {
      bytesPerRequest: 'bytes',
      latency: 'ms',
      improvement: 'percent',
      reliability: 'percent',
    },
    bars: {
      bandwidth_bytes_per_request: {
        baseline_uncompressed: Number(baselineBpr.toFixed(2)),
        fresh_compressed: Number(freshBpr.toFixed(2)),
        repeat_compressed: Number(repeatBpr.toFixed(2)),
        dedup_stable: Number(dedupStableBpr.toFixed(2)),
        dedup_churn: Number(dedupChurnBpr.toFixed(2)),
      },
      latency_avg_ms: {
        baseline_uncompressed: Number(baselineAvg.toFixed(2)),
        fresh_compressed: Number(freshAvg.toFixed(2)),
        repeat_compressed: Number(repeatAvg.toFixed(2)),
        dedup_stable: Number(dedupStableAvg.toFixed(2)),
        dedup_churn: Number(dedupChurnAvg.toFixed(2)),
      },
      latency_p95_ms: {
        baseline_uncompressed: Number(baselineP95.toFixed(2)),
        fresh_compressed: Number(freshP95.toFixed(2)),
        repeat_compressed: Number(repeatP95.toFixed(2)),
        dedup_stable: Number(dedupStableP95.toFixed(2)),
        dedup_churn: Number(dedupChurnP95.toFixed(2)),
      },
    },
    improvements_percent: {
      compression_bandwidth: Number.isFinite(compressionImprovementNum) ? Number(compressionImprovementNum) : null,
      dedup_latency_avg: Number.isFinite(Number(dedupHitVsMissImprovementAvg)) ? Number(dedupHitVsMissImprovementAvg) : null,
      dedup_latency_p95: Number.isFinite(dedupImprovementNum) ? dedupImprovementNum : null,
    },
    ai_decisions: {
      ai_compression_used_count: get('ai_compression_used', 'count'),
      ai_dedup_used_count: get('ai_dedup_used', 'count'),
      dedup_cache_hits: cacheHits,
      dedup_cache_misses: cacheMisses,
      dedup_cache_hit_rate_pct: Number.isFinite(Number(dedupCacheHitRatePct)) ? Number(dedupCacheHitRatePct) : null,
    },
    qualitative,
  };

  const barsCsv = [
    'metric,baseline_uncompressed,fresh_compressed,repeat_compressed,dedup_stable,dedup_churn,unit',
    `bytes_per_request,${baselineBpr.toFixed(2)},${freshBpr.toFixed(2)},${repeatBpr.toFixed(2)},${dedupStableBpr.toFixed(2)},${dedupChurnBpr.toFixed(2)},bytes`,
    `latency_avg,${baselineAvg.toFixed(2)},${freshAvg.toFixed(2)},${repeatAvg.toFixed(2)},${dedupStableAvg.toFixed(2)},${dedupChurnAvg.toFixed(2)},ms`,
    `latency_p95,${baselineP95.toFixed(2)},${freshP95.toFixed(2)},${repeatP95.toFixed(2)},${dedupStableP95.toFixed(2)},${dedupChurnP95.toFixed(2)},ms`,
  ].join('\n');

  const qualitativeTxt = [
    'SYNORIX Qualitative Assessment',
    `compression=${qualitative.compression}`,
    `dedup=${qualitative.dedup}`,
    `reliability=${qualitative.reliability}`,
    `compression_bandwidth_improvement_pct=${compressionBandwidthImprovement}`,
    `dedup_hit_vs_miss_p95_improvement_pct=${dedupHitVsMissImprovementP95}`,
    `dedup_hit_vs_miss_avg_improvement_pct=${dedupHitVsMissImprovementAvg}`,
    `dedup_cache_hits=${cacheHits}`,
    `dedup_cache_misses=${cacheMisses}`,
    `dedup_cache_hit_rate_pct=${dedupCacheHitRatePct}`,
  ].join('\n');

  const report = `
╔══════════════════════════════════════════════════════════════════════════╗
║      SYNORIX – Compression (Bandwidth) + Dedup (Latency) Comparison      ║
╠══════════════════════════════════════════════════════════════════════════╣
║  BANDWIDTH (Compression)                                                 ║
║  baseline bytes/req: ${baselineBpr.toFixed(0)}B                                            ║
║  fresh gzip bytes/req: ${freshBpr.toFixed(0)}B                                           ║
║  improvement: ${compressionBandwidthImprovement}%                                         ║
╠══════════════════════════════════════════════════════════════════════════╣
║  LATENCY (Dedup Cache)                                                   ║
║  fresh avg TTFB:   ${freshAvg.toFixed(1)}ms                                           ║
║  repeat avg TTFB:  ${repeatAvg.toFixed(1)}ms                                           ║
║  fresh p95 TTFB:   ${freshP95.toFixed(1)}ms                                           ║
║  repeat p95 TTFB:  ${repeatP95.toFixed(1)}ms                                           ║
║  improvement avg:  ${dedupLatencyImprovementAvg}%                                         ║
║  improvement p95:  ${dedupLatencyImprovementP95}%                                         ║
╠══════════════════════════════════════════════════════════════════════════╣
║  DEDUP HIT-vs-MISS (Stable vs Churn)                                     ║
║  stable avg TTFB: ${dedupStableAvg.toFixed(1)}ms                                           ║
║  churn avg TTFB:  ${dedupChurnAvg.toFixed(1)}ms                                           ║
║  stable p95 TTFB: ${dedupStableP95.toFixed(1)}ms                                           ║
║  churn p95 TTFB:  ${dedupChurnP95.toFixed(1)}ms                                           ║
║  gain avg:        ${dedupHitVsMissImprovementAvg}%                                         ║
║  gain p95:        ${dedupHitVsMissImprovementP95}%                                         ║
║  cache hits/miss: ${cacheHits}/${cacheMisses}  (hit-rate: ${dedupCacheHitRatePct}%)                     ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Qualitative: C=${qualitative.compression} D=${qualitative.dedup} R=${qualitative.reliability}                       ║
║  Graph files: k6_chart_data.json, k6_bar_metrics.csv, k6_qualitative.txt ║
╚══════════════════════════════════════════════════════════════════════════╝
`;

  return {
    [`${RESULTS_DIR}/k6_comparison_summary.json`]: JSON.stringify(data, null, 2),
    [`${RESULTS_DIR}/k6_chart_data.json`]: JSON.stringify(chartData, null, 2),
    [`${RESULTS_DIR}/k6_bar_metrics.csv`]: `${barsCsv}\n`,
    [`${RESULTS_DIR}/k6_qualitative.txt`]: `${qualitativeTxt}\n`,
    stdout: report,
  };
}
