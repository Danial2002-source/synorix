import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const API_KEY = __ENV.API_KEY || '';
const PROXY_URL = (__ENV.PROXY_URL || 'http://127.0.0.1:8080/user-proxy').replace(/\/$/, '');
const TARGET_PATH = __ENV.TARGET_PATH || '/';
const PROFILE = (__ENV.PROFILE || 'load').toLowerCase();
const THINK_TIME_MS = Number(__ENV.THINK_TIME_MS || 100);

if (!API_KEY) {
  throw new Error('API_KEY is required. Pass with -e API_KEY=nxr_...');
}

const failRate = new Rate('functional_fail_rate');
const ttfb = new Trend('ttfb_ms');
const payloadBytes = new Counter('payload_bytes');

function getOptions(profile) {
  switch (profile) {
    case 'smoke':
      return {
        scenarios: {
          smoke: {
            executor: 'ramping-vus',
            stages: [
              { duration: '30s', target: 5 },
              { duration: '1m', target: 10 },
              { duration: '30s', target: 0 },
            ],
          },
        },
      };
    case 'stress':
      return {
        scenarios: {
          stress: {
            executor: 'ramping-vus',
            stages: [
              { duration: '1m', target: 30 },
              { duration: '3m', target: 80 },
              { duration: '3m', target: 150 },
              { duration: '3m', target: 220 },
              { duration: '2m', target: 0 },
            ],
          },
        },
      };
    case 'spike':
      return {
        scenarios: {
          spike: {
            executor: 'ramping-vus',
            stages: [
              { duration: '20s', target: 20 },
              { duration: '20s', target: 300 },
              { duration: '1m', target: 300 },
              { duration: '20s', target: 20 },
              { duration: '40s', target: 0 },
            ],
          },
        },
      };
    case 'soak':
      return {
        scenarios: {
          soak: {
            executor: 'constant-vus',
            vus: 60,
            duration: '30m',
          },
        },
      };
    case 'load':
    default:
      return {
        scenarios: {
          load: {
            executor: 'ramping-vus',
            stages: [
              { duration: '1m', target: 20 },
              { duration: '5m', target: 60 },
              { duration: '2m', target: 100 },
              { duration: '2m', target: 0 },
            ],
          },
        },
      };
  }
}

export const options = {
  ...getOptions(PROFILE),
  thresholds: {
    http_req_failed: ['rate<0.02'],
    http_req_duration: ['p(90)<900', 'p(95)<1500', 'p(99)<3000'],
    checks: ['rate>0.98'],
    functional_fail_rate: ['rate<0.02'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

function makeHeaders() {
  return {
    'X-API-Key': API_KEY,
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'application/json',
  };
}

function getUrl(pathSuffix = '') {
  return `${PROXY_URL}${TARGET_PATH}${pathSuffix}`;
}

export default function () {
  // Repeated GET pattern to encourage dedup/cache behavior and realistic frontend reads
  const cacheKey = (__ITER % 40).toString();
  const getRes = http.get(getUrl(`?q=${cacheKey}`), {
    headers: makeHeaders(),
    timeout: '15s',
    tags: { endpoint: 'user-proxy-get' },
  });

  const getOk = check(getRes, {
    'GET status is not 5xx': (r) => r.status < 500,
    'GET latency < 3s': (r) => r.timings.duration < 3000,
  });
  failRate.add(!getOk);
  ttfb.add(getRes.timings.waiting);
  payloadBytes.add((getRes.body || '').length);

  // Periodic POST to mimic frontend writes with same body (dedup-friendly pattern)
  if (__ITER % 4 === 0) {
    const body = JSON.stringify({
      action: 'perf-check',
      app: 'fatima-user-flow',
      repeatedPayload: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      id: __ITER % 20,
      ts: Date.now(),
    });

    const postRes = http.post(getUrl(''), body, {
      headers: makeHeaders(),
      timeout: '15s',
      tags: { endpoint: 'user-proxy-post' },
    });

    const postOk = check(postRes, {
      'POST status is not 5xx': (r) => r.status < 500,
      'POST latency < 3s': (r) => r.timings.duration < 3000,
    });
    failRate.add(!postOk);
    ttfb.add(postRes.timings.waiting);
    payloadBytes.add((postRes.body || '').length);
  }

  sleep(THINK_TIME_MS / 1000);
}

export function handleSummary(data) {
  return {
    [`perf/results/k6_${PROFILE}_summary.json`]: JSON.stringify(data, null, 2),
    stdout: `\nCompleted PROFILE=${PROFILE} against ${PROXY_URL}${TARGET_PATH}\n`,
  };
}
