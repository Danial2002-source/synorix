const express = require('express');
const cors = require('cors');

const app = express();
const PORT = Number(process.env.PORT || 9000);

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl} from ${req.ip}`);
  next();
});

function makeCompressibleText(bytes) {
  const chunk = 'SYNORIX_COMPRESSIBLE_DATA_'.repeat(32);
  const repeats = Math.max(1, Math.ceil(bytes / chunk.length));
  return chunk.repeat(repeats).slice(0, bytes);
}

function makePseudoRandomText(bytes, seed = 1) {
  let x = seed >>> 0;
  let out = '';
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/';
  while (out.length < bytes) {
    x = (1664525 * x + 1013904223) >>> 0;
    out += alphabet[x % alphabet.length];
  }
  return out;
}

app.get('/', (req, res) => {
  res.json({
    message: 'Scenario backend running',
    note: 'Use through Synorix proxy',
    endpoints: [
      '/health',
      '/api/large-response',
      '/api/large-random',
      '/api/dedup/stable?id=0..9',
      '/api/dedup/churn?id=...',
      '/api/mixed-response?mode=compressible|random',
    ],
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK', server: 'Scenario Backend', ts: new Date().toISOString() });
});

app.get('/api/large-response', (req, res) => {
  const sizeKB = Math.max(24, Number(req.query.kb || 24));
  const payload = makeCompressibleText(sizeKB * 1024);
  res.json({
    kind: 'compressible',
    id: req.query.id || null,
    sizeKB,
    payload,
  });
});

app.get('/api/large-random', (req, res) => {
  const sizeKB = Math.max(24, Number(req.query.kb || 24));
  const seed = Number(req.query.seed || 12345);
  const payload = makePseudoRandomText(sizeKB * 1024, seed);
  res.json({
    kind: 'incompressible-like',
    id: req.query.id || null,
    sizeKB,
    seed,
    payload,
  });
});

app.get('/api/dedup/stable', (req, res) => {
  const id = Number(req.query.id || 0) % 10;
  const payload = makeCompressibleText(24 * 1024);
  res.json({
    kind: 'dedup-stable',
    id,
    key: `stable-${id}`,
    payload,
  });
});

app.get('/api/dedup/churn', (req, res) => {
  const id = String(req.query.id || Date.now());
  const payload = makeCompressibleText(24 * 1024);
  res.json({
    kind: 'dedup-churn',
    id,
    key: `churn-${id}`,
    payload,
  });
});

app.get('/api/mixed-response', (req, res) => {
  const mode = String(req.query.mode || 'compressible').toLowerCase();
  if (mode === 'random') {
    const payload = makePseudoRandomText(24 * 1024, Number(req.query.seed || 9876));
    return res.json({ mode, payload });
  }
  const payload = makeCompressibleText(24 * 1024);
  return res.json({ mode: 'compressible', payload });
});

app.post('/api/test-js-bundle', (req, res) => {
  const { buildId, requestIndex, fileName, contentType, bundle } = req.body || {};
  if (!bundle) {
    return res.status(400).json({ message: 'bundle is required' });
  }

  const size = Buffer.byteLength(String(bundle), 'utf8');
  return res.json({
    success: true,
    buildId: buildId || 'unknown',
    requestIndex: Number(requestIndex || 0),
    fileName: fileName || 'bundle.js',
    contentType: contentType || 'application/javascript',
    bundleSize: size,
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Scenario backend listening on http://0.0.0.0:${PORT}`);
});
