const { requestEventEmitter } = require('../middleware/requestLogger');

// Build allowed origin set from env (same logic as main CORS config)
const _allowedOriginSet = new Set(
  (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean)
);

/**
 * Server-Sent Events endpoint for real-time request monitoring
 */
function createSSEEndpoint(req, res) {
  // Determine the CORS origin value: reflect request origin only if it is
  // on the allowlist; otherwise omit the header (browser will block cross-origin).
  const requestOrigin = req.headers.origin || '';
  const allowedOrigin = _allowedOriginSet.has(requestOrigin) ? requestOrigin : null;

  const sseHeaders = {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Headers': 'Cache-Control, Authorization'
  };
  if (allowedOrigin) {
    sseHeaders['Access-Control-Allow-Origin'] = allowedOrigin;
    sseHeaders['Vary'] = 'Origin';
  }

  // Set SSE headers
  res.writeHead(200, sseHeaders);

  // Send initial connection confirmation
  res.write('data: {"type":"connected","timestamp":"' + new Date().toISOString() + '"}\n\n');

  // Keep connection alive with periodic pings
  const pingInterval = setInterval(() => {
    res.write(': ping\n\n');
  }, 30000);

  // Listen for request events
  const requestListener = (eventData) => {
    const sseData = {
      type: 'request',
      ...eventData
    };
    
    res.write(`data: ${JSON.stringify(sseData)}\n\n`);
  };

  // Listen for security events (blocked requests, alerts)
  const securityListener = (eventData) => {
    const sseData = {
      type: 'security',
      ...eventData
    };
    
    res.write(`data: ${JSON.stringify(sseData)}\n\n`);
  };

  // Subscribe to events
  requestEventEmitter.on('request', requestListener);
  requestEventEmitter.on('security', securityListener);

  // Cleanup on client disconnect
  req.on('close', () => {
    clearInterval(pingInterval);
    requestEventEmitter.removeListener('request', requestListener);
    requestEventEmitter.removeListener('security', securityListener);
    console.log('SSE client disconnected');
  });

  req.on('aborted', () => {
    clearInterval(pingInterval);
    requestEventEmitter.removeListener('request', requestListener);
    requestEventEmitter.removeListener('security', securityListener);
    console.log('SSE client aborted');
  });

  console.log('SSE client connected');
}

/**
 * WebSocket alternative for real-time events
 */
function createWebSocketHandler(ws) {
  console.log('WebSocket client connected');

  // Send initial connection confirmation
  ws.send(JSON.stringify({
    type: 'connected',
    timestamp: new Date().toISOString()
  }));

  // Listen for request events
  const requestListener = (eventData) => {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({
        type: 'request',
        ...eventData
      }));
    }
  };

  // Listen for security events
  const securityListener = (eventData) => {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({
        type: 'security',
        ...eventData
      }));
    }
  };

  // Subscribe to events
  requestEventEmitter.on('request', requestListener);
  requestEventEmitter.on('security', securityListener);

  // Cleanup on disconnect
  ws.on('close', () => {
    requestEventEmitter.removeListener('request', requestListener);
    requestEventEmitter.removeListener('security', securityListener);
    console.log('WebSocket client disconnected');
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    requestEventEmitter.removeListener('request', requestListener);
    requestEventEmitter.removeListener('security', securityListener);
  });
}

/**
 * Send custom events to all connected clients
 */
function broadcastEvent(type, data) {
  requestEventEmitter.emit(type, data);
}

module.exports = {
  createSSEEndpoint,
  createWebSocketHandler,
  broadcastEvent
};