const EventEmitter = require('events');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// In-memory cache for recent requests (last 1000 requests)
const requestCache = [];
const MAX_CACHE_SIZE = 1000;

// Event emitter for real-time events
const requestEventEmitter = new EventEmitter();

// Database for persistent storage
const logDbPath = path.join(__dirname, '..', 'request_logs.db');
const logDb = new sqlite3.Database(logDbPath);

// Initialize request logs database
logDb.serialize(() => {
  logDb.run(`
    CREATE TABLE IF NOT EXISTS request_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME NOT NULL,
      method TEXT NOT NULL,
      url TEXT NOT NULL,
      headers TEXT,
      client_ip TEXT NOT NULL,
      request_body TEXT,
      response_status INTEGER,
      response_time REAL,
      response_size INTEGER,
      compressed BOOLEAN DEFAULT 0,
      compression_saved INTEGER DEFAULT 0,
      waf_action TEXT DEFAULT 'allowed',
      waf_rule TEXT,
      suricata_action TEXT DEFAULT 'allowed', 
      suricata_alert TEXT,
      user_agent TEXT,
      referer TEXT,
      content_type TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  logDb.run(`
    CREATE INDEX IF NOT EXISTS idx_timestamp ON request_logs(timestamp);
  `);
  
  logDb.run(`
    CREATE INDEX IF NOT EXISTS idx_client_ip ON request_logs(client_ip);
  `);
  
  logDb.run(`
    CREATE INDEX IF NOT EXISTS idx_waf_action ON request_logs(waf_action);
  `);
  
  logDb.run(`
    CREATE INDEX IF NOT EXISTS idx_suricata_action ON request_logs(suricata_action);
  `);
});

/**
 * Generate unique request ID
 */
function generateRequestId() {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Get client IP from request
 */
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] ||
         req.connection?.remoteAddress ||
         req.socket?.remoteAddress ||
         req.ip ||
         'unknown';
}

/**
 * Sanitize request body for logging (limit size and remove sensitive data)
 */
function sanitizeRequestBody(body, contentType) {
  if (!body) return null;
  
  const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
  
  // Limit body size to 5KB for logging
  if (bodyStr.length > 5120) {
    return bodyStr.substring(0, 5120) + '... [truncated]';
  }
  
  // Remove passwords and sensitive data
  if (contentType?.includes('application/json')) {
    try {
      const parsed = JSON.parse(bodyStr);
      if (parsed.password) parsed.password = '[REDACTED]';
      if (parsed.token) parsed.token = '[REDACTED]';
      if (parsed.secret) parsed.secret = '[REDACTED]';
      return JSON.stringify(parsed);
    } catch (e) {
      return bodyStr;
    }
  }
  
  return bodyStr;
}

/**
 * Extract security headers and metadata
 */
function extractSecurityMetadata(req, res) {
  return {
    userAgent: req.headers['user-agent'] || '',
    referer: req.headers.referer || req.headers.referrer || '',
    contentType: req.headers['content-type'] || '',
    acceptEncoding: req.headers['accept-encoding'] || '',
    wafAction: req.headers['x-waf-action'] || res.getHeader('x-waf-action') || 'allowed',
    wafRule: req.headers['x-waf-rule'] || res.getHeader('x-waf-rule') || null,
    suricataAction: req.headers['x-suricata-action'] || res.getHeader('x-suricata-action') || 'allowed',
    suricataAlert: req.headers['x-suricata-alert'] || res.getHeader('x-suricata-alert') || null,
    compressed: res.getHeader('content-encoding') === 'gzip' || res.getHeader('x-compression-applied') === 'true',
    compressionSaved: parseInt(res.getHeader('x-compression-saved') || '0', 10),
    originalSize: parseInt(res.getHeader('x-compression-original-size') || '0', 10),
    clientIP: req.headers['x-client-ip'] || req.headers['x-real-ip'] || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || null
  };
}

/**
 * Main request logging middleware
 */
function requestLoggerMiddleware(req, res, next) {
  const startTime = Date.now();
  req.requestId = generateRequestId();
  req.startTime = startTime;
  
  // Capture request body if present
  let requestBody = '';
  const originalSend = res.send;
  const originalJson = res.json;
  let responseData = null;
  let responseSize = 0;

  // Override res.send to capture response
  res.send = function(data) {
    responseData = data;
    responseSize = Buffer.byteLength(data || '', 'utf8');
    return originalSend.call(this, data);
  };

  // Override res.json to capture JSON responses
  res.json = function(data) {
    responseData = JSON.stringify(data);
    responseSize = Buffer.byteLength(responseData, 'utf8');
    return originalJson.call(this, data);
  };

  // Capture request body for POST/PUT/PATCH requests
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
    requestBody = sanitizeRequestBody(req.body, req.headers['content-type']);
  }

  // On response finish, log the request
  res.on('finish', () => {
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    const securityMetadata = extractSecurityMetadata(req, res);
    const clientIP = securityMetadata.clientIP || getClientIP(req);
    
    // Create request log entry
    const logEntry = {
      id: req.requestId,
      timestamp: new Date(startTime).toISOString(),
      method: req.method,
      url: req.originalUrl || req.url,
      headers: JSON.stringify({
        'user-agent': req.headers['user-agent'],
        'accept': req.headers.accept,
        'content-type': req.headers['content-type'],
        'authorization': req.headers.authorization ? '[PRESENT]' : undefined
      }),
      clientIP,
      requestBody,
      responseStatus: res.statusCode,
      responseTime: responseTime / 1000, // Convert to seconds
      responseSize,
      compressed: securityMetadata.compressed,
      compressionSaved: securityMetadata.compressionSaved,
      wafAction: securityMetadata.wafAction,
      wafRule: securityMetadata.wafRule,
      suricataAction: securityMetadata.suricataAction,
      suricataAlert: securityMetadata.suricataAlert,
      userAgent: securityMetadata.userAgent,
      referer: securityMetadata.referer,
      contentType: securityMetadata.contentType
    };

    // Add to in-memory cache
    requestCache.unshift(logEntry);
    if (requestCache.length > MAX_CACHE_SIZE) {
      requestCache.pop();
    }

    // Emit real-time event
    const eventData = {
      id: logEntry.id,
      method: logEntry.method,
      url: logEntry.url,
      clientIP: logEntry.clientIP,
      statusCode: logEntry.responseStatus,
      responseTime: logEntry.responseTime,
      compressed: logEntry.compressed,
      wafAction: logEntry.wafAction,
      suricataAction: logEntry.suricataAction,
      timestamp: logEntry.timestamp
    };

    requestEventEmitter.emit('request', eventData);

    // Save to persistent database (async, don't block response)
    setImmediate(() => {
      saveRequestToDB(logEntry);
    });

    // Log to console for debugging
    console.log(`[${logEntry.timestamp}] ${logEntry.method} ${logEntry.url} - ${logEntry.responseStatus} (${responseTime}ms) ${clientIP}`);
  });

  next();
}

/**
 * Save request log to database
 */
function saveRequestToDB(logEntry) {
  const stmt = logDb.prepare(`
    INSERT INTO request_logs (
      timestamp, method, url, headers, client_ip, request_body,
      response_status, response_time, response_size, compressed,
      compression_saved, waf_action, waf_rule, suricata_action,
      suricata_alert, user_agent, referer, content_type
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run([
    logEntry.timestamp,
    logEntry.method,
    logEntry.url,
    logEntry.headers,
    logEntry.clientIP,
    logEntry.requestBody,
    logEntry.responseStatus,
    logEntry.responseTime,
    logEntry.responseSize,
    logEntry.compressed ? 1 : 0,
    logEntry.compressionSaved,
    logEntry.wafAction,
    logEntry.wafRule,
    logEntry.suricataAction,
    logEntry.suricataAlert,
    logEntry.userAgent,
    logEntry.referer,
    logEntry.contentType
  ], function(err) {
    if (err) {
      console.error('Failed to save request log to database:', err);
    }
  });

  stmt.finalize();
}

/**
 * Get recent requests from cache
 */
function getRecentRequests(limit = 100) {
  return requestCache.slice(0, Math.min(limit, requestCache.length));
}

/**
 * Get paginated requests from database
 */
function getRequestsFromDB(page = 1, limit = 50, filters = {}) {
  return new Promise((resolve, reject) => {
    const offset = (page - 1) * limit;
    let whereClause = 'WHERE 1=1';
    const params = [];

    // Apply filters
    if (filters.method) {
      whereClause += ' AND method = ?';
      params.push(filters.method);
    }
    
    if (filters.status) {
      whereClause += ' AND response_status = ?';
      params.push(filters.status);
    }
    
    if (filters.blocked) {
      whereClause += ' AND (waf_action != "allowed" OR suricata_action != "allowed")';
    }
    
    if (filters.compressed) {
      whereClause += ' AND compressed = 1';
    }
    
    if (filters.clientIP) {
      whereClause += ' AND client_ip = ?';
      params.push(filters.clientIP);
    }
    
    if (filters.startTime && filters.endTime) {
      whereClause += ' AND timestamp BETWEEN ? AND ?';
      params.push(filters.startTime, filters.endTime);
    }

    // Count total records for pagination
    const countQuery = `SELECT COUNT(*) as total FROM request_logs ${whereClause}`;
    logDb.get(countQuery, params, (err, countResult) => {
      if (err) {
        reject(err);
        return;
      }

      const total = countResult.total;

      // Get paginated records
      const dataQuery = `
        SELECT * FROM request_logs 
        ${whereClause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
      `;
      
      logDb.all(dataQuery, [...params, limit, offset], (err, rows) => {
        if (err) {
          reject(err);
          return;
        }

        resolve({
          data: rows,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
          }
        });
      });
    });
  });
}

/**
 * Get request statistics
 */
function getRequestStats(timeframe = '24h') {
  return new Promise((resolve, reject) => {
    let timeCondition = '';
    
    switch (timeframe) {
      case '1h':
        timeCondition = "AND timestamp >= datetime('now', '-1 hour')";
        break;
      case '24h':
        timeCondition = "AND timestamp >= datetime('now', '-1 day')";
        break;
      case '7d':
        timeCondition = "AND timestamp >= datetime('now', '-7 days')";
        break;
      case '30d':
        timeCondition = "AND timestamp >= datetime('now', '-30 days')";
        break;
    }

    const query = `
      SELECT 
        COUNT(*) as totalRequests,
        COUNT(CASE WHEN response_status >= 400 THEN 1 END) as errorRequests,
        COUNT(CASE WHEN waf_action != 'allowed' THEN 1 END) as wafBlocked,
        COUNT(CASE WHEN suricata_action != 'allowed' THEN 1 END) as suricataBlocked,
        COUNT(CASE WHEN compressed = 1 THEN 1 END) as compressedRequests,
        AVG(response_time) as avgResponseTime,
        SUM(response_size) as totalBandwidth,
        SUM(compression_saved) as totalCompressionSaved,
        COUNT(DISTINCT client_ip) as uniqueIPs
      FROM request_logs 
      WHERE 1=1 ${timeCondition}
    `;

    logDb.get(query, [], (err, stats) => {
      if (err) {
        reject(err);
        return;
      }

      resolve({
        ...stats,
        avgResponseTime: stats.avgResponseTime || 0,
        totalBandwidth: stats.totalBandwidth || 0,
        totalCompressionSaved: stats.totalCompressionSaved || 0,
        compressionRatio: stats.totalBandwidth > 0 
          ? ((stats.totalCompressionSaved || 0) / stats.totalBandwidth * 100).toFixed(2)
          : 0
      });
    });
  });
}

/**
 * Cleanup old logs (keep last 30 days)
 */
function cleanupOldLogs() {
  const query = "DELETE FROM request_logs WHERE timestamp < datetime('now', '-30 days')";
  logDb.run(query, function(err) {
    if (err) {
      console.error('Failed to cleanup old logs:', err);
    } else {
      console.log(`Cleaned up ${this.changes} old log entries`);
    }
  });
}

// Schedule cleanup every 24 hours
setInterval(cleanupOldLogs, 24 * 60 * 60 * 1000);

module.exports = {
  requestLoggerMiddleware,
  requestEventEmitter,
  getRecentRequests,
  getRequestsFromDB,
  getRequestStats,
  cleanupOldLogs
};