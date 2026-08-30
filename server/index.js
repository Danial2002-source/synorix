const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

// Import request logging middleware and controllers
const { requestLoggerMiddleware } = require('./middleware/requestLogger');
const { createSSEEndpoint } = require('./controllers/eventController');
const {
  getRequestLogs,
  getRequestStatistics,
  getTopIPs,
  getRequestTrends,
  searchRequestLogs,
  exportRequestLogs
} = require('./controllers/logsController');

// Import rules integration
const rulesRouter = require('./routes/rules');
const {
  ruleAuditLog,
  validateRuleParams,
  queuedExport,
  checkRulePermissions
} = require('./middleware/rulesIntegration');

const app = express();
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 3001;
let JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'dev-only-refresh-secret-change-in-prod';
const ALLOW_PRIVATE_BACKEND_URLS = process.env.ALLOW_PRIVATE_BACKEND_URLS
  ? process.env.ALLOW_PRIVATE_BACKEND_URLS === 'true'
  : NODE_ENV !== 'production';

// ======================= SECURITY UTILITY FUNCTIONS =======================

/**
 * Validate backend URL to prevent SSRF attacks
 */
const isValidBackendURL = (urlString) => {
  try {
    const url = new URL(urlString);
    if (!['http:', 'https:'].includes(url.protocol)) return false;
    const hostname = (url.hostname || '').toLowerCase();

    // Always block loopback/reserved/internal hostnames
    const alwaysBlockedPatterns = [
      /^127\./,
      /^0\.0\.0\.0$/,
      /::1/,
      /^localhost$/,
      /^internal$/,
      /\.internal$/
    ];

    if (alwaysBlockedPatterns.some(pattern => pattern.test(hostname))) {
      return false;
    }

    // Block private/link-local networks unless explicitly allowed
    const privateNetworkPatterns = [
      /^169\.254\./,
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^fc00:/,
      /^fe80:/
    ];

    if (!ALLOW_PRIVATE_BACKEND_URLS && privateNetworkPatterns.some(pattern => pattern.test(hostname))) {
      return false;
    }

    return true;
  } catch (err) {
    return false;
  }
};

/**
 * Sanitize user input to prevent XSS
 */
const sanitizeInput = (str, max = 500) => {
  if (!str || typeof str !== 'string') return '';
  const htmlEntityMap = {
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;'
  };
  return str.replace(/[<>"']/g, char => htmlEntityMap[char] || char).substring(0, max).trim();
};

/**
 * Validate username format
 */
const validateUsername = (username) => {
  if (!username || !/^[a-zA-Z0-9_-]{3,30}$/.test(username)) return false;
  const reserved = ['admin', 'root', 'api', 'test', 'system', 'null', 'undefined'];
  return !reserved.includes(username.toLowerCase());
};

/**
 * Generic error message to prevent info leakage
 */
const getGenericErrorMessage = (err) => {
  console.error('[ERROR]', err);
  if (err.code === 'ECONNREFUSED') return 'Backend unreachable';
  if (err.code === 'ETIMEDOUT') return 'Connection timeout';
  if (err.code === 'ENOTFOUND') return 'Backend hostname invalid';
  return 'Connectivity check failed';
};

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  if (NODE_ENV === 'production') {
    throw new Error('JWT_SECRET must be set to a strong value (>=32 chars) in production');
  }
  console.warn('⚠️  JWT_SECRET is missing/weak; using development-only fallback secret');
  JWT_SECRET = 'dev-only-jwt-secret-change-me-before-production';
}

if (NODE_ENV === 'production' && (!REFRESH_TOKEN_SECRET || REFRESH_TOKEN_SECRET.length < 32)) {
  throw new Error('REFRESH_TOKEN_SECRET must be set in production');
}

const INTERNAL_API_TOKEN = process.env.INTERNAL_API_TOKEN || '';
if (NODE_ENV === 'production' && !INTERNAL_API_TOKEN) {
  throw new Error('INTERNAL_API_TOKEN must be set in production for service-to-service endpoints');
}

// Disable ETags to prevent 304 Not Modified responses on dynamic endpoints
app.disable('etag');

// Trust proxy for rate limiting (needed when behind reverse proxy)
// Set to false for development to avoid rate limiting issues
app.set('trust proxy', process.env.NODE_ENV === 'production' ? 1 : false);

// Database setup
const dbPath = path.join(__dirname, 'synorix.db');
const db = new sqlite3.Database(dbPath);

// Initialize database tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      is_active BOOLEAN DEFAULT 1,
      is_banned BOOLEAN DEFAULT 0
    )
  `);
  
  // Create audit log table for security
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      success BOOLEAN DEFAULT 1,
      details TEXT,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);
  
  // Create detailed request logs table for enhanced security tracking
  db.run(`
    CREATE TABLE IF NOT EXISTS detailed_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      method TEXT NOT NULL,
      url TEXT NOT NULL,
      ip TEXT NOT NULL,
      user_agent TEXT,
      status_code INTEGER NOT NULL,
      response_time REAL,
      request_size INTEGER,
      response_size INTEGER,
      waf_checks TEXT,
      compression_info TEXT,
      ids_ips_info TEXT,
      security_events TEXT,
      headers TEXT,
      blocked BOOLEAN DEFAULT 0,
      block_reason TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  // Create request_logs table for basic monitoring
  db.run(`
    CREATE TABLE IF NOT EXISTS request_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      method TEXT NOT NULL,
      url TEXT NOT NULL,
      ip TEXT NOT NULL,
      user_agent TEXT,
      status_code INTEGER NOT NULL,
      response_time REAL,
      request_size INTEGER,
      response_size INTEGER,
      referer TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  // Create user_configs table for storing user backend URLs
  db.run(`
    CREATE TABLE IF NOT EXISTS user_configs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE NOT NULL,
      backend_url TEXT NOT NULL,
      proxy_api_key TEXT UNIQUE NOT NULL,
      is_configured BOOLEAN DEFAULT 0,
      connectivity_status TEXT DEFAULT 'untested',
      last_test_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `);

  // Create user_applications table for supporting multiple sites per user
  db.run(`
    CREATE TABLE IF NOT EXISTS user_applications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      app_name TEXT NOT NULL,
      backend_url TEXT NOT NULL,
      proxy_api_key TEXT UNIQUE NOT NULL,
      description TEXT,
      is_active BOOLEAN DEFAULT 1,
      connectivity_status TEXT DEFAULT 'untested',
      last_test_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
      UNIQUE(user_id, app_name)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS user_request_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      timestamp TEXT NOT NULL,
      method TEXT NOT NULL,
      url TEXT NOT NULL,
      backend_url TEXT NOT NULL,
      client_ip TEXT NOT NULL,
      user_agent TEXT,
      status_code INTEGER NOT NULL,
      response_time REAL,
      request_size INTEGER,
      response_size INTEGER,
      threat_level TEXT DEFAULT 'none',
      waf_triggered BOOLEAN DEFAULT 0,
      suricata_triggered BOOLEAN DEFAULT 0,
      compressed BOOLEAN DEFAULT 0,
      deduplicated BOOLEAN DEFAULT 0,
      compression_ratio REAL DEFAULT 0,
      original_size INTEGER DEFAULT 0,
      compressed_size INTEGER DEFAULT 0,
      dedup_size INTEGER DEFAULT 0,
      dedup_ratio REAL DEFAULT 0,
      app_id INTEGER REFERENCES user_applications(id) ON DELETE SET NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `);
  
  // Create user_alerts table for storing security alerts per user
  db.run(`
    CREATE TABLE IF NOT EXISTS user_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      alert_type TEXT NOT NULL CHECK(alert_type IN ('waf', 'suricata', 'system')),
      severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
      rule_id TEXT,
      rule_name TEXT,
      description TEXT NOT NULL,
      source_ip TEXT,
      target_url TEXT,
      recommended_action TEXT,
      action TEXT DEFAULT 'detected' CHECK(action IN ('detected', 'allowed', 'blocked', 'dropped', 'rejected', 'prevented')),
      source TEXT DEFAULT 'suricata',
      is_read BOOLEAN DEFAULT 0,
      status TEXT DEFAULT 'open' CHECK(status IN ('open', 'acknowledged', 'resolved', 'dismissed')),
      acknowledged_by TEXT,
      acknowledged_at DATETIME,
      resolved_at DATETIME,
      comment TEXT,
      auto_blocked BOOLEAN DEFAULT 0,
      correlation_id TEXT,
      scope TEXT DEFAULT 'global' CHECK(scope IN ('global','application')),
      occurrence_count INTEGER DEFAULT 1,
      app_id INTEGER REFERENCES user_applications(id) ON DELETE SET NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `);

  // Create alert_correlation table for grouping related alerts
  db.run(`
    CREATE TABLE IF NOT EXISTS alert_correlation (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      correlation_id TEXT UNIQUE NOT NULL,
      alert_pattern TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      alert_count INTEGER DEFAULT 1,
      severity TEXT NOT NULL,
      first_seen DATETIME NOT NULL,
      last_seen DATETIME NOT NULL,
      auto_action_taken TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create automated_responses table for tracking automatic actions
  db.run(`
    CREATE TABLE IF NOT EXISTS automated_responses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      correlation_id TEXT,
      action_type TEXT NOT NULL CHECK(action_type IN ('ip_block', 'rate_limit', 'notification')),
      target TEXT NOT NULL,
      reason TEXT NOT NULL,
      threshold_exceeded TEXT,
      is_active BOOLEAN DEFAULT 1,
      expires_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create notification_log table for tracking sent notifications
  db.run(`
    CREATE TABLE IF NOT EXISTS notification_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_id INTEGER,
      notification_type TEXT NOT NULL CHECK(notification_type IN ('email', 'webhook', 'sms')),
      recipient TEXT NOT NULL,
      payload TEXT,
      status TEXT NOT NULL CHECK(status IN ('sent', 'failed', 'pending')),
      error_message TEXT,
      sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (alert_id) REFERENCES user_alerts (id) ON DELETE CASCADE
    )
  `);

  // Create threat_intelligence table for storing threat data
  db.run(`
    CREATE TABLE IF NOT EXISTS threat_intelligence (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      indicator TEXT UNIQUE NOT NULL,
      indicator_type TEXT NOT NULL CHECK(indicator_type IN ('ip', 'domain', 'url', 'hash', 'email')),
      threat_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      source TEXT NOT NULL,
      confidence INTEGER DEFAULT 50,
      description TEXT,
      first_seen DATETIME NOT NULL,
      last_seen DATETIME NOT NULL,
      is_active BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create alerts table for system-wide Suricata alerts
  db.run(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      severity INTEGER NOT NULL,
      category TEXT,
      signature TEXT NOT NULL,
      src_ip TEXT NOT NULL,
      dest_ip TEXT NOT NULL,
      src_port INTEGER,
      dest_port INTEGER,
      protocol TEXT,
      flow_id TEXT,
      timestamp DATETIME NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create WAF rules table for database-backed WAF rules management
  db.run(`
    CREATE TABLE IF NOT EXISTS waf_rules (
      id INTEGER PRIMARY KEY,
      pattern TEXT NOT NULL,
      message TEXT NOT NULL,
      tags TEXT NOT NULL,
      severity INTEGER NOT NULL DEFAULT 3,
      enabled BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users (id)
    )
  `);

  // Create Suricata (IDS/IPS) rules table for database-backed IDS/IPS rules management
  db.run(`
    CREATE TABLE IF NOT EXISTS suricata_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sid INTEGER UNIQUE NOT NULL,
      action TEXT NOT NULL DEFAULT 'alert' CHECK(action IN ('alert', 'drop', 'reject', 'pass')),
      protocol TEXT NOT NULL DEFAULT 'http' CHECK(protocol IN ('http', 'tcp', 'udp', 'icmp', 'ip')),
      source_ip TEXT NOT NULL DEFAULT '$EXTERNAL_NET',
      source_port TEXT NOT NULL DEFAULT 'any',
      direction TEXT NOT NULL DEFAULT '->',
      dest_ip TEXT NOT NULL DEFAULT '$HTTP_SERVERS',
      dest_port TEXT NOT NULL DEFAULT 'any',
      msg TEXT NOT NULL,
      flow TEXT,
      content TEXT,
      http_uri BOOLEAN DEFAULT 0,
      http_method BOOLEAN DEFAULT 0,
      http_header BOOLEAN DEFAULT 0,
      http_request_body BOOLEAN DEFAULT 0,
      nocase BOOLEAN DEFAULT 0,
      pcre TEXT,
      classtype TEXT NOT NULL DEFAULT 'web-application-attack',
      rev INTEGER DEFAULT 1,
      priority INTEGER DEFAULT 2,
      enabled BOOLEAN DEFAULT 1,
      category TEXT DEFAULT 'custom',
      filename TEXT DEFAULT 'local.rules',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users (id)
    )
  `);
  
  // Create indexes for better query performance
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_logs_user_id ON user_request_logs(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_logs_timestamp ON user_request_logs(timestamp DESC)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_alerts_user_id ON user_alerts(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_alerts_timestamp ON user_alerts(timestamp DESC)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_alerts_status ON user_alerts(status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_alerts_correlation ON user_alerts(correlation_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_alert_correlation_ip ON alert_correlation(source_ip)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_automated_responses_target ON automated_responses(target)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_threat_intelligence_indicator ON threat_intelligence(indicator)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`);
  
  // Migration: Add action column to user_alerts if it doesn't exist
  db.all("PRAGMA table_info(user_alerts)", (err, columns) => {
    if (err) {
      console.error('Error checking table schema:', err);
      return;
    }
    
    const hasActionColumn = columns.some(col => col.name === 'action');
    if (!hasActionColumn) {
      console.log('📦 Migrating database: Adding action column to user_alerts...');
      db.run(`
        ALTER TABLE user_alerts 
        ADD COLUMN action TEXT DEFAULT 'detected' 
        CHECK(action IN ('detected', 'allowed', 'blocked', 'dropped', 'rejected', 'prevented'))
      `, (alterErr) => {
        if (alterErr) {
          console.error('❌ Migration failed:', alterErr);
        } else {
          console.log('✅ Migration successful: action column added');
        }
      });
    }
    
    const hasSourceColumn = columns.some(col => col.name === 'source');
    if (!hasSourceColumn) {
      console.log('📦 Migrating database: Adding source column to user_alerts...');
      db.run(`
        ALTER TABLE user_alerts 
        ADD COLUMN source TEXT DEFAULT 'suricata'
      `, (alterErr) => {
        if (alterErr) {
          console.error('❌ Source column migration failed:', alterErr);
        } else {
          console.log('✅ Migration successful: source column added');
        }
      });
    }
  });

  // Migration: Add compression and deduplication columns to user_request_logs if they don't exist
  db.all("PRAGMA table_info(user_request_logs)", (err, columns) => {
    if (err) {
      console.error('Error checking user_request_logs schema:', err);
      return;
    }

    const columnsToAdd = [
      { name: 'compressed', type: 'BOOLEAN DEFAULT 0' },
      { name: 'deduplicated', type: 'BOOLEAN DEFAULT 0' },
      { name: 'compression_ratio', type: 'REAL DEFAULT 0' },
      { name: 'original_size', type: 'INTEGER DEFAULT 0' },
      { name: 'compressed_size', type: 'INTEGER DEFAULT 0' },
      { name: 'dedup_size', type: 'INTEGER DEFAULT 0' },
      { name: 'dedup_ratio', type: 'REAL DEFAULT 0' }
    ];

    columnsToAdd.forEach(col => {
      const hasColumn = columns.some(c => c.name === col.name);
      if (!hasColumn) {
        console.log(`📦 Migrating database: Adding ${col.name} column to user_request_logs...`);
        db.run(`
          ALTER TABLE user_request_logs 
          ADD COLUMN ${col.name} ${col.type}
        `, (alterErr) => {
          if (alterErr) {
            console.error(`❌ Migration failed for ${col.name}:`, alterErr);
          } else {
            console.log(`✅ Migration successful: ${col.name} column added`);
          }
        });
      }
    });
  });

  // Migration: Add app_id column to user_request_logs and user_alerts
  db.all("PRAGMA table_info(user_request_logs)", (err, cols) => {
    if (!err && cols && !cols.some(c => c.name === 'app_id')) {
      db.run(`ALTER TABLE user_request_logs ADD COLUMN app_id INTEGER REFERENCES user_applications(id) ON DELETE SET NULL`, e => {
        if (e) {
          console.error('Migration notice: app_id on user_request_logs', e.message);
        } else {
          console.log('✅ app_id added to user_request_logs');
          // backfill existing rows by matching backend_url
          db.run(`UPDATE user_request_logs SET app_id = (
            SELECT ua.id FROM user_applications ua
            WHERE ua.user_id = user_request_logs.user_id AND ua.backend_url = user_request_logs.backend_url
            LIMIT 1
          ) WHERE app_id IS NULL`, (backfillErr) => {
            if (backfillErr) console.warn('Backfill app_id on user_request_logs notice:', backfillErr.message);
          });
        }
      });
    }
  });
  db.all("PRAGMA table_info(user_alerts)", (err2, cols2) => {
    if (!err2 && cols2) {
      if (!cols2.some(c => c.name === 'app_id')) {
        db.run(`ALTER TABLE user_alerts ADD COLUMN app_id INTEGER REFERENCES user_applications(id) ON DELETE SET NULL`, e =>
          e ? console.warn('Migration notice: app_id on user_alerts', e.message) : console.log('✅ app_id added to user_alerts'));
      }
      if (!cols2.some(c => c.name === 'scope')) {
        db.run(`ALTER TABLE user_alerts ADD COLUMN scope TEXT DEFAULT 'global' CHECK(scope IN ('global','application'))`, e =>
          e ? console.warn('Migration notice: scope on user_alerts', e.message) : console.log('✅ scope added to user_alerts'));
      }
      if (!cols2.some(c => c.name === 'occurrence_count')) {
        db.run(`ALTER TABLE user_alerts ADD COLUMN occurrence_count INTEGER DEFAULT 1`, e =>
          e ? console.warn('Migration notice: occurrence_count on user_alerts', e.message) : console.log('✅ occurrence_count added to user_alerts'));
      }
    }
  });

  // 30-day alert cleanup job (runs every 6 hours)
  setInterval(() => {
    db.run(`DELETE FROM user_alerts WHERE timestamp < datetime('now', '-30 days')`, (err) => {
      if (err) console.error('Alert cleanup failed:', err.message);
      else console.log('🧹 Old alerts cleaned up (>30 days)');
    });
  }, 6 * 60 * 60 * 1000);

  // Migration: Sync user_configs → user_applications (runs on every startup, idempotent)
  // Ensures users who configured via the legacy single-app flow always appear in the Applications tab
  db.run(`
    INSERT OR IGNORE INTO user_applications (user_id, app_name, backend_url, proxy_api_key, description, is_active, connectivity_status)
    SELECT 
      uc.user_id,
      u.username || '''s Application',
      uc.backend_url,
      uc.proxy_api_key,
      'Auto-configured application',
      1,
      uc.connectivity_status
    FROM user_configs uc
    JOIN users u ON u.id = uc.user_id
    WHERE uc.backend_url != ''
    AND NOT EXISTS (
      SELECT 1 FROM user_applications ua WHERE ua.proxy_api_key = uc.proxy_api_key
    )
  `, (err) => {
    if (err) {
      console.warn('Migration user_configs→user_applications notice:', err.message);
    } else {
      // Backfill app_id on logs/alerts after ensuring apps exist
      db.run(`UPDATE user_request_logs SET app_id = (
        SELECT ua.id FROM user_applications ua
        WHERE ua.user_id = user_request_logs.user_id AND ua.backend_url = user_request_logs.backend_url
        LIMIT 1
      ) WHERE app_id IS NULL`, (backfillErr) => {
        if (backfillErr) console.warn('Backfill app_id on user_request_logs notice:', backfillErr.message);
      });
    }
  });

  // Create default admin account if it doesn't exist
  db.get("SELECT id FROM users WHERE role = 'admin'", async (err, admin) => {
    if (err) {
      console.error('Error checking for admin:', err);
      return;
    }
    
    if (!admin) {
      const enableBootstrapAdmin = process.env.ENABLE_BOOTSTRAP_ADMIN === 'true';
      const bootstrapAdminPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD || '';

      if (!enableBootstrapAdmin) {
        console.warn('⚠️  No admin account exists. Set ENABLE_BOOTSTRAP_ADMIN=true with BOOTSTRAP_ADMIN_PASSWORD to bootstrap one.');
        return;
      }

      if (bootstrapAdminPassword.length < 12) {
        console.error('❌ BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters when bootstrapping admin');
        return;
      }

      try {
        const hashedPassword = await bcrypt.hash(bootstrapAdminPassword, 12);
        db.run(
          'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
          ['admin', 'admin@synorix.local', hashedPassword, 'admin'],
          function(insertErr) {
            if (insertErr) {
              console.error('Error creating bootstrap admin:', insertErr);
            } else {
              console.log('✅ Bootstrap admin account created (username: admin)');
              
              // Create user config for admin
              const crypto = require('crypto');
              const apiKey = `nxr_${crypto.randomBytes(32).toString('hex')}`;
              db.run(
                'INSERT INTO user_configs (user_id, backend_url, proxy_api_key) VALUES (?, ?, ?)',
                [this.lastID, '', apiKey],
                (configErr) => {
                  if (configErr) {
                    console.error('Error creating admin config:', configErr);
                  }
                }
              );
            }
          }
        );
      } catch (hashErr) {
        console.error('Error hashing admin password:', hashErr);
      }
    }
  });

  // Import WAF rules from file to database if database is empty
  db.get("SELECT COUNT(*) as count FROM waf_rules", (err, result) => {
    if (err) {
      console.error('Error checking WAF rules:', err);
      return;
    }
    
    if (result.count === 0) {
      console.log('📦 Importing WAF rules from file to database...');
      const fs = require('fs');
      const wafPath = fs.existsSync(path.join(__dirname, '../services/firewall/waf-rules.json'))
        ? path.join(__dirname, '../services/firewall/waf-rules.json')
        : path.join(__dirname, '../security-proxy/data/waf_rules.json');
      
      fs.readFile(wafPath, 'utf8', (readErr, data) => {
        if (readErr) {
          console.error('❌ Failed to read WAF rules file:', readErr);
          return;
        }
        
        try {
          const wafRules = JSON.parse(data);
          if (Array.isArray(wafRules)) {
            const stmt = db.prepare(
              `INSERT OR IGNORE INTO waf_rules (id, pattern, message, tags, severity, enabled) 
               VALUES (?, ?, ?, ?, ?, ?)`
            );
            
            wafRules.forEach(rule => {
              stmt.run([
                rule.id,
                rule.pattern,
                rule.message,
                rule.tags,
                rule.severity,
                rule.enabled ? 1 : 0
              ]);
            });
            
            stmt.finalize(() => {
              console.log(`✅ Imported ${wafRules.length} WAF rules to database`);
            });
          }
        } catch (parseErr) {
          console.error('❌ Failed to parse WAF rules:', parseErr);
        }
      });
    }
  });

  // Import Suricata rules from files to database if database is empty
  db.get("SELECT COUNT(*) as count FROM suricata_rules", (err, result) => {
    if (err) {
      console.error('Error checking Suricata rules:', err);
      return;
    }
    
    if (result.count === 0) {
      console.log('📦 Importing Suricata rules from files to database...');
      const fs = require('fs');
      const rulesPath = path.join(__dirname, '../services/suricata/rules');
      
      fs.readdir(rulesPath, (readErr, files) => {
        if (readErr) {
          console.error('❌ Failed to read Suricata rules directory:', readErr);
          return;
        }
        
        const ruleFiles = files.filter(f => f.endsWith('.rules'));
        let totalRulesImported = 0;
        
        ruleFiles.forEach(filename => {
          fs.readFile(path.join(rulesPath, filename), 'utf8', (fileErr, content) => {
            if (fileErr) {
              console.error(`❌ Failed to read ${filename}:`, fileErr);
              return;
            }
            
            const lines = content.split('\n');
            const stmt = db.prepare(
              `INSERT OR IGNORE INTO suricata_rules (
                sid, action, protocol, source_ip, source_port, direction, dest_ip, dest_port,
                msg, flow, content, http_uri, http_method, http_header, http_request_body,
                nocase, pcre, classtype, rev, priority, enabled, category, filename
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            );
            
            lines.forEach(line => {
              line = line.trim();
              if (line && !line.startsWith('#')) {
                try {
                  // Parse Suricata rule (basic parsing)
                  const match = line.match(/^(alert|drop|reject|pass)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<-|<>)\s+(\S+)\s+(\S+)\s+\((.*)\)$/);
                  if (match) {
                    const [, action, protocol, srcIp, srcPort, direction, destIp, destPort, optionsStr] = match;
                    
                    // Parse options
                    const options = {};
                    const optionMatches = optionsStr.matchAll(/(\w+):([^;]+);?/g);
                    for (const optMatch of optionMatches) {
                      const key = optMatch[1];
                      const value = optMatch[2].replace(/^"(.*)"$/, '$1');
                      options[key] = value;
                    }
                    
                    // Check for flags without values
                    const flags = ['nocase', 'http.uri', 'http.method', 'http.header', 'http.request_body'];
                    flags.forEach(flag => {
                      if (optionsStr.includes(flag + ';') || optionsStr.includes(flag + ')')) {
                        options[flag.replace('.', '_')] = true;
                      }
                    });
                    
                    const sid = parseInt(options.sid) || Math.floor(Math.random() * 1000000) + 9000000;
                    
                    stmt.run([
                      sid,
                      action,
                      protocol,
                      srcIp,
                      srcPort,
                      direction,
                      destIp,
                      destPort,
                      options.msg || 'Imported rule',
                      options.flow || null,
                      options.content || null,
                      options.http_uri ? 1 : 0,
                      options.http_method ? 1 : 0,
                      options.http_header ? 1 : 0,
                      options.http_request_body ? 1 : 0,
                      options.nocase ? 1 : 0,
                      options.pcre || null,
                      options.classtype || 'web-application-attack',
                      parseInt(options.rev) || 1,
                      parseInt(options.priority) || 2,
                      1, // enabled by default
                      'imported',
                      filename
                    ]);
                    totalRulesImported++;
                  }
                } catch (parseErr) {
                  // Silently skip malformed rules
                }
              }
            });
            
            stmt.finalize(() => {
              console.log(`✅ Imported ${totalRulesImported} Suricata rules from ${ruleFiles.length} file(s) to database`);
            });
          });
        });
      });
    }
  });
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: NODE_ENV === 'production' ? 31536000 : 0,
    includeSubDomains: true,
    preload: true,
  },
  frameguard: {
    action: 'deny',
  },
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin',
  },
  noSniff: true,
  xssFilter: true,
}));

const configuredAllowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const allowAllOrigins = configuredAllowedOrigins.includes('*');

if (NODE_ENV === 'production' && (allowAllOrigins || configuredAllowedOrigins.length === 0)) {
  throw new Error('ALLOWED_ORIGINS must be explicitly set in production and cannot be "*"');
}

const defaultDevOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:4173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:4173',
];

const allowedOriginSet = new Set(
  configuredAllowedOrigins.length > 0 ? configuredAllowedOrigins : defaultDevOrigins
);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowAllOrigins || allowedOriginSet.has(origin)) return callback(null, true);
    // Reject silently — do NOT pass an Error or Express returns 500
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Internal-Token', 'Cache-Control', 'Pragma', 'Expires'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 5 : 1000, // 5 in prod, 1000 in dev
  message: { 
    error: 'Too many authentication attempts, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5000, // 5000 requests per window for dev/testing
  message: { 
    error: 'Too many requests, please try again later.'
  },
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);
app.use('/api', generalLimiter);

// Add request logging middleware (should be after rate limiting but before routes)
app.use(requestLoggerMiddleware);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const requireInternalServiceToken = (req, res, next) => {
  if (!INTERNAL_API_TOKEN) {
    return res.status(503).json({ error: 'Internal service token not configured' });
  }

  const providedToken = (req.headers['x-internal-token'] || '').toString().trim();
  if (!providedToken || providedToken !== INTERNAL_API_TOKEN) {
    return res.status(401).json({ error: 'Invalid internal service token' });
  }

  next();
};

// Register rules middleware and routes
app.use(ruleAuditLog);
app.use(validateRuleParams);
app.use(queuedExport);
app.use(checkRulePermissions);
app.use('/api', rulesRouter);

// Validation middleware
const validateSignup = [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores, and hyphens'),
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 12 })
    .withMessage('Password must be at least 12 characters long')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/)
    .withMessage('Password must contain at least one special character (!@#$%^&*...)'),
];

const validateLogin = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 1 })
    .withMessage('Password is required'),
];

// Utility function to log audit events
const logAuditEvent = (userId, action, req, success = true, details = null) => {
  db.run(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, success, details)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      userId,
      action,
      req?.ip || 'unknown',
      req?.get?.('User-Agent') || 'unknown',
      success,
      details
    ],
    (err) => {
      if (err) {
        console.error('Audit log write failed:', err.code || err.message || err);
      }
    }
  );
};

// Auth Routes
app.post('/api/auth/signup', validateSignup, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logAuditEvent(null, 'SIGNUP_VALIDATION_FAILED', req, false, JSON.stringify(errors.array()));
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM users WHERE email = ? OR username = ?',
        [email, username],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (existingUser) {
      const field = existingUser.email === email ? 'email' : 'username';
      logAuditEvent(null, 'SIGNUP_DUPLICATE_USER', req, false, `Duplicate ${field}: ${field === 'email' ? email : username}`);
      return res.status(409).json({ 
        message: `User with this ${field} already exists` 
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const userId = await new Promise((resolve, reject) => {
      const stmt = db.prepare(`
        INSERT INTO users (username, email, password)
        VALUES (?, ?, ?)
      `);
      
      stmt.run(username, email, hashedPassword, function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      });
      
      stmt.finalize();
    });

    // Generate unique API key for the user
    const crypto = require('crypto');
    const apiKey = `nxr_${crypto.randomBytes(32).toString('hex')}`;
    
    // Create user config with API key
    await new Promise((resolve, reject) => {
      const stmt = db.prepare(`
        INSERT INTO user_configs (user_id, backend_url, proxy_api_key)
        VALUES (?, ?, ?)
      `);
      stmt.run(userId, '', apiKey, function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      });
      stmt.finalize();
    });

    // Generate short-lived access token (15 minutes)
    const accessToken = jwt.sign(
      { userId, username, email, role: 'user' },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    // Generate long-lived refresh token (7 days)
    const refreshToken = jwt.sign(
      { userId },
      REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // Set refresh token as httpOnly cookie
    const isProduction = NODE_ENV === 'production';
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/api/auth'
    });

    logAuditEvent(userId, 'SIGNUP_SUCCESS', req, true);

    res.status(201).json({
      message: 'Account created successfully',
      accessToken,
      user: { id: userId, username, email, role: 'user' }
    });

  } catch (error) {
    console.error('Signup error:', error);
    logAuditEvent(null, 'SIGNUP_ERROR', req, false, error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/login', validateLogin, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logAuditEvent(null, 'LOGIN_VALIDATION_FAILED', req, false, JSON.stringify(errors.array()));
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { email, password } = req.body;

    // Find user by email
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM users WHERE email = ? AND is_active = 1 AND is_banned = 0',
        [email],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!user) {
      logAuditEvent(null, 'LOGIN_USER_NOT_FOUND', req, false, `Email: ${email}`);
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    if (user.is_banned) {
      logAuditEvent(user.id, 'LOGIN_BANNED_USER', req, false);
      return res.status(403).json({ message: 'Your account has been banned' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      logAuditEvent(user.id, 'LOGIN_INVALID_PASSWORD', req, false);
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Update last login
    db.run(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
      [user.id]
    );

    // Generate short-lived access token (15 minutes)
    const accessToken = jwt.sign(
      { userId: user.id, username: user.username, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    // Generate long-lived refresh token (7 days)
    const refreshToken = jwt.sign(
      { userId: user.id },
      REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // Set refresh token as httpOnly cookie
    const isProduction = NODE_ENV === 'production';
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/api/auth' // restrict to auth endpoints only
    });

    logAuditEvent(user.id, 'LOGIN_SUCCESS', req, true);

    res.json({
      message: 'Login successful',
      accessToken,
      user: { 
        id: user.id, 
        username: user.username, 
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    logAuditEvent(null, 'LOGIN_ERROR', req, false, error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get current user (protected route)
app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, username, email, role, created_at, last_login FROM users WHERE id = ?',
    [req.user.userId],
    (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      res.json({ user });
    }
  );
});

// Logout endpoint (optional - mainly for audit logging)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  logAuditEvent(req.user.userId, 'LOGOUT', req, true);
  
  // Clear refresh token cookie
  res.clearCookie('refreshToken', { path: '/api/auth' });
  
  res.json({ message: 'Logout successful' });
});

// Refresh access token using refresh token from cookie
app.post('/api/auth/refresh', (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({ message: 'Refresh token not found' });
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    } catch (err) {
      res.clearCookie('refreshToken', { path: '/api/auth' });
      return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }

    // Get user data
    const user = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(decoded.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate new short-lived access token
    const newAccessToken = jwt.sign(
      { userId: user.id, username: user.username, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({ accessToken: newAccessToken });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== USER CONFIG ROUTES ====================

// Get user configuration
app.get('/api/user/config', authenticateToken, async (req, res) => {
  try {
    let config = await new Promise((resolve, reject) => {
      db.get(
        'SELECT backend_url, proxy_api_key, is_configured, connectivity_status, last_test_at FROM user_configs WHERE user_id = ?',
        [req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    // If no config exists, create one with default values
    if (!config) {
      const apiKey = `nxr_${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;
      
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO user_configs (user_id, proxy_api_key, backend_url, is_configured) VALUES (?, ?, ?, ?)',
          [req.user.userId, apiKey, '', false],
          function(err) {
            if (err) reject(err);
            else resolve(this.lastID);
          }
        );
      });

      config = {
        backend_url: '',
        proxy_api_key: apiKey,
        is_configured: false,
        connectivity_status: null,
        last_test_at: null
      };
    }

    res.json({ config });
  } catch (error) {
    console.error('Get config error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update user backend URL
app.put('/api/user/config', authenticateToken, async (req, res) => {
  try {
    const { backend_url } = req.body;

    if (!backend_url || !backend_url.trim()) {
      return res.status(400).json({ message: 'Backend URL is required' });
    }

    // Validate URL format
    try {
      new URL(backend_url);
    } catch (err) {
      return res.status(400).json({ message: 'Invalid URL format' });
    }

    // SSRF Prevention: Validate against private IP ranges and reserved URLs
    if (!isValidBackendURL(backend_url)) {
      logAuditEvent(req.user.userId, 'SSRF_ATTEMPT_BLOCKED', req, false, `Attempted to set internal URL: ${backend_url}`);
      return res.status(400).json({ message: 'Backend URL is blocked by security policy' });
    }

    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE user_configs SET backend_url = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?',
        [backend_url, req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    logAuditEvent(req.user.userId, 'UPDATE_BACKEND_URL', req, true);

    res.json({ message: 'Backend URL updated successfully', backend_url });
  } catch (error) {
    console.error('Update config error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Test connectivity to user's backend
app.post('/api/user/config/test', authenticateToken, async (req, res) => {
  try {
    const config = await new Promise((resolve, reject) => {
      db.get(
        'SELECT backend_url FROM user_configs WHERE user_id = ?',
        [req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!config || !config.backend_url) {
      return res.status(400).json({ message: 'Backend URL not configured' });
    }

    // SSRF Prevention: Validate before making request
    if (!isValidBackendURL(config.backend_url)) {
      logAuditEvent(req.user.userId, 'SSRF_ATTEMPT_BLOCKED', req, false, `Attempted to test internal URL: ${config.backend_url}`);
      return res.status(400).json({ message: 'Backend URL appears to be invalid' });
    }

    // Test connection to backend
    const axios = require('axios');
    let status = 'failed';
    let message = 'Connection failed';

    try {
      const response = await axios.get(config.backend_url, { timeout: 8000 });
      // Any HTTP response (even 404/500) means the server is reachable
      status = 'success';
      message = `Successfully connected to backend (HTTP ${response.status})`;
    } catch (error) {
      // If we got an HTTP error response (4xx/5xx), server IS reachable
      if (error.response) {
        status = 'success';
        message = `Backend is reachable (HTTP ${error.response.status})`;
      } else {
        // Network-level failure: use generic messages to prevent info leakage
        message = getGenericErrorMessage(error);
      }
    }

    // Update connectivity status
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE user_configs SET connectivity_status = ?, last_test_at = CURRENT_TIMESTAMP, is_configured = ? WHERE user_id = ?',
        [status, status === 'success' ? 1 : 0, req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    logAuditEvent(req.user.userId, 'TEST_CONNECTIVITY', req, true, `Status: ${status}`);

    res.json({ status, message });
  } catch (error) {
    console.error('Test connectivity error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Mark setup as complete
app.post('/api/user/config/complete-setup', authenticateToken, async (req, res) => {
  try {
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE user_configs SET is_configured = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?',
        [req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    res.json({ message: 'Setup completed successfully' });
  } catch (error) {
    console.error('Complete setup error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== USER PROFILE ROUTES ====================

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, username, email, created_at FROM users WHERE id = ?',
        [req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile (username and email)
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { username, email } = req.body;

    // Validation
    if (!username || !email) {
      return res.status(400).json({ error: 'Username and email are required' });
    }

    const trimmedUsername = username.trim();
    const trimmedEmail = email.trim();

    if (trimmedUsername.length < 2) {
      return res.status(400).json({ error: 'Username must be at least 2 characters' });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Check if username or email already exists (for other users)
    const existing = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
        [trimmedUsername, trimmedEmail, req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (existing) {
      return res.status(409).json({ error: 'Username or email already in use' });
    }

    // Update user
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET username = ?, email = ? WHERE id = ?',
        [trimmedUsername, trimmedEmail, req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    logAuditEvent(req.user.userId, 'UPDATE_PROFILE', req, true);

    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Change password
app.put('/api/user/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Validation
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new passwords are required' });
    }

    // Enforce strong password policy
    const passwordErrors = [];
    if (newPassword.length < 12) passwordErrors.push('must be at least 12 characters');
    if (!/[a-z]/.test(newPassword)) passwordErrors.push('must contain lowercase letters');
    if (!/[A-Z]/.test(newPassword)) passwordErrors.push('must contain uppercase letters');
    if (!/[0-9]/.test(newPassword)) passwordErrors.push('must contain numbers');
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword)) passwordErrors.push('must contain special characters');
    
    if (passwordErrors.length > 0) {
      return res.status(400).json({ error: 'New password ' + passwordErrors.join(' and ') });
    }

    if (currentPassword === newPassword) {
      return res.status(400).json({ error: 'New password must be different from current password' });
    }

    // Get user and verify current password
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, password FROM users WHERE id = ?',
        [req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      logAuditEvent(req.user.userId, 'CHANGE_PASSWORD_FAILURE', req, false, 'Invalid current password');
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET password = ? WHERE id = ?',
        [hashedPassword, req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    logAuditEvent(req.user.userId, 'CHANGE_PASSWORD_SUCCESS', req, true);

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// ==================== USER APPLICATIONS ROUTES ====================

// Get all applications for user (with per-app stats)
app.get('/api/user/applications', authenticateToken, async (req, res) => {
  try {
    const applications = await new Promise((resolve, reject) => {
      db.all(
        `SELECT ua.id, ua.app_name, ua.backend_url, ua.proxy_api_key, ua.description, ua.is_active,
          ua.connectivity_status, ua.last_test_at, ua.created_at,
          (SELECT COUNT(*) FROM user_request_logs rl WHERE rl.app_id = ua.id) as request_count,
          (SELECT COUNT(*) FROM user_alerts al WHERE al.user_id = ua.user_id AND (al.app_id = ua.id OR al.app_id IS NULL)) as alert_count,
          (SELECT COUNT(*) FROM user_alerts al WHERE al.user_id = ua.user_id AND (al.app_id = ua.id OR al.app_id IS NULL) AND al.is_read = 0) as unread_alert_count,
          (SELECT COUNT(*) FROM user_request_logs rl WHERE rl.app_id = ua.id AND rl.waf_triggered = 1) as waf_blocks,
          (SELECT AVG(rl.response_time) FROM user_request_logs rl WHERE rl.app_id = ua.id) as avg_response_time
        FROM user_applications ua WHERE ua.user_id = ? ORDER BY ua.created_at DESC`,
        [req.user.userId],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows || []);
        }
      );
    });

    res.json({ applications });
  } catch (error) {
    console.error('Get applications error:', error);
    res.status(500).json({ error: 'Failed to fetch applications' });
  }
});

// Create new application
app.post('/api/user/applications', authenticateToken, async (req, res) => {
  try {
    const { app_name, backend_url, description } = req.body;
    console.log('Creating application:', { app_name, backend_url, userId: req.user.userId });

    // Validation
    if (!app_name || !backend_url) {
      return res.status(400).json({ error: 'Application name and backend URL are required' });
    }

    if (app_name.length < 2 || app_name.length > 50) {
      return res.status(400).json({ error: 'Application name must be between 2-50 characters' });
    }

    // Validate URL
    try {
      new URL(backend_url);
    } catch (err) {
      return res.status(400).json({ error: 'Invalid backend URL format. Use http:// or https://' });
    }

    // SSRF Prevention: Validate against private IP ranges and reserved URLs
    if (!isValidBackendURL(backend_url)) {
      logAuditEvent(req.user.userId, 'SSRF_ATTEMPT_BLOCKED', req, false, `Attempted to register internal URL: ${backend_url}`);
      return res.status(400).json({ error: 'Backend URL is blocked by security policy' });
    }

    // Check if app name is unique for this user
    const existing = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id FROM user_applications WHERE user_id = ? AND app_name = ?',
        [req.user.userId, app_name],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (existing) {
      return res.status(409).json({ error: 'Application name already exists for your account' });
    }

    // Generate a cryptographically secure, globally unique API key
    let apiKey;
    let attempts = 0;
    while (true) {
      apiKey = `nxr_${crypto.randomBytes(32).toString('hex')}`;
      const existing = await new Promise((resolve, reject) => {
        db.get('SELECT id FROM user_applications WHERE proxy_api_key = ?', [apiKey], (err, row) => {
          if (err) reject(err); else resolve(row);
        });
      });
      if (!existing) break;
      if (++attempts > 5) throw new Error('Failed to generate unique API key');
    }

    // Create application
    const result = await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO user_applications (user_id, app_name, backend_url, proxy_api_key, description) VALUES (?, ?, ?, ?, ?)',
        [req.user.userId, app_name, backend_url, apiKey, description || ''],
        function(err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });

    logAuditEvent(req.user.userId, 'CREATE_APPLICATION', req, true, `App: ${app_name}`);

    res.json({ 
      message: 'Application created successfully',
      id: result,
      proxy_api_key: apiKey
    });
  } catch (error) {
    console.error('Create application error:', error);
    res.status(500).json({ error: `Failed to create application: ${error.message}` });
  }
});

// Get specific application
app.get('/api/user/applications/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const app = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM user_applications WHERE id = ? AND user_id = ?',
        [id, req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!app) {
      return res.status(404).json({ error: 'Application not found' });
    }

    res.json({ application: app });
  } catch (error) {
    console.error('Get application error:', error);
    res.status(500).json({ error: 'Failed to fetch application' });
  }
});

// Update application
app.put('/api/user/applications/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { app_name, backend_url, description, is_active } = req.body;

    // Get existing app to verify ownership
    const app = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id FROM user_applications WHERE id = ? AND user_id = ?',
        [id, req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!app) {
      return res.status(404).json({ error: 'Application not found' });
    }

    // Validation
    if (app_name && (app_name.length < 2 || app_name.length > 50)) {
      return res.status(400).json({ error: 'Application name must be between 2-50 characters' });
    }

    if (backend_url) {
      try {
        new URL(backend_url);
      } catch (err) {
        return res.status(400).json({ error: 'Invalid backend URL format' });
      }
    }

    // Build update query
    const updates = [];
    const values = [];
    if (app_name !== undefined) { updates.push('app_name = ?'); values.push(app_name); }
    if (backend_url !== undefined) { updates.push('backend_url = ?'); values.push(backend_url); }
    if (description !== undefined) { updates.push('description = ?'); values.push(description); }
    if (is_active !== undefined) { updates.push('is_active = ?'); values.push(is_active ? 1 : 0); }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(id);
    values.push(req.user.userId);

    await new Promise((resolve, reject) => {
      db.run(
        `UPDATE user_applications SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`,
        values,
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    logAuditEvent(req.user.userId, 'UPDATE_APPLICATION', req, true, `App ID: ${id}`);

    res.json({ message: 'Application updated successfully' });
  } catch (error) {
    console.error('Update application error:', error);
    res.status(500).json({ error: 'Failed to update application' });
  }
});

// Delete application
app.delete('/api/user/applications/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await new Promise((resolve, reject) => {
      db.run(
        'DELETE FROM user_applications WHERE id = ? AND user_id = ?',
        [id, req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve(this.changes);
        }
      );
    });

    if (result === 0) {
      return res.status(404).json({ error: 'Application not found' });
    }

    logAuditEvent(req.user.userId, 'DELETE_APPLICATION', req, true, `App ID: ${id}`);

    res.json({ message: 'Application deleted successfully' });
  } catch (error) {
    console.error('Delete application error:', error);
    res.status(500).json({ error: 'Failed to delete application' });
  }
});

// Test application connectivity
app.post('/api/user/applications/:id/test', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const app = await new Promise((resolve, reject) => {
      db.get(
        'SELECT backend_url FROM user_applications WHERE id = ? AND user_id = ?',
        [id, req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!app) {
      return res.status(404).json({ error: 'Application not found' });
    }

    // SSRF Prevention: Validate before making request
    if (!isValidBackendURL(app.backend_url)) {
      logAuditEvent(req.user.userId, 'SSRF_ATTEMPT_BLOCKED', req, false, `Attempted to test internal URL: ${app.backend_url}`);
      return res.status(400).json({ error: 'Backend URL appears to be invalid' });
    }

    let status = 'failed';
    let message = 'Backend could not be reached';

    try {
      const parsedUrl = new URL(app.backend_url);
      const transport = parsedUrl.protocol === 'https:' ? require('https') : require('http');
      const allowInsecureTLS = process.env.ALLOW_INSECURE_BACKEND_TLS === 'true';

      const statusCode = await new Promise((resolve, reject) => {
        const reqOptions = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          method: 'GET',
          timeout: 10000,
          ...(parsedUrl.protocol === 'https:' && allowInsecureTLS ? { rejectUnauthorized: false } : {}),
        };
        const probe = transport.request(reqOptions, (r) => resolve(r.statusCode));
        probe.on('timeout', () => { probe.destroy(); reject(new Error('Request timed out')); });
        probe.on('error', reject);
        probe.end();
      });

      // Any HTTP response (including 4xx/5xx) means the server is reachable
      status = 'success';
      message = `Backend is reachable (HTTP ${statusCode})`;
      console.log(`Connectivity test for ${app.backend_url}: ${status} — ${message}`);
    } catch (err) {
      status = 'failed';
      message = 'Could not reach backend: ' + (err.message || 'Unknown error');
      console.error(`Connectivity test failed for ${app.backend_url}:`, err.message);
    }

    // Update connectivity status
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE user_applications SET connectivity_status = ?, last_test_at = CURRENT_TIMESTAMP WHERE id = ?',
        [status, id],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    logAuditEvent(req.user.userId, 'TEST_APP_CONNECTIVITY', req, true, `App ID: ${id}, Status: ${status}`);

    res.json({ status, message });
  } catch (error) {
    console.error('Test connectivity error:', error);
    res.status(500).json({ error: 'Failed to test connectivity' });
  }
});

// ==================== USER LOGS ROUTES ====================

// Get user-specific request logs
app.get('/api/user/logs', authenticateToken, async (req, res) => {
  try {
    // Disable caching for dynamic logs endpoint
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    
    const { limit = 100, offset = 0, threat_level, waf_triggered, suricata_triggered, app_id } = req.query;
    
    let baseWhere = 'WHERE user_id = ?';
    let baseParams = [req.user.userId];

    if (app_id) { baseWhere += ' AND (app_id = ? OR app_id IS NULL)'; baseParams.push(parseInt(app_id)); }
    if (threat_level) { baseWhere += ' AND threat_level = ?'; baseParams.push(threat_level); }
    if (waf_triggered !== undefined && waf_triggered !== '') {
      baseWhere += ' AND waf_triggered = ?'; baseParams.push(waf_triggered === 'true' ? 1 : 0);
    }
    if (suricata_triggered !== undefined && suricata_triggered !== '') {
      baseWhere += ' AND suricata_triggered = ?'; baseParams.push(suricata_triggered === 'true' ? 1 : 0);
    }

    const total = await new Promise((resolve, reject) => {
      db.get(`SELECT COUNT(*) as cnt FROM user_request_logs ${baseWhere}`, baseParams, (err, row) => {
        if (err) reject(err); else resolve(row ? row.cnt : 0);
      });
    });

    const logs = await new Promise((resolve, reject) => {
      db.all(`SELECT * FROM user_request_logs ${baseWhere} ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
        [...baseParams, parseInt(limit), parseInt(offset)],
        (err, rows) => { if (err) reject(err); else resolve(rows || []); });
    });

    res.json({ logs, count: logs.length, total });
  } catch (error) {
    console.error('Get user logs error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get user logs statistics
app.get('/api/user/logs/stats', authenticateToken, async (req, res) => {
  try {
    // Disable caching for dynamic stats endpoint
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    
    const { app_id } = req.query;
    const appFilter = app_id ? ' AND app_id = ?' : '';
    const baseParams = app_id ? [req.user.userId, parseInt(app_id)] : [req.user.userId];

    // total_requests and avg_response_time come from the request log
    const trafficStats = await new Promise((resolve, reject) => {
      db.get(
        `SELECT COUNT(*) as total_requests, AVG(response_time) as avg_response_time
        FROM user_request_logs WHERE user_id = ?${appFilter}`,
        baseParams,
        (err, row) => { if (err) reject(err); else resolve(row); }
      );
    });

    // Security counts come from user_alerts which is always accurately populated
    const alertStats = await new Promise((resolve, reject) => {
      db.get(
        `SELECT
          SUM(CASE WHEN alert_type = 'waf' THEN 1 ELSE 0 END) as waf_blocks,
          SUM(CASE WHEN alert_type = 'suricata' THEN 1 ELSE 0 END) as suricata_alerts,
          SUM(CASE WHEN alert_type IN ('waf', 'suricata', 'system') THEN 1 ELSE 0 END) as threats_detected
        FROM user_alerts WHERE user_id = ?${appFilter}`,
        baseParams,
        (err, row) => { if (err) reject(err); else resolve(row); }
      );
    });

    const stats = {
      total_requests:  trafficStats.total_requests  || 0,
      avg_response_time: trafficStats.avg_response_time || 0,
      waf_blocks:      alertStats.waf_blocks        || 0,
      suricata_alerts: alertStats.suricata_alerts   || 0,
      threats_detected: alertStats.threats_detected || 0,
    };

    res.json({ stats });
  } catch (error) {
    console.error('Get user logs stats error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get top endpoints for user
app.get('/api/user/logs/top-endpoints', authenticateToken, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const { limit = 5, app_id } = req.query;
    const appFilter = app_id ? ' AND app_id = ?' : '';
    const params = app_id ? [req.user.userId, parseInt(app_id), parseInt(limit)] : [req.user.userId, parseInt(limit)];

    const rows = await new Promise((resolve, reject) => {
      db.all(
        `SELECT
          method,
          url,
          backend_url,
          COUNT(*) as calls,
          AVG(response_time) as avg_response_time,
          MAX(status_code) as last_status
        FROM user_request_logs
        WHERE user_id = ?${appFilter}
        GROUP BY method, url
        ORDER BY calls DESC
        LIMIT ?`,
        params,
        (err, rows) => { if (err) reject(err); else resolve(rows || []); }
      );
    });

    res.json({ endpoints: rows });
  } catch (error) {
    console.error('Get top endpoints error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== USER ALERTS ROUTES ====================

// Get user-specific alerts
app.get('/api/user/alerts', authenticateToken, async (req, res) => {
  try {
    // Disable caching for dynamic alerts endpoint
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    
    const { limit = 100, offset = 0, severity, alert_type, is_read, app_id } = req.query;
    
    let baseWhere = 'WHERE user_id = ?';
    let baseParams = [req.user.userId];

    if (app_id) {
      baseWhere += ' AND (app_id = ? OR app_id IS NULL)';
      baseParams.push(parseInt(app_id));
    }
    if (severity) { baseWhere += ' AND severity = ?'; baseParams.push(severity); }
    if (alert_type) { baseWhere += ' AND alert_type = ?'; baseParams.push(alert_type); }
    if (is_read !== undefined && is_read !== '') {
      baseWhere += ' AND is_read = ?';
      baseParams.push(is_read === 'true' ? 1 : 0);
    }

    const total = await new Promise((resolve, reject) => {
      db.get(`SELECT COUNT(*) as cnt FROM user_alerts ${baseWhere}`, baseParams, (err, row) => {
        if (err) reject(err); else resolve(row ? row.cnt : 0);
      });
    });

    const alerts = await new Promise((resolve, reject) => {
      db.all(`SELECT * FROM user_alerts ${baseWhere} ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
        [...baseParams, parseInt(limit), parseInt(offset)],
        (err, rows) => { if (err) reject(err); else resolve(rows || []); });
    });

    res.json({ alerts, count: alerts.length, total });
  } catch (error) {
    console.error('Get user alerts error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Mark alert as read
app.put('/api/user/alerts/:id/read', authenticateToken, async (req, res) => {
  try {
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE user_alerts SET is_read = 1 WHERE id = ? AND user_id = ?',
        [req.params.id, req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    res.json({ message: 'Alert marked as read' });
  } catch (error) {
    console.error('Mark alert read error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Mark ALL alerts as read for current user
app.put('/api/user/alerts/read-all', authenticateToken, async (req, res) => {
  try {
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE user_alerts SET is_read = 1 WHERE user_id = ?',
        [req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    res.json({ message: 'All alerts marked as read' });
  } catch (error) {
    console.error('Mark all alerts read error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get unread alerts count
app.get('/api/user/alerts/unread-count', authenticateToken, async (req, res) => {
  try {
    const count = await new Promise((resolve, reject) => {
      db.get(
        'SELECT COUNT(*) as count FROM user_alerts WHERE user_id = ? AND is_read = 0',
        [req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row?.count || 0);
        }
      );
    });

    res.json({ count });
  } catch (error) {
    console.error('Get unread count error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Delete alert
app.delete('/api/user/alerts/:id', authenticateToken, async (req, res) => {
  try {
    await new Promise((resolve, reject) => {
      db.run(
        'DELETE FROM user_alerts WHERE id = ? AND user_id = ?',
        [req.params.id, req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    res.json({ message: 'Alert deleted successfully' });
  } catch (error) {
    console.error('Delete alert error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Insert Suricata/WAF alert (from trusted internal services)
app.post('/api/security/alerts/insert', requireInternalServiceToken, async (req, res) => {
  try {
    const {
      // Raw suricata/WAF fields
      source, severity, category, signature, src_ip, dest_ip,
      src_port, dest_port, protocol, flow_id, timestamp, description,
      // user_alerts fields (may come from WAF middleware)
      alert_type, rule_id, rule_name, target_url, recommended_action, action, auto_blocked
    } = req.body;

    // --- 1. Insert into raw alerts table (Suricata-style, backwards compat) ---
    const rawSeverity = typeof severity === 'number' ? severity :
      (severity === 'critical' ? 1 : severity === 'high' ? 2 :
       severity === 'medium' ? 3 : severity === 'low' ? 4 : 3);

    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO alerts (source, severity, category, signature, src_ip, dest_ip, src_port, dest_port, protocol, flow_id, timestamp, description)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          source || alert_type || 'system',
          rawSeverity,
          category || alert_type || 'unknown',
          signature || rule_name || rule_id || 'unknown',
          src_ip || '0.0.0.0',
          dest_ip || '127.0.0.1',
          src_port || 0,
          dest_port || 8080,
          protocol || 'HTTP',
          flow_id || null,
          timestamp || new Date().toISOString(),
          description || signature || rule_name || ''
        ],
        function(err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });

    // --- 2. Insert into user_alerts with correct scoping ---
    // Routing rules:
    //  a) Explicit user_id in payload (from Go proxy inline WAF/IPS) → that user only
    //  b) IPS drop/block from eve.json → try to match dest_ip:dest_port against
    //     user_configs.backend_url; if matched → that user + admins; else → admins only
    //  c) IDS detect from eve.json (no block) → admins only
    const severityStr = typeof severity === 'string' ? severity :
      (rawSeverity <= 1 ? 'critical' : rawSeverity === 2 ? 'high' :
       rawSeverity === 3 ? 'medium' : 'low');

    const alertTypeStr = (() => {
      if (alert_type === 'waf' || source === 'waf') return 'waf';
      // ids-inline = HTTP-layer regex checks from the Go proxy (application layer, same as WAF)
      // These should NOT appear in the Suricata IDS/IPS view
      if (source === 'ids-inline') return 'waf';
      // Real Suricata network-level alerts only: suricata-ids, suricata-ips, or generic 'suricata'
      if (source === 'suricata' || source === 'suricata-ids' || source === 'suricata-ips' ||
          (typeof source === 'string' && source.startsWith('suricata'))) return 'suricata';
      return 'system';
    })();

    const validSeverities = ['low', 'medium', 'high', 'critical'];
    const finalSeverity = validSeverities.includes(severityStr) ? severityStr : 'medium';
    const isBlockingAction = ['blocked','dropped','rejected','prevented'].includes(action);
    const finalAction = ['detected','allowed','blocked','dropped','rejected','prevented'].includes(action)
      ? action : (alertTypeStr === 'waf' ? 'blocked' : 'detected');

    // Determine target recipients
    // directUserIds  → admins + IP-correlated users → is_read=0 (they need to act / investigate)
    // broadcastUserIds → recently active users added by fallback → is_read=1 (informational context)
    const directUserIds = new Set();
    const broadcastUserIds = new Set();
    const explicitUserId = req.body.user_id ? parseInt(req.body.user_id) : null;

    if (explicitUserId) {
      // (a) Go proxy passed a specific user — directly involved
      directUserIds.add(explicitUserId);
    } else {
      // Always include admins — they must see everything
      const admins = await new Promise((resolve, reject) => {
        db.all(`SELECT id FROM users WHERE role = 'admin'`, [], (err, rows) => {
          if (err) reject(err);
          else resolve(rows || []);
        });
      });
      admins.forEach(a => directUserIds.add(a.id));

      // (b) Dest IP matches a user's configured backend — their server was targeted
      if (dest_ip) {
        const configs = await new Promise((resolve, reject) => {
          db.all(`SELECT user_id, backend_url FROM user_configs WHERE backend_url IS NOT NULL AND backend_url != ''`, [], (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        });
        for (const cfg of configs) {
          try {
            const u = new URL(cfg.backend_url);
            const cfgHost = u.hostname;
            const cfgPort = u.port || (u.protocol === 'https:' ? '443' : '80');
            if (cfgHost === dest_ip && (!dest_port || String(dest_port) === cfgPort)) {
              directUserIds.add(cfg.user_id);
            }
          } catch (_) { /* skip malformed urls */ }
        }
      }

      // (c)+(d) Suricata is a network-level sensor — alerts cannot be scoped to a user.
      // Only admins receive Suricata alerts. WAF/system alerts still use src_ip matching.
      if (alertTypeStr !== 'suricata') {
        const effectiveSrcIp = src_ip || (req.body.source_ip);
        if (effectiveSrcIp && effectiveSrcIp !== '0.0.0.0' && effectiveSrcIp !== 'unknown') {
          const ipUsers = await new Promise((resolve, reject) => {
            db.all(
              `SELECT DISTINCT user_id FROM user_request_logs
               WHERE client_ip = ?
                 AND timestamp >= datetime('now', '-30 minutes')
               LIMIT 5`,
              [effectiveSrcIp],
              (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
              }
            );
          });
          ipUsers.forEach(r => directUserIds.add(r.user_id));
        }
      }
    }

    const alertScope = alertTypeStr === 'waf' ? 'application' : 'global';
    const sigKey = signature || rule_name || rule_id || 'unknown';

    // Insert for directly-involved users (unread — they need to know)
    for (const uid of directUserIds) {
      const existing = await new Promise((resolve) => {
        db.get(
          `SELECT id FROM user_alerts
           WHERE user_id = ? AND source_ip = ? AND rule_id = ?
             AND timestamp >= datetime('now', '-10 minutes')
           ORDER BY timestamp DESC LIMIT 1`,
          [uid, src_ip || '0.0.0.0', sigKey],
          (err, row) => resolve(row || null)
        );
      });
      if (existing) {
        db.run(`UPDATE user_alerts SET occurrence_count = occurrence_count + 1, timestamp = ? WHERE id = ?`,
          [new Date().toISOString(), existing.id]);
      } else {
        await new Promise((resolve) => {
          db.run(
            `INSERT INTO user_alerts
              (user_id, alert_type, severity, rule_id, rule_name, description,
               source_ip, target_url, recommended_action, action, source, auto_blocked,
               scope, occurrence_count, is_read, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)`,
            [
              uid, alertTypeStr, finalSeverity, sigKey,
              rule_name || signature || (alertTypeStr.toUpperCase() + ' Alert'),
              description || signature || rule_name || 'Security alert detected',
              src_ip || '0.0.0.0', target_url || dest_ip || '',
              recommended_action || 'Review and investigate this alert',
              finalAction, source || alertTypeStr || 'system',
              auto_blocked ? 1 : 0, alertScope, new Date().toISOString()
            ],
            resolve
          );
        });
      }
    }

    // Insert broadcast copies as pre-read (informational context only)
    for (const uid of broadcastUserIds) {
      const existing = await new Promise((resolve) => {
        db.get(
          `SELECT id FROM user_alerts
           WHERE user_id = ? AND source_ip = ? AND rule_id = ?
             AND timestamp >= datetime('now', '-10 minutes')
           ORDER BY timestamp DESC LIMIT 1`,
          [uid, src_ip || '0.0.0.0', sigKey],
          (err, row) => resolve(row || null)
        );
      });
      if (existing) {
        db.run(`UPDATE user_alerts SET occurrence_count = occurrence_count + 1, timestamp = ? WHERE id = ?`,
          [new Date().toISOString(), existing.id]);
      } else {
        await new Promise((resolve) => {
          db.run(
            `INSERT INTO user_alerts
              (user_id, alert_type, severity, rule_id, rule_name, description,
               source_ip, target_url, recommended_action, action, source, auto_blocked,
               scope, occurrence_count, is_read, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?)`,
            [
              uid, alertTypeStr, finalSeverity, sigKey,
              rule_name || signature || (alertTypeStr.toUpperCase() + ' Alert'),
              description || signature || rule_name || 'Security alert detected',
              src_ip || '0.0.0.0', target_url || dest_ip || '',
              recommended_action || 'Review and investigate this alert',
              finalAction, source || alertTypeStr || 'system',
              auto_blocked ? 1 : 0, alertScope, new Date().toISOString()
            ],
            resolve
          );
        });
      }
    }

    console.log(`✅ Alert inserted [${alertTypeStr}/${finalSeverity}]: ${signature || rule_name} from ${src_ip}`);
    res.status(201).json({ success: true, message: 'Alert inserted' });
  } catch (error) {
    console.error('Insert alert error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Admin: Get aggregated alerts (grouped by src_ip + rule_id) with time window + severity filter
app.get('/api/admin/alerts/aggregated', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

    const { window = '24h', severity, limit = 50, offset = 0 } = req.query;

    const windowMap = { '1h': '-1 hours', '24h': '-24 hours', '7d': '-7 days', '30d': '-30 days' };
    const interval = windowMap[window] || '-24 hours';

    let query = `
      SELECT
        source_ip,
        rule_id,
        rule_name,
        alert_type,
        severity,
        scope,
        source,
        MAX(action) as action,
        SUM(occurrence_count) as total_hits,
        COUNT(*) as row_count,
        MAX(timestamp) as last_seen,
        MIN(timestamp) as first_seen,
        GROUP_CONCAT(DISTINCT description) as descriptions
      FROM user_alerts
      WHERE timestamp >= datetime('now', ?)
    `;
    const params = [interval];

    if (severity) {
      if (severity === 'high_critical') {
        query += ` AND severity IN ('high','critical')`;
      } else {
        query += ` AND severity = ?`;
        params.push(severity);
      }
    } else {
      // Default: only show high + critical
      query += ` AND severity IN ('high','critical')`;
    }

    // Admin dashboard IDS/IPS alert table: force Suricata-only (exclude WAF/system)
    query += ` AND alert_type = 'suricata'`;

    query += `
      GROUP BY source_ip, rule_id, alert_type, severity
      ORDER BY last_seen DESC
      LIMIT ? OFFSET ?
    `;
    params.push(parseInt(limit), parseInt(offset));

    const rows = await new Promise((resolve, reject) => {
      db.all(query, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });

    // Get total count for pagination
    let countQuery = `SELECT COUNT(DISTINCT source_ip || '|' || rule_id || '|' || alert_type || '|' || severity) as total
      FROM user_alerts WHERE timestamp >= datetime('now', ?)`;
    const countParams = [interval];
    if (severity) {
      if (severity === 'high_critical') { countQuery += ` AND severity IN ('high','critical')`; }
      else { countQuery += ` AND severity = ?`; countParams.push(severity); }
    } else {
      countQuery += ` AND severity IN ('high','critical')`;
    }
    countQuery += ` AND alert_type = 'suricata'`;

    const totalRow = await new Promise((resolve) => {
      db.get(countQuery, countParams, (err, row) => resolve(row || { total: 0 }));
    });

    res.json({ alerts: rows, total: totalRow.total, limit: parseInt(limit), offset: parseInt(offset) });
  } catch (error) {
    console.error('Admin aggregated alerts error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== ADMIN ROUTES ====================

// Middleware to check admin role
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admin role required.' });
  }
  next();
};

// Ban/unban user (admin only)
app.put('/api/admin/users/:id/ban', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { is_banned } = req.body;
    
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET is_banned = ? WHERE id = ?',
        [is_banned ? 1 : 0, req.params.id],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    logAuditEvent(req.user.userId, `USER_${is_banned ? 'BANNED' : 'UNBANNED'}`, req, true, `Target user ID: ${req.params.id}`);

    res.json({ message: `User ${is_banned ? 'banned' : 'unbanned'} successfully` });
  } catch (error) {
    console.error('Ban user error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Reset user configuration (admin only)
app.delete('/api/admin/users/:id/config', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE user_configs SET backend_url = "", is_configured = 0, connectivity_status = "untested" WHERE user_id = ?',
        [req.params.id],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    logAuditEvent(req.user.userId, 'RESET_USER_CONFIG', req, true, `Target user ID: ${req.params.id}`);

    res.json({ message: 'User configuration reset successfully' });
  } catch (error) {
    console.error('Reset config error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get all user logs (admin only)
app.get('/api/admin/user-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { limit = 100, offset = 0 } = req.query;
    
    const logs = await new Promise((resolve, reject) => {
      db.all(
        `SELECT url.*, u.username, u.email 
         FROM user_request_logs url
         LEFT JOIN users u ON url.user_id = u.id
         ORDER BY url.timestamp DESC 
         LIMIT ? OFFSET ?`,
        [parseInt(limit), parseInt(offset)],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows || []);
        }
      );
    });

    res.json({ logs });
  } catch (error) {
    console.error('Get all user logs error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'Synorix Authentication Service'
  });
});

// Security headers for all responses
app.use((req, res, next) => {
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  next();
});

// Test endpoint for compression testing
app.get('/api/large-response', (req, res) => {
  // Generate a large JSON response > 1024 bytes to trigger compression
  const largeData = {
    message: 'This is a test endpoint for compression testing',
    timestamp: new Date().toISOString(),
    data: Array.from({ length: 100 }, (_, i) => ({
      id: i + 1,
      name: `Test Item ${i + 1}`,
      description: `This is a detailed description for test item number ${i + 1}. It contains sufficient text to make the response large enough to trigger compression logic in the security proxy.`,
      metadata: {
        created: new Date().toISOString(),
        updated: new Date().toISOString(),
        tags: [`tag${i}`, `category${i % 5}`, 'compression-test'],
        properties: {
          enabled: i % 2 === 0,
          priority: i % 3,
          score: Math.random() * 100
        }
      }
    })),
    stats: {
      total_items: 100,
      response_size_note: 'This response is designed to be > 1024 bytes to trigger AI compression evaluation',
      compression_test: true
    }
  };
  
  res.json(largeData);
});

// Request Logging and Monitoring API Routes
app.get('/api/logs', getRequestLogs);
app.get('/api/logs/stats', getRequestStatistics);
app.get('/api/logs/top-ips', getTopIPs);
app.get('/api/logs/trends', getRequestTrends);
app.get('/api/logs/search', searchRequestLogs);
app.get('/api/logs/export', exportRequestLogs);

// Enhanced logging endpoint for detailed request tracking
app.post('/api/logs/detailed', (req, res) => {
  try {
    const detailedLog = req.body;
    
    // Store in detailed_logs table
    const stmt = db.prepare(`
      INSERT INTO detailed_logs (
        timestamp, method, url, ip, user_agent, status_code, 
        response_time, request_size, response_size, waf_checks,
        compression_info, ids_ips_info, security_events, headers,
        blocked, block_reason
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(
      detailedLog.timestamp,
      detailedLog.method,
      detailedLog.url,
      detailedLog.ip,
      detailedLog.user_agent,
      detailedLog.status_code,
      detailedLog.response_time,
      detailedLog.request_size,
      detailedLog.response_size,
      JSON.stringify(detailedLog.waf_checks || []),
      JSON.stringify(detailedLog.compression_info || {}),
      JSON.stringify(detailedLog.ids_ips_info || {}),
      JSON.stringify(detailedLog.security_events || []),
      JSON.stringify(detailedLog.headers || {}),
      detailedLog.blocked ? 1 : 0,
      detailedLog.block_reason || null
    );
    
    // Emit real-time event for SSE
    global.sseClients?.forEach(client => {
      client.write(`data: ${JSON.stringify({
        type: 'detailed_request',
        data: detailedLog
      })}\\n\\n`);
    });
    
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error storing detailed log:', error);
    res.status(500).json({ error: 'Failed to store detailed log' });
  }
});

// Get detailed logs with filtering
app.get('/api/logs/detailed', (req, res) => {
  try {
    const { limit = 50, offset = 0, filter } = req.query;
    
    let query = 'SELECT * FROM detailed_logs ORDER BY timestamp DESC';
    let params = [];
    
    if (filter) {
      if (filter === 'blocked') {
        query = 'SELECT * FROM detailed_logs WHERE blocked = 1 ORDER BY timestamp DESC';
      } else if (filter === 'compressed') {
        query = "SELECT * FROM detailed_logs WHERE json_extract(compression_info, '$.enabled') = true ORDER BY timestamp DESC";
      } else if (filter === 'waf_triggered') {
        query = "SELECT * FROM detailed_logs WHERE json_extract(waf_checks, '$[0].matched') = true ORDER BY timestamp DESC";
      }
    }
    
    query += ' LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    // Check if table exists first
    const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='detailed_logs'").get();
    if (!tableExists) {
      return res.json([]);
    }
    
    const logs = db.prepare(query).all(...params);
    
    // Parse JSON fields safely
    const parsedLogs = logs.map(log => {
      try {
        return {
          ...log,
          waf_checks: JSON.parse(log.waf_checks || '[]'),
          compression_info: JSON.parse(log.compression_info || '{}'),
          ids_ips_info: JSON.parse(log.ids_ips_info || '{}'),
          security_events: JSON.parse(log.security_events || '[]'),
          headers: JSON.parse(log.headers || '{}')
        };
      } catch (parseError) {
        console.error('Error parsing log JSON fields:', parseError);
        return {
          ...log,
          waf_checks: [],
          compression_info: {},
          ids_ips_info: {},
          security_events: [],
          headers: {}
        };
      }
    });
    
    res.json(parsedLogs);
  } catch (error) {
    console.error('Error fetching detailed logs:', error);
    res.status(500).json({ error: 'Failed to fetch detailed logs' });
  }
});

// Server-Sent Events endpoint for real-time monitoring
app.get('/api/events', createSSEEndpoint);

// WAF Rules endpoint - serve rules from security-proxy data directory
app.get('/api/waf/rules', (req, res) => {
  try {
    const fs = require('fs');
    const wafRulesPath = path.join(__dirname, '../security-proxy/data/waf_rules.json');
    
    if (!fs.existsSync(wafRulesPath)) {
      return res.status(404).json({ error: 'WAF rules file not found' });
    }
    
    const rulesData = fs.readFileSync(wafRulesPath, 'utf8');
    const rules = JSON.parse(rulesData);
    
    res.json({ rules });
  } catch (error) {
    console.error('Error reading WAF rules:', error);
    res.status(500).json({ error: 'Failed to load WAF rules' });
  }
});

// WAF Statistics endpoint
app.get('/api/waf/stats', (req, res) => {
  try {
    const fs = require('fs');
    const wafRulesPath = path.join(__dirname, '../security-proxy/data/waf_rules.json');
    
    // Count enabled/disabled rules by severity and category
    const rulesData = fs.readFileSync(wafRulesPath, 'utf8');
    const rules = JSON.parse(rulesData);
    
    const stats = {
      totalRules: rules.length,
      enabledRules: rules.filter(r => r.enabled).length,
      disabledRules: rules.filter(r => !r.enabled).length,
      highSeverity: rules.filter(r => r.severity >= 4).length,
      mediumSeverity: rules.filter(r => r.severity === 3).length,
      lowSeverity: rules.filter(r => r.severity <= 2).length,
      categoryCounts: {}
    };
    
    // Count by category (tags)
    rules.forEach(rule => {
      const category = rule.tags || 'unknown';
      stats.categoryCounts[category] = (stats.categoryCounts[category] || 0) + 1;
    });
    
    res.json(stats);
  } catch (error) {
    console.error('Error calculating WAF stats:', error);
    res.status(500).json({ error: 'Failed to calculate WAF stats' });
  }
});

// Compression Statistics endpoint
app.get('/api/compression/stats', (req, res) => {
  try {
    // Query user_request_logs for compression statistics produced by security proxy
    db.get(`
      SELECT
        COUNT(*) as total_compressed,
        SUM(
          CASE
            WHEN original_size > compressed_size THEN (original_size - compressed_size)
            ELSE 0
          END
        ) as total_savings,
        AVG(compression_ratio) as average_ratio
      FROM user_request_logs
      WHERE compressed = 1
    `, [], (err, stats) => {
      if (err) {
        console.error('Error querying compression logs:', err);
        return res.json({
          totalCompressed: 0,
          totalSavings: 0,
          averageRatio: 0,
          activeConnections: 0
        });
      }

      res.json({
        totalCompressed: stats?.total_compressed || 0,
        totalSavings: stats?.total_savings || 0,
        averageRatio: stats?.average_ratio || 0,
        activeConnections: 0 // This would come from the proxy in real-time
      });
    });
  } catch (error) {
    console.error('Error fetching compression stats:', error);
    res.json({
      totalCompressed: 0,
      totalSavings: 0,
      averageRatio: 0,
      activeConnections: 0
    });
  }
});

// Compression Logs endpoint
app.get('/api/compression/logs', (req, res) => {
  try {
    const { limit = 50 } = req.query;
    
    // Query user_request_logs for compression data
    db.all(`
      SELECT 
        timestamp,
        url,
        original_size,
        compressed_size,
        compression_ratio,
        compressed
      FROM user_request_logs 
      WHERE compressed = 1
      ORDER BY timestamp DESC
      LIMIT ?
    `, [parseInt(limit)], (err, logs) => {
      if (err) {
        console.error('Error querying compression logs:', err);
        return res.json({ logs: [] });
      }
      
      // Format logs for frontend
      const formattedLogs = logs.map(log => ({
        timestamp: log.timestamp,
        url: log.url,
        original_size: log.original_size || 0,
        compressed_size: log.compressed_size || 0,
        compression_ratio: log.compression_ratio || 0,
        method: 'gzip',
        status: 'success'
      }));
      
      res.json({ logs: formattedLogs });
    });
  } catch (error) {
    console.error('Error fetching compression logs:', error);
    res.json({ logs: [] });
  }
});

// Deduplication Statistics endpoint
app.get('/api/deduplication/stats', (req, res) => {
  try {
    // Query user_request_logs for real deduplication statistics
    db.all(`
      SELECT 
        COUNT(*) as total_deduplicated,
        SUM(
          CASE
            WHEN original_size > dedup_size THEN (original_size - dedup_size)
            ELSE 0
          END
        ) as total_savings,
        COUNT(*) as cache_hits
      FROM user_request_logs 
      WHERE deduplicated = 1
    `, [], (err, statsResult) => {
      if (err) {
        console.error('Error querying deduplication stats:', err);
        return res.json({
          totalDeduplicated: 0,
          totalSavings: 0,
          hitRate: 0,
          cacheSize: 0
        });
      }
      
      const stats = statsResult[0] || { total_deduplicated: 0, total_savings: 0, cache_hits: 0 };
      
      // Get total requests for hit rate calculation
      db.get(`
        SELECT COUNT(*) as total 
        FROM user_request_logs
      `, [], (err, totalResult) => {
        const totalRequests = totalResult?.total || 1;
        const hitRate = (stats.cache_hits / totalRequests) * 100;
        
        res.json({
          totalDeduplicated: stats.total_deduplicated || 0,
          totalSavings: stats.total_savings || 0,
          hitRate: parseFloat(hitRate.toFixed(2)),
          cacheSize: stats.cache_hits || 0
        });
      });
    });
  } catch (error) {
    console.error('Error fetching deduplication stats:', error);
    res.json({
      totalDeduplicated: 0,
      totalSavings: 0,
      hitRate: 0,
      cacheSize: 0
    });
  }
});

// Deduplication Logs endpoint
app.get('/api/deduplication/logs', (req, res) => {
  try {
    const { limit = 50 } = req.query;
    
    // Query user_request_logs for deduplication data
    db.all(`
      SELECT 
        timestamp,
        url,
        response_size as original_size,
        dedup_size as deduplicated_size,
        dedup_ratio,
        deduplicated
      FROM user_request_logs 
      WHERE deduplicated = 1
      ORDER BY timestamp DESC
      LIMIT ?
    `, [parseInt(limit)], (err, logs) => {
      if (err) {
        console.error('Error querying deduplication logs:', err);
        return res.json({ logs: [] });
      }
      
      // Format logs for frontend
      const formattedLogs = logs.map(log => ({
        timestamp: log.timestamp,
        url: log.url,
        original_size: log.original_size || 0,
        deduplicated_size: log.deduplicated_size || 0,
        dedup_ratio: log.dedup_ratio || 0,
        content_type: 'application/json',
        hit: true,
        status: 'success'
      }));
      
      res.json({ logs: formattedLogs });
    });
  } catch (error) {
    console.error('Error fetching deduplication logs:', error);
    res.json({ logs: [] });
  }
});

// Proxy Statistics endpoint
app.get('/api/proxy/stats', (req, res) => {
  try {
    db.all(`
      SELECT 
        COUNT(*) as total,
        AVG(response_time) as avg_latency,
        SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
      FROM request_logs
    `, [], (err, statsResult) => {
      if (err) {
        console.error('Error querying proxy stats:', err);
        return res.json({
          totalRequests: 0,
          activeConnections: 0,
          averageLatency: 0,
          requestsPerSecond: 0,
          uptime: 0,
          errorRate: 0
        });
      }
      
      const stats = statsResult[0] || { total: 0, avg_latency: 0, errors: 0 };
      
      // Calculate uptime (time since first request)
      db.get(`
        SELECT 
          (julianday('now') - julianday(MIN(timestamp))) * 86400 as uptime_seconds
        FROM request_logs
      `, [], (err, uptimeResult) => {
        const uptime = uptimeResult?.uptime_seconds || 0;
        const errorRate = stats.total > 0 ? (stats.errors / stats.total) * 100 : 0;
        
        // Calculate requests per second based on recent activity
        db.get(`
          SELECT COUNT(*) as recent_count
          FROM request_logs
          WHERE timestamp >= datetime('now', '-60 seconds')
        `, [], (err, recentResult) => {
          const recentCount = recentResult?.recent_count || 0;
          const rps = recentCount / 60;
          
          res.json({
            totalRequests: stats.total || 0,
            activeConnections: 0, // Would need real-time tracking
            averageLatency: stats.avg_latency || 0,
            requestsPerSecond: rps,
            uptime: uptime,
            errorRate: errorRate
          });
        });
      });
    });
  } catch (error) {
    console.error('Error fetching proxy stats:', error);
    res.json({
      totalRequests: 0,
      activeConnections: 0,
      averageLatency: 0,
      requestsPerSecond: 0,
      uptime: 0,
      errorRate: 0
    });
  }
});

// Proxy Latency endpoint
app.get('/api/proxy/latency', (req, res) => {
  try {
    db.all(`
      SELECT 
        timestamp,
        response_time as latency
      FROM request_logs
      WHERE response_time IS NOT NULL
      ORDER BY timestamp DESC
      LIMIT 100
    `, [], (err, logs) => {
      if (err) {
        console.error('Error querying latency data:', err);
        return res.json({ data: [] });
      }
      
      res.json({ data: logs || [] });
    });
  } catch (error) {
    console.error('Error fetching latency data:', error);
    res.json({ data: [] });
  }
});

// Public Suricata alerts endpoint used by IDS/IPS dashboard
app.get('/api/suricata/alerts', (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);

    db.all(
      `SELECT id, source, severity, category, signature, src_ip, dest_ip, src_port, dest_port, protocol, flow_id, timestamp
       FROM alerts
       WHERE (
         source = 'suricata'
         OR source = 'suricata-ids'
         OR source = 'suricata-ips'
         OR source LIKE 'suricata%'
       )
       AND source != 'ids-inline'
       ORDER BY timestamp DESC
       LIMIT ?`,
      [limit],
      (err, rows) => {
        if (err) {
          console.error('Error fetching Suricata alerts:', err);
          return res.status(500).json({ error: 'Failed to fetch Suricata alerts' });
        }

        const alerts = (rows || []).map((row) => {
          const sev = Number(row.severity);
          const normalizedSeverity = Number.isFinite(sev)
            ? (sev <= 1 ? 1 : sev === 2 ? 2 : 3)
            : 2;

          return {
            timestamp: row.timestamp,
            flow_id: Number(row.flow_id) || row.id,
            src_ip: row.src_ip || '0.0.0.0',
            dest_ip: row.dest_ip || '127.0.0.1',
            src_port: Number(row.src_port) || 0,
            dest_port: Number(row.dest_port) || 0,
            proto: row.protocol || 'TCP',
            alert: {
              signature: row.signature || 'Suricata alert',
              category: row.category || 'network-alert',
              severity: normalizedSeverity
            },
            severity: normalizedSeverity,
            category: row.category || 'Suricata Alert'
          };
        });

        return res.json({ alerts });
      }
    );
  } catch (error) {
    console.error('Error in /api/suricata/alerts:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== ALERT ACKNOWLEDGMENT WORKFLOW ====================

// Get alerts with filtering
app.get('/api/security/alerts', authenticateToken, (req, res) => {
  try {
    const { status, severity, alert_type, limit = 100 } = req.query;
    const userId = req.user.userId;
    
    let query = `SELECT * FROM user_alerts WHERE user_id = ?`;
    const params = [userId];
    
    if (status) {
      query += ` AND status = ?`;
      params.push(status);
    }
    if (severity) {
      query += ` AND severity = ?`;
      params.push(severity);
    }
    if (alert_type) {
      query += ` AND alert_type = ?`;
      params.push(alert_type);
    }
    
    query += ` ORDER BY timestamp DESC LIMIT ?`;
    params.push(parseInt(limit));
    
    db.all(query, params, (err, alerts) => {
      if (err) {
        console.error('Error fetching alerts:', err);
        return res.status(500).json({ error: 'Failed to fetch alerts' });
      }
      res.json({ alerts: alerts || [] });
    });
  } catch (error) {
    console.error('Error in get alerts:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Acknowledge alert
app.post('/api/security/alerts/:id/acknowledge', authenticateToken, (req, res) => {
  try {
    const alertId = req.params.id;
    const { comment } = req.body;
    const username = req.user.username;
    
    db.run(`
      UPDATE user_alerts 
      SET status = 'acknowledged', 
          acknowledged_by = ?,
          acknowledged_at = datetime('now'),
          comment = ?,
          is_read = 1
      WHERE id = ? AND user_id = ?
    `, [username, comment || null, alertId, req.user.userId], function(err) {
      if (err) {
        console.error('Error acknowledging alert:', err);
        return res.status(500).json({ error: 'Failed to acknowledge alert' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      res.json({ success: true, message: 'Alert acknowledged' });
    });
  } catch (error) {
    console.error('Error in acknowledge alert:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Resolve alert
app.post('/api/security/alerts/:id/resolve', authenticateToken, (req, res) => {
  try {
    const alertId = req.params.id;
    const { comment } = req.body;
    
    db.run(`
      UPDATE user_alerts 
      SET status = 'resolved',
          resolved_at = datetime('now'),
          comment = CASE 
            WHEN comment IS NULL THEN ?
            ELSE comment || ' | ' || ?
          END,
          is_read = 1
      WHERE id = ? AND user_id = ?
    `, [comment || 'Resolved', comment || 'Resolved', alertId, req.user.userId], function(err) {
      if (err) {
        console.error('Error resolving alert:', err);
        return res.status(500).json({ error: 'Failed to resolve alert' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      res.json({ success: true, message: 'Alert resolved' });
    });
  } catch (error) {
    console.error('Error in resolve alert:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Dismiss alert
app.post('/api/security/alerts/:id/dismiss', authenticateToken, (req, res) => {
  try {
    const alertId = req.params.id;
    const { comment } = req.body;
    
    db.run(`
      UPDATE user_alerts 
      SET status = 'dismissed',
          comment = ?,
          is_read = 1
      WHERE id = ? AND user_id = ?
    `, [comment || 'Dismissed', alertId, req.user.userId], function(err) {
      if (err) {
        console.error('Error dismissing alert:', err);
        return res.status(500).json({ error: 'Failed to dismiss alert' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      res.json({ success: true, message: 'Alert dismissed' });
    });
  } catch (error) {
    console.error('Error in dismiss alert:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add comment to alert
app.post('/api/security/alerts/:id/comment', authenticateToken, (req, res) => {
  try {
    const alertId = req.params.id;
    const { comment } = req.body;
    const username = req.user.username;
    const timestamp = new Date().toISOString();
    
    if (!comment) {
      return res.status(400).json({ error: 'Comment is required' });
    }

    // Sanitize comment to prevent XSS
    const sanitizedComment = sanitizeInput(comment, 1000);
    
    const commentText = `[${timestamp}] ${username}: ${sanitizedComment}`;
    
    db.run(`
      UPDATE user_alerts 
      SET comment = CASE 
        WHEN comment IS NULL THEN ?
        ELSE comment || ' | ' || ?
      END
      WHERE id = ? AND user_id = ?
    `, [commentText, commentText, alertId, req.user.userId], function(err) {
      if (err) {
        console.error('Error adding comment:', err);
        return res.status(500).json({ error: 'Failed to add comment' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      res.json({ success: true, message: 'Comment added' });
    });
  } catch (error) {
    console.error('Error in add comment:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== AUTOMATED RESPONSE ACTIONS ====================

// Check alert correlation and trigger automated responses
function checkAlertCorrelation(correlationId, srcIp, pattern, severity) {
  // Check if correlation exists
  db.get(`
    SELECT * FROM alert_correlation WHERE correlation_id = ?
  `, [correlationId], (err, correlation) => {
    if (err) {
      console.error('Error checking correlation:', err);
      return;
    }
    
    if (correlation) {
      // Update existing correlation
      const newCount = correlation.alert_count + 1;
      db.run(`
        UPDATE alert_correlation 
        SET alert_count = ?, last_seen = datetime('now')
        WHERE correlation_id = ?
      `, [newCount, correlationId], (err) => {
        if (err) console.error('Error updating correlation:', err);
      });
      
      // Check thresholds for automated response
      if (newCount >= 5 && !correlation.auto_action_taken) {
        // Block IP after 5 correlated alerts
        blockIPAutomatically(srcIp, correlationId, `Threshold exceeded: ${newCount} alerts`);
        
        // Update correlation to mark action taken
        db.run(`
          UPDATE alert_correlation 
          SET auto_action_taken = 'ip_block'
          WHERE correlation_id = ?
        `, [correlationId]);
        
        // Send critical notification
        sendNotification({
          alert_id: null,
          type: 'webhook',
          recipient: process.env.WEBHOOK_URL || 'http://localhost:3001/api/webhooks/alerts',
          payload: {
            event: 'auto_block',
            ip: srcIp,
            reason: `Automated block after ${newCount} correlated alerts`,
            pattern: pattern,
            correlationId: correlationId
          }
        });
      }
      
      // Rate limit after 3 alerts
      if (newCount >= 3 && correlation.auto_action_taken !== 'rate_limit') {
        rateLimitIP(srcIp, correlationId, `Rate limit after ${newCount} alerts`);
      }
    } else {
      // Create new correlation
      db.run(`
        INSERT INTO alert_correlation (
          correlation_id, alert_pattern, source_ip, alert_count, 
          severity, first_seen, last_seen
        ) VALUES (?, ?, ?, 1, ?, datetime('now'), datetime('now'))
      `, [correlationId, pattern || 'Unknown', srcIp, severity || 'medium'], (err) => {
        if (err) console.error('Error creating correlation:', err);
      });
    }
  });
}

// Block IP automatically
function blockIPAutomatically(ip, correlationId, reason) {
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours
  
  db.run(`
    INSERT INTO automated_responses (
      correlation_id, action_type, target, reason, 
      threshold_exceeded, expires_at
    ) VALUES (?, 'ip_block', ?, ?, ?, ?)
  `, [correlationId, ip, reason, 'alert_count >= 5', expiresAt], (err) => {
    if (err) {
      console.error('Error recording IP block:', err);
    } else {
      console.log(`🔒 Automatically blocked IP: ${ip} - Reason: ${reason}`);
      
      // Call security proxy to actually block the IP
      const axios = require('axios');
      axios.post('http://localhost:8080/api/security/block-ip', {
        ip: ip,
        reason: reason,
        duration: 86400 // 24 hours in seconds
      }, {
        headers: INTERNAL_API_TOKEN ? { 'X-Internal-Token': INTERNAL_API_TOKEN } : {}
      }).catch(err => console.error('Error calling proxy to block IP:', err));
    }
  });
}

// Rate limit IP
function rateLimitIP(ip, correlationId, reason) {
  db.run(`
    INSERT INTO automated_responses (
      correlation_id, action_type, target, reason, threshold_exceeded
    ) VALUES (?, 'rate_limit', ?, ?, ?)
  `, [correlationId, ip, reason, 'alert_count >= 3'], (err) => {
    if (err) {
      console.error('Error recording rate limit:', err);
    } else {
      console.log(`⏱️  Rate limited IP: ${ip} - Reason: ${reason}`);
    }
  });
}

// Get automated responses
app.get('/api/security/automated-responses', authenticateToken, (req, res) => {
  try {
    db.all(`
      SELECT * FROM automated_responses 
      WHERE is_active = 1 
      ORDER BY created_at DESC 
      LIMIT 100
    `, [], (err, responses) => {
      if (err) {
        console.error('Error fetching automated responses:', err);
        return res.status(500).json({ error: 'Failed to fetch responses' });
      }
      res.json({ responses: responses || [] });
    });
  } catch (error) {
    console.error('Error in get automated responses:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== ALERT CORRELATION ENGINE ====================

// Get correlated alerts
app.get('/api/security/correlation', authenticateToken, (req, res) => {
  try {
    db.all(`
      SELECT 
        c.*,
        GROUP_CONCAT(a.description, ' | ') as alert_descriptions,
        COUNT(a.id) as related_alerts
      FROM alert_correlation c
      LEFT JOIN user_alerts a ON c.correlation_id = a.correlation_id
      GROUP BY c.id
      ORDER BY c.last_seen DESC
      LIMIT 50
    `, [], (err, correlations) => {
      if (err) {
        console.error('Error fetching correlations:', err);
        return res.status(500).json({ error: 'Failed to fetch correlations' });
      }
      res.json({ correlations: correlations || [] });
    });
  } catch (error) {
    console.error('Error in get correlation:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get attack patterns
app.get('/api/security/attack-patterns', authenticateToken, (req, res) => {
  try {
    db.all(`
      SELECT 
        alert_pattern,
        COUNT(*) as occurrences,
        MAX(severity) as max_severity,
        COUNT(DISTINCT source_ip) as unique_sources,
        MAX(last_seen) as last_occurrence
      FROM alert_correlation
      GROUP BY alert_pattern
      ORDER BY occurrences DESC
      LIMIT 20
    `, [], (err, patterns) => {
      if (err) {
        console.error('Error fetching attack patterns:', err);
        return res.status(500).json({ error: 'Failed to fetch patterns' });
      }
      res.json({ patterns: patterns || [] });
    });
  } catch (error) {
    console.error('Error in get attack patterns:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== NOTIFICATION SYSTEM ====================

// Send notification (internally used)
function sendNotification({ alert_id, type, recipient, payload }) {
  const payloadStr = JSON.stringify(payload);
  
  db.run(`
    INSERT INTO notification_log (alert_id, notification_type, recipient, payload, status)
    VALUES (?, ?, ?, ?, 'pending')
  `, [alert_id, type, recipient, payloadStr], function(err) {
    if (err) {
      console.error('Error logging notification:', err);
      return;
    }
    
    const notificationId = this.lastID;
    
    // Actually send the notification based on type
    if (type === 'webhook') {
      sendWebhook(notificationId, recipient, payload);
    } else if (type === 'email') {
      sendEmail(notificationId, recipient, payload);
    } else if (type === 'sms') {
      sendSMS(notificationId, recipient, payload);
    }
  });
}

// Send webhook notification
function sendWebhook(notificationId, url, payload) {
  const axios = require('axios');
  
  axios.post(url, payload, {
    timeout: 5000,
    headers: { 'Content-Type': 'application/json' }
  })
  .then(response => {
    db.run(`
      UPDATE notification_log 
      SET status = 'sent', sent_at = datetime('now')
      WHERE id = ?
    `, [notificationId]);
    console.log(`✅ Webhook notification sent: ${url}`);
  })
  .catch(error => {
    db.run(`
      UPDATE notification_log 
      SET status = 'failed', error_message = ?
      WHERE id = ?
    `, [error.message, notificationId]);
    console.error(`❌ Webhook notification failed: ${error.message}`);
  });
}

// Send email notification (placeholder)
function sendEmail(notificationId, email, payload) {
  // In production, integrate with SendGrid, AWS SES, etc.
  console.log(`📧 Email notification to ${email}:`, payload);
  
  // Simulate success for now
  db.run(`
    UPDATE notification_log 
    SET status = 'sent', sent_at = datetime('now')
    WHERE id = ?
  `, [notificationId]);
}

// Send SMS notification (placeholder)
function sendSMS(notificationId, phone, payload) {
  // In production, integrate with Twilio, AWS SNS, etc.
  console.log(`📱 SMS notification to ${phone}:`, payload);
  
  // Simulate success for now
  db.run(`
    UPDATE notification_log 
    SET status = 'sent', sent_at = datetime('now')
    WHERE id = ?
  `, [notificationId]);
}

// Configure notification settings
app.post('/api/security/notifications/configure', authenticateToken, (req, res) => {
  try {
    const { email, webhook_url, sms_phone, critical_only } = req.body;
    
    // Store in user preferences or separate table
    // For now, just acknowledge
    res.json({ 
      success: true, 
      message: 'Notification settings saved',
      settings: { email, webhook_url, sms_phone, critical_only }
    });
  } catch (error) {
    console.error('Error in configure notifications:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get notification log
app.get('/api/security/notifications/log', authenticateToken, (req, res) => {
  try {
    db.all(`
      SELECT * FROM notification_log 
      ORDER BY sent_at DESC 
      LIMIT 100
    `, [], (err, logs) => {
      if (err) {
        console.error('Error fetching notification log:', err);
        return res.status(500).json({ error: 'Failed to fetch log' });
      }
      res.json({ logs: logs || [] });
    });
  } catch (error) {
    console.error('Error in get notification log:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== THREAT INTELLIGENCE ====================

// Add threat intelligence indicator
app.post('/api/security/threat-intel', authenticateToken, (req, res) => {
  try {
    const { indicator, indicator_type, threat_type, severity, source, confidence, description } = req.body;
    
    if (!indicator || !indicator_type || !threat_type) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const now = new Date().toISOString();
    
    db.run(`
      INSERT INTO threat_intelligence (
        indicator, indicator_type, threat_type, severity, source, 
        confidence, description, first_seen, last_seen
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(indicator) DO UPDATE SET
        last_seen = ?,
        confidence = ?,
        is_active = 1
    `, [
      indicator, indicator_type, threat_type, severity || 'medium',
      source || 'manual', confidence || 50, description || '',
      now, now, now, confidence || 50
    ], function(err) {
      if (err) {
        console.error('Error adding threat intel:', err);
        return res.status(500).json({ error: 'Failed to add threat intelligence' });
      }
      res.json({ success: true, message: 'Threat intelligence added' });
    });
  } catch (error) {
    console.error('Error in add threat intel:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get threat intelligence
app.get('/api/security/threat-intel', authenticateToken, (req, res) => {
  try {
    const { indicator_type, is_active = true } = req.query;
    
    let query = `SELECT * FROM threat_intelligence WHERE 1=1`;
    const params = [];
    
    if (indicator_type) {
      query += ` AND indicator_type = ?`;
      params.push(indicator_type);
    }
    
    if (is_active !== undefined) {
      query += ` AND is_active = ?`;
      params.push(is_active === 'true' || is_active === true ? 1 : 0);
    }
    
    query += ` ORDER BY last_seen DESC LIMIT 500`;
    
    db.all(query, params, (err, intel) => {
      if (err) {
        console.error('Error fetching threat intel:', err);
        return res.status(500).json({ error: 'Failed to fetch threat intelligence' });
      }
      res.json({ threat_intelligence: intel || [] });
    });
  } catch (error) {
    console.error('Error in get threat intel:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Check if IP is in threat intelligence
app.get('/api/security/threat-intel/check/:ip', authenticateToken, (req, res) => {
  try {
    const ip = req.params.ip;
    
    db.get(`
      SELECT * FROM threat_intelligence 
      WHERE indicator = ? AND indicator_type = 'ip' AND is_active = 1
    `, [ip], (err, intel) => {
      if (err) {
        console.error('Error checking threat intel:', err);
        return res.status(500).json({ error: 'Failed to check threat intelligence' });
      }
      res.json({ 
        is_threat: !!intel, 
        intelligence: intel || null 
      });
    });
  } catch (error) {
    console.error('Error in check threat intel:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Import threat intelligence feed
app.post('/api/security/threat-intel/import', authenticateToken, (req, res) => {
  try {
    const { feed_url, feed_type } = req.body;
    
    if (!feed_url) {
      return res.status(400).json({ error: 'Feed URL is required' });
    }
    
    // Fetch and import threat intelligence (simplified)
    const axios = require('axios');
    axios.get(feed_url, { timeout: 10000 })
      .then(response => {
        // Parse feed based on type (CSV, JSON, etc.)
        // This is a simplified implementation
        let imported = 0;
        
        // Example: assume JSON array
        if (Array.isArray(response.data)) {
          const now = new Date().toISOString();
          
          response.data.forEach(item => {
            if (item.indicator && item.type) {
              db.run(`
                INSERT INTO threat_intelligence (
                  indicator, indicator_type, threat_type, severity, 
                  source, confidence, description, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET last_seen = ?
              `, [
                item.indicator,
                item.type || 'ip',
                item.threat_type || 'unknown',
                item.severity || 'medium',
                feed_url,
                item.confidence || 70,
                item.description || '',
                now,
                now,
                now
              ], (err) => {
                if (!err) imported++;
              });
            }
          });
          
          setTimeout(() => {
            res.json({ 
              success: true, 
              message: `Imported ${imported} threat indicators from feed` 
            });
          }, 1000);
        } else {
          res.json({ 
            success: false, 
            message: 'Unsupported feed format' 
          });
        }
      })
      .catch(error => {
        console.error('Error importing threat feed:', error);
        res.status(500).json({ error: 'Failed to import threat intelligence feed' });
      });
  } catch (error) {
    console.error('Error in import threat intel:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// Admin Dashboard API Endpoints
// ============================================

// Get admin dashboard stats
app.get('/api/admin/dashboard/stats', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const stats = {};
    let completed = 0;
    const totalQueries = 8; // Increased from 6 to 8

    const checkComplete = () => {
      completed++;
      if (completed === totalQueries) {
        console.log('📊 Dashboard stats calculated:', stats);
        res.json(stats);
      }
    };

    // Total users count
    db.get('SELECT COUNT(*) as count FROM users WHERE is_active = 1', (err, row) => {
      if (!err && row) {
        stats.totalUsers = row.count;
        console.log('✓ Total users:', row.count);
      } else {
        console.error('Error querying total users:', err);
        stats.totalUsers = 0;
      }
      checkComplete();
    });

    // Total websites (user_configs with backend_url)
    db.get('SELECT COUNT(*) as count FROM user_configs WHERE backend_url IS NOT NULL AND backend_url != ""', (err, row) => {
      if (!err && row) {
        stats.totalWebsites = row.count;
        console.log('✓ Total websites:', row.count);
      } else {
        console.error('Error querying total websites:', err);
        stats.totalWebsites = 0;
      }
      checkComplete();
    });

    // Total requests today
    db.get('SELECT COUNT(*) as count FROM user_request_logs WHERE DATE(timestamp) = DATE("now")', (err, row) => {
      if (!err && row) {
        stats.totalRequestsToday = row.count;
        console.log('✓ Requests today:', row.count);
      } else {
        console.error('Error querying requests today:', err);
        stats.totalRequestsToday = 0;
      }
      checkComplete();
    });

    // Active WAF rules (from database)
    db.get('SELECT COUNT(*) as count FROM waf_rules WHERE enabled = 1', (err, row) => {
      if (!err && row) {
        stats.activeWafRules = row.count;
        console.log('✓ Active WAF rules:', row.count);
      } else {
        console.error('Error querying WAF rules:', err);
        stats.activeWafRules = 0;
      }
      checkComplete();
    });

    // Active Suricata rules (from database)
    db.get('SELECT COUNT(*) as count FROM suricata_rules WHERE enabled = 1', (err, row) => {
      if (!err && row) {
        stats.activeSuricataRules = row.count;
        console.log('✓ Active Suricata rules:', row.count);
      } else {
        console.error('Error querying Suricata rules:', err);
        stats.activeSuricataRules = 0;
      }
      checkComplete();
    });

    // Active alerts count (unresolved user alerts)
    db.get('SELECT COUNT(*) as count FROM user_alerts WHERE status = "open"', (err, row) => {
      if (!err && row) {
        stats.activeAlerts = row.count;
        console.log('✓ Active alerts:', row.count);
      } else {
        console.error('Error querying active alerts:', err);
        stats.activeAlerts = 0;
      }
      checkComplete();
    });

    // Total IPS-blocked requests (from alerts table — suricata_triggered not set in proxy logs)
    db.get('SELECT COUNT(*) as count FROM alerts WHERE source = \'suricata-ips\'', (err, row) => {
      if (!err && row) {
        stats.totalBlockedRequests = row.count;
        console.log('✓ Total blocked requests (IPS):', row.count);
      } else {
        console.error('Error querying blocked requests:', err);
        stats.totalBlockedRequests = 0;
      }
      checkComplete();
    });

    // Blocked requests today
    db.get('SELECT COUNT(*) as count FROM alerts WHERE source = \'suricata-ips\' AND DATE(SUBSTR(timestamp,1,10)) = DATE(\'now\')', (err, row) => {
      if (!err && row) {
        stats.blockedRequestsToday = row.count;
        console.log('✓ Blocked requests today (IPS):', row.count);
      } else {
        console.error('Error querying blocked requests today:', err);
        stats.blockedRequestsToday = 0;
      }
      checkComplete();
    });
  } catch (error) {
    console.error('Error fetching admin stats:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// Get dashboard events (recent security events)
app.get('/api/admin/dashboard/events', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const limit = parseInt(req.query.limit) || 10;
    
    const query = `
      SELECT 
        id,
        source as alert_type,
        CASE severity WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium' ELSE 'low' END as severity,
        description,
        src_ip as source_ip,
        NULL as target_url,
        'detected' as action,
        timestamp,
        'open' as status
      FROM alerts
      WHERE source != 'waf'
      ORDER BY timestamp DESC 
      LIMIT ?
    `;

    db.all(query, [limit], (err, events) => {
      if (err) {
        console.error('Error fetching dashboard events:', err);
        return res.status(500).json({ error: 'Failed to fetch events' });
      }
      res.json(events || []);
    });
  } catch (error) {
    console.error('Error in dashboard events:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get system health status
app.get('/api/admin/dashboard/health', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {}
    };

    let checksCompleted = 0;
    const totalChecks = 3;

    const checkComplete = () => {
      checksCompleted++;
      if (checksCompleted === totalChecks) {
        // Determine overall status
        const serviceStatuses = Object.values(health.services);
        if (serviceStatuses.some(s => s.status === 'down')) {
          health.status = 'unhealthy';
        } else if (serviceStatuses.some(s => s.status === 'degraded')) {
          health.status = 'degraded';
        }
        res.json(health);
      }
    };

    // Check database
    db.get('SELECT COUNT(*) as count FROM users', (err) => {
      health.services.database = {
        status: err ? 'down' : 'healthy',
        message: err ? err.message : 'Connected',
        lastCheck: new Date().toISOString()
      };
      checkComplete();
    });

    // Check WAF rules availability
    db.get('SELECT COUNT(*) as count FROM waf_rules WHERE enabled = 1', (err, row) => {
      health.services.waf = {
        status: err ? 'down' : 'healthy',
        message: err ? err.message : `${row?.count || 0} active rules`,
        lastCheck: new Date().toISOString()
      };
      checkComplete();
    });

    // Check Suricata rules availability
    db.get('SELECT COUNT(*) as count FROM suricata_rules WHERE enabled = 1', (err, row) => {
      health.services.suricata = {
        status: err ? 'down' : 'healthy',
        message: err ? err.message : `${row?.count || 0} active rules`,
        lastCheck: new Date().toISOString()
      };
      checkComplete();
    });

  } catch (error) {
    console.error('Error in dashboard health:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get alert severity over time (last 7 days) for admin dashboard
app.get('/api/admin/dashboard/severity-over-time', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    // Apply client timezone offset so day-of-week matches user's local date, not UTC
    const tzOffsetMin = parseInt(req.query.tzOffset) || 0;
    const tzSign = tzOffsetMin >= 0 ? '+' : '-';
    const tzHours = Math.floor(Math.abs(tzOffsetMin) / 60);
    const tzMins = Math.abs(tzOffsetMin) % 60;
    const tzModifier = `${tzSign}${String(tzHours).padStart(2,'0')}:${String(tzMins).padStart(2,'0')}`;
    const query = `
      SELECT
        strftime('%w', datetime(SUBSTR(timestamp, 1, 19), '${tzModifier}')) as dow_num,
        CASE strftime('%w', datetime(SUBSTR(timestamp, 1, 19), '${tzModifier}'))
          WHEN '0' THEN 'Sun' WHEN '1' THEN 'Mon' WHEN '2' THEN 'Tue'
          WHEN '3' THEN 'Wed' WHEN '4' THEN 'Thu' WHEN '5' THEN 'Fri'
          WHEN '6' THEN 'Sat'
        END as day,
        SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 3 THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 4 THEN 1 ELSE 0 END) as low
      FROM alerts
      WHERE source != 'waf'
      GROUP BY dow_num, day
      ORDER BY dow_num ASC
    `;
    db.all(query, [], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Query failed' });
      // Ensure all 7 days are present
      const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
      const map = {};
      (rows || []).forEach(r => { map[r.day] = r; });
      const result = days.map(d => ({
        day: d,
        critical: map[d]?.critical || 0,
        high:     map[d]?.high     || 0,
        medium:   map[d]?.medium   || 0,
        low:      map[d]?.low      || 0,
      }));
      res.json(result);
    });
  } catch (e) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get security events / attack breakdown for admin dashboard
app.get('/api/admin/dashboard/attack-stats', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    let completed = 0;
    const result = {};
    const total = 5;
    const done = () => { if (++completed === total) res.json(result); };

    db.get(`SELECT COUNT(*) as count FROM user_request_logs WHERE waf_triggered = 1`, (err, row) => {
      result.wafBlocked = row?.count || 0; done();
    });
    // Count IPS drops from the alerts table — suricata_triggered is not set in user_request_logs
    // because Suricata IPS drops packets at the network level before the proxy logs them
    db.get(`SELECT COUNT(*) as count FROM alerts WHERE source = 'suricata-ips'`, (err, row) => {
      result.suricataBlocked = row?.count || 0; done();
    });
    db.get(`SELECT COUNT(*) as count FROM user_request_logs WHERE threat_level IN ('high','critical')`, (err, row) => {
      result.highThreats = row?.count || 0; done();
    });
    db.get(`SELECT COUNT(*) as count FROM user_request_logs WHERE waf_triggered = 1 AND DATE(timestamp) = DATE('now')`, (err, row) => {
      result.wafToday = row?.count || 0; done();
    });
    db.get(`SELECT COUNT(*) as count FROM alerts WHERE source = 'suricata-ips' AND DATE(SUBSTR(timestamp,1,10)) = DATE('now')`, (err, row) => {
      result.suricataToday = row?.count || 0; done();
    });
  } catch (error) {
    console.error('Error fetching attack stats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get security trends data
app.get('/api/admin/dashboard/trends', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const days = parseInt(req.query.days) || 7;
    
    const query = `
      SELECT 
        DATE(timestamp) as date,
        COUNT(*) as total_requests,
        SUM(CASE WHEN waf_triggered = 1 OR suricata_triggered = 1 THEN 1 ELSE 0 END) as blocked_requests,
        SUM(CASE WHEN threat_level = 'high' OR threat_level = 'critical' THEN 1 ELSE 0 END) as high_threats
      FROM user_request_logs 
      WHERE timestamp >= datetime('now', '-' || ? || ' days')
      GROUP BY DATE(timestamp)
      ORDER BY date ASC
    `;

    db.all(query, [days], (err, trends) => {
      if (err) {
        console.error('Error fetching dashboard trends:', err);
        return res.status(500).json({ error: 'Failed to fetch trends' });
      }
      res.json(trends || []);
    });
  } catch (error) {
    console.error('Error in dashboard trends:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get recent security activity
app.get('/api/admin/dashboard/activity', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const timeframe = req.query.timeframe || '7d';
    const days = timeframe === '90d' ? 90 : timeframe === '30d' ? 30 : 7;

    // Use a broad enough window to always catch recent data;
    // if nothing falls in the strict window, widen to the last 365 days
    // and limit to the requested number of most-recent days with activity.
    const query = `
      SELECT
        date(timestamp) as day,
        SUM(CASE WHEN waf_triggered = 1 OR suricata_triggered = 1 THEN 1 ELSE 0 END) as blocked,
        SUM(CASE WHEN waf_triggered = 0 AND suricata_triggered = 0 THEN 1 ELSE 0 END) as allowed,
        COUNT(*) as total
      FROM user_request_logs
      GROUP BY date(timestamp)
      ORDER BY day DESC
      LIMIT ${days}
    `;

    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Error fetching dashboard activity:', err);
        return res.status(500).json({ error: 'Failed to fetch activity' });
      }
      // Format day label for the frontend (reverse so oldest → newest left to right)
      const formatted = (rows || []).reverse().map(r => {
        const d = new Date(r.day);
        const label = days === 7
          ? d.toLocaleDateString('en-US', { weekday: 'short' })
          : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        return { day: label, allowed: r.allowed || 0, blocked: r.blocked || 0, total: r.total || 0 };
      });
      res.json(formatted);
    });
  } catch (error) {
    console.error('Error in dashboard activity:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get threat summary
app.get('/api/admin/dashboard/threats', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const threats = {};
    let completed = 0;
    const totalQueries = 4;

    const checkComplete = () => {
      completed++;
      if (completed === totalQueries) {
        res.json(threats);
      }
    };

    // Threats by severity (from global alerts table, severity is integer 1-4)
    db.all(`
      SELECT 
        CASE severity WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium' ELSE 'low' END as severity,
        COUNT(*) as count 
      FROM alerts 
      WHERE source != 'waf'
      GROUP BY severity
    `, (err, rows) => {
      threats.bySeverity = err ? [] : rows;
      checkComplete();
    });

    // Threats by type — exclude WAF (per-user/application, not a global network threat)
    db.all(`
      SELECT source as alert_type, COUNT(*) as count 
      FROM alerts 
      WHERE source != 'waf'
      GROUP BY source
    `, (err, rows) => {
      threats.byType = err ? [] : rows;
      checkComplete();
    });

    // Top threat sources (IPs)
    db.all(`
      SELECT src_ip as source_ip, COUNT(*) as count, MAX(timestamp) as last_seen
      FROM alerts 
      WHERE source != 'waf' AND src_ip IS NOT NULL AND src_ip != '0.0.0.0'
      GROUP BY src_ip 
      ORDER BY count DESC 
      LIMIT 10
    `, (err, rows) => {
      threats.topSources = err ? [] : rows;
      checkComplete();
    });

    // Recent critical threats
    db.all(`
      SELECT id, 
        CASE severity WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium' ELSE 'low' END as severity,
        description, src_ip as source_ip, timestamp 
      FROM alerts 
      WHERE severity = 1 AND source != 'waf'
      ORDER BY timestamp DESC 
      LIMIT 5
    `, (err, rows) => {
      threats.critical = err ? [] : rows;
      checkComplete();
    });

  } catch (error) {
    console.error('Error in dashboard threats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all users with their website info
app.get('/api/admin/users', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const query = `
      SELECT 
        u.id,
        u.username,
        u.email,
        u.role,
        u.created_at,
        u.last_login,
        u.is_active,
        u.is_banned,
        uc.backend_url,
        uc.is_configured,
        uc.connectivity_status,
        uc.last_test_at,
        (SELECT COUNT(*) FROM user_request_logs WHERE user_id = u.id) as total_requests,
        (SELECT COUNT(*) FROM user_alerts WHERE user_id = u.id AND status = 'open') as open_alerts
      FROM users u
      LEFT JOIN user_configs uc ON u.id = uc.user_id
      ORDER BY u.created_at DESC
    `;

    db.all(query, (err, rows) => {
      if (err) {
        console.error('Error fetching users:', err);
        return res.status(500).json({ error: 'Failed to fetch users' });
      }
      res.json(rows);
    });
  } catch (error) {
    console.error('Error in get users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get websites registered by users
app.get('/api/admin/websites', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const query = `
      SELECT 
        uc.id,
        uc.user_id,
        u.username,
        u.email,
        uc.backend_url,
        uc.proxy_api_key,
        uc.is_configured,
        uc.connectivity_status,
        uc.last_test_at,
        uc.created_at,
        (SELECT COUNT(*) FROM user_request_logs WHERE user_id = uc.user_id) as total_requests,
        (SELECT COUNT(*) FROM user_request_logs WHERE user_id = uc.user_id AND waf_triggered = 1) as blocked_requests
      FROM user_configs uc
      JOIN users u ON uc.user_id = u.id
      WHERE uc.backend_url IS NOT NULL AND uc.backend_url != ""
      ORDER BY uc.created_at DESC
    `;

    db.all(query, (err, rows) => {
      if (err) {
        console.error('Error fetching websites:', err);
        return res.status(500).json({ error: 'Failed to fetch websites' });
      }
      res.json(rows);
    });
  } catch (error) {
    console.error('Error in get websites:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get WAF rules configuration
app.get('/api/admin/waf/rules', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Get rules from database
    db.all('SELECT * FROM waf_rules ORDER BY id', (err, rules) => {
      if (err) {
        console.error('Error reading WAF rules from database:', err);
        return res.status(500).json({ error: 'Failed to read WAF rules' });
      }

      // Convert boolean values (SQLite stores as 0/1)
      const formattedRules = rules.map(rule => ({
        ...rule,
        enabled: Boolean(rule.enabled)
      }));

      res.json(formattedRules);
    });
  } catch (error) {
    console.error('Error in get WAF rules:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Sync WAF rules from database to file (for backward compatibility with Go proxy)
function syncWafRulesToFile(callback) {
  db.all('SELECT * FROM waf_rules WHERE enabled = 1 ORDER BY id', (err, rules) => {
    if (err) {
      console.error('Error reading WAF rules from database:', err);
      if (callback) callback(err);
      return;
    }

    const formattedRules = rules.map(rule => ({
      id: rule.id,
      pattern: rule.pattern,
      message: rule.message,
      tags: rule.tags,
      severity: rule.severity,
      enabled: Boolean(rule.enabled)
    }));

    const fs = require('fs');
    const wafPath = path.join(__dirname, '../security-proxy/data/waf_rules.json');
    
    fs.writeFile(wafPath, JSON.stringify(formattedRules, null, 2), 'utf8', (writeErr) => {
      if (writeErr) {
        console.error('Error writing WAF rules to file:', writeErr);
        if (callback) callback(writeErr);
      } else {
        console.log('✅ WAF rules synced to file successfully');
        if (callback) callback(null);
      }
    });
  });
}

// Update WAF rules configuration (deprecated - use individual rule endpoints)
app.post('/api/admin/waf/rules', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const fs = require('fs');
    const wafPath = path.join(__dirname, '../security-proxy/data/waf_rules.json');
    
    // Validate the incoming data
    if (!req.body || !req.body.rules) {
      return res.status(400).json({ error: 'Invalid WAF rules data' });
    }

    // Write to file (for backward compatibility)
    fs.writeFile(wafPath, JSON.stringify(req.body, null, 2), 'utf8', (err) => {
      if (err) {
        console.error('Error writing WAF rules:', err);
        return res.status(500).json({ error: 'Failed to update WAF rules' });
      }
      
      logAuditEvent(req.user.id, 'WAF_RULES_UPDATE', req, true, `Updated WAF rules configuration`);
      res.json({ success: true, message: 'WAF rules updated successfully' });
    });
  } catch (error) {
    console.error('Error in update WAF rules:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get IDS/IPS (Suricata) rules configuration
app.get('/api/admin/suricata/rules', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Get rules from database
    db.all('SELECT * FROM suricata_rules ORDER BY sid', (err, rules) => {
      if (err) {
        console.error('Error reading Suricata rules from database:', err);
        return res.status(500).json({ error: 'Failed to read Suricata rules' });
      }

      // Convert boolean values (SQLite stores as 0/1)
      const formattedRules = rules.map(rule => ({
        ...rule,
        enabled: Boolean(rule.enabled),
        http_uri: Boolean(rule.http_uri),
        http_method: Boolean(rule.http_method),
        http_header: Boolean(rule.http_header),
        http_request_body: Boolean(rule.http_request_body),
        nocase: Boolean(rule.nocase)
      }));

      res.json(formattedRules);
    });
  } catch (error) {
    console.error('Error in get Suricata rules:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Sync Suricata rules from database to file (for backward compatibility)
function syncSuricataRulesToFile(callback) {
  db.all('SELECT * FROM suricata_rules WHERE enabled = 1 ORDER BY sid', (err, rules) => {
    if (err) {
      console.error('Error reading Suricata rules from database:', err);
      if (callback) callback(err);
      return;
    }

    // Group rules by filename
    const fileContents = {};
    
    rules.forEach(rule => {
      const filename = rule.filename || 'local.rules';
      if (!fileContents[filename]) {
        fileContents[filename] = [];
      }

      // Build Suricata rule string
      let ruleString = `${rule.action} ${rule.protocol} ${rule.source_ip} ${rule.source_port} ${rule.direction} ${rule.dest_ip} ${rule.dest_port} (`;
      
      const options = [];
      options.push(`msg:"${rule.msg}"`);
      
      if (rule.flow) options.push(`flow:${rule.flow}`);
      if (rule.content) options.push(`content:"${rule.content}"`);
      if (rule.http_uri) options.push('http.uri');
      if (rule.http_method) options.push('http.method');
      if (rule.http_header) options.push('http.header');
      if (rule.http_request_body) options.push('http.request_body');
      if (rule.nocase) options.push('nocase');
      if (rule.pcre) options.push(`pcre:"${rule.pcre}"`);
      if (rule.classtype) options.push(`classtype:${rule.classtype}`);
      options.push(`sid:${rule.sid}`);
      options.push(`rev:${rule.rev}`);
      if (rule.priority) options.push(`priority:${rule.priority}`);
      
      ruleString += options.join('; ') + ';)';
      fileContents[filename].push(ruleString);
    });

    const fs = require('fs');
    const rulesPath = path.join(__dirname, '../services/suricata/rules');
    
    // Ensure directory exists
    if (!fs.existsSync(rulesPath)) {
      fs.mkdirSync(rulesPath, { recursive: true });
    }

    let filesWritten = 0;
    const filesToWrite = Object.keys(fileContents);
    
    if (filesToWrite.length === 0) {
      if (callback) callback(null);
      return;
    }

    filesToWrite.forEach(filename => {
      const content = `# Auto-generated from database\n# Total Rules: ${fileContents[filename].length}\n\n` + 
                     fileContents[filename].join('\n') + '\n';
      
      fs.writeFile(path.join(rulesPath, filename), content, 'utf8', (writeErr) => {
        if (writeErr) {
          console.error(`Error writing Suricata rule file ${filename}:`, writeErr);
        }
        filesWritten++;
        
        if (filesWritten === filesToWrite.length) {
          console.log(`✅ Suricata rules synced to ${filesToWrite.length} file(s) successfully`);
          if (callback) callback(null);
        }
      });
    });
  });
}

// Add new Suricata rule
app.post('/api/admin/suricata/rules/add', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const {
      sid, action, protocol, source_ip, source_port, direction, dest_ip, dest_port,
      msg, flow, content, http_uri, http_method, http_header, http_request_body,
      nocase, pcre, classtype, rev, priority, enabled, category, filename
    } = req.body;

    if (!sid || !msg) {
      return res.status(400).json({ error: 'SID and message are required' });
    }

    db.run(
      `INSERT INTO suricata_rules (
        sid, action, protocol, source_ip, source_port, direction, dest_ip, dest_port,
        msg, flow, content, http_uri, http_method, http_header, http_request_body,
        nocase, pcre, classtype, rev, priority, enabled, category, filename, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        parseInt(sid),
        action || 'alert',
        protocol || 'http',
        source_ip || '$EXTERNAL_NET',
        source_port || 'any',
        direction || '->',
        dest_ip || '$HTTP_SERVERS',
        dest_port || 'any',
        msg,
        flow || null,
        content || null,
        http_uri ? 1 : 0,
        http_method ? 1 : 0,
        http_header ? 1 : 0,
        http_request_body ? 1 : 0,
        nocase ? 1 : 0,
        pcre || null,
        classtype || 'web-application-attack',
        parseInt(rev) || 1,
        parseInt(priority) || 2,
        enabled !== undefined ? (enabled ? 1 : 0) : 1,
        category || 'custom',
        filename || ((action === 'drop' || action === 'reject') ? 'ips-rules.rules' : 'ids-rules.rules'),
        req.user.userId
      ],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Rule SID already exists' });
          }
          console.error('Error adding Suricata rule:', err);
          return res.status(500).json({ error: 'Failed to add Suricata rule' });
        }

        // Sync to file for backward compatibility
        syncSuricataRulesToFile((syncErr) => {
          if (syncErr) {
            console.error('Warning: Failed to sync Suricata rules to file:', syncErr);
          }
        });

        db.get('SELECT * FROM suricata_rules WHERE id = ?', [this.lastID], (getErr, newRule) => {
          if (getErr) {
            return res.status(500).json({ error: 'Rule added but failed to retrieve details' });
          }

          logAuditEvent(req.user.userId, 'SURICATA_RULE_ADDED', req, true, `Added Suricata rule: ${msg}`);
          res.json({ 
            success: true, 
            message: 'Suricata rule added successfully', 
            rule: {
              ...newRule,
              enabled: Boolean(newRule.enabled),
              http_uri: Boolean(newRule.http_uri),
              http_method: Boolean(newRule.http_method),
              http_header: Boolean(newRule.http_header),
              http_request_body: Boolean(newRule.http_request_body),
              nocase: Boolean(newRule.nocase)
            }
          });
        });
      }
    );
  } catch (error) {
    console.error('Error adding Suricata rule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update Suricata rule
app.put('/api/admin/suricata/rules/:ruleId', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const ruleId = parseInt(req.params.ruleId);
    const updates = [];
    const values = [];

    // List of allowed update fields
    const allowedFields = [
      'sid', 'action', 'protocol', 'source_ip', 'source_port', 'direction', 
      'dest_ip', 'dest_port', 'msg', 'flow', 'content', 'http_uri', 
      'http_method', 'http_header', 'http_request_body', 'nocase', 'pcre', 
      'classtype', 'rev', 'priority', 'enabled', 'category', 'filename'
    ];

    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = ?`);
        // Convert booleans to 0/1 for SQLite
        if (typeof req.body[field] === 'boolean') {
          values.push(req.body[field] ? 1 : 0);
        } else {
          values.push(req.body[field]);
        }
      }
    });

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(ruleId);

    db.run(
      `UPDATE suricata_rules SET ${updates.join(', ')} WHERE id = ?`,
      values,
      function(err) {
        if (err) {
          console.error('Error updating Suricata rule:', err);
          return res.status(500).json({ error: 'Failed to update Suricata rule' });
        }

        if (this.changes === 0) {
          return res.status(404).json({ error: 'Suricata rule not found' });
        }

        // Sync to file
        syncSuricataRulesToFile((syncErr) => {
          if (syncErr) {
            console.error('Warning: Failed to sync Suricata rules to file:', syncErr);
          }
        });

        db.get('SELECT * FROM suricata_rules WHERE id = ?', [ruleId], (getErr, rule) => {
          if (getErr) {
            return res.status(500).json({ error: 'Rule updated but failed to retrieve details' });
          }

          logAuditEvent(req.user.userId, 'SURICATA_RULE_UPDATED', req, true, `Updated Suricata rule: ${rule.msg}`);
          res.json({ 
            success: true, 
            message: 'Suricata rule updated successfully',
            rule: {
              ...rule,
              enabled: Boolean(rule.enabled),
              http_uri: Boolean(rule.http_uri),
              http_method: Boolean(rule.http_method),
              http_header: Boolean(rule.http_header),
              http_request_body: Boolean(rule.http_request_body),
              nocase: Boolean(rule.nocase)
            }
          });
        });
      }
    );
  } catch (error) {
    console.error('Error updating Suricata rule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete Suricata rule
app.delete('/api/admin/suricata/rules/:ruleId', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const ruleId = parseInt(req.params.ruleId);

    // First, get the rule details for logging
    db.get('SELECT * FROM suricata_rules WHERE id = ?', [ruleId], (err, rule) => {
      if (err) {
        console.error('Error fetching Suricata rule:', err);
        return res.status(500).json({ error: 'Failed to fetch Suricata rule' });
      }

      if (!rule) {
        return res.status(404).json({ error: 'Suricata rule not found' });
      }

      db.run('DELETE FROM suricata_rules WHERE id = ?', [ruleId], function(deleteErr) {
        if (deleteErr) {
          console.error('Error deleting Suricata rule:', deleteErr);
          return res.status(500).json({ error: 'Failed to delete Suricata rule' });
        }

        // Sync to file
        syncSuricataRulesToFile((syncErr) => {
          if (syncErr) {
            console.error('Warning: Failed to sync Suricata rules to file:', syncErr);
          }
        });

        logAuditEvent(req.user.userId, 'SURICATA_RULE_DELETED', req, true, `Deleted Suricata rule: ${rule.msg}`);
        res.json({ success: true, message: 'Suricata rule deleted successfully' });
      });
    });
  } catch (error) {
    console.error('Error deleting Suricata rule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update specific Suricata rule file (deprecated - kept for backward compatibility)
app.post('/api/admin/suricata/rules/:filename', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { filename } = req.params;
    const { content } = req.body;
    
    if (!filename || !content) {
      return res.status(400).json({ error: 'Filename and content are required' });
    }

    // Security: validate filename to prevent directory traversal
    if (filename.includes('..') || filename.includes('/') || !filename.endsWith('.rules')) {
      return res.status(400).json({ error: 'Invalid filename' });
    }

    const fs = require('fs');
    const rulesPath = path.join(__dirname, '../services/suricata/rules', filename);
    
    fs.writeFile(rulesPath, content, 'utf8', (err) => {
      if (err) {
        console.error('Error writing Suricata rule file:', err);
        return res.status(500).json({ error: 'Failed to update rule file' });
      }
      
      logAuditEvent(req.user.id, 'SURICATA_RULES_UPDATE', req, true, `Updated Suricata rule file: ${filename}`);
      res.json({ success: true, message: 'Suricata rule file updated successfully' });
    });
  } catch (error) {
    console.error('Error in update Suricata rules:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reload Suricata configurations (restart services to apply new rules)
app.post('/api/admin/suricata/reload', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { exec } = require('child_process');
    const path = require('path');
    
    // Send immediate response
    res.json({ 
      success: true, 
      message: 'Suricata reload initiated. Services will restart in background.', 
      status: 'in_progress'
    });

    // Execute reload script asynchronously
    const scriptPath = path.join(__dirname, '../services/suricata/reload-suricata.sh');
    
    exec(`chmod +x ${scriptPath} && ${scriptPath}`, { 
      cwd: path.join(__dirname, '../services/suricata'),
      timeout: 120000  // Increased to 120 seconds (2 minutes)
    }, (error, stdout, stderr) => {
      const timestamp = new Date().toISOString();
      
      if (error) {
        console.error(`[${timestamp}] Suricata reload failed:`, error);
        console.error(`[${timestamp}] stderr:`, stderr);
        logAuditEvent(req.user.userId, 'SURICATA_RELOAD_FAILED', req, false, `Error: ${error.message}`);
      } else {
        console.log(`[${timestamp}] Suricata reload completed successfully`);
        console.log(`[${timestamp}] stdout:`, stdout);
        logAuditEvent(req.user.userId, 'SURICATA_RELOAD_SUCCESS', req, true, 'Suricata services reloaded successfully');
      }
    });

  } catch (error) {
    console.error('Error initiating Suricata reload:', error);
    res.status(500).json({ error: 'Failed to initiate Suricata reload' });
  }
});

// Get active site users (users with traffic in last 24h)
app.get('/api/admin/active-users', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const query = `
      SELECT 
        u.id,
        u.username,
        u.email,
        COUNT(DISTINCT url.id) as request_count,
        MAX(url.timestamp) as last_activity,
        SUM(CASE WHEN url.waf_triggered = 1 OR url.suricata_triggered = 1 THEN 1 ELSE 0 END) as blocked_count
      FROM users u
      JOIN user_request_logs url ON u.id = url.user_id
      WHERE url.timestamp > datetime('now', '-1 day')
      GROUP BY u.id, u.username, u.email
      ORDER BY request_count DESC
    `;

    db.all(query, (err, rows) => {
      if (err) {
        console.error('Error fetching active users:', err);
        return res.status(500).json({ error: 'Failed to fetch active users' });
      }
      res.json(rows);
    });
  } catch (error) {
    console.error('Error in get active users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create admin account (only accessible by existing admins)
app.post('/api/admin/create-admin', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    // Check if user already exists
    const existingUser = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id FROM users WHERE email = ? OR username = ?',
        [email, username],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (existingUser) {
      return res.status(409).json({ error: 'User with this email or username already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create admin user
    const userId = await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        [username, email, hashedPassword, 'admin'],
        function(err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });

    // Create user config
    const crypto = require('crypto');
    const apiKey = `nxr_${crypto.randomBytes(32).toString('hex')}`;
    
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO user_configs (user_id, backend_url, proxy_api_key) VALUES (?, ?, ?)',
        [userId, '', apiKey],
        function(err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });

    logAuditEvent(req.user.id, 'ADMIN_ACCOUNT_CREATED', req, true, `Created admin account: ${username}`);

    res.json({ 
      success: true, 
      message: 'Admin account created successfully',
      user: { id: userId, username, email, role: 'admin' }
    });
  } catch (error) {
    console.error('Error creating admin account:', error);
    res.status(500).json({ error: 'Failed to create admin account' });
  }
});

// ============================================
// User Management CRUD Operations
// ============================================

// Update user details
app.put('/api/admin/users/:userId', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.params;
    const { username, email, role, is_active, is_banned } = req.body;

    // Check if user exists
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT id FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Build update query dynamically
    const updates = [];
    const values = [];

    if (username !== undefined) {
      updates.push('username = ?');
      values.push(username);
    }
    if (email !== undefined) {
      updates.push('email = ?');
      values.push(email);
    }
    if (role !== undefined) {
      updates.push('role = ?');
      values.push(role);
    }
    if (is_active !== undefined) {
      updates.push('is_active = ?');
      values.push(is_active ? 1 : 0);
    }
    if (is_banned !== undefined) {
      updates.push('is_banned = ?');
      values.push(is_banned ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(userId);

    await new Promise((resolve, reject) => {
      db.run(
        `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
        values,
        function(err) {
          if (err) reject(err);
          else resolve(this.changes);
        }
      );
    });

    logAuditEvent(req.user.id, 'USER_UPDATED', req, true, `Updated user ID: ${userId}`);

    res.json({ success: true, message: 'User updated successfully' });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Delete user
app.delete('/api/admin/users/:userId', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.params;

    // Prevent deleting yourself
    if (parseInt(userId) === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    // Check if user exists
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Delete user (cascading will handle related records)
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
        if (err) reject(err);
        else resolve(this.changes);
      });
    });

    logAuditEvent(req.user.id, 'USER_DELETED', req, true, `Deleted user: ${user.username} (ID: ${userId})`);

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Reset user password
app.post('/api/admin/users/:userId/reset-password', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.params;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET password = ? WHERE id = ?',
        [hashedPassword, userId],
        function(err) {
          if (err) reject(err);
          else resolve(this.changes);
        }
      );
    });

    logAuditEvent(req.user.id, 'PASSWORD_RESET', req, true, `Reset password for user: ${user.username} (ID: ${userId})`);

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Ban/Unban user
app.post('/api/admin/users/:userId/ban', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.params;
    const { banned } = req.body;

    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET is_banned = ? WHERE id = ?',
        [banned ? 1 : 0, userId],
        function(err) {
          if (err) reject(err);
          else resolve(this.changes);
        }
      );
    });

    logAuditEvent(req.user.id, banned ? 'USER_BANNED' : 'USER_UNBANNED', req, true, `User ID: ${userId}`);

    res.json({ success: true, message: `User ${banned ? 'banned' : 'unbanned'} successfully` });
  } catch (error) {
    console.error('Error updating ban status:', error);
    res.status(500).json({ error: 'Failed to update ban status' });
  }
});

// ============================================
// WAF Rules CRUD Operations
// ============================================

// Add new WAF rule
app.post('/api/admin/waf/rules/add', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id, pattern, message, tags, severity, enabled } = req.body;

    if (!id || !pattern || !message) {
      return res.status(400).json({ error: 'ID, pattern, and message are required' });
    }

    // Insert into database
    db.run(
      `INSERT INTO waf_rules (id, pattern, message, tags, severity, enabled, created_by) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        parseInt(id),
        pattern,
        message,
        tags || 'custom',
        parseInt(severity) || 3,
        enabled !== undefined ? (enabled ? 1 : 0) : 1,
        req.user.userId
      ],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Rule ID already exists' });
          }
          console.error('Error adding WAF rule to database:', err);
          return res.status(500).json({ error: 'Failed to add WAF rule' });
        }

        const newRule = {
          id: parseInt(id),
          pattern,
          message,
          tags: tags || 'custom',
          severity: parseInt(severity) || 3,
          enabled: enabled !== undefined ? enabled : true
        };

        // Sync to file for backward compatibility
        syncWafRulesToFile((syncErr) => {
          if (syncErr) {
            console.error('Warning: Failed to sync WAF rules to file:', syncErr);
          }
        });

        logAuditEvent(req.user.userId, 'WAF_RULE_ADDED', req, true, `Added WAF rule: ${message}`);
        res.json({ success: true, message: 'WAF rule added successfully', rule: newRule });
      }
    );
  } catch (error) {
    console.error('Error adding WAF rule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete WAF rule
app.delete('/api/admin/waf/rules/:ruleId', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const ruleId = parseInt(req.params.ruleId);

    // First, get the rule details for logging
    db.get('SELECT * FROM waf_rules WHERE id = ?', [ruleId], (err, rule) => {
      if (err) {
        console.error('Error fetching WAF rule:', err);
        return res.status(500).json({ error: 'Failed to fetch WAF rule' });
      }

      if (!rule) {
        return res.status(404).json({ error: 'WAF rule not found' });
      }

      // Delete from database
      db.run('DELETE FROM waf_rules WHERE id = ?', [ruleId], function(deleteErr) {
        if (deleteErr) {
          console.error('Error deleting WAF rule from database:', deleteErr);
          return res.status(500).json({ error: 'Failed to delete WAF rule' });
        }

        // Sync to file for backward compatibility
        syncWafRulesToFile((syncErr) => {
          if (syncErr) {
            console.error('Warning: Failed to sync WAF rules to file:', syncErr);
          }
        });

        logAuditEvent(req.user.userId, 'WAF_RULE_DELETED', req, true, `Deleted WAF rule: ${rule.message}`);
        res.json({ success: true, message: 'WAF rule deleted successfully' });
      });
    });
  } catch (error) {
    console.error('Error deleting WAF rule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update WAF rule
app.put('/api/admin/waf/rules/:ruleId', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const ruleId = parseInt(req.params.ruleId);
    const { pattern, message, tags, severity, enabled } = req.body;
    
    // Build update query dynamically
    const updates = [];
    const values = [];

    if (message !== undefined) {
      updates.push('message = ?');
      values.push(message);
    }
    if (pattern !== undefined) {
      updates.push('pattern = ?');
      values.push(pattern);
    }
    if (tags !== undefined) {
      updates.push('tags = ?');
      values.push(tags);
    }
    if (severity !== undefined) {
      updates.push('severity = ?');
      values.push(parseInt(severity));
    }
    if (enabled !== undefined) {
      updates.push('enabled = ?');
      values.push(enabled ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(ruleId);

    db.run(
      `UPDATE waf_rules SET ${updates.join(', ')} WHERE id = ?`,
      values,
      function(err) {
        if (err) {
          console.error('Error updating WAF rule in database:', err);
          return res.status(500).json({ error: 'Failed to update WAF rule' });
        }

        if (this.changes === 0) {
          return res.status(404).json({ error: 'WAF rule not found' });
        }

        // Get updated rule
        db.get('SELECT * FROM waf_rules WHERE id = ?', [ruleId], (getErr, rule) => {
          if (getErr) {
            console.error('Error fetching updated rule:', getErr);
            return res.status(500).json({ error: 'Failed to fetch updated rule' });
          }

          // Sync to file for backward compatibility
          syncWafRulesToFile((syncErr) => {
            if (syncErr) {
              console.error('Warning: Failed to sync WAF rules to file:', syncErr);
            }
          });

          logAuditEvent(req.user.userId, 'WAF_RULE_UPDATED', req, true, `Updated WAF rule: ${rule.message}`);
          res.json({ 
            success: true, 
            message: 'WAF rule updated successfully', 
            rule: {
              ...rule,
              enabled: Boolean(rule.enabled)
            }
          });
        });
      }
    );
  } catch (error) {
    console.error('Error updating WAF rule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get ALL WAF rules from all phase files
app.get('/api/admin/waf/rules/all-phases', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Fetch all WAF rules from database
    db.all('SELECT * FROM waf_rules ORDER BY id', (err, rules) => {
      if (err) {
        console.error('Error reading WAF rules from database:', err);
        return res.status(500).json({ error: 'Failed to read WAF rules' });
      }

      if (!rules || rules.length === 0) {
        return res.json({
          total: 0,
          rules: []
        });
      }

      // Format rules with phase information
      const formattedRules = rules.map((rule, idx) => {
        // Determine phase based on rule properties
        let phase = 'Phase 1';
        if (rule.tags && rule.tags.includes('advanced')) {
          phase = 'Phase 2-Advanced';
        } else if (rule.tags && rule.tags.includes('phase2')) {
          phase = 'Phase 2';
        } else if (rule.tags && rule.tags.includes('phase3')) {
          phase = 'Phase 3';
        }

        return {
          id: rule.id,
          phase: phase,
          message: rule.message || rule.pattern || 'No description',
          pattern: rule.pattern,
          category: rule.tags ? rule.tags.split(',')[0].trim() : 'General',
          tags: rule.tags,
          severity: rule.severity || 'medium',
          enabled: Boolean(rule.enabled),
          created_at: rule.created_at,
          updated_at: rule.updated_at
        };
      });

      console.log(`✅ Returning ${formattedRules.length} WAF rules from database`);
      res.json({
        total: formattedRules.length,
        rules: formattedRules
      });
    });
  } catch (error) {
    console.error('Error reading all WAF phase rules:', error);
    res.status(500).json({ error: 'Failed to read WAF rules' });
  }
});

// Test endpoint for WAF without authentication
app.get('/api/test/waf/rules/all-phases', (req, res) => {
  try {
    const fs = require('fs');
    const allRules = [];
    const phaseFiles = [
      'data/phase1_waf_rules.json',
      'data/phase2_waf_rules.json',
      'data/phase2_advanced_waf_rules.json',
      'data/phase3_waf_rules.json'
    ];

    phaseFiles.forEach((file, idx) => {
      try {
        const filePath = path.join(__dirname, '../security-proxy', file);
        if (fs.existsSync(filePath)) {
          const fileData = fs.readFileSync(filePath, 'utf8');
          const rules = JSON.parse(fileData);
          const phaseNum = idx === 1 ? 2 : idx === 2 ? '2-Advanced' : idx === 3 ? 3 : 1;
          rules.forEach(rule => {
            allRules.push({
              ...rule,
              phase: `Phase ${phaseNum}`
            });
          });
        }
      } catch (err) {
        console.warn(`Warning: Could not read ${file}: ${err.message}`);
      }
    });

    res.json({
      total: allRules.length,
      rules: allRules
    });
  } catch (error) {
    console.error('Error reading all WAF phase rules (test):', error);
    res.status(500).json({ error: 'Failed to read WAF rules' });
  }
});

// Get ALL Suricata rules from all phase files
app.get('/api/admin/suricata/rules/all-phases', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Fetch all Suricata rules from database (both IPS DROP and IDS ALERT)
    db.all('SELECT * FROM suricata_rules ORDER BY sid', (err, rules) => {
      if (err) {
        console.error('Error reading Suricata rules from database:', err);
        return res.status(500).json({ error: 'Failed to read Suricata rules' });
      }

      if (!rules || rules.length === 0) {
        return res.json({
          total: 0,
          rules: []
        });
      }

      // Format rules with all fields
      const formattedRules = rules.map((rule) => {
        // Determine rule type (IPS for drop, IDS for alert)
        const ruleType = rule.action === 'drop' ? 'IPS' : 'IDS';
        
        return {
          id: rule.id,
          sid: rule.sid,
          protocol: rule.protocol,
          message: rule.msg || rule.message || 'No description',
          msg: rule.msg || rule.message,
          action: rule.action,
          type: ruleType,
          enabled: Boolean(rule.enabled),
          source_ip: rule.source_ip,
          source_port: rule.source_port,
          direction: rule.direction,
          dest_ip: rule.dest_ip,
          dest_port: rule.dest_port,
          flow: rule.flow,
          content: rule.content,
          classtype: rule.classtype,
          priority: rule.priority,
          rev: rule.rev,
          category: rule.category,
          filename: rule.filename,
          http_uri: Boolean(rule.http_uri),
          http_method: Boolean(rule.http_method),
          http_header: Boolean(rule.http_header),
          http_request_body: Boolean(rule.http_request_body),
          nocase: Boolean(rule.nocase),
          pcre: rule.pcre,
          created_at: rule.created_at,
          updated_at: rule.updated_at
        };
      });

      console.log(`✅ Returning ${formattedRules.length} Suricata rules from database (IPS: ${formattedRules.filter(r => r.type === 'IPS').length}, IDS: ${formattedRules.filter(r => r.type === 'IDS').length})`);
      res.json({
        total: formattedRules.length,
        rules: formattedRules
      });
    });
  } catch (error) {
    console.error('Error reading all Suricata phase rules:', error);
    res.status(500).json({ error: 'Failed to read Suricata rules' });
  }
});

// Test endpoint without authentication for debugging
app.get('/api/test/suricata/rules/all-phases', (req, res) => {
  db.all('SELECT * FROM suricata_rules ORDER BY sid ASC', [], (err, rows) => {
    if (err) {
      console.error('Error fetching Suricata rules from DB (test endpoint):', err);
      return res.status(500).json({ error: 'Failed to fetch rules' });
    }
    const rules = rows.map(r => ({
      id: r.id,
      sid: r.sid,
      action: r.action,
      protocol: r.protocol,
      message: r.message,
      phase: r.action === 'drop' ? 'IPS (Drop)' : 'IDS (Alert)',
      filename: r.filename,
      enabled: r.enabled,
      raw: r.raw_rule ? r.raw_rule.substring(0, 120) + (r.raw_rule.length > 120 ? '...' : '') : ''
    }));
    res.json({ total: rules.length, rules });
  });
});

// Sync IPS drops from eve.json as System alerts (for visibility since drop rules don't generate alerts)
app.post('/api/sync-ips-drops', authenticateToken, async (req, res) => {
  try {
    const fs = require('fs');
    const eveJsonPath = '/var/log/suricata/eve.json';
    
    if (!fs.existsSync(eveJsonPath)) {
      return res.json({ synced: 0, message: 'eve.json not found' });
    }

    const fileContent = fs.readFileSync(eveJsonPath, 'utf8');
    const lines = fileContent.trim().split('\n');
    
    let synced = 0;
    const recentDrops = {};
    
    // Parse last 500 lines to find recent IPS drops
    for (let i = Math.max(0, lines.length - 500); i < lines.length; i++) {
      try {
        const event = JSON.parse(lines[i]);
        if (event.event_type === 'alert' && event.alert && event.alert.action === 'drop') {
          const key = `${event.src_ip}|${event.dest_ip}|${event.alert.signature}`;
          if (!recentDrops[key]) {
            recentDrops[key] = event;
          }
        }
      } catch (e) {
        // Skip invalid JSON lines
      }
    }

    // Create System alerts for each unique dropped packet signature
    for (const key in recentDrops) {
      const event = recentDrops[key];
      const timestamp = event.timestamp || new Date().toISOString();
      const msg = event.alert.signature || 'IPS Drop';
      const severity = event.alert.severity === 1 ? 'critical' : event.alert.severity === 2 ? 'high' : 'medium';
      
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO user_alerts (user_id, alert_type, severity, description, timestamp, source, source_ip, is_read, action)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            req.user.userId,
            'system',
            severity,
            `IPS Drop: ${msg} from ${event.src_ip}`,
            timestamp,
            'ips-dropped-packet',
            event.src_ip,
            0,
            'blocked'
          ],
          (err) => {
            if (err) console.error('DB insert error:', err);
            else synced++;
            resolve();
          }
        );
      });
    }

    res.json({ synced, message: `Synced ${synced} IPS drops as System alerts` });
  } catch (error) {
    console.error('Error syncing IPS drops:', error);
    res.status(500).json({ message: 'Failed to sync IPS drops' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  logAuditEvent(null, 'SYSTEM_ERROR', req, false, err.message);
  res.status(500).json({ message: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down gracefully...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0);
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Synorix Authentication Server running on port ${PORT}`);
  console.log(`🔒 Security features enabled: Rate limiting, CORS, Helmet`);
  console.log(`📊 Database: SQLite (${dbPath})`);
  console.log(`🌟 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
