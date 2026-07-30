/**
 * SYNORIX Rules Integration Middleware
 * Handles integration between API, database, and Suricata
 */

const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

/**
 * Middleware to log all rule operations
 */
const ruleAuditLog = (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
        if (req.path.includes('/rules') || req.path.includes('/firewall')) {
            const logEntry = {
                timestamp: new Date().toISOString(),
                method: req.method,
                path: req.path,
                user: req.user?.id || 'anonymous',
                status: res.statusCode,
                data: typeof data === 'string' ? data : JSON.stringify(data)
            };
            
            const logDir = path.join(__dirname, '..', '..', 'logs');
            const logFile = path.join(logDir, 'rules-audit.log');
            try {
                if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
                fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n', { flag: 'a' });
            } catch (logErr) {
                console.warn('Rules audit log write failed:', logErr.message);
            }
        }
        
        return originalSend.call(this, data);
    };
    
    next();
};

/**
 * Middleware to validate rule parameters
 */
const validateRuleParams = (req, res, next) => {
    if (req.method === 'POST' && req.path.endsWith('/rules')) {
        const { sid, action, protocol, msg } = req.body;
        
        if (!sid || !action || !protocol || !msg) {
            return res.status(400).json({
                error: 'Missing required fields: sid, action, protocol, msg'
            });
        }
        
        // Validate action
        if (!['alert', 'drop', 'pass', 'reject'].includes(action)) {
            return res.status(400).json({
                error: 'Invalid action. Must be: alert, drop, pass, reject'
            });
        }
        
        // Validate protocol
        if (!['tcp', 'udp', 'icmp', 'ip'].includes(protocol)) {
            return res.status(400).json({
                error: 'Invalid protocol. Must be: tcp, udp, icmp, ip'
            });
        }
    }
    
    next();
};

/**
 * Middleware to handle export queue
 */
const exportQueue = {
    queue: [],
    processing: false,
    
    add(task) {
        this.queue.push(task);
        this.process();
    },
    
    async process() {
        if (this.processing || this.queue.length === 0) return;
        
        this.processing = true;
        const task = this.queue.shift();
        
        try {
            await task();
        } catch (err) {
            console.error('Export task failed:', err);
        }
        
        this.processing = false;
        if (this.queue.length > 0) {
            this.process();
        }
    }
};

/**
 * Middleware for queuing exports
 */
const queuedExport = (req, res, next) => {
    res.queueExport = (fn) => {
        exportQueue.add(fn);
    };
    next();
};

/**
 * Middleware for permission checks
 */
const checkRulePermissions = (req, res, next) => {
    // Only enforce on rules/firewall management paths; pass everything else through
    const isRulesPath = req.path.includes('/rules') || req.path.includes('/firewall');
    if (!isRulesPath) {
        return next();
    }

    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const jwtSecret = process.env.JWT_SECRET || '';

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    if (!jwtSecret) {
        return res.status(503).json({ error: 'JWT secret not configured' });
    }

    let decoded;
    try {
        decoded = jwt.verify(token, jwtSecret);
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.user = decoded;

    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Permission denied' });
        }
    }

    next();
};

module.exports = {
    ruleAuditLog,
    validateRuleParams,
    queuedExport,
    checkRulePermissions,
    exportQueue
};
