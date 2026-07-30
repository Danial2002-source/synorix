#!/usr/bin/env node
/**
 * SYNORIX API Routes - Rules Management with Auto-Export
 * Integrates database rules with automatic Suricata export
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const DB_PATH = path.join(__dirname, '..', 'synorix.db');
const SURICATA_DIR = path.join(__dirname, '..', 'services', 'suricata');
const FIREWALL_DIR = path.join(__dirname, '..', 'services', 'firewall');

// Initialize database connection
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error('Database error:', err);
    else console.log('✅ Connected to SYNORIX database');
});

/**
 * Trigger auto-export of rules to Suricata format (ids-rules.rules / ips-rules.rules)
 */
async function autoExportRules() {
    return new Promise((resolve, reject) => {
        const exportScript = path.join(__dirname, 'rules-export.js');
        execFile('node', [exportScript], (error, stdout, stderr) => {
            if (error) {
                console.error('Export error:', error);
                reject(error);
                return;
            }
            console.log('📤 Rules auto-exported to Suricata format');
            resolve(stdout);
        });
    });
}

/**
 * Reload Suricata IDS + IPS instances to apply updated rules
 */
async function reloadSuricata() {
    return new Promise((resolve, reject) => {
        const reloadScript = path.join(SURICATA_DIR, 'reload-suricata.sh');
        execFile('bash', [reloadScript], { timeout: 60000 }, (error, stdout, stderr) => {
            if (error) {
                console.error('Suricata reload error:', error);
                // Don't hard-reject — reload may fail if Suricata is not running in this env
                resolve({ success: false, error: error.message, stdout, stderr });
                return;
            }
            console.log('🔄 Suricata reloaded successfully');
            resolve({ success: true, stdout, stderr });
        });
    });
}

/**
 * Trigger firewall rules generation
 */
async function generateFirewallRules() {
    return new Promise((resolve, reject) => {
        const pythonScript = path.join(FIREWALL_DIR, 'generate-firewall-rules.py');
        execFile('python3', [pythonScript], (error, stdout, stderr) => {
            if (error) {
                console.error('Firewall generation error:', error);
                reject(error);
                return;
            }
            console.log('🔥 Firewall rules regenerated');
            resolve(stdout);
        });
    });
}

// ==================== IPS Rules Routes ====================

/**
 * GET /api/rules/ips - List all IPS (DROP) rules
 */
router.get('/rules/ips', (req, res) => {
    db.all(`
        SELECT * FROM suricata_rules 
        WHERE action = 'drop' 
        ORDER BY sid
    `, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({
            type: 'IPS',
            count: rows.length,
            rules: rows
        });
    });
});

/**
 * GET /api/rules/ids - List all IDS (ALERT) rules
 */
router.get('/rules/ids', (req, res) => {
    db.all(`
        SELECT * FROM suricata_rules 
        WHERE action = 'alert' 
        ORDER BY sid
    `, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({
            type: 'IDS',
            count: rows.length,
            rules: rows
        });
    });
});

/**
 * GET /api/rules - List all rules with statistics
 */
router.get('/rules', (req, res) => {
    db.serialize(() => {
        db.get(`SELECT COUNT(*) as total FROM suricata_rules`, (err, total) => {
            db.get(`SELECT COUNT(*) as ips FROM suricata_rules WHERE action = 'drop'`, (err, ips) => {
                db.get(`SELECT COUNT(*) as ids FROM suricata_rules WHERE action = 'alert'`, (err, ids) => {
                    res.json({
                        summary: {
                            total: total.total,
                            ips: ips.ips,
                            ids: ids.ids
                        },
                        endpoints: {
                            allRules: '/api/rules',
                            ipsRules: '/api/rules/ips',
                            idsRules: '/api/rules/ids',
                            createRule: 'POST /api/rules',
                            updateRule: 'PUT /api/rules/:id',
                            deleteRule: 'DELETE /api/rules/:id',
                            searchRules: 'GET /api/rules/search?query=...',
                            exportRules: 'POST /api/rules/export',
                            firewallRules: 'POST /api/firewall/generate'
                        }
                    });
                });
            });
        });
    });
});

/**
 * POST /api/rules - Create new rule (with auto-export)
 */
router.post('/rules', (req, res) => {
    const {
        sid, action, protocol, source_ip, source_port, direction,
        dest_ip, dest_port, msg, flow, content, pcre, classtype, priority, category
    } = req.body;

    const inferredFilename = (action === 'drop' || action === 'reject') ? 'ips-rules.rules' : 'ids-rules.rules';

    const sql = `
        INSERT INTO suricata_rules  
        (sid, action, protocol, source_ip, source_port, direction, 
         dest_ip, dest_port, msg, flow, content, pcre, classtype, 
         priority, enabled, category, filename, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    `;

    db.run(sql, [
        sid, action, protocol, source_ip, source_port, direction,
        dest_ip, dest_port, msg, flow, content, pcre, classtype,
        priority, category, inferredFilename, req.user?.id || 'api'
    ], async function(err) {
        if (err) {
            res.status(400).json({ error: err.message });
            return;
        }

        try {
            await autoExportRules();
            await generateFirewallRules();
            const reload = await reloadSuricata();
            res.json({
                status: 'success',
                message: 'Rule created, exported and Suricata reloaded',
                sid: sid,
                exported: true,
                firewallUpdated: true,
                suricataReloaded: reload.success
            });
        } catch (exportErr) {
            res.status(201).json({
                status: 'created',
                message: 'Rule created but export/reload failed',
                error: exportErr.message,
                sid: sid
            });
        }
    });
});

/**
 * PUT /api/rules/:sid - Update rule (with auto-export)
 */
router.put('/rules/:sid', (req, res) => {
    const { sid } = req.params;
    const { enabled, priority, msg, category } = req.body;

    let updates = [];
    let params = [];

    if (enabled !== undefined) {
        updates.push('enabled = ?');
        params.push(enabled);
    }
    if (priority !== undefined) {
        updates.push('priority = ?');
        params.push(priority);
    }
    if (msg !== undefined) {
        updates.push('msg = ?');
        params.push(msg);
    }
    if (category !== undefined) {
        updates.push('category = ?');
        params.push(category);
    }

    if (updates.length === 0) {
        res.status(400).json({ error: 'No fields to update' });
        return;
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    params.push(sid);

    const sql = `UPDATE suricata_rules SET ${updates.join(', ')} WHERE sid = ?`;

    db.run(sql, params, async function(err) {
        if (err) {
            res.status(400).json({ error: err.message });
            return;
        }

        try {
            await autoExportRules();
            await generateFirewallRules();
            const reload = await reloadSuricata();
            res.json({
                status: 'success',
                message: 'Rule updated, exported and Suricata reloaded',
                sid: sid,
                changes: updates.length - 1,
                exported: true,
                suricataReloaded: reload.success
            });
        } catch (exportErr) {
            res.status(200).json({
                status: 'updated',
                message: 'Rule updated but export/reload failed',
                error: exportErr.message,
                sid: sid
            });
        }
    });
});

/**
 * DELETE /api/rules/:sid - Delete rule (with auto-export)
 */
router.delete('/rules/:sid', (req, res) => {
    const { sid } = req.params;

    db.run('DELETE FROM suricata_rules WHERE sid = ?', [sid], async function(err) {
        if (err) {
            res.status(400).json({ error: err.message });
            return;
        }

        if (this.changes === 0) {
            res.status(404).json({ error: 'Rule not found' });
            return;
        }

        try {
            await autoExportRules();
            await generateFirewallRules();
            const reload = await reloadSuricata();
            res.json({
                status: 'success',
                message: 'Rule deleted, exported and Suricata reloaded',
                sid: sid,
                exported: true,
                suricataReloaded: reload.success
            });
        } catch (exportErr) {
            res.status(200).json({
                status: 'deleted',
                message: 'Rule deleted but export/reload failed',
                error: exportErr.message,
                sid: sid
            });
        }
    });
});

/**
 * GET /api/rules/search - Search rules
 */
router.get('/rules/search', (req, res) => {
    const { query, type } = req.query;

    if (!query) {
        res.status(400).json({ error: 'Query parameter required' });
        return;
    }

    let sql = `
        SELECT * FROM suricata_rules 
        WHERE msg LIKE ? OR sid LIKE ? OR category LIKE ?
    `;
    let params = [`%${query}%`, `%${query}%`, `%${query}%`];

    if (type === 'ips') {
        sql += ' AND action = "drop"';
    } else if (type === 'ids') {
        sql += ' AND action = "alert"';
    }

    sql += ' ORDER BY sid LIMIT 50';

    db.all(sql, params, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({
            query: query,
            results: rows.length,
            rules: rows
        });
    });
});

/**
 * POST /api/rules/export - Manually trigger export
 */
router.post('/rules/export', async (req, res) => {
    try {
        const result = await autoExportRules();
        res.json({
            status: 'success',
            message: 'Rules exported successfully',
            output: result
        });
    } catch (err) {
        res.status(500).json({
            status: 'error',
            error: err.message
        });
    }
});

/**
 * POST /api/rules/reload - Export rules then reload Suricata IDS/IPS
 */
router.post('/rules/reload', async (req, res) => {
    try {
        // Step 1: export updated rules from DB to .rules files
        await autoExportRules();

        // Step 2: restart Suricata instances
        const result = await reloadSuricata();

        res.json({
            status: result.success ? 'success' : 'partial',
            message: result.success
                ? 'Rules exported and Suricata reloaded'
                : 'Rules exported but Suricata reload reported an error',
            suricata: {
                success: result.success,
                stdout: result.stdout,
                stderr: result.stderr,
                error:  result.error || null
            }
        });
    } catch (err) {
        res.status(500).json({
            status: 'error',
            error: err.message
        });
    }
});

/**
 * POST /api/firewall/generate - Generate firewall rules
 */
router.post('/firewall/generate', async (req, res) => {
    try {
        const result = await generateFirewallRules();
        res.json({
            status: 'success',
            message: 'Firewall rules generated successfully',
            output: result
        });
    } catch (err) {
        res.status(500).json({
            status: 'error',
            error: err.message
        });
    }
});

/**
 * GET /api/firewall/status - Get firewall status
 */
router.get('/firewall/status', (req, res) => {
    res.json({
        status: 'active',
        firewall: 'iptables/firewall-cmd',
        rules: {
            file: path.join(FIREWALL_DIR, 'synorix-firewall-rules.sh'),
            firewallCmd: path.join(FIREWALL_DIR, 'synorix-firewall-cmd.sh')
        },
        lastGenerated: new Date().toISOString(),
        capabilities: [
            'DDoS Protection',
            'Port Scanning Prevention',
            'SQL Injection Blocking',
            'XXE Detection',
            'Path Traversal Blocking',
            'Rate Limiting',
            'Zone-based Protection'
        ]
    });
});

module.exports = router;
