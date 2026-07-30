#!/usr/bin/env node

/**
 * SYNORIX Rules Export Module (Node.js)
 * Exports rules from SQLite database to Suricata format
 * Can be used as a module or CLI tool
 */

const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const dbPath = path.join(__dirname, 'synorix.db');
const rulesDir = path.join(__dirname, '..', 'services', 'suricata', 'rules');

// Ensure rules directory exists
if (!fs.existsSync(rulesDir)) {
  fs.mkdirSync(rulesDir, { recursive: true });
}

function formatSuricataRule(rule) {
  const [sid, action, protocol, sourceIp, sourcePort, direction, destIp, destPort,
    msg, flow, content, pcre, classtype, priority, enabled, category] = rule;
  
  if (!enabled) return null;
  
  let ruleParts = [
    action,
    protocol,
    sourceIp,
    sourcePort,
    direction,
    destIp,
    destPort,
    `(msg:"${msg}";`,
  ];
  
  if (flow) ruleParts.push(`flow:${flow};`);
  if (content) ruleParts.push(`content:"${content}";`);
  if (pcre) ruleParts.push(`pcre:"${pcre}";`);
  
  ruleParts.push(
    `classtype:${classtype};`,
    `sid:${sid};`,
    `rev:1;`,
    `priority:${priority};)`
  );
  
  return ruleParts.join(' ');
}

function exportDropRules() {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath);
    
    const query = `
      SELECT sid, action, protocol, source_ip, source_port, direction, dest_ip, 
             dest_port, msg, flow, content, pcre, classtype, priority, enabled, category
      FROM suricata_rules 
      WHERE action = 'drop' AND enabled = 1
      ORDER BY sid
    `;
    
    db.all(query, (err, rows) => {
      if (err) {
        db.close();
        reject(err);
        return;
      }
      
      const rulesFile = path.join(rulesDir, 'synorix-drop-rules.rules');
      const timestamp = new Date().toISOString();
      
      let content = `# SYNORIX IPS Rules - DROP (Blocking)\n`;
      content += `# Generated: ${timestamp}\n`;
      content += `# Total Rules: ${rows.length}\n`;
      content += `# Database: ${dbPath}\n\n`;
      
      rows.forEach(rule => {
        const formatted = formatSuricataRule(rule);
        if (formatted) {
          content += formatted + '\n';
        }
      });
      
      fs.writeFileSync(rulesFile, content);
      db.close();
      resolve({ type: 'DROP', count: rows.length, file: rulesFile });
    });
  });
}

function exportAlertRules() {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath);
    
    const query = `
      SELECT sid, action, protocol, source_ip, source_port, direction, dest_ip, 
             dest_port, msg, flow, content, pcre, classtype, priority, enabled, category
      FROM suricata_rules 
      WHERE action = 'alert' AND enabled = 1
      ORDER BY sid
    `;
    
    db.all(query, (err, rows) => {
      if (err) {
        db.close();
        reject(err);
        return;
      }
      
      const rulesFile = path.join(rulesDir, 'synorix-alert-rules.rules');
      const timestamp = new Date().toISOString();
      
      let content = `# SYNORIX IDS Rules - ALERT (Detection)\n`;
      content += `# Generated: ${timestamp}\n`;
      content += `# Total Rules: ${rows.length}\n`;
      content += `# Database: ${dbPath}\n\n`;
      
      rows.forEach(rule => {
        const formatted = formatSuricataRule(rule);
        if (formatted) {
          content += formatted + '\n';
        }
      });
      
      fs.writeFileSync(rulesFile, content);
      db.close();
      resolve({ type: 'ALERT', count: rows.length, file: rulesFile });
    });
  });
}

function exportAllRules() {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath);
    
    const query = `
      SELECT sid, action, protocol, source_ip, source_port, direction, dest_ip, 
             dest_port, msg, flow, content, pcre, classtype, priority, enabled, category
      FROM suricata_rules 
      WHERE enabled = 1
      ORDER BY action, sid
    `;
    
    db.all(query, (err, rows) => {
      if (err) {
        db.close();
        reject(err);
        return;
      }
      
      const rulesFile = path.join(rulesDir, 'synorix-local.rules');
      const timestamp = new Date().toISOString();
      const dropCount = rows.filter(r => r[1] === 'drop').length;
      const alertCount = rows.filter(r => r[1] === 'alert').length;
      
      let content = `# SYNORIX Complete Rules - IPS/IDS Combined\n`;
      content += `# Generated: ${timestamp}\n`;
      content += `# Total Rules: ${rows.length} (IPS: ${dropCount}, IDS: ${alertCount})\n`;
      content += `# Source: SQLite Database ${dbPath}\n`;
      content += `# Status: Production Ready\n\n`;
      
      rows.forEach(rule => {
        const formatted = formatSuricataRule(rule);
        if (formatted) {
          content += formatted + '\n';
        }
      });
      
      fs.writeFileSync(rulesFile, content);
      db.close();
      resolve({ 
        type: 'ALL', 
        count: rows.length, 
        drop: dropCount, 
        alert: alertCount, 
        file: rulesFile 
      });
    });
  });
}

async function exportRules() {
  try {
    console.log('🚀 Exporting SYNORIX Rules...\n');
    
    const [dropResult, alertResult, allResult] = await Promise.all([
      exportDropRules(),
      exportAlertRules(),
      exportAllRules()
    ]);
    
    console.log('✅ Export Results:');
    console.log(`  • DROP (IPS) rules: ${dropResult.count}`);
    console.log(`  • ALERT (IDS) rules: ${alertResult.count}`);
    console.log(`  • Total rules: ${allResult.count}\n`);
    
    console.log(`📁 Output directory: ${rulesDir}\n`);
    
    return {
      success: true,
      drop: dropResult.count,
      alert: alertResult.count,
      total: allResult.count,
      directory: rulesDir
    };
  } catch (err) {
    console.error('❌ Export error:', err.message);
    return { success: false, error: err.message };
  }
}

// Export functions for use as module
module.exports = {
  exportRules,
  exportDropRules,
  exportAlertRules,
  exportAllRules,
  formatSuricataRule,
  rulesDir
};

// Run as CLI if executed directly
if (require.main === module) {
  exportRules().then(result => {
    process.exit(result.success ? 0 : 1);
  });
}
