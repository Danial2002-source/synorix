const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const dbPath = path.resolve(__dirname, 'synorix.db');
const db = new sqlite3.Database(dbPath);
const rulesDir = path.resolve(__dirname, '..', 'services', 'suricata', 'rules');

const SQL = `INSERT OR IGNORE INTO suricata_rules
  (sid, action, protocol, source_ip, source_port, direction, dest_ip, dest_port,
   msg, flow, content, http_uri, http_method, http_header, http_request_body,
   nocase, pcre, classtype, rev, priority, enabled, category, filename)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

let imported = 0, skipped = 0;
const files = ['ids-rules.rules', 'ips-rules.rules'];

db.serialize(() => {
  files.forEach(filename => {
    const content = fs.readFileSync(path.join(rulesDir, filename), 'utf8');
    const lines = content.split('\n');

    lines.forEach(line => {
      line = line.trim();
      if (!line || line.startsWith('#')) return;
      const m = line.match(/^(alert|drop|reject|pass)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<-|<>)\s+(\S+)\s+(\S+)\s+\((.*)\)\s*$/);
      if (!m) return;
      const [, action, proto, srcIp, srcPort, dir, dstIp, dstPort, opts] = m;
      const get = (key) => { const r = opts.match(new RegExp(key + ':"([^"]+)"')); return r ? r[1] : null; };
      const getK = (key) => { const r = opts.match(new RegExp(key + ':([^;)]+)')); return r ? r[1].trim() : null; };
      const has = (key) => opts.includes(key + ';') || opts.includes(key + ')');
      const sid = parseInt(getK('sid')) || (Math.floor(Math.random() * 1000000) + 9000000);
      db.run(SQL, [
        sid, action, proto, srcIp, srcPort, dir, dstIp, dstPort,
        get('msg') || 'Imported rule', getK('flow'), get('content'),
        has('http.uri') ? 1 : 0, has('http.method') ? 1 : 0,
        has('http.header') ? 1 : 0, has('http.request_body') ? 1 : 0,
        has('nocase') ? 1 : 0, get('pcre'),
        getK('classtype') || 'web-application-attack',
        parseInt(getK('rev')) || 1, parseInt(getK('priority')) || 2,
        1, 'imported', filename
      ], function(err) {
        if (err) console.error('Row error:', err.message);
        else if (this.changes > 0) imported++; else skipped++;
      });
    });
    console.log('Processed:', filename);
  });

  // Wait a moment then report and close
  setTimeout(() => {
    console.log('Imported:', imported, '| Skipped (duplicates):', skipped);
    db.close();
  }, 2000);
});
