// Script to seed default admin and test user accounts with pre-configured applications
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const dbPath = path.resolve(__dirname, '..', 'server', 'synorix.db');
const db = new sqlite3.Database(dbPath);

const usersToSeed = [
  {
    username: 'admin',
    email: 'admin@synorix.local',
    password: 'admin123',
    role: 'admin',
    appName: 'Synorix Management Gateway',
    backendUrl: 'http://localhost:3001',
    description: 'System Administrative Gateway'
  },
  {
    username: 'daniyal',
    email: 'daniyal@synorix.local',
    password: 'user123',
    role: 'user',
    appName: 'E-Commerce Production API',
    backendUrl: 'http://192.168.100.20:3000',
    description: 'High-traffic customer shopping API with WAF protection'
  },
  {
    username: 'hamnah',
    email: 'hamnah@synorix.local',
    password: 'user123',
    role: 'user',
    appName: 'Security Audit Portal',
    backendUrl: 'http://localhost:5000',
    description: 'Internal vulnerability & audit management web app'
  },
  {
    username: 'testuser',
    email: 'testuser@synorix.local',
    password: 'user123',
    role: 'user',
    appName: 'Corporate Blog & CMS',
    backendUrl: 'http://localhost:8081',
    description: 'WordPress / CMS blog monitored by Synorix proxy'
  }
];

function runQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function getQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

async function seedDatabase() {
  try {
    console.log('🚀 Checking SQLite tables...');

    // Create tables if not existing
    await runQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await runQuery(`
      CREATE TABLE IF NOT EXISTS user_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        backend_url TEXT DEFAULT '',
        proxy_api_key TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await runQuery(`
      CREATE TABLE IF NOT EXISTS user_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        app_name TEXT NOT NULL,
        backend_url TEXT NOT NULL,
        proxy_api_key TEXT UNIQUE NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    console.log('👥 Seeding users into database...');

    for (const u of usersToSeed) {
      const existing = await getQuery("SELECT id, username, role FROM users WHERE username = ? OR email = ?", [u.username, u.email]);
      
      let userId;
      if (existing) {
        userId = existing.id;
        console.log(`ℹ️  User '${u.username}' already exists (ID: ${userId}, Role: ${existing.role})`);
      } else {
        const hashedPassword = await bcrypt.hash(u.password, 10);
        const result = await runQuery(
          'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
          [u.username, u.email, hashedPassword, u.role]
        );
        userId = result.lastID;
        console.log(`✅ Created User '${u.username}' (Role: ${u.role}, Password: ${u.password})`);
      }

      // Ensure user_config exists
      const config = await getQuery("SELECT id, proxy_api_key FROM user_configs WHERE user_id = ?", [userId]);
      let apiKey;
      if (!config) {
        apiKey = `syn_${crypto.randomBytes(24).toString('hex')}`;
        await runQuery(
          'INSERT INTO user_configs (user_id, backend_url, proxy_api_key) VALUES (?, ?, ?)',
          [userId, u.backendUrl, apiKey]
        );
      } else {
        apiKey = config.proxy_api_key;
      }

      // Ensure user_applications has an application
      const app = await getQuery("SELECT id FROM user_applications WHERE user_id = ? AND app_name = ?", [userId, u.appName]);
      if (!app) {
        const appApiKey = `syn_app_${crypto.randomBytes(20).toString('hex')}`;
        await runQuery(
          'INSERT INTO user_applications (user_id, app_name, backend_url, proxy_api_key, description) VALUES (?, ?, ?, ?, ?)',
          [userId, u.appName, u.backendUrl, appApiKey, u.description]
        );
        console.log(`   📦 Attached Application: '${u.appName}' -> ${u.backendUrl}`);
      }
    }

    console.log('\n✨ Database seeding completed successfully!\n');
    console.log('---------------------------------------------------------');
    console.log('📋 AVAILABLE TEST ACCOUNTS:');
    console.log('---------------------------------------------------------');
    console.log('1. Admin:    Username: admin    | Password: admin123 | Role: admin');
    console.log('2. User 1:   Username: daniyal  | Password: user123  | Role: user');
    console.log('3. User 2:   Username: hamnah   | Password: user123  | Role: user');
    console.log('4. User 3:   Username: testuser | Password: user123  | Role: user');
    console.log('---------------------------------------------------------\n');

  } catch (err) {
    console.error('❌ Error during seeding:', err);
  } finally {
    db.close();
  }
}

seedDatabase();
