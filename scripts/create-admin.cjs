// Script to create default admin account
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const dbPath = path.resolve(__dirname, '..', 'server', 'synorix.db');
const db = new sqlite3.Database(dbPath);

const adminUsername = 'admin';
const adminEmail = 'admin@synorix.local';
const adminPassword = 'admin123'; // Change this after first login!

async function createAdmin() {
  try {
    // Check if admin exists
    const admin = await new Promise((resolve, reject) => {
      db.get("SELECT id FROM users WHERE role = 'admin' OR email = ?", [adminEmail], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (admin) {
      console.log('✅ Admin account already exists');
      db.close();
      return;
    }

    console.log('🔐 Creating default admin account...');
    
    // Hash password
    const hashedPassword = await bcrypt.hash(adminPassword, 12);
    
    // Create admin user
    const userId = await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        [adminUsername, adminEmail, hashedPassword, 'admin'],
        function(err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });

    // Create user config
    const apiKey = `syn_${crypto.randomBytes(32).toString('hex')}`;
    
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

    console.log('✅ Admin account created successfully!');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📧 Username: admin');
    console.log('📧 Email: admin@synorix.local');
    console.log('🔑 Password: admin123');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('⚠️  IMPORTANT: Change the password after first login!');
    console.log('🌐 Login at: http://localhost:5173/login');
    
    db.close();
  } catch (error) {
    console.error('❌ Error creating admin account:', error);
    db.close();
    process.exit(1);
  }
}

createAdmin();
