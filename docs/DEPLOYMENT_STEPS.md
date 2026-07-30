# Synorix Deployment Guide - Customized for Your Setup

## Current Setup Analysis
- **Local Path**: `/home/asna/synorix/`
- **Database**: `/home/asna/synorix/server/synorix.db` (804KB with existing data)
- **Components**: Frontend (React), Backend (Node.js), Security Proxy (Go), Suricata IDS, AI Service (Python)

---

## Step 1: Prepare Your Server (DigitalOcean Droplet)

### Create Droplet (if not done)
1. Go to DigitalOcean Dashboard
2. Create Droplet:
   - **OS**: Ubuntu 22.04 LTS
   - **Size**: Minimum 4GB RAM, 2 vCPUs (for all services)
   - **Datacenter**: Choose closest to your location
3. Note your **Droplet IP Address**: `YOUR_DROPLET_IP`

### Initial Server Setup
```bash
# SSH into your droplet (from your laptop)
ssh root@YOUR_DROPLET_IP

# Update system
apt update && apt upgrade -y

# Install required packages
apt install -y nodejs npm git curl build-essential python3 python3-pip golang-go

# Create synorix directory
mkdir -p /opt/synorix

# Exit for now
exit
```

---

## Step 2: Upload Code + Database

### A. Upload Your Codebase
```bash
# FROM YOUR LAPTOP (in /home/asna directory)
rsync -avz --progress \
  --exclude node_modules \
  --exclude .venv \
  --exclude "*.db" \
  --exclude .git \
  --exclude test-results \
  --exclude logs \
  /home/asna/synorix/ root@YOUR_DROPLET_IP:/opt/synorix/
```

**What this does:**
- Syncs all code files to server
- Skips node_modules (will be installed on server)
- Skips Python virtual env (will be created on server)
- Skips database (uploaded separately next)
- Skips Git history and test files
- Shows progress with `--progress`

### B. Upload Database with All Users/Data
```bash
# Upload your database (contains all users, rules, alerts)
scp /home/asna/synorix/server/synorix.db \
  root@YOUR_DROPLET_IP:/opt/synorix/server/synorix.db
```

**Important**: This preserves all your:
- User accounts and credentials
- Security rules
- Alert configurations
- Historical data

---

## Step 3: Install Dependencies on Server

```bash
# SSH back into server
ssh root@YOUR_DROPLET_IP

# Navigate to project
cd /opt/synorix

# Install Node.js dependencies
cd /opt/synorix/server
npm install

cd /opt/synorix
npm install

# Install Python dependencies
cd /opt/synorix/ai-compression-service
pip3 install -r requirements.txt

# Build Go security proxy
cd /opt/synorix/security-proxy
go build -o security-proxy

# Set permissions
chmod +x /opt/synorix/security-proxy/security-proxy
chmod +x /opt/synorix/test_all_services.sh
```

---

## Step 4: Configure Environment Variables

```bash
# Create environment file
cat > /opt/synorix/server/.env << 'EOF'
NODE_ENV=production
JWT_SECRET=$(openssl rand -base64 32)
PORT=3001
DB_PATH=/opt/synorix/server/synorix.db
EOF

# For Security Proxy
cat > /opt/synorix/security-proxy/.env << 'EOF'
DB_PATH=/opt/synorix/server/synorix.db
DATA_DIR=/opt/synorix/security-proxy/data
EOF
```

---

## Step 5: Setup Systemd Services

### A. Backend API Service
```bash
cat > /etc/systemd/system/synorix-backend.service << 'EOF'
[Unit]
Description=Synorix Backend API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/synorix/server
Environment="NODE_ENV=production"
Environment="PORT=3001"
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

### B. Security Proxy Service
```bash
cat > /etc/systemd/system/synorix-proxy.service << 'EOF'
[Unit]
Description=Synorix Security Proxy
After=network.target synorix-backend.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/synorix/security-proxy
Environment="DB_PATH=/opt/synorix/server/synorix.db"
Environment="DATA_DIR=/opt/synorix/security-proxy/data"
ExecStart=/opt/synorix/security-proxy/security-proxy
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

### C. AI Service
```bash
cat > /etc/systemd/system/synorix-ai.service << 'EOF'
[Unit]
Description=Synorix AI Compression Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/synorix/ai-compression-service
ExecStart=/usr/bin/python3 inference_service.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

### D. Enable and Start All Services
```bash
systemctl daemon-reload
systemctl enable synorix-backend synorix-proxy synorix-ai
systemctl start synorix-backend synorix-proxy synorix-ai

# Check status
systemctl status synorix-backend
systemctl status synorix-proxy
systemctl status synorix-ai
```

---

## Step 6: Configure Firewall

```bash
# Enable UFW firewall
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 3001/tcp  # Backend API
ufw allow 8080/tcp  # Security Proxy
ufw --force enable

# Check status
ufw status
```

---

## Step 7: Setup Nginx Reverse Proxy (Optional but Recommended)

```bash
# Install Nginx
apt install -y nginx

# Create Nginx config
cat > /etc/nginx/sites-available/synorix << 'EOF'
server {
    listen 80;
    server_name YOUR_DOMAIN_OR_IP;

    # Frontend
    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # Backend API
    location /api/ {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

# Enable site
ln -s /etc/nginx/sites-available/synorix /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

---

## Step 8: Verify Deployment

```bash
# Check all services are running
systemctl status synorix-backend synorix-proxy synorix-ai

# Test backend API
curl http://localhost:3001/api/rules

# Check logs
journalctl -u synorix-backend -n 50
journalctl -u synorix-proxy -n 50
journalctl -u synorix-ai -n 50
```

---

## Step 9: Setup SSL (HTTPS) with Let's Encrypt

```bash
# Install certbot
apt install -y certbot python3-certbot-nginx

# Get SSL certificate (replace with your domain)
certbot --nginx -d your-domain.com

# Auto-renewal is configured automatically
```

---

## 📊 Post-Deployment Checklist

- [ ] All systemd services running
- [ ] Database has existing users (test login)
- [ ] API endpoints responding
- [ ] Security proxy blocking attacks
- [ ] AI service processing requests
- [ ] Logs being generated
- [ ] Firewall configured
- [ ] SSL certificate installed (if using domain)
- [ ] Backup strategy configured

---

## 🔄 Updating Code After Deployment

When you make changes locally and want to update the server:

```bash
# 1. Sync code changes
rsync -avz --progress \
  --exclude node_modules \
  --exclude .venv \
  --exclude "*.db" \
  --exclude .git \
  /home/asna/synorix/ root@YOUR_DROPLET_IP:/opt/synorix/

# 2. SSH to server and restart services
ssh root@YOUR_DROPLET_IP
systemctl restart synorix-backend synorix-proxy synorix-ai
```

---

## 🗄️ Database Backup Strategy

```bash
# On server, create backup script
cat > /opt/synorix/backup-db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR=/opt/synorix/backups
mkdir -p $BACKUP_DIR
DATE=$(date +%Y%m%d_%H%M%S)
cp /opt/synorix/server/synorix.db $BACKUP_DIR/synorix_$DATE.db
# Keep only last 7 backups
ls -t $BACKUP_DIR/synorix_*.db | tail -n +8 | xargs rm -f
EOF

chmod +x /opt/synorix/backup-db.sh

# Add to crontab (daily backup at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/synorix/backup-db.sh") | crontab -
```

---

## 🆘 Troubleshooting

### Services Won't Start
```bash
# Check logs
journalctl -u synorix-backend -xe
journalctl -u synorix-proxy -xe

# Check ports
netstat -tulpn | grep -E '3001|8080'
```

### Database Errors
```bash
# Verify database exists and has correct permissions
ls -lh /opt/synorix/server/synorix.db
sqlite3 /opt/synorix/server/synorix.db "SELECT COUNT(*) FROM users;"
```

### Can't Connect from Outside
```bash
# Check firewall
ufw status verbose

# Check if service is listening on all interfaces (not just localhost)
ss -tlnp | grep -E '3001|8080'
```

---

## 📝 Access Your Deployed Application

- **Frontend**: `http://YOUR_DROPLET_IP:8080`
- **Backend API**: `http://YOUR_DROPLET_IP:3001/api`
- **With Domain + SSL**: `https://your-domain.com`

**Login with your existing database users!**

---

## 🎓 FYP Presentation Points

✅ **Multi-component Architecture**: Frontend, Backend, WAF, IDS, AI
✅ **Production-Ready Deployment**: Systemd services, auto-restart
✅ **Security**: Firewall, SSL, rate limiting, authentication
✅ **Data Persistence**: SQLite with backup strategy
✅ **Scalability**: Can migrate to PM2 cluster mode
✅ **Monitoring**: Systemd logs, health checks

Good luck with your FYP! 🚀
