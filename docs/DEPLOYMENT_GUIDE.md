# Synorix — VMware Homelab Setup & Deployment Guide

This guide explains how to set up and run the entire Synorix Smart AI-Driven Proxy system across VMware Virtual Machines for local homelab demonstration and FYP evaluation.

---

## 1. Homelab Architecture & VM Topology

To mirror enterprise proxy environments and match your demo presentation, we configure **3 Virtual Machines**:

```
                               ┌──────────────────────────────────────────────┐
                               │             VMware Virtual Network            │
                               │               (Bridged or NAT)               │
                               └───────┬──────────────┬──────────────┬────────┘
                                       │              │              │
                     ┌─────────────────┘              │              └─────────────────┐
                     ▼                                ▼                                ▼
  ┌─────────────────────────────────────┐  ┌───────────────────────┐  ┌──────────────────────────────────┐
  │         VM 1: Security Proxy        │  │ VM 2: App & Dashboard │  │       VM 3: Client Machine       │
  │          (Ubuntu 22.04 LTS)         │  │   (Ubuntu 22.04 LTS)  │  │        (Windows or Ubuntu)       │
  │             IP: 192.168.1.10        │  │    IP: 192.168.1.20   │  │          IP: 192.168.1.30        │
  ├─────────────────────────────────────┤  ├───────────────────────┤  ├──────────────────────────────────┤
  │ • Go Security Proxy (:8080 / :443)  │  │ • Node.js Backend     │  │ • Web Browser (Chrome / Firefox) │
  │ • Python AI Service (:8082)         │  │   API (:3001)         │  │ • Proxy Settings:                │
  │ • Suricata IDS / IPS Engine         │  │ • React Dashboard     │  │   192.168.1.10:8080             │
  │ • Shared SQLite DB (synorix.db)     │  │   (:3000 or Nginx)    │  │ • Kali / Test Scripts (Attacks)  │
  └─────────────────────────────────────┘  └───────────────────────┘  └──────────────────────────────────┘
```

---

## 2. Hardware & Network Prerequisites

* **VMware Workstation Pro / Player** (or ESXi / VirtualBox).
* **VM Specifications**:
  * **VM 1 (Proxy & Security)**: Ubuntu 22.04 LTS — 4 GB RAM, 2 vCPUs, 20 GB Disk.
  * **VM 2 (Backend & UI)**: Ubuntu 22.04 LTS — 4 GB RAM, 2 vCPUs, 20 GB Disk.
  * **VM 3 (Client / Attacker)**: Windows 10/11 or Ubuntu/Kali — 2–4 GB RAM, 1–2 vCPUs.
* **Network Mode**: **Bridged Network** (or **Host-Only / NAT** if offline). Ensure all 3 VMs can `ping` each other.

---

## 3. Step-by-Step Installation & Configuration

### Step A: Configure VM 1 (Proxy, AI & Suricata)

1. **Install Prerequisites**:
   ```bash
   sudo apt update && sudo apt install -y golang-go python3 python3-pip python3-venv suricata git curl sqlite3
   ```

2. **Clone / Copy Synorix Repository**:
   ```bash
   git clone https://github.com/Danial2002-source/synorix.git /opt/synorix
   cd /opt/synorix
   ```

3. **Set Up Python AI Inference Service**:
   ```bash
   cd /opt/synorix/services/ai-compression-service
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   # Start AI Service on port 8082 in background or tmux:
   python3 inference_service.py &
   ```

4. **Build & Configure Go Security Proxy**:
   ```bash
   cd /opt/synorix/security-proxy
   # Generate TLS certificates for HTTPS termination:
   bash generate-certs.sh
   # Build the Go binary:
   go build -o synorix-proxy ./main.go
   # Run the proxy:
   ./synorix-proxy &
   ```

5. **Start Suricata IDS**:
   ```bash
   sudo suricata -c /opt/synorix/services/suricata/suricata.yaml -i eth0 -D
   ```

---

### Step B: Configure VM 2 (Node.js Backend & React Dashboard)

1. **Install Node.js 18+ & NPM**:
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt install -y nodejs
   ```

2. **Clone / Copy Repository**:
   ```bash
   git clone https://github.com/Danial2002-source/synorix.git /opt/synorix
   cd /opt/synorix
   ```

3. **Install Dependencies**:
   ```bash
   npm install
   cd server && npm install && cd ..
   ```

4. **Configure Environment Variables**:
   Create `/opt/synorix/.env`:
   ```env
   NODE_ENV=production
   PORT=3001
   JWT_SECRET=super_secret_synorix_jwt_key_2026
   INTERNAL_API_TOKEN=synorix_shared_internal_token_32char
   ALLOWED_ORIGINS=http://192.168.1.20:3000,https://synorix.vercel.app
   SECURITY_PROXY_URL=http://192.168.1.10:8080
   ENABLE_BOOTSTRAP_ADMIN=true
   BOOTSTRAP_ADMIN_PASSWORD=Admin@Synorix2026!
   ```

5. **Start Backend & Frontend**:
   ```bash
   # Start Express Backend on port 3001:
   npm run server &

   # Start Vite Dashboard on port 3000:
   npm run dev -- --host 0.0.0.0 &
   ```

---

### Step C: Configure VM 3 (Client / Testing Machine)

1. **Configure Browser Proxy**:
   * Open **Chrome / Firefox** Settings → **Network / Proxy**.
   * Select **Manual Proxy Configuration**:
     * **HTTP Proxy**: `192.168.1.10` | **Port**: `8080`
     * **HTTPS Proxy**: `192.168.1.10` | **Port**: `8080`
   * Check *"Also use this proxy for HTTPS"*.

2. **Trust Self-Signed CA (for HTTPS inspection)**:
   * Copy `security-proxy/certs/ca.crt` from VM 1 to VM 3.
   * Import it into Trusted Root Certification Authorities.

---

## 4. How to Verify & Demonstrate Locally

1. **Dashboard Access**:
   * Open `http://192.168.1.20:3000` (or `https://synorix.vercel.app`) in the browser.
   * Log in with `admin` / `Admin@Synorix2026!`.

2. **Test Normal Traffic & Compression**:
   * On VM 3, browse websites through the proxy.
   * Check **Traffic Monitor** on the dashboard to see real-time HTTP requests, response times, and AI compression ratio savings (>90% on text payloads).

3. **Test WAF Blocking (SQL Injection & XSS)**:
   * From VM 3 terminal or browser, execute:
     ```bash
     curl -x http://192.168.1.10:8080 "http://example.com/login?user=admin' OR '1'='1"
     ```
   * **Result**: Proxy immediately blocks with `403 Forbidden` and logs a Critical WAF alert on the dashboard.

4. **Test Suricata IDS Threat Detection**:
   * Run test attack scans or payloads from VM 3.
   * Check the **Alert Management / User Alerts** screen to see Suricata signature triggers mapped by IP and severity.
