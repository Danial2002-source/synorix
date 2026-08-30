# Synorix — VMware Homelab Setup & Simulation Guide

This guide provides an end-to-end tutorial on configuring and running the **Synorix Smart AI-Driven Proxy** system across VMware Virtual Machines for local simulation, testing, and FYP evaluation.

---

## 1. Network Topology & VM Architecture

The simulation environment uses a **3-VM Virtual Network** to recreate a realistic enterprise proxy deployment:

```
                               ┌──────────────────────────────────────────────┐
                               │           VMware Virtual Network (NAT)       │
                               │               Subnet: 192.168.100.0/24       │
                               └───────┬──────────────┬──────────────┬────────┘
                                       │              │              │
                     ┌─────────────────┘              │              └─────────────────┐
                     ▼                                ▼                                ▼
  ┌─────────────────────────────────────┐  ┌───────────────────────┐  ┌──────────────────────────────────┐
  │         VM 1: Security Proxy        │  │ VM 2: App & Dashboard │  │       VM 3: Client Machine       │
  │          (Ubuntu 22.04 LTS)         │  │   (Ubuntu 22.04 LTS)  │  │      (Windows 10/11 or Kali)     │
  │          IP: 192.168.100.10         │  │   IP: 192.168.100.20  │  │        IP: 192.168.100.30        │
  ├─────────────────────────────────────┤  ├───────────────────────┤  ├──────────────────────────────────┤
  │ • Go Security Proxy (:8080 / :443)  │  │ • Node.js Backend     │  │ • Web Browser (Chrome / Firefox) │
  │ • Python AI Service (:8082)         │  │   API (:3001)         │  │ • Proxy Config:                  │
  │ • Suricata IDS / IPS Engine         │  │ • React Dashboard     │  │   192.168.100.10:8080             │
  │ • Shared SQLite DB (synorix.db)     │  │   (:3000)             │  │ • Attack Scripts (cURL / k6)     │
  └─────────────────────────────────────┘  └───────────────────────┘  └──────────────────────────────────┘
```

---

## 2. Hardware & VM Specifications

| Virtual Machine | Operating System | RAM | vCPUs | Disk | Assigned Roles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VM 1 (Proxy & AI)** | Ubuntu 22.04 Server / Desktop | 4 GB | 2 | 25 GB | Go Proxy Core, XGBoost AI, Suricata IDS |
| **VM 2 (Backend & UI)** | Ubuntu 22.04 Desktop | 4 GB | 2 | 20 GB | Express API, SQLite Database, React UI |
| **VM 3 (Client / Test)** | Windows 10/11 or Kali Linux | 2–4 GB | 1–2 | 20 GB | Browser Proxying, cURL, Attack Simulation |

> **Network Mode**: Set all 3 VMs to **NAT (VMnet8)** or **Bridged**. Verify that `ping 192.168.100.10` succeeds from both VM 2 and VM 3.

---

## 3. Step-by-Step Installation

### 🖥️ Step A: Set Up VM 1 (Proxy, AI & Suricata)

1. **Install required packages**:
   ```bash
   sudo apt update && sudo apt install -y golang-go python3 python3-pip python3-venv suricata git curl sqlite3
   ```

2. **Clone the Synorix codebase**:
   ```bash
   sudo git clone https://github.com/Danial2002-source/synorix.git /opt/synorix
   sudo chown -R $USER:$USER /opt/synorix
   cd /opt/synorix
   ```

3. **Start the Python AI Inference Microservice (Port 8082)**:
   ```bash
   cd /opt/synorix/services/ai-compression-service
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 inference_service.py &
   ```
   *Verify it is running*:
   ```bash
   curl http://localhost:8082/health
   # Expected response: {"status":"healthy"}
   ```

4. **Build and start the Go Security Proxy (Port 8080)**:
   ```bash
   cd /opt/synorix/security-proxy
   bash generate-certs.sh
   go build -o synorix-proxy ./main.go
   ./synorix-proxy &
   ```

5. **Start Suricata Network Intrusion Detection**:
   ```bash
   sudo suricata -c /opt/synorix/services/suricata/suricata.yaml -i eth0 -D
   ```

---

### 🖥️ Step B: Set Up VM 2 (Backend API & React UI)

1. **Install Node.js 18+ and Git**:
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt install -y nodejs git
   ```

2. **Clone the codebase**:
   ```bash
   sudo git clone https://github.com/Danial2002-source/synorix.git /opt/synorix
   sudo chown -R $USER:$USER /opt/synorix
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
   JWT_SECRET=synorix_jwt_secure_secret_2026_key
   INTERNAL_API_TOKEN=synorix_shared_internal_token_32char
   ALLOWED_ORIGINS=http://192.168.100.20:3000,https://synorix.vercel.app
   SECURITY_PROXY_URL=http://192.168.100.10:8080
   ENABLE_BOOTSTRAP_ADMIN=true
   BOOTSTRAP_ADMIN_PASSWORD=Admin@Synorix2026!
   ```

5. **Start the Express API & React Dashboard**:
   ```bash
   # Start backend API (port 3001)
   npm run server &

   # Start frontend dashboard (port 3000)
   npm run dev -- --host 0.0.0.0 &
   ```

---

### 🖥️ Step C: Set Up VM 3 (Client Machine)

1. **Configure Browser Proxy**:
   * Open **Chrome / Firefox** Settings ➔ **Network Settings** ➔ **Manual Proxy Configuration**.
   * **HTTP Proxy**: `192.168.100.10` | **Port**: `8080`
   * **HTTPS Proxy**: `192.168.100.10` | **Port**: `8080`
   * Check *"Also use this proxy for HTTPS"*.

2. **Trust Root CA (for HTTPS Inspection)**:
   * Copy `security-proxy/certs/ca.crt` from VM 1 to VM 3.
   * On Windows: Double-click `ca.crt` ➔ Install Certificate ➔ Local Machine ➔ Place in **Trusted Root Certification Authorities**.

---

## 4. Testing & Presentation Demo Scenarios

Open the dashboard on **VM 3** at `http://192.168.100.20:3000` and log in (`admin` / `Admin@Synorix2026!`).

### Scenario 1: Normal Traffic & AI Compression
1. On VM 3, browse any text-heavy web page (e.g. `http://example.com` or API JSON endpoints).
2. Go to **Dashboard ➔ User Traffic Logs**:
   * Inspect the logged HTTP request.
   * Observe **Original Size vs Compressed Size** and the compression savings percentage calculated by the XGBoost model.

### Scenario 2: Web Application Firewall (WAF) SQL Injection Blocking
1. On VM 3, run in terminal:
   ```bash
   curl -x http://192.168.100.10:8080 "http://target.local/login?user=admin' OR 1=1--"
   ```
2. **Observation**:
   * The client receives `403 Forbidden` with a WAF block message.
   * The dashboard **Alert Management** tab instantly displays a **Critical SQL Injection** alert with the source IP (`192.168.100.30`).

### Scenario 3: Cross-Site Scripting (XSS) Attack Blocking
1. On VM 3, run in terminal:
   ```bash
   curl -x http://192.168.100.10:8080 "http://target.local/search?q=<script>alert('XSS')</script>"
   ```
2. **Observation**:
   * The client receives `403 Forbidden`.
   * The dashboard records an XSS attack attempt in the audit log.

### Scenario 4: Suricata Network Threat Detection
1. On VM 3, run a rapid port sweep or abnormal packet scan against VM 1:
   ```bash
   nmap -sS -p 80,443,8080,8082 192.168.100.10
   ```
2. **Observation**:
   * Suricata logs signatures to `eve.json`.
   * The alert appears in the **User Alerts / IDS Feed** view with network-layer details.

---

## 5. Quick Service Control Commands

| Service | Start Command | Check Status |
| :--- | :--- | :--- |
| **Python AI Engine** | `python3 inference_service.py &` | `curl http://localhost:8082/health` |
| **Go Security Proxy** | `./synorix-proxy &` | `curl http://localhost:8080/health` |
| **Express Backend** | `npm run server &` | `curl http://localhost:3001/api/auth/me` |
| **React Dashboard** | `npm run dev -- --host 0.0.0.0 &` | Access `http://<VM2_IP>:3000` |
| **Suricata IDS** | `sudo suricata -c suricata.yaml -i eth0 -D` | `ps aux \| grep suricata` |
