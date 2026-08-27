# Synorix — Presentation & Live Demonstration Script

This script provides a step-by-step roadmap for presenting Synorix during your FYP orientation / evaluation session using your 3-VM homelab.

---

## 📋 Pre-Demo Checklist (10 Minutes Before Presentation)

- [ ] **VM 1 (Proxy & AI)**:
  - `inference_service.py` is running on port `8082`.
  - `synorix-proxy` is running on port `8080`.
  - Suricata daemon is active on network interface.
- [ ] **VM 2 (Backend & UI)**:
  - Express API is running on port `3001`.
  - React Vite server (or Nginx) is running on port `3000`.
- [ ] **VM 3 (Client)**:
  - Proxy configured to `VM1_IP:8080`.
  - Dashboard opened in browser (`http://VM2_IP:3000` or `https://synorix.vercel.app`).
  - Terminal open for attack simulations.

---

## ⏱️ Minute-by-Minute Presentation Walkthrough

### 00:00 – 03:00 | Introduction & Problem Statement
* **Speaker**: Introduce the project title: **Synorix — Smart AI-Driven Reverse Proxy with Integrated Threat Detection & Optimization**.
* **Talking Points**:
  * Traditional proxies (Nginx, HAProxy) separate security from traffic optimization.
  * In modern networks, uncompressed redundant payloads waste bandwidth, while security tools (WAF/IDS) often add significant latency.
  * **Synorix Solution**: A unified defense-in-depth architecture combining AI-assisted compression/deduplication, application-layer WAF, and network-layer Suricata IDS.

### 03:00 – 06:00 | Architecture & Technology Overview
* **Show Diagram**: Point out the 3 layers:
  1. **Go Security Proxy**: High-performance TLS termination, regex WAF, and routing.
  2. **Python AI Inference Microservice**: Sub-10ms XGBoost binary classification.
  3. **React + Node.js Management Dashboard**: Real-time traffic observability, rule management, and security alerts.

### 06:00 – 10:00 | Live Demo: Normal Traffic & AI Compression
* **Action**: On VM 3, open the browser and access a test web application through the proxy.
* **Show Dashboard**:
  * Open **User Traffic Logs**.
  * Point out the live request entries, latency metrics, and **Compression Savings**.
  * Highlight: *"The XGBoost model analyzes payload characteristics in <10ms and dynamically compresses responses, achieving up to 90%+ size reduction."*

### 10:00 – 14:00 | Live Demo: Security Defense (WAF & IDS Blocking)
* **Scenario A — Application Attack (SQL Injection)**:
  * In the VM 3 terminal, execute an SQLi payload:
    ```bash
    curl -x http://<VM1_IP>:8080 "http://target.local/login?user=admin' OR 1=1--"
    ```
  * **Result**: Show HTTP `403 Forbidden` response.
  * **Dashboard**: Switch to **Alert Management** to show the real-time WAF alert with attack type, timestamp, and source IP.
* **Scenario B — Network Anomaly (Suricata IDS)**:
  * Show Suricata event correlation in the security feed detecting port scans / anomaly thresholds.

### 14:00 – 17:00 | Admin Observability & Multi-Tenancy
* **Action**: Tour the Admin Dashboard:
  * User management & API key provisioning.
  * WAF rule activation / deactivation toggles.
  * Overall system health and traffic throughput metrics.

### 17:00 – 20:00 | FYP Phase 2 Roadmap & Q&A
* **Talking Points for Phase 2 (Ongoing Final FYP Work)**:
  * Transition from passive IDS to inline active IPS packet dropping.
  * Physical Redis RAM caching layer for content deduplication.
  * Model retraining using 10,000+ collected proxy traffic logs.
* **Q&A**: Open the floor to faculty questions.
