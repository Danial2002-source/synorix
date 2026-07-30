# Synorix Performance Testing - Quick Reference

## Overview
Comprehensive testing suite for WAF, Suricata IDS/IPS, AI Compression, and AI Deduplication features using k6 and Grafana.

## Quick Start

### YOUR SETUP
- WSL: 192.168.0.147:8080/user-proxy
- VM1: 192.168.0.160:9000
- VM2: 192.168.0.176:8000
- API: nxr_a851479c0184f6389b953c9dddd90390c22bcd00ab1c94981ba6f40eb23b97b1

### 1. Setup (WSL Ubuntu - One Time)
```bash
cd /home/asna/synorix/perf
chmod +x setup_testing.sh
./setup_testing.sh
```

### 2. Run from VMs (Recommended!)
```bash
# Copy to VM and run
chmod +x vm_quick_test.sh
./vm_quick_test.sh

# Or with custom settings
CONCURRENT_USERS=50 ./vm_quick_test.sh
```

### 3. View Results
Open browser: http://192.168.0.147:3000
- User: admin
- Pass: synorix-grafana-2026

### 3. Run Tests

#### From WSL (Full Suite)
```bash
cd /home/asna/synorix/perf
./run_comprehensive_tests.sh
```

#### From Kali VMs (Distributed Load)
```bash
# Copy vm_client_test.sh to VM
# Then on VM:
export WSL_IP="192.168.x.x"
export API_KEY="nxr_key"
export CONCURRENT_USERS=20
./vm_client_test.sh
```

## Test Types

| Type   | Duration | Users    | Purpose                    |
|--------|----------|----------|----------------------------|
| smoke  | 4 min    | 5-10     | Quick validation           |
| load   | 17 min   | 20-100   | Normal load simulation     |
| stress | 25 min   | 50-400   | Find breaking points       |
| spike  | 5 min    | 20-500   | Sudden traffic spike       |
| soak   | 30 min   | 80       | Sustained load, find leaks |

### Run Specific Test
```bash
export TEST_TYPE="load"  # or smoke, stress, spike, soak
./run_comprehensive_tests.sh
```

## Grafana Dashboard

**URL:** `http://<WSL_IP>:3000`
- Username: `admin`
- Password: `synorix-grafana-2026`

### Key Metrics Displayed
1. Concurrent Users
2. Request Duration (P95, P99)
3. Success Rate
4. Requests/sec
5. WAF Block Rate
6. IDS Detection Rate
7. Compression Ratio
8. Dedup Cache Hit Rate
9. Network Throughput
10. Feature Processing Times

## Files Structure

```
perf/
├── k6_comprehensive_test.js          # Main k6 test script
├── run_comprehensive_tests.sh         # WSL test orchestrator
├── vm_client_test.sh                  # VM client script
├── setup_testing.sh                   # One-time setup
├── docker-compose-monitoring.yml      # Monitoring stack
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/
│   │   │   └── datasources.yml
│   │   └── dashboards/
│   │       └── dashboards.yml
│   └── dashboards/
│       └── synorix-dashboard.json      # Main dashboard
├── prometheus/
│   └── prometheus.yml
└── results/
    └── run_<timestamp>/               # Test results
```

## Troubleshooting

### Cannot connect to WSL from VM
```bash
# On WSL, check IP
hostname -I

# On VM, test connectivity
curl http://<WSL_IP>:8080/health

# On Windows, allow ports (run PowerShell as Admin)
New-NetFirewallRule -DisplayName "WSL Proxy" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
```

### InfluxDB not receiving data
```bash
# Check InfluxDB
docker ps | grep influxdb
curl http://localhost:8086/health

# Check logs
docker logs synorix-influxdb
```

### Grafana shows no data
1. Check time range (top right corner)
2. Verify InfluxDB datasource in Settings
3. Ensure tests are running with InfluxDB output:
   ```bash
   --out influxdb=http://localhost:8086/k6
   ```

## Performance Targets

### Normal Load (50-100 users)
- ✓ P95 Response Time: < 500ms
- ✓ P99 Response Time: < 1000ms
- ✓ Success Rate: > 99%
- ✓ RPS: 200-500
- ✓ WAF Block Rate: > 90%
- ✓ Compression Ratio: > 40%
- ✓ Dedup Hit Rate: > 60%

### Stress Load (200-400 users)
- ✓ P95 Response Time: < 2000ms
- ✓ Success Rate: > 95%
- ✓ System remains stable

## Advanced Usage

### Distributed Load Test
Run simultaneously from all locations:

**WSL Terminal:**
```bash
export TEST_TYPE="stress"
./run_comprehensive_tests.sh
```

**VM1 Terminal:**
```bash
export CONCURRENT_USERS=30
./vm_client_test.sh
```

**VM2 Terminal:**
```bash
export CONCURRENT_USERS=25
./vm_client_test.sh
```

Total: ~155 concurrent users

### Custom Test Duration
```bash
# On VMs
export TEST_DURATION=600  # 10 minutes
./vm_client_test.sh
```

### View Test Results
```bash
# Latest run
ls -lt perf/results/

# View summary
cat perf/results/run_*/README.md

# Compare metrics
jq '.' perf/results/run_*/baseline/compression_before.json
jq '.' perf/results/run_*/post/compression_after.json
```

## Monitoring Stack Management

### Start
```bash
docker-compose -f perf/docker-compose-monitoring.yml up -d
```

### Stop
```bash
docker-compose -f perf/docker-compose-monitoring.yml down
```

### Restart
```bash
docker-compose -f perf/docker-compose-monitoring.yml restart
```

### View Logs
```bash
docker logs synorix-influxdb
docker logs synorix-grafana
docker logs synorix-prometheus
```

## Export Results

### Export Grafana Dashboard
1. Open dashboard
2. Click Share icon
3. Export → Save to file
4. Commit to git

### Export Test Data
```bash
# Create archive of test run
tar -czf test_results_$(date +%Y%m%d).tar.gz perf/results/run_*
```

## Metrics Reference

| Metric | Description | Good Value |
|--------|-------------|------------|
| http_req_duration | Total request time | P95 < 1000ms |
| http_req_waiting | Time to first byte | P95 < 500ms |
| http_req_blocked | Time blocked by WAF | P95 < 100ms |
| waf_block_rate | % of blocked requests | > 90% for attacks |
| compression_ratio | Compression savings | > 40% |
| dedup_cache_hit_rate | Cache hit percentage | > 60% |
| success_rate | Successful requests | > 99% |

## Environment Variables

### WSL
```bash
export WSL_IP="auto-detected"
export API_KEY="nxr_..."
export PROXY_URL="http://${WSL_IP}:8080"
export BACKEND_URL="http://${WSL_IP}:3001"
export TEST_TYPE="load"  # smoke|load|stress|spike|soak|all
```

### VM
```bash
export WSL_IP="192.168.x.x"
export API_KEY="nxr_..."
export PROXY_URL="http://${WSL_IP}:8080"
export CONCURRENT_USERS=20
export TEST_DURATION=300
```

## Support

For detailed instructions, see [TESTING_GUIDE.md](../TESTING_GUIDE.md)

---
**Version:** 1.0  
**Last Updated:** May 2026
