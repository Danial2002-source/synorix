"""
Suricata Integration Service for Synorix Security Infrastructure
Provides real-time IDS/IPS alerts and statistics via REST API
"""

import json
import asyncio
import aiofiles
import uvicorn
import logging
import datetime
import os
import time
import subprocess
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, deque, Counter
from pathlib import Path

from urllib.parse import unquote_plus
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SuricataAlert:
    """Data class for Suricata alerts"""
    timestamp: str
    flow_id: int
    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    proto: str
    alert: Dict[str, Any]
    severity: int = 3
    category: str = "unknown"
    
class SuricataStats:
    """Statistics collector for Suricata events"""
    
    def __init__(self, max_alerts: int = 1000):
        self.max_alerts = max_alerts
        self.recent_alerts = deque(maxlen=max_alerts)
        self.stats = {
            "total_alerts": 0,
            "alerts_by_severity": defaultdict(int),
            "alerts_by_category": defaultdict(int),
            "top_source_ips": Counter(),
            "top_signatures": Counter(),
            "protocols": defaultdict(int),
            "last_update": None
        }
        self.start_time = time.time()
    
    def add_alert(self, alert: SuricataAlert):
        """Add an alert to statistics"""
        self.recent_alerts.append(alert)
        self.stats["total_alerts"] += 1
        self.stats["alerts_by_severity"][alert.severity] += 1
        self.stats["alerts_by_category"][alert.category] += 1
        self.stats["top_source_ips"][alert.src_ip] += 1
        self.stats["protocols"][alert.proto] += 1
        
        if "signature" in alert.alert:
            self.stats["top_signatures"][alert.alert["signature"]] += 1
        
        self.stats["last_update"] = datetime.datetime.utcnow().isoformat()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get statistics summary"""
        uptime = time.time() - self.start_time
        
        return {
            "uptime_seconds": int(uptime),
            "total_alerts": self.stats["total_alerts"],
            "recent_alerts_count": len(self.recent_alerts),
            "alerts_by_severity": dict(self.stats["alerts_by_severity"]),
            "alerts_by_category": dict(self.stats["alerts_by_category"]),
            "top_source_ips": dict(list(self.stats["top_source_ips"].most_common(10))),
            "top_signatures": dict(list(self.stats["top_signatures"].most_common(10))),
            "protocols": dict(self.stats["protocols"]),
            "last_update": self.stats["last_update"],
            "alerts_per_hour": self.stats["total_alerts"] / max(uptime / 3600, 1)
        }

class SuricataLogParser:
    """Parser for Suricata EVE JSON logs"""
    
    def __init__(self, log_file: str, label: str = "ids"):
        self.log_file = log_file
        self.label = label  # "ids" or "ips"
        # Start at end-of-file so only alerts written AFTER this service starts
        # are processed. Without this, every restart replays the entire eve.json
        # and floods the database with duplicate historical alerts.
        try:
            with open(log_file, 'r') as f:
                f.seek(0, 2)  # Seek to end
                self.last_position = f.tell()
            logger.info(f"[{label.upper()}] Log parser initialised at position {self.last_position} (end of existing file)")
        except (FileNotFoundError, OSError) as e:
            logger.warning(f"[{label.upper()}] Could not access log file {log_file}: {e}")
            self.last_position = 0
        
    async def parse_alert(self, line: str) -> Optional[SuricataAlert]:
        """Parse a single EVE JSON line into SuricataAlert"""
        try:
            data = json.loads(line.strip())
            
            # Only process alert events
            if data.get("event_type") != "alert":
                return None
            
            alert_data = data.get("alert", {})
            src_ip = data.get("src_ip", "unknown")
            dest_ip = data.get("dest_ip", "unknown")
            
            # Determine severity and category
            severity = alert_data.get("severity", 3)
            category = alert_data.get("category", "unknown")
            
            return SuricataAlert(
                timestamp=data.get("timestamp", datetime.datetime.utcnow().isoformat()),
                flow_id=data.get("flow_id", 0),
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_port=data.get("src_port", 0),
                dest_port=data.get("dest_port", 0),
                proto=data.get("proto", "unknown"),
                alert=alert_data,
                severity=severity,
                category=category
            )
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Failed to parse alert: {e}")
            return None
    
    async def tail_logs(self):
        """Generator to tail log file and yield new alerts"""
        if not os.path.exists(self.log_file):
            logger.warning(f"Log file {self.log_file} does not exist yet")
            return
        
        try:
            # Handle file truncation (e.g. after log rotation or manual truncate)
            file_size = os.path.getsize(self.log_file)
            if file_size < self.last_position:
                logger.info(f"Log file was truncated ({self.last_position} -> {file_size}), resetting position to 0")
                self.last_position = 0

            async with aiofiles.open(self.log_file, 'r') as f:
                # Seek to last position
                await f.seek(self.last_position)
                
                async for line in f:
                    alert = await self.parse_alert(line)
                    if alert:
                        yield alert
                
                # Update position
                self.last_position = await f.tell()
                
        except FileNotFoundError:
            logger.warning(f"Log file {self.log_file} not found")
        except Exception as e:
            logger.error(f"Error reading log file: {e}")

class SuricataIntegrationService:
    """Main service for Suricata integration"""
    
    def __init__(self):
        self.app = FastAPI(title="Suricata Integration Service", version="1.0.0")
        self.stats = SuricataStats()

        # IDS: passive — reads copy of packets via AF_PACKET, writes alerts action="alert"
        ids_log = os.getenv("IDS_LOG", "/var/log/suricata/ids/eve.json")
        # IPS: inline — drops packets via NFQUEUE, writes alerts with action="drop"
        ips_log = os.getenv("IPS_LOG", "/var/log/suricata/ips/eve.json")

        self.ids_parser = SuricataLogParser(ids_log, label="ids")
        self.ips_parser = SuricataLogParser(ips_log, label="ips")

        self.websocket_connections: List[WebSocket] = []
        self.security_proxy_url: str = os.getenv("SECURITY_PROXY_URL", "http://localhost:8080")
        self.backend_url: str = os.getenv("BACKEND_URL", "http://localhost:3001")
        self.internal_api_token: str = os.getenv("INTERNAL_API_TOKEN", "")
        
        # Alert aggregation: batch alerts from same source within time window
        self.pending_alerts: Dict[str, List[SuricataAlert]] = defaultdict(list)
        self.alert_batch_time = 2.0  # seconds - aggregate alerts within this window
        self.last_flush_time: Dict[str, float] = {}
        # In-memory dedup cache: (src_ip, sig_id) → last_sent epoch; skip if within 5 min
        self._dedup_cache: Dict[tuple, float] = {}
        # Global per-signature rate limit: sig_id → last_sent epoch; max 1 per 30 min per sig
        self._sig_global_cache: Dict[int, float] = {}
        
        self.setup_routes()
        self.setup_middleware()
    
    def setup_middleware(self):
        """Setup CORS and other middleware"""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # In production, specify exact origins
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    def setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/")
        async def root():
            return {"service": "Suricata Integration", "status": "running"}
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            try:
                result = subprocess.run(["pgrep", "-f", "suricata.*-c"],
                                      capture_output=True, text=True)
                suricata_running = result.returncode == 0

                ids_log = self.ids_parser.log_file
                ips_log = self.ips_parser.log_file
                ids_exists = os.path.exists(ids_log)
                ips_exists = os.path.exists(ips_log)

                return {
                    "status": "healthy" if suricata_running else "degraded",
                    "suricata_running": suricata_running,
                    "ids_log_exists": ids_exists,
                    "ids_log_size_bytes": os.path.getsize(ids_log) if ids_exists else 0,
                    "ips_log_exists": ips_exists,
                    "ips_log_size_bytes": os.path.getsize(ips_log) if ips_exists else 0,
                    "timestamp": datetime.datetime.utcnow().isoformat()
                }
            except Exception as e:
                raise HTTPException(status_code=503, detail=f"Health check failed: {e}")
        
        @self.app.get("/stats")
        async def get_stats():
            """Get Suricata statistics"""
            return self.stats.get_summary()
        
        @self.app.get("/alerts")
        async def get_alerts(limit: int = 100, severity: Optional[int] = None):
            """Get recent alerts"""
            alerts = list(self.stats.recent_alerts)
            
            # Filter by severity if specified
            if severity is not None:
                alerts = [a for a in alerts if a.severity <= severity]
            
            # Apply limit
            alerts = alerts[-limit:] if limit > 0 else alerts
            
            return {
                "alerts": [asdict(alert) for alert in alerts],
                "total": len(alerts)
            }
        
        @self.app.post("/reload-rules")
        async def reload_rules():
            """Reload Suricata rules"""
            try:
                # Send USR2 signal to Suricata for rule reload
                subprocess.run(["pkill", "-USR2", "suricata"], check=True)
                return {"status": "success", "message": "Rules reloaded"}
            except subprocess.CalledProcessError as e:
                raise HTTPException(status_code=500, detail=f"Failed to reload rules: {e}")
        
        @self.app.get("/config")
        async def get_config():
            """Get Suricata configuration status"""
            rules_dir = Path(__file__).resolve().parent.parent / "rules"
            try:
                rules_count = len(list(rules_dir.glob("*.rules"))) if rules_dir.exists() else 0
                return {
                    "ids_log_file": self.ids_parser.log_file,
                    "ids_log_exists": os.path.exists(self.ids_parser.log_file),
                    "ips_log_file": self.ips_parser.log_file,
                    "ips_log_exists": os.path.exists(self.ips_parser.log_file),
                    "rules_directory": rules_dir,
                    "rules_files_count": rules_count,
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to get config: {e}")

        @self.app.post("/analyze-request")
        async def analyze_request(request_data: dict):
            """Analyze HTTP request inline and generate alerts based on patterns"""
            import re
            
            alerts_generated = []
            
            # Extract request data
            url = request_data.get("url", "")
            method = request_data.get("method", "GET")
            headers = request_data.get("headers", {})
            body = request_data.get("body", "")
            src_ip = request_data.get("src_ip", "unknown")
            # User context — present when called from Go proxy handleUserProxy
            user_id = request_data.get("user_id", None)
            app_id = request_data.get("app_id", None)
            dest_ip = request_data.get("dest_ip", "127.0.0.1")
            src_port = request_data.get("src_port", 0)
            dest_port = request_data.get("dest_port", 8080)
            user_agent = headers.get("User-Agent", "") if isinstance(headers, dict) else ""
            
            # Combine all searchable content
            # URL-decode so that + and %XX are turned into spaces/chars before pattern matching
            decoded_url = unquote_plus(url)
            decoded_body = unquote_plus(body)
            # Include all headers in search content (not just User-Agent)
            headers_content = " ".join([f"{k}:{unquote_plus(str(v))}" for k, v in headers.items()]) if isinstance(headers, dict) else ""
            search_content = f"{decoded_url} {decoded_body} {headers_content}".lower()
            
            # Check for SQL Injection
            sql_patterns = [
                (r"(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|update\s+.*\s+set|drop\s+table)", 
                 "SYNORIX: SQL injection attempt in login form"),
                (r"('\s+or\s+'1'\s*=\s*'1|'\s+or\s+1\s*=\s*1)", 
                 "SYNORIX: SQL injection with OR 1=1"),
            ]
            
            for pattern, signature in sql_patterns:
                if re.search(pattern, search_content, re.IGNORECASE):
                    alert = self.create_inline_alert(signature, "Web Application Attack", 1, src_ip, dest_ip, src_port, dest_port)
                    alerts_generated.append(alert)
                    break
            
            # Check for XSS
            xss_patterns = [
                (r"<script[^>]*>.*?</script>", "SYNORIX: XSS attempt detected"),
                (r"javascript:|on\w+\s*=", "SYNORIX: XSS event handler injection"),
            ]
            
            for pattern, signature in xss_patterns:
                if re.search(pattern, search_content, re.IGNORECASE):
                    alert = self.create_inline_alert(signature, "Web Application Attack", 1, src_ip, dest_ip, src_port, dest_port)
                    alerts_generated.append(alert)
                    break
            
            # Check for Command Injection
            if re.search(r"(;|\||&|`|\$\(|<\()", url):
                alert = self.create_inline_alert("SYNORIX: Command injection attempt", "Web Application Attack", 1, src_ip, dest_ip, src_port, dest_port)
                alerts_generated.append(alert)
            
            # Check for Directory Traversal
            if re.search(r"(\.\./|\.\.\\)", url):
                alert = self.create_inline_alert("SYNORIX: Directory traversal attempt", "Web Application Attack", 2, src_ip, dest_ip, src_port, dest_port)
                alerts_generated.append(alert)
            
            # Check for Log4Shell (CVE-2021-44228) JNDI injection
            if re.search(r"(\$\{jndi:(ldap|rmi|dns|nis)://|jndi\s*:\s*(ldap|rmi|dns|nis))", search_content, re.IGNORECASE):
                alert = self.create_inline_alert("SYNORIX IDS: CVE-2021-44228 - Log4Shell JNDI LDAP Detected", "Remote Code Execution", 3, src_ip, dest_ip, src_port, dest_port)
                alerts_generated.append(alert)
            
            # Check for curl (Bot detection)
            if "curl" in user_agent.lower():
                alert = self.create_inline_alert("SYNORIX IDS: Bot - curl Detected", "Attempted Information Leak", 2, src_ip, dest_ip, src_port, dest_port)
                alerts_generated.append(alert)
            
            # Check for malicious user agents
            if re.search(r"(nmap|nikto|sqlmap|metasploit|gobuster|dirbuster|dirb|ffuf)", user_agent, re.IGNORECASE):
                alert = self.create_inline_alert("SYNORIX: Malicious scanning tool detected", "Attempted Information Leak", 2, src_ip, dest_ip, src_port, dest_port)
                alerts_generated.append(alert)
            
            # Process all generated alerts
            # source="ids-inline" distinguishes these proxy-side HTTP regex checks
            # from real Suricata network-level alerts read from eve.json
            for alert in alerts_generated:
                self.stats.add_alert(alert)
                await self.broadcast_alert(alert)
                await self.notify_security_proxy(alert, source="ids-inline", user_id=user_id, app_id=app_id)
                logger.info(f"🚨 Generated alert: {alert.alert.get('signature')} from {src_ip}")
            
            return {
                "status": "analyzed",
                "alerts_count": len(alerts_generated),
                "alerts": [asdict(alert) for alert in alerts_generated]
            }
        
        @self.app.post("/test/inject-alert")
        async def inject_test_alert(request: dict = None):
            """Inject a test alert for frontend testing"""
            import random
            
            # Default values
            signature = "SYNORIX: Test SQL injection attempt"
            category = "Web Application Attack"
            severity = 1
            src_ip = "192.168.1.100"
            dest_ip = "127.0.0.1"
            src_port = 54321
            dest_port = 8080
            proto = "TCP"
            
            # Override with request data if provided
            if request:
                signature = request.get("signature", signature)
                category = request.get("category", category)
                severity = request.get("severity", severity)
                src_ip = request.get("src_ip", src_ip)
                dest_ip = request.get("dest_ip", dest_ip)
                src_port = request.get("src_port", src_port)
                dest_port = request.get("dest_port", dest_port)
                proto = request.get("proto", proto)
            
            test_alert = SuricataAlert(
                timestamp=datetime.datetime.utcnow().isoformat(),
                flow_id=random.randint(100000, 999999),
                src_ip=src_ip, 
                dest_ip=dest_ip,
                src_port=src_port,
                dest_port=dest_port,
                proto=proto,
                alert={
                    "action": "blocked",  # Test alerts marked as blocked for IPS
                    "gid": 1,
                    "signature_id": random.randint(1000000, 1999999),
                    "rev": 1,
                    "signature": signature,
                    "category": category,
                    "severity": severity
                },
                severity=severity,
                category=category
            )
            
            # Add to statistics
            self.stats.add_alert(test_alert)
            
            # Broadcast to WebSocket clients
            await self.broadcast_alert(test_alert)
            
            # Send to security proxy database
            await self.notify_security_proxy(test_alert)
            
            return {"status": "success", "message": "Test alert injected and stored", "alert": asdict(test_alert)}
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time alerts"""
            await websocket.accept()
            self.websocket_connections.append(websocket)
            
            try:
                # Keep connection alive
                while True:
                    await websocket.receive_text()
            except WebSocketDisconnect:
                self.websocket_connections.remove(websocket)
    
    def create_inline_alert(self, signature: str, category: str, severity: int, src_ip: str, dest_ip: str, src_port: int, dest_port: int) -> SuricataAlert:
        """Create an alert from inline request analysis"""
        import random
        
        return SuricataAlert(
            timestamp=datetime.datetime.utcnow().isoformat(),
            flow_id=random.randint(100000, 999999999),
            src_ip=src_ip,
            dest_ip=dest_ip,
            src_port=src_port,
            dest_port=dest_port,
            proto="TCP",
            alert={
                "action": "blocked",  # Inline alerts are blocked
                "gid": 1,
                "signature_id": random.randint(1000001, 1000030),
                "rev": 1,
                "signature": signature,
                "category": category,
                "severity": severity
            },
            severity=severity,
            category=category
        )
    
    async def broadcast_alert(self, alert: SuricataAlert):
        """Broadcast alert to all connected WebSocket clients"""
        if not self.websocket_connections:
            return
        
        message = {
            "type": "suricata_alert",
            "data": asdict(alert)
        }
        
        # Remove disconnected clients
        connected_clients = []
        for websocket in self.websocket_connections:
            try:
                await websocket.send_text(json.dumps(message))
                connected_clients.append(websocket)
            except Exception:
                pass  # Client disconnected
        
        self.websocket_connections = connected_clients
    
    async def notify_security_proxy(self, alert: SuricataAlert, source: str = "suricata", user_id=None, app_id=None):
        """
        Notify the security proxy about alerts and store in database.

        source values:
          "suricata-ids"  — real Suricata IDS alert (AF_PACKET, passive)
          "suricata-ips"  — real Suricata IPS alert (NFQUEUE, packet was dropped)
          "ids-inline"    — inline HTTP-request pattern analysis (proxy-side regex)

        user_id / app_id — when provided (called from Go proxy inline analysis),
                           the alert is also stored in user_alerts for that user.
        """
        try:
            alert_action = alert.alert.get("action", "allowed")
            action_mapping = {
                "allowed": "detected", "drop": "dropped", "dropped": "dropped",
                "reject": "rejected", "rejected": "rejected",
                "block": "blocked", "blocked": "blocked", "alert": "detected"
            }
            normalized_action = action_mapping.get(alert_action.lower(), "detected")

            if source == "ids-inline":
                source_label = "Inline HTTP Analysis"
                system_type = "IDS"
            elif source == "suricata-ips":
                source_label = "Suricata IPS (NFQUEUE)"
                system_type = "IPS"
            elif source == "suricata-ids":
                source_label = "Suricata IDS (AF_PACKET)"
                system_type = "IDS"
            else:
                source_label = "Suricata"
                system_type = "IDS"

            alert_payload = {
                "source": source,
                "severity": alert.severity,
                "category": alert.category,
                "signature": alert.alert.get("signature", "Unknown Signature"),
                "src_ip": alert.src_ip,
                "dest_ip": alert.dest_ip,
                "src_port": alert.src_port,
                "dest_port": alert.dest_port,
                "protocol": alert.proto,
                "flow_id": alert.flow_id,
                "timestamp": alert.timestamp,
                "action": normalized_action,
                "description": (
                    f"{source_label}: {alert.alert.get('signature', 'Unknown')} "
                    f"from {alert.src_ip}:{alert.src_port} to {alert.dest_ip}:{alert.dest_port} "
                    f"[Action: {normalized_action.upper()}]"
                )
            }
            # Attach user context when available (inline analysis from Go proxy)
            if user_id is not None:
                alert_payload["user_id"] = user_id
            if app_id is not None:
                alert_payload["app_id"] = app_id

            # Store alert in database via backend API
            try:
                headers = {}
                if self.internal_api_token:
                    headers["X-Internal-Token"] = self.internal_api_token
                response = requests.post(
                    f"{self.backend_url}/api/security/alerts/insert",
                    json=alert_payload,
                    headers=headers,
                    timeout=5
                )
                if response.status_code in [200, 201]:
                    logger.info(f"✅ [{system_type}] Alert stored: {alert.alert.get('signature', 'Unknown')}")
                else:
                    logger.warning(f"⚠️  Failed to store alert: {response.status_code} - {response.text}")
            except requests.exceptions.RequestException as e:
                logger.warning(f"❌ Failed to send alert to backend: {e}")

            # ── Reactive IP blocking ─────────────────────────────────────────
            # When Suricata IPS drops a packet, the Go proxy may not have seen
            # that request at all (NFQUEUE drops before TCP is accepted).
            # We reactively block the IP in the proxy so subsequent requests
            # from the same IP are also stopped at the application layer.
            if normalized_action in ("dropped", "blocked", "rejected") and alert.src_ip not in ("unknown", ""):
                try:
                    block_payload = {
                        "ip": alert.src_ip,
                        "reason": f"Suricata IPS: {alert.alert.get('signature', 'Unknown')}",
                        "duration": 3600  # block for 1 hour; 0 = permanent
                    }
                    headers = {}
                    if self.internal_api_token:
                        headers["X-Internal-Token"] = self.internal_api_token
                    block_resp = requests.post(
                        f"{self.security_proxy_url}/api/security/block-ip",
                        json=block_payload,
                        headers=headers,
                        timeout=5
                    )
                    if block_resp.status_code == 200:
                        logger.info(f"🔒 Reactively blocked IP {alert.src_ip} in proxy (IPS drop)")
                    else:
                        logger.warning(f"⚠️  Could not block IP {alert.src_ip}: {block_resp.status_code}")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"❌ Failed to block IP in proxy: {e}")

        except Exception as e:
            logger.error(f"Error in notify_security_proxy: {e}")
    
    async def process_alerts(self):
        """Background task to process alerts from both IDS and IPS Suricata logs"""
        logger.info("Starting real Suricata alert processing (IDS + IPS)...")
        logger.info(f"  IDS log: {self.ids_parser.log_file}")
        logger.info(f"  IPS log: {self.ips_parser.log_file}")

        async def tail_one(parser: SuricataLogParser, source_tag: str):
            """Continuously tail a single Suricata eve.json file"""
            while True:
                try:
                    async for alert in parser.tail_logs():
                        self.stats.add_alert(alert)
                        await self.broadcast_alert(alert)

                        # Severity filter: only forward severity 1 (critical) and 2 (high)
                        # to the backend unless this is an active block/drop action
                        alert_action = alert.alert.get("action", "alert").lower()
                        is_blocking = alert_action in ("drop", "dropped", "block", "blocked", "reject", "rejected")
                        if alert.severity > 2 and not is_blocking:
                            continue  # skip low/medium non-blocking alerts

                        # In-memory dedup: skip if same src_ip+sig_id seen within 5 min
                        sig_id = alert.alert.get("signature_id", 0)
                        dedup_key = (alert.src_ip, sig_id)
                        now = time.time()
                        if now - self._dedup_cache.get(dedup_key, 0) < 300:  # 5 minutes
                            logger.debug(f"[{source_tag.upper()}] Dedup suppressed: {alert.alert.get('signature')} from {alert.src_ip}")
                            continue
                        self._dedup_cache[dedup_key] = now
                        # Global per-signature rate limit: max 1 alert per signature per 30 min
                        # regardless of source IP — prevents flooding from many different IPs
                        if now - self._sig_global_cache.get(sig_id, 0) < 1800:  # 30 minutes
                            logger.debug(f"[{source_tag.upper()}] Global rate limit: {alert.alert.get('signature')} (sig_id={sig_id})")
                            continue
                        self._sig_global_cache[sig_id] = now

                        await self.notify_security_proxy(alert, source=source_tag)
                        logger.info(
                            f"[{source_tag.upper()}] {alert.alert.get('signature', 'Unknown')} "
                            f"from {alert.src_ip} action={alert.alert.get('action', 'alert')}"
                        )
                    await asyncio.sleep(1)  # pause before next poll
                except Exception as e:
                    logger.error(f"[{source_tag.upper()}] Error tailing log: {e}")
                    await asyncio.sleep(5)

        # Run IDS and IPS tailers concurrently
        await asyncio.gather(
            tail_one(self.ids_parser, "suricata-ids"),
            tail_one(self.ips_parser, "suricata-ips"),
        )

# Create the service instance
service = SuricataIntegrationService()
app = service.app

@app.on_event("startup")
async def startup_event():
    """Start background tasks on startup"""
    logger.info("Starting Suricata Integration Service...")
    
    # Start alert processing in background
    asyncio.create_task(service.process_alerts())

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8083,
        log_level="info"
    )
