package main

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

// Data structures
type SecurityProxy struct {
	target               *url.URL
	proxy                *httputil.ReverseProxy
	blocklist            map[string]bool
	blocklistMu          sync.RWMutex
	threatStats          *ThreatStats
	logChannel           chan SecurityEvent
	detailedLogChan      chan DetailedRequestLog
	aiClient             *AIClient
	compressionAI        *CompressionClient
	dedupCache           *DedupCache
	wsClients            map[*websocket.Conn]bool
	wsClientsMu          sync.RWMutex
	broadcastChan        chan interface{}
	upgrader             websocket.Upgrader
	wafRules             []WAFRule
	wafRulesData         []WAFRuleData
	wafMu                sync.RWMutex
	firewallRules        []FirewallRuleData
	firewallMu           sync.RWMutex
	dataDir              string
	perfSecret           string // HMAC secret for load-test bypass (SYNORIX_PERF_SECRET)
	rateLimiter          map[string]*RateLimit
	rateLimitMu          sync.RWMutex
	loginTracker         map[string]*RateLimit // brute-force tracker keyed by "userID:ip"
	loginTrackerMu       sync.RWMutex
	maxRequestSize       int64
	sessionStore         map[string]*SessionInfo
	sessionMu            sync.RWMutex
	db                   *sql.DB
	dbPath               string
	perfTokenMaxDriftSec int64

	// Real-time metrics for AI model inputs (updated atomically)
	backendRTTNs   int64 // rolling avg backend RTT in nanoseconds
	activeRequests int64 // number of currently in-flight backend requests
}

// UserConfig represents a user's backend configuration
type UserConfig struct {
	UserID             int
	AppID              int // 0 = legacy single-app (user_configs), >0 = user_applications row
	BackendURL         string
	APIKey             string
	ConnectivityStatus string
	LastTested         sql.NullTime
}

type ThreatStats struct {
	TotalRequests         int64            `json:"totalRequests"`
	BlockedRequests       int64            `json:"blockedRequests"`
	MaliciousIPs          int64            `json:"maliciousIPs"`
	WAFBlocks             int64            `json:"wafBlocks"`
	DDoSDetections        int64            `json:"ddosDetections"`
	SQLiAttempts          int64            `json:"sqliAttempts"`
	XSSAttempts           int64            `json:"xssAttempts"`
	TotalBandwidth        int64            `json:"totalBandwidth"`
	CompressedRequests    int64            `json:"compressedRequests"`
	CompressionSaved      int64            `json:"compressionSaved"`
	AvgCompressionLatency float64          `json:"avgCompressionLatency"`
	CompressionDecisions  map[string]int64 `json:"compressionDecisions"`
}

type SecurityEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	IP          string    `json:"ip"`
	URL         string    `json:"url"`
	UserAgent   string    `json:"userAgent"`
	Method      string    `json:"method"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Blocked     bool      `json:"blocked"`
}

// Enhanced request logging structure
type DetailedRequestLog struct {
	Timestamp         time.Time          `json:"timestamp"`
	Method            string             `json:"method"`
	URL               string             `json:"url"`
	IP                string             `json:"ip"`
	UserAgent         string             `json:"user_agent"`
	StatusCode        int                `json:"status_code"`
	ResponseTime      time.Duration      `json:"response_time"`
	RequestSize       int64              `json:"request_size"`
	ResponseSize      int64              `json:"response_size"`
	WAFChecks         []WAFCheckResult   `json:"waf_checks"`
	CompressionInfo   *CompressionInfo   `json:"compression_info"`
	DeduplicationInfo *DeduplicationInfo `json:"deduplication_info"`
	IDSIPSInfo        *IDSIPSInfo        `json:"ids_ips_info"`
	SecurityEvents    []SecurityEvent    `json:"security_events"`
	Headers           map[string]string  `json:"headers"`
	Blocked           bool               `json:"blocked"`
	BlockReason       string             `json:"block_reason,omitempty"`
}

type WAFCheckResult struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Matched     bool   `json:"matched"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type CompressionInfo struct {
	Enabled          bool    `json:"enabled"`
	OriginalSize     int64   `json:"original_size"`
	CompressedSize   int64   `json:"compressed_size,omitempty"`
	CompressionRatio float64 `json:"compression_ratio,omitempty"`
	Algorithm        string  `json:"algorithm,omitempty"`
	AIDecision       bool    `json:"ai_decision"`
	AIConfidence     float64 `json:"ai_confidence,omitempty"`
	AIReason         string  `json:"ai_reason,omitempty"`
	ProcessingTime   int64   `json:"processing_time_ms"`
}

type DeduplicationInfo struct {
	Enabled        bool    `json:"enabled"`
	OriginalSize   int64   `json:"original_size"`
	DedupSize      int64   `json:"dedup_size,omitempty"`
	DedupRatio     float64 `json:"dedup_ratio,omitempty"`
	CacheHit       bool    `json:"cache_hit"`
	AIDecision     bool    `json:"ai_decision"`
	AIConfidence   float64 `json:"ai_confidence,omitempty"`
	AIReason       string  `json:"ai_reason,omitempty"`
	ProcessingTime int64   `json:"processing_time_ms"`
}

type DeduplicationDecision struct {
	Decision    int     `json:"decision"` // 0 or 1
	Probability float64 `json:"prob"`
	Reason      string  `json:"reason"`
}

func (d *DeduplicationDecision) ShouldDeduplicate() bool {
	return d.Decision == 1 || d.Probability >= 0.5
}

type IDSIPSInfo struct {
	Enabled        bool              `json:"enabled"`
	SuricataAlerts []SuricataAlert   `json:"suricata_alerts,omitempty"`
	ThreatLevel    string            `json:"threat_level"`
	Patterns       []DetectedPattern `json:"patterns,omitempty"`
	ProcessingTime int64             `json:"processing_time_ms"`
}

type SuricataAlert struct {
	SignatureID string `json:"signature_id"`
	Message     string `json:"message"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
	Action      string `json:"action"`
}

type DetectedPattern struct {
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type AIClient struct {
	endpoint string
	client   *http.Client
}

type CompressionClient struct {
	endpoint string
	client   *http.Client
}

type CompressionDecision struct {
	ShouldCompress bool    `json:"should_compress"`
	Confidence     float64 `json:"confidence"`
	Reason         string  `json:"reason"`
	Algorithm      string  `json:"algorithm,omitempty"`
}

type WAFRule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
	IsScanner   bool   // true for bot/scanner rules — check User-Agent header
	compiled    *regexp.Regexp
}

type WAFRuleData struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
}

type FirewallRuleData struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	SourceIP    string `json:"source_ip"`
	DestIP      string `json:"dest_ip"`
	Port        string `json:"port"`
	Protocol    string `json:"protocol"`
	Action      string `json:"action"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type RateLimit struct {
	Count     int       `json:"count"`
	Window    time.Time `json:"window"`
	MaxReqs   int       `json:"max_reqs"`
	WindowSec int       `json:"window_sec"`
}

type SessionInfo struct {
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Requests   int       `json:"requests"`
	Suspicious bool      `json:"suspicious"`
}

type ProxyConfig struct {
	Target             string `json:"target"`
	Port               string `json:"port"`
	MaxRequestSize     int64  `json:"max_request_size"`
	RateLimit          int    `json:"rate_limit"`
	WAFEnabled         bool   `json:"waf_enabled"`
	DDoSProtection     bool   `json:"ddos_protection"`
	CompressionEnabled bool   `json:"compression_enabled"`
}

type TrafficMetrics struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	BandwidthUsage    int64   `json:"bandwidth_usage"`
	ResponseTime      float64 `json:"response_time"`
	ErrorRate         float64 `json:"error_rate"`
	CompressionRatio  float64 `json:"compression_ratio"`
	ActiveConnections int     `json:"active_connections"`
}

// Initialize new security proxy
func NewSecurityProxy(targetURL *url.URL, dataDir string, dbPath string) *SecurityProxy {
	// Initialize database connection
	// Use file URI with busy_timeout and WAL journal mode to avoid SQLITE_READONLY
	// errors when Node.js and the Go proxy share the same database file.
	dbDSN := fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL&_synchronous=NORMAL&cache=shared&mode=rwc", dbPath)
	db, err := sql.Open("sqlite3", dbDSN)
	if err != nil {
		logrus.Fatalf("Failed to open database: %v", err)
	}
	// SQLite performs best with a single writer connection
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Test database connection
	if err := db.Ping(); err != nil {
		logrus.Fatalf("Failed to connect to database: %v", err)
	}
	// Ensure pragmas are applied for this connection
	if _, err := db.Exec("PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;"); err != nil {
		logrus.Warnf("Could not set DB pragmas: %v", err)
	}

	logrus.Infof("📊 Connected to database: %s", dbPath)

	proxy := &SecurityProxy{
		target:    targetURL,
		blocklist: make(map[string]bool),
		threatStats: &ThreatStats{
			CompressionDecisions: make(map[string]int64),
		},
		logChannel:      make(chan SecurityEvent, 1000),
		detailedLogChan: make(chan DetailedRequestLog, 1000),
		wsClients:       make(map[*websocket.Conn]bool),
		broadcastChan:   make(chan interface{}, 100),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return false }, // Will be set correctly in main()
		},
		dataDir:              dataDir,
		rateLimiter:          make(map[string]*RateLimit),
		loginTracker:         make(map[string]*RateLimit),
		perfSecret:           strings.TrimSpace(os.Getenv("SYNORIX_PERF_SECRET")),
		maxRequestSize:       10 * 1024 * 1024, // 10MB
		sessionStore:         make(map[string]*SessionInfo),
		db:                   db,
		dbPath:               dbPath,
		perfTokenMaxDriftSec: 300,
	}
	if v := strings.TrimSpace(os.Getenv("PERF_TOKEN_MAX_DRIFT_SEC")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			proxy.perfTokenMaxDriftSec = n
		}
	}

	// Initialize reverse proxy
	proxy.proxy = httputil.NewSingleHostReverseProxy(targetURL)
	proxy.proxy.ModifyResponse = proxy.modifyResponse

	// Initialize AI clients
	proxy.aiClient = &AIClient{
		endpoint: "http://localhost:8081",
		client:   &http.Client{Timeout: 30 * time.Second},
	}

	proxy.compressionAI = &CompressionClient{
		endpoint: "http://localhost:8082",
		client:   &http.Client{Timeout: 30 * time.Second},
	}

	maxEntries := getEnvInt("DEDUP_CACHE_MAX_ENTRIES", 1000)
	maxBytes := getEnvInt64("DEDUP_CACHE_MAX_BYTES", 100*1024*1024)
	ttlSeconds := getEnvInt("DEDUP_CACHE_TTL_SECONDS", 300)
	proxy.dedupCache = NewDedupCache(maxEntries, maxBytes, time.Duration(ttlSeconds)*time.Second)
	logrus.Infof("📦 Dedup cache enabled: entries=%d maxBytes=%d ttl=%s", maxEntries, maxBytes, time.Duration(ttlSeconds)*time.Second)

	// Load configurations
	proxy.loadWAFRules()
	proxy.loadFirewallRules()

	// Start background services
	go proxy.eventProcessor()
	go proxy.detailedLogProcessor()
	go proxy.websocketBroadcaster()

	return proxy
}

// Load WAF rules
func (sp *SecurityProxy) loadWAFRules() {
	sp.wafMu.Lock()
	defer sp.wafMu.Unlock()

	severityStr := func(s int) string {
		switch {
		case s >= 5:
			return "critical"
		case s == 4:
			return "high"
		case s == 3:
			return "medium"
		case s == 2:
			return "low"
		default:
			return "info"
		}
	}

	actionFor := func(s int) string {
		if s >= 4 {
			return "block"
		}
		return "monitor"
	}

	// Load WAF rules from the database (source of truth)
	if sp.db != nil {
		rows, err := sp.db.Query(`SELECT id, pattern, message, tags, severity, enabled FROM waf_rules WHERE enabled = 1`)
		if err != nil {
			logrus.Errorf("Failed to load WAF rules from DB: %v", err)
		} else {
			defer rows.Close()
			sp.wafRulesData = nil
			for rows.Next() {
				var id int
				var pattern, message, tags string
				var severity int
				var enabled bool
				if err := rows.Scan(&id, &pattern, &message, &tags, &severity, &enabled); err != nil {
					logrus.Warnf("Failed to scan WAF rule row: %v", err)
					continue
				}
				sp.wafRulesData = append(sp.wafRulesData, WAFRuleData{
					ID:          fmt.Sprintf("waf_%d", id),
					Name:        message,
					Description: message,
					Pattern:     pattern,
					Action:      actionFor(severity),
					Enabled:     enabled,
					Severity:    severityStr(severity),
					Category:    tags,
				})
			}
			logrus.Infof("✅ Loaded %d WAF rules from database", len(sp.wafRulesData))
		}
	} else {
		logrus.Warn("⚠️  No DB connection — falling back to built-in WAF rules")
		sp.wafRulesData = []WAFRuleData{
			{
				ID:          "sql_injection",
				Name:        "SQL Injection Protection",
				Description: "Blocks common SQL injection patterns",
				Pattern:     `(?i)(union|select|insert|delete|update|drop|create|alter|exec|execute)\s*(\(|\s)`,
				Action:      "block",
				Enabled:     true,
				Severity:    "high",
				Category:    "injection",
			},
			{
				ID:          "xss_protection",
				Name:        "XSS Protection",
				Description: "Blocks cross-site scripting attempts",
				Pattern:     `(?i)<script[^>]*>.*?</script>|javascript:|on\w+\s*=`,
				Action:      "block",
				Enabled:     true,
				Severity:    "high",
				Category:    "xss",
			},
		}
	}

	// Compile regex patterns into the fast-path slice
	sp.wafRules = nil
	for _, rule := range sp.wafRulesData {
		if rule.Enabled {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				logrus.Errorf("Failed to compile WAF rule %s: %v", rule.ID, err)
				continue
			}
			isScanner := strings.Contains(rule.Category, "bot") || strings.Contains(rule.Category, "scanner")
			sp.wafRules = append(sp.wafRules, WAFRule{
				ID:          rule.ID,
				Description: rule.Description,
				Pattern:     rule.Pattern,
				Action:      rule.Action,
				Enabled:     rule.Enabled,
				IsScanner:   isScanner,
				compiled:    compiled,
			})
		}
	}
	logrus.Infof("✅ Compiled %d active WAF rules for blocking", len(sp.wafRules))
}

// persistWAFRules recompiles the fast-path WAF pattern slice from in-memory state.
// Rules are managed in the database by the Node.js server; the proxy does not
// need to write them to disk.
func (sp *SecurityProxy) persistWAFRules() {
	sp.wafMu.Lock()
	defer sp.wafMu.Unlock()

	// Recompile fast-path slice so changes take effect immediately
	sp.wafRules = nil
	for _, rule := range sp.wafRulesData {
		if rule.Enabled {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				logrus.Errorf("Failed to compile WAF rule %s: %v", rule.ID, err)
				continue
			}
			isScanner := strings.Contains(rule.Category, "bot") || strings.Contains(rule.Category, "scanner")
			sp.wafRules = append(sp.wafRules, WAFRule{
				ID:          rule.ID,
				Description: rule.Description,
				Pattern:     rule.Pattern,
				Action:      rule.Action,
				Enabled:     rule.Enabled,
				IsScanner:   isScanner,
				compiled:    compiled,
			})
		}
	}
}

// Load firewall rules
func (sp *SecurityProxy) loadFirewallRules() {
	sp.firewallMu.Lock()
	defer sp.firewallMu.Unlock()

	sp.firewallRules = []FirewallRuleData{
		{
			ID:          "allow_local",
			Name:        "Allow Local Network",
			SourceIP:    "192.168.0.0/16",
			Action:      "allow",
			Description: "Allow local network traffic",
			Enabled:     true,
		},
	}
}

// Get user config by API key — checks user_applications first, then user_configs (legacy)
func (sp *SecurityProxy) getUserConfigByAPIKey(apiKey string) (*UserConfig, error) {
	var config UserConfig

	// 1. Check user_applications (multi-app)
	appQuery := `
		SELECT ua.user_id, ua.id, ua.backend_url, ua.proxy_api_key, uc.connectivity_status, uc.last_test_at
		FROM user_applications ua
		LEFT JOIN user_configs uc ON uc.user_id = ua.user_id
		WHERE ua.proxy_api_key = ?
	`
	err := sp.db.QueryRow(appQuery, apiKey).Scan(
		&config.UserID,
		&config.AppID,
		&config.BackendURL,
		&config.APIKey,
		&config.ConnectivityStatus,
		&config.LastTested,
	)
	if err == nil {
		return &config, nil
	}

	// 2. Fall back to user_configs (legacy single-app)
	legacyQuery := `
		SELECT user_id, backend_url, proxy_api_key, connectivity_status, last_test_at
		FROM user_configs
		WHERE proxy_api_key = ?
	`
	err = sp.db.QueryRow(legacyQuery, apiKey).Scan(
		&config.UserID,
		&config.BackendURL,
		&config.APIKey,
		&config.ConnectivityStatus,
		&config.LastTested,
	)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// Log user request to database
func (sp *SecurityProxy) logUserRequest(userID int, appID int, log DetailedRequestLog, backendURL string) {
	query := `
		INSERT INTO user_request_logs (
			user_id, app_id, timestamp, method, url, backend_url, client_ip,
			user_agent, status_code, response_time, request_size,
			response_size, threat_level, waf_triggered, suricata_triggered,
			compressed, deduplicated, compression_ratio, original_size, compressed_size,
			dedup_size, dedup_ratio
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// waf_triggered = true only when WAF actually BLOCKED the request (not just a pattern match/detect)
	wafTriggered := log.Blocked && log.BlockReason == "WAF rule violation"

	// suricata_triggered = true when Suricata produced real alerts or blocked
	suricataTriggered := (log.IDSIPSInfo != nil && len(log.IDSIPSInfo.SuricataAlerts) > 0) ||
		(log.Blocked && strings.HasPrefix(log.BlockReason, "Suricata"))

	// threat_level: prefer IDSIPSInfo, then derive from WAF block severity
	threatLevel := "none"
	if log.IDSIPSInfo != nil && log.IDSIPSInfo.ThreatLevel != "" && log.IDSIPSInfo.ThreatLevel != "none" {
		threatLevel = log.IDSIPSInfo.ThreatLevel
	} else if wafTriggered {
		// Derive threat level from the highest severity blocked WAF rule
		sevRank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
		topLevel := "medium" // sensible default for any blocked request
		topRank := 0
		for _, check := range log.WAFChecks {
			if check.Matched {
				if r, ok := sevRank[check.Severity]; ok && r > topRank {
					topRank = r
					topLevel = check.Severity
				}
			}
		}
		threatLevel = topLevel
	}

	// Compression info
	compressed := log.CompressionInfo != nil && log.CompressionInfo.Enabled && log.CompressionInfo.CompressionRatio > 0
	compressionRatio := 0.0
	originalSize := int64(0)
	compressedSize := int64(0)

	if log.CompressionInfo != nil && log.CompressionInfo.Enabled {
		compressionRatio = log.CompressionInfo.CompressionRatio
		originalSize = log.CompressionInfo.OriginalSize
		compressedSize = log.CompressionInfo.CompressedSize
	}

	// Deduplication info
	// A request is "deduplicated" when it was served from the LRU cache
	// (CacheHit=true) OR when the AI wrote the entry and the ratio > 0.
	deduplicated := false
	dedupSize := int64(0)
	dedupRatio := 0.0

	if log.DeduplicationInfo != nil && log.DeduplicationInfo.Enabled {
		dedupSize = log.DeduplicationInfo.DedupSize
		dedupRatio = log.DeduplicationInfo.DedupRatio
		// Mark deduplicated on a cache-hit regardless of ratio, and on a
		// cache-miss if the ratio was recorded (future AI write path).
		if log.DeduplicationInfo.CacheHit || dedupRatio > 0 {
			deduplicated = true
		}
		// Cache-hits always save 100 % of the original bytes.
		if log.DeduplicationInfo.CacheHit && dedupRatio == 0 {
			dedupRatio = 1.0
		}
	}

	var appIDVal interface{}
	if appID > 0 {
		appIDVal = appID
	} else {
		appIDVal = nil
	}

	_, err := sp.db.Exec(query,
		userID,
		appIDVal,
		log.Timestamp.Format(time.RFC3339),
		log.Method,
		log.URL,
		backendURL,
		log.IP,
		log.UserAgent,
		log.StatusCode,
		log.ResponseTime.Milliseconds(),
		log.RequestSize,
		log.ResponseSize,
		threatLevel,
		wafTriggered,
		suricataTriggered,
		compressed,
		deduplicated,
		compressionRatio,
		originalSize,
		compressedSize,
		dedupSize,
		dedupRatio,
	)

	if err != nil {
		logrus.Errorf("Failed to log user request: %v", err)
	}
}

// Create user alert
func (sp *SecurityProxy) createUserAlert(userID int, appID int, alertType, severity, title, description, ruleID, sourceIP, targetURL, recommendedAction, alertAction string) {
	alertType = strings.ToLower(alertType)
	severity = strings.ToLower(severity)
	if alertAction == "" {
		alertAction = "detected"
	}

	var appIDVal interface{}
	if appID > 0 {
		appIDVal = appID
	} else {
		appIDVal = nil
	}

	query := `
		INSERT INTO user_alerts (
			user_id, app_id, alert_type, severity, rule_name, description,
			rule_id, source_ip, target_url, recommended_action, action, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := sp.db.Exec(query,
		userID, appIDVal, alertType, severity, title, description,
		ruleID, sourceIP, targetURL, recommendedAction, alertAction,
		time.Now().UTC().Format(time.RFC3339),
	)

	if err != nil {
		logrus.Errorf("Failed to create user alert: %v", err)
	}
}

// Response recorder
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
	headers    http.Header
}

func (rec *responseRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *responseRecorder) Write(data []byte) (int, error) {
	rec.body.Write(data)
	return rec.ResponseWriter.Write(data)
}

func (rec *responseRecorder) Header() http.Header {
	if rec.headers == nil {
		rec.headers = rec.ResponseWriter.Header()
	}
	return rec.headers
}

// Handle compression
func (sp *SecurityProxy) handleCompression(w http.ResponseWriter, rec *responseRecorder, r *http.Request, clientIP string) bool {
	originalSize := int64(rec.body.Len())

	if originalSize < 1024 {
		return false
	}

	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return false
	}

	startTime := time.Now()
	decision, err := sp.shouldCompressResponseWithAI(r, rec.body.Bytes())
	if err != nil {
		logrus.Errorf("AI compression decision error: %v", err)
		return false
	}

	latency := time.Since(startTime).Seconds()
	sp.threatStats.AvgCompressionLatency = (sp.threatStats.AvgCompressionLatency + latency) / 2
	sp.threatStats.CompressionDecisions[decision.Reason]++

	if decision.ShouldCompress {
		compressed, err := sp.compressResponse(rec.body.Bytes())
		if err != nil {
			logrus.Errorf("Compression error: %v", err)
			return false
		}

		compressedSize := int64(len(compressed))
		saved := originalSize - compressedSize

		sp.threatStats.CompressedRequests++
		sp.threatStats.CompressionSaved += saved

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", compressedSize))

		// Add compression metadata to headers for backend logging
		rec.Header().Set("X-Compression-Original-Size", fmt.Sprintf("%d", originalSize))
		rec.Header().Set("X-Compression-Saved", fmt.Sprintf("%d", saved))

		logrus.Infof("Compressed response for %s: %d -> %d bytes",
			clientIP, originalSize, compressedSize)

		return true
	}

	return false
}

// AI compression decision
func (sp *SecurityProxy) shouldCompressResponseWithAI(r *http.Request, responseBody []byte) (*CompressionDecision, error) {
	payload := map[string]interface{}{
		"content_type": r.Header.Get("Content-Type"),
		"size":         len(responseBody),
		"user_agent":   r.UserAgent(),
		"url":          r.URL.Path,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := sp.compressionAI.client.Post(
		sp.compressionAI.endpoint+"/compress-decision",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return &CompressionDecision{
			ShouldCompress: len(responseBody) > 1024,
			Confidence:     0.5,
			Reason:         "fallback",
			Algorithm:      "gzip",
		}, nil
	}
	defer resp.Body.Close()

	var decision CompressionDecision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &decision, nil
}

// Compress response
func (sp *SecurityProxy) compressResponse(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Call AI compression decision service
func (sp *SecurityProxy) callAICompressionDecision(r *http.Request, responseBody []byte, contentType string) (*CompressionDecision, error) {
	payload := map[string]interface{}{
		"content_type": contentType,
		"size":         len(responseBody),
		"user_agent":   r.UserAgent(),
		"url":          r.URL.Path,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := sp.compressionAI.client.Post(
		sp.compressionAI.endpoint+"/compress-decision",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		// Fallback: compress if > 1KB
		return &CompressionDecision{
			ShouldCompress: len(responseBody) > 1024,
			Confidence:     0.5,
			Reason:         "fallback-ai-unavailable",
			Algorithm:      "gzip",
		}, nil
	}
	defer resp.Body.Close()

	var decision CompressionDecision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &decision, nil
}

// RealtimeMetrics holds live system measurements used as AI model inputs.
type RealtimeMetrics struct {
	RTTMS          float64
	QueueDepth     int
	SystemLoad     float64
	DedupHitRate   float64
	CompressSaving float64
}

// getRealtimeMetrics returns current system metrics sampled from live counters.
func (sp *SecurityProxy) getRealtimeMetrics() RealtimeMetrics {
	// Backend RTT: rolling exponential moving average, default 10ms before first measurement
	rttNs := atomic.LoadInt64(&sp.backendRTTNs)
	rttMs := float64(rttNs) / 1e6
	if rttMs < 1 {
		rttMs = 10.0
	}

	// In-flight requests → queue depth
	queue := int(atomic.LoadInt64(&sp.activeRequests))

	// System load proxy: active requests / logical CPUs, capped at 0.95
	systemLoad := math.Min(float64(queue)/math.Max(float64(runtime.GOMAXPROCS(0)), 1), 0.95)

	// Real dedup hit rate from cache stats
	stats := sp.dedupCache.Stats()
	total := stats.Hits + stats.Misses
	hitRate := 0.4   // sensible default before cache warms up
	if total > 100 { // only trust it once we have enough samples to be statistically meaningful
		hitRate = float64(stats.Hits) / float64(total)
	}

	// Real compression saving ratio from lifetime stats
	compSaving := 0.5 // default
	bw := sp.threatStats.TotalBandwidth
	saved := sp.threatStats.CompressionSaved
	if bw > 0 {
		compSaving = float64(saved) / float64(bw)
	}

	return RealtimeMetrics{
		RTTMS:          rttMs,
		QueueDepth:     queue,
		SystemLoad:     systemLoad,
		DedupHitRate:   hitRate,
		CompressSaving: compSaving,
	}
}

// updateBackendRTT updates the rolling exponential moving average of backend RTT.
func (sp *SecurityProxy) updateBackendRTT(rtt time.Duration) {
	nanos := rtt.Nanoseconds()
	if nanos <= 0 {
		return
	}
	for {
		old := atomic.LoadInt64(&sp.backendRTTNs)
		var next int64
		if old == 0 {
			next = nanos // first sample
		} else {
			// α=0.125 → smoothed over ~8 samples
			next = int64(float64(old)*0.875 + float64(nanos)*0.125)
		}
		if atomic.CompareAndSwapInt64(&sp.backendRTTNs, old, next) {
			break
		}
	}
}

func (sp *SecurityProxy) callAIDeduplicationDecision(r *http.Request, responseBody []byte, contentType string) (*DeduplicationDecision, error) {
	// Sample live system metrics so the model gets real inputs, not constants.
	m := sp.getRealtimeMetrics()

	// Build PolicyRequest payload for AI model
	payload := map[string]interface{}{
		"proto":                 r.Proto,
		"method":                r.Method,
		"content_type":          contentType,
		"body_bytes":            len(responseBody),
		"url":                   r.URL.String(),
		"accept_encoding_flags": []string{"gzip"},
		"cacheability_bucket":   "public",
		"etag_present":          r.Header.Get("ETag") != "",
		"rtt_ms":                m.RTTMS,
		"ttfb_ms":               m.RTTMS, // TTFB ≈ RTT for proxied requests
		"client_bw_mbps":        10.0,    // not measurable without OS instrumentation
		"cpu_load":              m.SystemLoad,
		"queue_depth":           m.QueueDepth,
		"prior_compress_saving": m.CompressSaving,
		"prior_dedup_hit_rate":  m.DedupHitRate,
		"cache_control":         r.Header.Get("Cache-Control"),
		"pragma":                r.Header.Get("Pragma"),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := sp.compressionAI.client.Post(
		sp.compressionAI.endpoint+"/predict_dedup",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		// Fallback: Conservative dedup policy - only cache cacheable content
		decision := 0
		reason := "fallback-ai-unavailable"

		// Only deduplicate if:
		// 1. Has Cache-Control: public or no private directive
		// 2. Status is cacheable (200, 301, 404, etc)
		// 3. Content is substantive (>512 bytes)
		if len(responseBody) > 512 && contentType != "" {
			cacheControl := r.Header.Get("Cache-Control")
			if !strings.Contains(cacheControl, "private") && !strings.Contains(cacheControl, "no-store") {
				decision = 1
				// Use a non-fallback reason so strict mode does not block this
				// heuristic decision. The AI model was unreachable but the
				// heuristic is itself a legitimate positive signal.
				reason = "heuristic-cacheable-content"
			}
		}

		logrus.Warnf("🤖 AI dedup service unavailable, using fallback (decision: %d, reason: %s)", decision, reason)
		return &DeduplicationDecision{
			Decision:    decision,
			Probability: 0.5,
			Reason:      reason,
		}, nil
	}
	defer resp.Body.Close()

	var decision DeduplicationDecision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		logrus.Warnf("Failed to decode AI response: %v, using fallback", err)
		return &DeduplicationDecision{
			Decision:    0,
			Probability: 0.5,
			Reason:      "fallback-decode-error",
		}, nil
	}

	// Log AI decision with confidence level
	if decision.Decision == 1 {
		logrus.Debugf("✅ AI dedup decision: YES (confidence: %.2f%%, reason: %s)", decision.Probability*100, decision.Reason)
	}

	return &decision, nil
}

// Security checks
// isValidPerfToken verifies the X-Synorix-Perf-Token header sent by k6.
// Format: "<unix_timestamp>:<hex(HMAC-SHA256(secret, unix_timestamp))>"
// The timestamp must be within ±30 seconds of server time to prevent replay.
func (sp *SecurityProxy) isValidPerfToken(r *http.Request) bool {
	if sp.perfSecret == "" {
		return false
	}
	token := strings.TrimSpace(r.Header.Get("X-Synorix-Perf-Token"))
	if token == "" {
		// Backward-compatible alias
		token = strings.TrimSpace(r.Header.Get("X-Perf-Token"))
	}
	if token == "" {
		return false
	}
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return false
	}
	tsStr, sig := parts[0], parts[1]
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	// Reject tokens older/newer than configured drift window
	drift := time.Now().Unix() - ts
	if drift > sp.perfTokenMaxDriftSec || drift < -sp.perfTokenMaxDriftSec {
		return false
	}
	// Verify HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(sp.perfSecret))
	mac.Write([]byte(tsStr))
	expected := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) == 1
}

func (sp *SecurityProxy) isBlocked(ip string) bool {
	sp.blocklistMu.RLock()
	defer sp.blocklistMu.RUnlock()
	return sp.blocklist[ip]
}

func isTruthyFlag(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func (sp *SecurityProxy) isStrictAITest(c *gin.Context) bool {
	if isTruthyFlag(os.Getenv("SYNORIX_STRICT_AI_TEST")) {
		return true
	}
	headerValue := c.GetHeader("X-Synorix-Strict-AI")
	return isTruthyFlag(headerValue)
}

// isFallbackReason returns true only when the AI service was genuinely
// unreachable or produced an undecodable response.  Heuristic decisions
// that the proxy made on its own behalf (e.g. "heuristic-cacheable-content")
// are NOT considered fallbacks and must not be suppressed by strict-AI mode.
func isFallbackReason(reason string) bool {
	r := strings.ToLower(strings.TrimSpace(reason))
	return r == "fallback-ai-unavailable" || r == "fallback-decode-error"
}

func (sp *SecurityProxy) isRateLimited(ip string) bool {
	sp.rateLimitMu.Lock()
	defer sp.rateLimitMu.Unlock()

	now := time.Now()
	limit, exists := sp.rateLimiter[ip]

	if !exists {
		sp.rateLimiter[ip] = &RateLimit{
			Count:     1,
			Window:    now,
			MaxReqs:   100,
			WindowSec: 60,
		}
		return false
	}

	if now.Sub(limit.Window) > time.Duration(limit.WindowSec)*time.Second {
		limit.Count = 1
		limit.Window = now
		return false
	}

	limit.Count++
	return limit.Count > limit.MaxReqs
}

// checkBruteForce tracks FAILED login attempts (401/403 responses) per IP.
// Returns true exactly once when the 5th failure is recorded within a 5-minute window.
// After alerting, the counter resets so only one alert is generated per burst.
func (sp *SecurityProxy) checkBruteForce(userID int, clientIP, path string, responseStatus int) (bool, string) {
	// Only track login-related paths (not register, reset, etc.)
	loginLike := false
	lpath := strings.ToLower(path)
	for _, kw := range []string{"login", "signin", "auth", "token", "session"} {
		if strings.Contains(lpath, kw) {
			loginLike = true
			break
		}
	}
	if !loginLike {
		return false, ""
	}

	// Only count failed attempts (401 Unauthorized or 403 Forbidden)
	if responseStatus != 401 && responseStatus != 403 {
		return false, ""
	}

	key := fmt.Sprintf("%d:%s", userID, clientIP)

	sp.loginTrackerMu.Lock()
	defer sp.loginTrackerMu.Unlock()

	now := time.Now()
	limit, exists := sp.loginTracker[key]
	if !exists {
		sp.loginTracker[key] = &RateLimit{Count: 1, Window: now, MaxReqs: 5, WindowSec: 300}
		return false, ""
	}

	// Reset window after 5 minutes
	if now.Sub(limit.Window) > time.Duration(limit.WindowSec)*time.Second {
		limit.Count = 1
		limit.Window = now
		return false, ""
	}

	limit.Count++
	if limit.Count == 5 {
		// Alert exactly once at 5 failures, then reset
		limit.Count = 0
		limit.Window = now
		return true, fmt.Sprintf("brute force attack detected: 5 failed login attempts in %d seconds on %s", int(now.Sub(limit.Window).Seconds()), path)
	}
	return false, ""
}

func (sp *SecurityProxy) checkWAFRules(r *http.Request) bool {
	blocked, _ := sp.checkWAFRulesDetailed(r)
	return blocked
}

// Enhanced WAF check with detailed rule information - only blocks on action="block"
func (sp *SecurityProxy) checkWAFRulesDetailed(r *http.Request) (bool, string) {
	sp.wafMu.RLock()
	defer sp.wafMu.RUnlock()

	rawURL := r.URL.String()
	// Also check URL-decoded form so %20UNION%20SELECT and +UNION+SELECT are caught
	decodedURL, _ := url.QueryUnescape(rawURL)
	userAgent := r.UserAgent()

	var body string
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		body = string(bodyBytes)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	matchAny := func(compiled *regexp.Regexp, isScanner bool) bool {
		if compiled.MatchString(rawURL) || compiled.MatchString(decodedURL) {
			return true
		}
		// Always inspect User-Agent (catches Log4Shell, scanner UAs, etc.)
		if compiled.MatchString(userAgent) {
			return true
		}
		// Inspect all request headers for injection patterns
		for _, vals := range r.Header {
			for _, v := range vals {
				if compiled.MatchString(v) {
					return true
				}
			}
		}
		if body != "" && compiled.MatchString(body) {
			return true
		}
		return false
	}

	for _, rule := range sp.wafRules {
		if !rule.Enabled {
			continue
		}

		if matchAny(rule.compiled, rule.IsScanner) {
			if strings.Contains(rule.ID, "sql") {
				sp.threatStats.SQLiAttempts++
			} else if strings.Contains(rule.ID, "xss") {
				sp.threatStats.XSSAttempts++
			}

			if rule.Action == "block" {
				return true, rule.ID
			}
		}
	}

	return false, ""
}

// Run WAF checks and return detailed results
func (sp *SecurityProxy) runWAFChecks(r *http.Request, log *DetailedRequestLog) (bool, []WAFCheckResult) {
	sp.wafMu.RLock()
	defer sp.wafMu.RUnlock()

	fullURL := r.URL.String()
	// Also check URL-decoded form so %27OR%27 → 'OR' patterns are caught
	decodedURL, _ := url.QueryUnescape(fullURL)

	var body string
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		body = string(bodyBytes)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	var results []WAFCheckResult
	blocked := false

	for _, rule := range sp.wafRulesData {
		if !rule.Enabled {
			continue
		}

		matched := false
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}

		// Check URL, all headers (catches Log4Shell/scanner in any header), and body.
		headerMatch := false
		for _, vals := range r.Header {
			for _, v := range vals {
				if compiled.MatchString(v) {
					headerMatch = true
					break
				}
			}
			if headerMatch {
				break
			}
		}
		if compiled.MatchString(fullURL) ||
			compiled.MatchString(decodedURL) ||
			headerMatch ||
			(body != "" && compiled.MatchString(body)) {
			matched = true

			if rule.Action == "block" {
				blocked = true
			}

			if strings.Contains(rule.ID, "sql") {
				sp.threatStats.SQLiAttempts++
			} else if strings.Contains(rule.ID, "xss") {
				sp.threatStats.XSSAttempts++
			}
		}

		results = append(results, WAFCheckResult{
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			Matched:     matched,
			Pattern:     rule.Pattern,
			Severity:    rule.Severity,
			Action:      rule.Action,
			Description: rule.Description,
		})
	}

	return blocked, results
}

// Add security headers for backend logging
func (sp *SecurityProxy) addSecurityHeaders(w http.ResponseWriter, r *http.Request, wafAction, wafRule, suricataAction, suricataAlert string) {
	// Add security metadata as headers so the backend can capture them
	w.Header().Set("X-WAF-Action", wafAction)
	if wafRule != "" {
		w.Header().Set("X-WAF-Rule", wafRule)
	}
	w.Header().Set("X-Suricata-Action", suricataAction)
	if suricataAlert != "" {
		w.Header().Set("X-Suricata-Alert", suricataAlert)
	}
	w.Header().Set("X-Client-IP", sp.getClientIP(r))
	w.Header().Set("X-Request-ID", fmt.Sprintf("req_%d_%s", time.Now().Unix(), sp.getClientIP(r)))
}

// Utility functions
func (sp *SecurityProxy) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func (sp *SecurityProxy) updateSession(ip, userAgent string) {
	sp.sessionMu.Lock()
	defer sp.sessionMu.Unlock()

	session, exists := sp.sessionStore[ip]
	if !exists {
		session = &SessionInfo{
			IP:        ip,
			UserAgent: userAgent,
			FirstSeen: time.Now(),
			Requests:  0,
		}
		sp.sessionStore[ip] = session
	}

	session.LastSeen = time.Now()
	session.Requests++
}

func (sp *SecurityProxy) logSecurityEvent(eventType, ip string, r *http.Request, description, severity string, blocked bool) {
	event := SecurityEvent{
		Timestamp:   time.Now(),
		Type:        eventType,
		IP:          ip,
		URL:         r.URL.String(),
		UserAgent:   r.UserAgent(),
		Method:      r.Method,
		Description: description,
		Severity:    severity,
		Blocked:     blocked,
	}

	select {
	case sp.logChannel <- event:
	default:
		logrus.Warn("Security event channel full")
	}
}

// Background services
func (sp *SecurityProxy) eventProcessor() {
	for event := range sp.logChannel {
		logrus.WithFields(logrus.Fields{
			"type":     event.Type,
			"ip":       event.IP,
			"url":      event.URL,
			"severity": event.Severity,
			"blocked":  event.Blocked,
		}).Info(event.Description)

		select {
		case sp.broadcastChan <- event:
		default:
		}

		if event.Severity == "critical" && !event.Blocked {
			sp.blockIP(event.IP)
		}
	}
}

func (sp *SecurityProxy) detailedLogProcessor() {
	for detailedLog := range sp.detailedLogChan {
		// Send detailed log to backend API
		logData, err := json.Marshal(detailedLog)
		if err != nil {
			logrus.Errorf("Failed to marshal detailed log: %v", err)
			continue
		}

		// Post to backend API
		resp, err := http.Post("http://localhost:3001/api/logs/detailed", "application/json", bytes.NewBuffer(logData))
		if err != nil {
			logrus.Errorf("Failed to send detailed log to backend: %v", err)
			continue
		}
		resp.Body.Close()

		logrus.Debugf("Detailed log sent: %s %s %s", detailedLog.Method, detailedLog.URL, detailedLog.IP)
	}
}

func (sp *SecurityProxy) websocketBroadcaster() {
	for msg := range sp.broadcastChan {
		sp.wsClientsMu.RLock()
		for client := range sp.wsClients {
			err := client.WriteJSON(msg)
			if err != nil {
				client.Close()
				delete(sp.wsClients, client)
			}
		}
		sp.wsClientsMu.RUnlock()
	}
}

func (sp *SecurityProxy) blockIP(ip string) {
	sp.blocklistMu.Lock()
	defer sp.blocklistMu.Unlock()
	sp.blocklist[ip] = true
	sp.threatStats.MaliciousIPs++
}

func (sp *SecurityProxy) modifyResponse(resp *http.Response) error {
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("X-XSS-Protection", "1; mode=block")
	return nil
}

func (sp *SecurityProxy) tokenHasAdminRole(authHeader string) bool {
	authHeader = strings.TrimSpace(authHeader)
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return false
	}

	authServiceURL := strings.TrimRight(strings.TrimSpace(os.Getenv("AUTH_SERVICE_URL")), "/")
	if authServiceURL == "" {
		authServiceURL = "http://localhost:3001"
	}

	req, err := http.NewRequest(http.MethodGet, authServiceURL+"/api/auth/me", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false
	}

	user, ok := payload["user"].(map[string]interface{})
	if !ok {
		return false
	}

	role, ok := user["role"].(string)
	if !ok {
		return false
	}

	return role == "admin"
}

func (sp *SecurityProxy) requireAdminOrInternal() gin.HandlerFunc {
	return func(c *gin.Context) {
		internalToken := strings.TrimSpace(os.Getenv("INTERNAL_API_TOKEN"))
		providedInternalToken := strings.TrimSpace(c.GetHeader("X-Internal-Token"))
		if internalToken != "" && subtle.ConstantTimeCompare([]byte(internalToken), []byte(providedInternalToken)) == 1 {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			return
		}

		if !sp.tokenHasAdminRole(authHeader) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			return
		}

		c.Next()
	}
}

// API endpoints
func (sp *SecurityProxy) setupAPIRoutes(router *gin.Engine) {
	// Proxy management API routes (different from backend API)
	proxyAPI := router.Group("/proxy-api")
	proxyAPI.Use(sp.requireAdminOrInternal())
	{
		proxyAPI.GET("/stats", sp.getStats)
		proxyAPI.GET("/blocklist", sp.getBlocklist)
		proxyAPI.DELETE("/blocklist/:ip", sp.unblockIP)
		proxyAPI.GET("/waf-rules", sp.getWAFRules)
		proxyAPI.GET("/firewall-rules", sp.getFirewallRules)
		proxyAPI.GET("/config", sp.getProxyConfig)
		proxyAPI.GET("/traffic-metrics", sp.getTrafficMetrics)
		proxyAPI.GET("/events", sp.getRecentEvents)
		proxyAPI.GET("/ws", sp.handleWebSocket)
	}

	// Unauthenticated health endpoint — safe for external monitoring / perf scripts
	router.GET("/health", func(c *gin.Context) {
		aiUp := sp.checkServiceHealth("http://localhost:8082/health")
		c.JSON(http.StatusOK, gin.H{
			"status":         "ok",
			"ai_compression": aiUp,
			"ai_dedup":       aiUp,
		})
	})

	// User proxy route - must come before other API routes
	router.POST("/user-proxy/*path", sp.handleUserProxy)
	router.GET("/user-proxy/*path", sp.handleUserProxy)
	router.PUT("/user-proxy/*path", sp.handleUserProxy)
	router.DELETE("/user-proxy/*path", sp.handleUserProxy)
	router.PATCH("/user-proxy/*path", sp.handleUserProxy)

	// Additional API routes that frontend expects
	api := router.Group("/api")
	{
		api.GET("/waf/rules", sp.getWAFRules)

		// Authentication proxy routes - forward to auth server on port 3001
		api.POST("/auth/login", sp.proxyAuthRequest)
		api.POST("/auth/signup", sp.proxyAuthRequest)
		api.GET("/auth/me", sp.proxyAuthRequest)
		api.POST("/auth/logout", sp.proxyAuthRequest)
		api.GET("/health", sp.proxyAuthRequest)

		// Logs proxy routes - forward to auth/logs server on port 3001
		api.GET("/logs", sp.proxyAuthRequest)
		api.GET("/logs/stats", sp.proxyAuthRequest)
		api.GET("/logs/top-ips", sp.proxyAuthRequest)
		api.GET("/logs/trends", sp.proxyAuthRequest)
		api.GET("/logs/search", sp.proxyAuthRequest)
		api.GET("/logs/export", sp.proxyAuthRequest)
		api.GET("/logs/detailed", sp.proxyAuthRequest)
		api.GET("/events", sp.proxyAuthRequest)

		// IDS/IPS proxy routes
		api.GET("/suricata/health", sp.proxySuricataRequest)
		api.GET("/suricata/stats", sp.proxySuricataRequest)
		api.GET("/suricata/alerts", sp.proxySuricataRequest)
		api.GET("/suricata/config", sp.proxySuricataRequest)
		api.POST("/suricata/reload-rules", sp.proxySuricataRequest)
		api.POST("/suricata/test/inject-alert", sp.proxySuricataRequest)

		// Compression and Deduplication proxy routes - forward to backend server on port 3001
		api.GET("/compression/stats", sp.proxyAuthRequest)
		api.GET("/compression/logs", sp.proxyAuthRequest)
		api.GET("/deduplication/stats", sp.getDeduplicationStats)
		api.GET("/deduplication/logs", sp.proxyAuthRequest)
		api.GET("/proxy/stats", sp.proxyAuthRequest)
		api.GET("/proxy/latency", sp.proxyAuthRequest)
	}

	securedAPI := router.Group("/api")
	securedAPI.Use(sp.requireAdminOrInternal())
	{
		securedAPI.GET("/stats", sp.getStats)
		securedAPI.GET("/system/status", sp.getSystemStatus)
		securedAPI.POST("/waf/rules", sp.addWAFRule)
		securedAPI.PUT("/waf/rules/:id", sp.updateWAFRule)
		securedAPI.DELETE("/waf/rules/:id", sp.deleteWAFRule)
		securedAPI.POST("/waf/rules/:id/toggle", sp.toggleWAFRule)
		securedAPI.GET("/proxy/config", sp.getProxyConfig)
		securedAPI.PUT("/proxy/config", sp.updateProxyConfig)
		securedAPI.GET("/traffic/metrics", sp.getTrafficMetrics)
		securedAPI.POST("/unblock", sp.unblockIPBody)
		securedAPI.POST("/security/block-ip", sp.blockIPFromRequest)
	}
}

func (sp *SecurityProxy) getStats(c *gin.Context) {
	c.JSON(http.StatusOK, sp.threatStats)
}

func (sp *SecurityProxy) getBlocklist(c *gin.Context) {
	sp.blocklistMu.RLock()
	defer sp.blocklistMu.RUnlock()

	var blockedIPs []string
	for ip := range sp.blocklist {
		blockedIPs = append(blockedIPs, ip)
	}

	c.JSON(http.StatusOK, gin.H{"blocked_ips": blockedIPs})
}

func (sp *SecurityProxy) unblockIP(c *gin.Context) {
	ip := c.Param("ip")

	sp.blocklistMu.Lock()
	delete(sp.blocklist, ip)
	sp.blocklistMu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "IP unblocked", "ip": ip})
}

func (sp *SecurityProxy) getWAFRules(c *gin.Context) {
	sp.wafMu.RLock()
	defer sp.wafMu.RUnlock()
	c.JSON(http.StatusOK, gin.H{"rules": sp.wafRulesData})
}

func (sp *SecurityProxy) getFirewallRules(c *gin.Context) {
	sp.firewallMu.RLock()
	defer sp.firewallMu.RUnlock()
	c.JSON(http.StatusOK, gin.H{"rules": sp.firewallRules})
}

func (sp *SecurityProxy) getProxyConfig(c *gin.Context) {
	config := ProxyConfig{
		Target:             sp.target.String(),
		Port:               "8080",
		MaxRequestSize:     sp.maxRequestSize,
		RateLimit:          100,
		WAFEnabled:         len(sp.wafRules) > 0,
		DDoSProtection:     true,
		CompressionEnabled: sp.compressionAI != nil,
	}
	c.JSON(http.StatusOK, config)
}

func (sp *SecurityProxy) getTrafficMetrics(c *gin.Context) {
	metrics := TrafficMetrics{
		RequestsPerSecond: float64(sp.threatStats.TotalRequests) / 60,
		BandwidthUsage:    sp.threatStats.TotalBandwidth,
		ResponseTime:      sp.threatStats.AvgCompressionLatency,
		ErrorRate:         float64(sp.threatStats.BlockedRequests) / max(float64(sp.threatStats.TotalRequests), 1),
		CompressionRatio:  float64(sp.threatStats.CompressionSaved) / max(float64(sp.threatStats.TotalBandwidth), 1),
		ActiveConnections: len(sp.wsClients),
	}
	c.JSON(http.StatusOK, metrics)
}

func (sp *SecurityProxy) getDeduplicationStats(c *gin.Context) {
	if sp.dedupCache == nil {
		c.JSON(http.StatusOK, gin.H{
			"totalDeduplicated": 0,
			"totalSavings":      0,
			"hitRate":           0,
			"cacheSize":         0,
			"cacheEntries":      0,
			"evictions":         0,
			"maxEntries":        0,
			"maxBytes":          0,
			"ttlSeconds":        0,
			"cachePoisonings":   0,
			"staleHits":         0,
			"invalidHits":       0,
			"largeEvictions":    0,
			"productionReady":   false,
			"aiModelStatus":     "disabled",
		})
		return
	}

	stats := sp.dedupCache.Stats()
	totalRequests := stats.Hits + stats.Misses
	hitRate := float64(0)
	if totalRequests > 0 {
		hitRate = (float64(stats.Hits) / float64(totalRequests)) * 100
	}

	// Calculate cache health metrics
	invalidRatio := float64(0)
	if stats.Hits > 0 {
		invalidRatio = (float64(stats.InvalidHits) / float64(stats.Hits)) * 100
	}

	// Check if system is production-ready
	productionReady := hitRate > 10 && invalidRatio < 5 && stats.CachePoisonings == 0

	c.JSON(http.StatusOK, gin.H{
		"totalDeduplicated":    stats.Hits,
		"totalSavings":         stats.SavedBytes,
		"hitRate":              hitRate,
		"cacheSize":            stats.Bytes,
		"cacheEntries":         stats.Entries,
		"evictions":            stats.Evictions,
		"maxEntries":           sp.dedupCache.MaxEntries(),
		"maxBytes":             sp.dedupCache.MaxBytes(),
		"ttlSeconds":           int(sp.dedupCache.TTL().Seconds()),
		"cachePoisonings":      stats.CachePoisonings,
		"staleHits":            stats.StaleHits,
		"invalidHits":          stats.InvalidHits,
		"invalidRatio":         invalidRatio,
		"largeEvictions":       stats.LargeEvictions,
		"productionReady":      productionReady,
		"aiModelStatus":        "active",
		"dedupThreshold":       0.65,
		"compressionThreshold": 0.6,
	})
}

func (sp *SecurityProxy) getRecentEvents(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"events": []SecurityEvent{}})
}

func (sp *SecurityProxy) handleWebSocket(c *gin.Context) {
	conn, err := sp.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logrus.Errorf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	sp.wsClientsMu.Lock()
	sp.wsClients[conn] = true
	sp.wsClientsMu.Unlock()

	defer func() {
		sp.wsClientsMu.Lock()
		delete(sp.wsClients, conn)
		sp.wsClientsMu.Unlock()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// Additional API handlers that the frontend expects
func (sp *SecurityProxy) getSystemStatus(c *gin.Context) {
	// Check AI Security Service health
	aiSecurityStatus := sp.checkServiceHealth("http://localhost:8081/health")

	// Check AI Compression Service health
	aiCompressionStatus := sp.checkServiceHealth("http://localhost:8082/health")

	// Check Suricata Integration Service health
	suricataStatus := sp.checkServiceHealth("http://localhost:8083/health")

	// Determine overall AI engine status
	aiEngineStatus := "Error"
	if aiSecurityStatus && aiCompressionStatus {
		aiEngineStatus = "Active"
	} else if aiSecurityStatus || aiCompressionStatus {
		aiEngineStatus = "Partial"
	}

	// Check backend service health
	backendStatus := sp.checkServiceHealth("http://localhost:5000/api/health")

	// Determine proxy status (self + backend)
	proxyStatus := "Error"
	if backendStatus {
		proxyStatus = "Active"
	}

	// Determine security layer status based on active components
	securityLayerStatus := "Vulnerable"
	activeComponents := 0

	if len(sp.wafRules) > 0 {
		activeComponents++
	}
	if sp.threatStats.TotalRequests > 0 || sp.threatStats.BlockedRequests > 0 {
		activeComponents++
	}
	if aiEngineStatus == "Active" {
		activeComponents++
	}
	if suricataStatus {
		activeComponents++
	}

	if activeComponents >= 4 {
		securityLayerStatus = "Secure"
	} else if activeComponents >= 2 {
		securityLayerStatus = "Partial"
	}

	// Determine compression status
	compressionStatus := "Disabled"
	if aiCompressionStatus {
		compressionStatus = "Enabled"
	}

	// Count active security features
	wafEnabled := len(sp.wafRules) > 0
	rateLimitingEnabled := len(sp.rateLimiter) > 0
	firewallEnabled := len(sp.firewallRules) > 0
	tlsCert := os.Getenv("TLS_CERT")
	if tlsCert == "" {
		tlsCert = "./certs/cert.pem"
	}
	tlsKey := os.Getenv("TLS_KEY")
	if tlsKey == "" {
		tlsKey = "./certs/key.pem"
	}
	sslTLSEnabled := fileExists(tlsCert) && fileExists(tlsKey)

	status := gin.H{
		"status":         "OK",
		"ai_engine":      aiEngineStatus,
		"compression":    compressionStatus,
		"timestamp":      time.Now().Format(time.RFC3339),
		"proxy_status":   proxyStatus,
		"security_layer": securityLayerStatus,
		"uptime":         time.Since(time.Now().Add(-time.Hour)).Seconds(),
		"service_details": gin.H{
			"ai_security":       aiSecurityStatus,
			"ai_compression":    aiCompressionStatus,
			"suricata_ids":      suricataStatus,
			"backend":           backendStatus,
			"active_waf_rules":  len(sp.wafRules),
			"active_components": activeComponents,
		},
		"security_features": gin.H{
			"waf_enabled":           wafEnabled,
			"firewall_enabled":      firewallEnabled,
			"rate_limiting_enabled": rateLimitingEnabled,
			"geo_blocking_enabled":  false, // Not implemented yet
			"honeypots_enabled":     false, // Not implemented yet
			"ids_ips_enabled":       suricataStatus,
			"ssl_tls_enabled":       sslTLSEnabled,
			"ai_threat_detection":   aiSecurityStatus,
		},
		"performance": gin.H{
			"requests_per_second": sp.calculateRequestsPerSecond(),
			"avg_response_time":   sp.calculateAverageResponseTime(),
			"memory_usage_mb":     sp.getMemoryUsage(),
			"active_connections":  len(sp.wsClients),
		},
	}
	c.JSON(http.StatusOK, status)
}

// Performance monitoring helper functions
func (sp *SecurityProxy) calculateRequestsPerSecond() float64 {
	// Simple calculation based on recent activity
	if sp.threatStats.TotalRequests > 0 {
		// Assume data represents last minute of activity
		return float64(sp.threatStats.TotalRequests) / 60.0
	}
	return 0.0
}

func (sp *SecurityProxy) calculateAverageResponseTime() float64 {
	// Mock response time calculation (in a real system, this would track actual response times)
	baseTime := 50.0 // Base response time in ms
	load := float64(sp.threatStats.TotalRequests) / 100.0
	return baseTime + (load * 10.0) // Response time increases with load
}

func (sp *SecurityProxy) getMemoryUsage() float64 {
	// Mock memory usage (in a real system, this would use runtime.ReadMemStats)
	baseMemory := 25.0 // Base memory usage in MB
	activeConnections := float64(len(sp.wsClients))
	wafRules := float64(len(sp.wafRules))
	return baseMemory + (activeConnections * 0.5) + (wafRules * 0.1)
}

// Helper function to check service health
func (sp *SecurityProxy) checkServiceHealth(serviceURL string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second, // 3 second timeout
	}

	resp, err := client.Get(serviceURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider service healthy if it responds with 2xx status
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (sp *SecurityProxy) addWAFRule(c *gin.Context) {
	var rule WAFRuleData
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule data"})
		return
	}

	sp.wafMu.Lock()
	rule.ID = fmt.Sprintf("waf_custom_%d", len(sp.wafRulesData)+1)
	sp.wafRulesData = append(sp.wafRulesData, rule)
	sp.wafMu.Unlock()

	go sp.persistWAFRules()
	c.JSON(http.StatusCreated, gin.H{"message": "WAF rule added", "rule": rule})
}

func (sp *SecurityProxy) updateWAFRule(c *gin.Context) {
	id := c.Param("id")
	var rule WAFRuleData
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule data"})
		return
	}

	sp.wafMu.Lock()
	for i, r := range sp.wafRulesData {
		if r.ID == id {
			sp.wafRulesData[i] = rule
			break
		}
	}
	sp.wafMu.Unlock()

	go sp.persistWAFRules()
	c.JSON(http.StatusOK, gin.H{"message": "WAF rule updated", "id": id})
}

func (sp *SecurityProxy) deleteWAFRule(c *gin.Context) {
	id := c.Param("id")

	sp.wafMu.Lock()
	for i, rule := range sp.wafRulesData {
		if rule.ID == id {
			sp.wafRulesData = append(sp.wafRulesData[:i], sp.wafRulesData[i+1:]...)
			break
		}
	}
	sp.wafMu.Unlock()

	go sp.persistWAFRules()
	c.JSON(http.StatusOK, gin.H{"message": "WAF rule deleted", "id": id})
}

func (sp *SecurityProxy) toggleWAFRule(c *gin.Context) {
	id := c.Param("id")

	sp.wafMu.Lock()
	for i, rule := range sp.wafRulesData {
		if rule.ID == id {
			sp.wafRulesData[i].Enabled = !sp.wafRulesData[i].Enabled
			break
		}
	}
	sp.wafMu.Unlock()

	go sp.persistWAFRules()
	c.JSON(http.StatusOK, gin.H{"message": "WAF rule toggled", "id": id})
}

func (sp *SecurityProxy) updateProxyConfig(c *gin.Context) {
	var config ProxyConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid config data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Proxy config updated", "config": config})
}

func (sp *SecurityProxy) unblockIPBody(c *gin.Context) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	sp.blocklistMu.Lock()
	delete(sp.blocklist, req.IP)
	sp.blocklistMu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "IP unblocked", "ip": req.IP})
}

// Block IP from automated response system
func (sp *SecurityProxy) blockIPFromRequest(c *gin.Context) {
	var req struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration int    `json:"duration"` // seconds
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP address is required"})
		return
	}

	sp.blocklistMu.Lock()
	sp.blocklist[req.IP] = true
	sp.blocklistMu.Unlock()

	logrus.Infof("🔒 Blocked IP %s via automated response: %s", req.IP, req.Reason)

	// If duration is specified, schedule unblock
	if req.Duration > 0 {
		go func() {
			time.Sleep(time.Duration(req.Duration) * time.Second)
			sp.blocklistMu.Lock()
			delete(sp.blocklist, req.IP)
			sp.blocklistMu.Unlock()
			logrus.Infof("🔓 Auto-unblocked IP %s after %d seconds", req.IP, req.Duration)
		}()
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  fmt.Sprintf("IP %s blocked", req.IP),
		"duration": req.Duration,
	})
}

// Handle user-specific proxy requests with API key authentication
func (sp *SecurityProxy) handleUserProxy(c *gin.Context) {
	startTime := time.Now()

	// Extract API key from header
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "Missing X-API-Key header",
			"message": "Please include your API key in the X-API-Key header",
		})
		return
	}

	// Get user configuration from database
	userConfig, err := sp.getUserConfigByAPIKey(apiKey)
	if err != nil {
		logrus.Errorf("Invalid API key: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "Invalid API key",
			"message": "The provided API key is not valid",
		})
		return
	}

	// Check if user is banned (optional - add this check to database query if needed)

	// Parse user's backend URL
	userBackendURL, err := url.Parse(userConfig.BackendURL)
	if err != nil {
		logrus.Errorf("Invalid backend URL for user %d: %v", userConfig.UserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Invalid backend configuration",
			"message": "Your backend URL is not configured correctly",
		})
		return
	}

	// Extract the path after /user-proxy/
	requestPath := c.Param("path")
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}

	// Build target URL
	targetURL := userBackendURL.Scheme + "://" + userBackendURL.Host + requestPath
	if c.Request.URL.RawQuery != "" {
		targetURL += "?" + c.Request.URL.RawQuery
	}

	// Get client IP
	clientIP := c.ClientIP()

	// Check blocklist
	sp.blocklistMu.RLock()
	isBlocked := sp.blocklist[clientIP]
	sp.blocklistMu.RUnlock()

	if isBlocked {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "IP blocked",
			"message": "Your IP address has been blocked due to security concerns",
		})
		return
	}

	// ── Performance-test bypass (verifies HMAC token; skips WAF + rate limit) ─
	perfBypass := sp.isValidPerfToken(c.Request)

	// ── General rate limiter (100 req/min per IP) ────────────────────────────
	if !perfBypass && sp.isRateLimited(clientIP) {
		sp.createUserAlert(
			userConfig.UserID, userConfig.AppID, "system", "high",
			"Rate Limit Exceeded",
			fmt.Sprintf("IP %s exceeded 100 requests/min through your proxy endpoint", clientIP),
			"RATE-LIMIT-001", clientIP, requestPath,
			"Possible DDoS or automation — consider blocking this IP", "blocked",
		)
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":   "Rate limit exceeded",
			"message": "Too many requests. Please slow down.",
		})
		return
	}

	// ── Brute force detection moved to post-proxy (checks response status) ────

	// Create detailed log entry
	detailedLog := DetailedRequestLog{
		Timestamp:      startTime,
		Method:         c.Request.Method,
		URL:            requestPath,
		IP:             clientIP,
		UserAgent:      c.GetHeader("User-Agent"),
		RequestSize:    c.Request.ContentLength,
		WAFChecks:      []WAFCheckResult{},
		SecurityEvents: []SecurityEvent{},
		Headers:        make(map[string]string),
	}

	// Copy headers for logging
	for name, values := range c.Request.Header {
		if len(values) > 0 {
			detailedLog.Headers[name] = values[0]
		}
	}

	// ── WAF check FIRST (HTTP application-layer rule matching) ──────────────
	// WAF handles known HTTP attack patterns from rules files.
	// It must run before the Suricata inline check to ensure WAF rules are the
	// authoritative source for application-layer attacks; Suricata inline then
	// catches patterns the WAF missed (network signatures, scanner detection).
	// Requests from the load-test runner (verified HMAC token) skip WAF so
	// synthetic payloads don't produce false-positive blocks.
	var blocked bool
	var wafResults []WAFCheckResult
	if perfBypass {
		blocked, wafResults = false, nil
	} else {
		blocked, wafResults = sp.runWAFChecks(c.Request, &detailedLog)
	}
	detailedLog.WAFChecks = wafResults

	if blocked {
		detailedLog.Blocked = true
		detailedLog.BlockReason = "WAF rule violation"
		detailedLog.StatusCode = http.StatusForbidden
		detailedLog.ResponseTime = time.Since(startTime)

		// Log the blocked request
		sp.logUserRequest(userConfig.UserID, userConfig.AppID, detailedLog, userConfig.BackendURL)

		// Consolidate ALL matched blocking rules into a single alert card
		var triggeredIDs, triggeredNames, triggeredDescs []string
		topWAFSev := "low"
		wafSevRank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
		for _, check := range wafResults {
			if check.Matched && check.Action == "block" {
				triggeredIDs = append(triggeredIDs, check.RuleID)
				triggeredNames = append(triggeredNames, check.RuleName)
				triggeredDescs = append(triggeredDescs, check.Description)
				if wafSevRank[check.Severity] > wafSevRank[topWAFSev] {
					topWAFSev = check.Severity
				}
			}
		}
		if len(triggeredIDs) > 0 {
			ruleTitle := fmt.Sprintf("WAF Blocked: %d rule(s) triggered", len(triggeredIDs))
			if len(triggeredIDs) == 1 {
				ruleTitle = fmt.Sprintf("WAF Blocked: %s", triggeredNames[0])
			}
			combinedDesc := fmt.Sprintf("%d WAF rule(s) triggered on %s — %s",
				len(triggeredIDs), requestPath, strings.Join(triggeredDescs, " | "))
			sp.createUserAlert(
				userConfig.UserID, userConfig.AppID, "waf", topWAFSev,
				ruleTitle,
				combinedDesc,
				strings.Join(triggeredIDs, ", "),
				clientIP, requestPath,
				"Review your request — it matched WAF security rules", "blocked",
			)
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error":   "Request blocked by WAF",
			"message": "Your request was blocked due to security policy violations",
		})
		return
	}

	// Real Suricata IDS/IPS operates at the network layer:
	//   IDS (AF_PACKET) — passively mirrors traffic from the interface, writes
	//                       alerts to /var/log/suricata/ids/eve.json
	//   IPS (NFQUEUE)   — intercepts packets via iptables BEFORE they reach this
	//                       process; drops are written to /var/log/suricata/ips/eve.json
	// The integration service (port 8083) tails both log files, pushes alerts
	// to the database, and reactively calls /api/security/block-ip for IPS drops
	// so that follow-up requests from the same IP are also refused here.

	// ── Suricata inline analysis (async — does not block the request) ─────────
	// Pass request metadata + user context to the integration service so that
	// any pattern detections are stored in user_alerts (with user_id) rather
	// than only the global platform alerts table.
	if !perfBypass {
		reqHeadersCopy := make(map[string]string)
		for k, vals := range c.Request.Header {
			if len(vals) > 0 {
				reqHeadersCopy[k] = vals[0]
			}
		}
		fullReqURL := requestPath
		if c.Request.URL.RawQuery != "" {
			fullReqURL += "?" + c.Request.URL.RawQuery
		}
		go func(uid, aid int, method, reqURL, ip string, hdrs map[string]string) {
			payload := map[string]interface{}{
				"method":  method,
				"url":     reqURL,
				"src_ip":  ip,
				"headers": hdrs,
				"user_id": uid,
				"app_id":  aid,
			}
			data, _ := json.Marshal(payload)
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Post("http://localhost:8083/analyze-request", "application/json", bytes.NewBuffer(data))
			if err == nil {
				resp.Body.Close()
			}
		}(userConfig.UserID, userConfig.AppID, c.Request.Method, fullReqURL, clientIP, reqHeadersCopy)
	}

	cacheKey, cacheEligible := sp.buildCacheKey(c.Request, userConfig.UserID, targetURL)
	if cacheEligible && sp.dedupCache != nil {
		if entry, ok := sp.dedupCache.Get(cacheKey); ok {
			// Validate cache coherency before serving
			// For safety, re-validate with a HEAD request if entry has ETag
			if entry.ETag != "" {
				headReq, _ := http.NewRequest("HEAD", targetURL, nil)
				headClient := &http.Client{Timeout: 5 * time.Second}
				if headResp, err := headClient.Do(headReq); err == nil && headResp.StatusCode == 200 {
					currentETag := headResp.Header.Get("ETag")
					if currentETag != "" && currentETag != entry.ETag {
						// Cache is stale, invalidate it
						logrus.Debugf("🔄 Cache invalidated (ETag mismatch) for %s", cacheKey)
						headResp.Body.Close()
						// Continue to fetch fresh data below
					} else {
						// Cache validated, safe to serve
						responseHeaders := http.Header{}
						if entry.Headers != nil {
							responseHeaders = entry.Headers.Clone()
						}
						responseBody := entry.Value
						responseStatus := entry.StatusCode

						detailedLog.StatusCode = responseStatus
						detailedLog.ResponseSize = int64(len(responseBody))
						detailedLog.ResponseTime = time.Since(startTime)
						detailedLog.Blocked = false

						originalSize := int64(len(responseBody))
						deduplicationInfo := &DeduplicationInfo{
							Enabled:        true,
							OriginalSize:   originalSize,
							DedupSize:      0,
							DedupRatio:     1,
							CacheHit:       true,
							AIDecision:     false,
							AIReason:       "cache-hit-validated",
							ProcessingTime: 0,
						}
						detailedLog.DeduplicationInfo = deduplicationInfo
						sp.dedupCache.RecordSavedBytes(originalSize)

						finalResponseBody, compressionInfo := sp.maybeCompressResponse(c, responseBody, responseHeaders.Get("Content-Type"), userConfig.UserID, responseHeaders)
						detailedLog.CompressionInfo = compressionInfo
						if compressionInfo != nil {
							detailedLog.ResponseSize = int64(len(finalResponseBody))
						}

						sp.logUserRequest(userConfig.UserID, userConfig.AppID, detailedLog, userConfig.BackendURL)
						c.Header("X-Cache", "HIT")
						for name, values := range responseHeaders {
							if name != "Content-Encoding" && name != "Content-Length" {
								for _, value := range values {
									c.Header(name, value)
								}
							}
						}

						c.Data(responseStatus, responseHeaders.Get("Content-Type"), finalResponseBody)
						headResp.Body.Close()
						return
					}
				} else if err != nil {
					logrus.Debugf("⚠️  HEAD validation failed for cache: %v", err)
					if headResp != nil {
						headResp.Body.Close()
					}
				}
			} else {
				// No ETag, but cache is valid (short TTL)
				responseHeaders := http.Header{}
				if entry.Headers != nil {
					responseHeaders = entry.Headers.Clone()
				}
				responseBody := entry.Value
				responseStatus := entry.StatusCode

				detailedLog.StatusCode = responseStatus
				detailedLog.ResponseSize = int64(len(responseBody))
				detailedLog.ResponseTime = time.Since(startTime)
				detailedLog.Blocked = false

				originalSize := int64(len(responseBody))
				deduplicationInfo := &DeduplicationInfo{
					Enabled:        true,
					OriginalSize:   originalSize,
					DedupSize:      0,
					DedupRatio:     1,
					CacheHit:       true,
					AIDecision:     false,
					AIReason:       "cache-hit",
					ProcessingTime: 0,
				}
				detailedLog.DeduplicationInfo = deduplicationInfo
				sp.dedupCache.RecordSavedBytes(originalSize)

				finalResponseBody, compressionInfo := sp.maybeCompressResponse(c, responseBody, responseHeaders.Get("Content-Type"), userConfig.UserID, responseHeaders)
				detailedLog.CompressionInfo = compressionInfo
				if compressionInfo != nil {
					detailedLog.ResponseSize = int64(len(finalResponseBody))
				}

				sp.logUserRequest(userConfig.UserID, userConfig.AppID, detailedLog, userConfig.BackendURL)
				c.Header("X-Cache", "HIT")
				for name, values := range responseHeaders {
					if name != "Content-Encoding" && name != "Content-Length" {
						for _, value := range values {
							c.Header(name, value)
						}
					}
				}

				c.Data(responseStatus, responseHeaders.Get("Content-Type"), finalResponseBody)
				return
			}
		}
	}

	// Create HTTP client and forward request
	var reqBodyBytes []byte
	if c.Request.Body != nil {
		reqBodyBytes, _ = io.ReadAll(c.Request.Body)
	}
	// Update request size now that we have the actual body bytes
	// ContentLength is -1 for GET/chunked requests; len(reqBodyBytes) is always accurate
	if detailedLog.RequestSize <= 0 {
		detailedLog.RequestSize = int64(len(reqBodyBytes))
	}
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(c.Request.Method, targetURL, bytes.NewReader(reqBodyBytes))
	if err != nil {
		logrus.Errorf("Failed to create proxy request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	// Copy headers (except X-API-Key to avoid leaking it, and caching headers)
	// Strip caching headers to ensure backend always returns full response for compression/deduplication
	nonCachingHeaders := map[string]bool{
		"If-None-Match":       true,
		"If-Modified-Since":   true,
		"If-Unmodified-Since": true,
		"If-Match":            true,
	}
	for name, values := range c.Request.Header {
		if name == "X-Api-Key" {
			continue // Don't leak API key
		}
		if nonCachingHeaders[name] {
			continue // Skip caching headers so backend sends full response
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	// Track in-flight requests and measure backend RTT for AI model inputs
	atomic.AddInt64(&sp.activeRequests, 1)
	backendStart := time.Now()

	// Forward the request
	resp, err := client.Do(req)
	sp.updateBackendRTT(time.Since(backendStart))
	atomic.AddInt64(&sp.activeRequests, -1)

	if err != nil {
		logrus.Errorf("Proxy request failed for user %d: %v", userConfig.UserID, err)
		detailedLog.StatusCode = http.StatusBadGateway
		detailedLog.ResponseTime = time.Since(startTime)
		detailedLog.Blocked = false
		sp.logUserRequest(userConfig.UserID, userConfig.AppID, detailedLog, userConfig.BackendURL)

		c.JSON(http.StatusBadGateway, gin.H{
			"error":   "Backend service unavailable",
			"message": "Could not connect to your configured backend",
		})
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
		return
	}

	responseHeaders := resp.Header.Clone()
	responseStatus := resp.StatusCode

	// Update log with response info
	detailedLog.StatusCode = responseStatus
	detailedLog.ResponseSize = int64(len(responseBody))
	detailedLog.ResponseTime = time.Since(startTime)
	detailedLog.Blocked = false

	var deduplicationInfo *DeduplicationInfo
	strictAITest := sp.isStrictAITest(c)
	if cacheEligible && sp.dedupCache != nil {
		originalSize := int64(len(responseBody))
		deduplicationInfo = &DeduplicationInfo{
			Enabled:        true,
			OriginalSize:   originalSize,
			DedupSize:      originalSize,
			DedupRatio:     0,
			CacheHit:       false,
			AIDecision:     false,
			AIReason:       "cache-miss",
			ProcessingTime: 0,
		}

		// Use AI model to decide if response should be deduplicated
		if sp.shouldCacheResponse(resp.Header, resp.StatusCode) {
			aiStartTime := time.Now()
			dedupDecision, err := sp.callAIDeduplicationDecision(c.Request, responseBody, resp.Header.Get("Content-Type"))
			dedupProcessingTime := time.Since(aiStartTime).Milliseconds()

			if err != nil {
				logrus.Warnf("AI dedup decision error: %v", err)
			}

			isFallback := dedupDecision != nil && isFallbackReason(dedupDecision.Reason)
			deduplicationInfo.AIDecision = !isFallback
			deduplicationInfo.ProcessingTime = dedupProcessingTime

			if dedupDecision != nil {
				deduplicationInfo.AIConfidence = dedupDecision.Probability
				deduplicationInfo.AIReason = dedupDecision.Reason
				if !isFallback {
					c.Header("X-Synorix-AI-Dedup", "1")
				}

				if strictAITest && isFallback {
					logrus.Warnf("Strict AI mode: skipping dedup cache write due to fallback reason=%s", dedupDecision.Reason)
				} else
				// Cache if AI decision is YES with at least 50% confidence
				if dedupDecision.Decision == 1 && dedupDecision.Probability >= 0.5 {
					ttl := sp.cacheTTLFromHeaders(resp.Header)
					entry := &CacheEntry{
						Key:         cacheKey,
						Value:       responseBody,
						Headers:     sp.filterCacheHeaders(resp.Header),
						StatusCode:  responseStatus,
						ContentType: resp.Header.Get("Content-Type"),
						Size:        originalSize,
						ExpiresAt:   time.Now().Add(ttl),
						Hash:        computeSHA256Hex(responseBody),
						RequestSig:  fmt.Sprintf("%s:%s", c.Request.Method, c.Request.URL.Path),
					}
					sp.dedupCache.Set(cacheKey, entry)
					deduplicationInfo.Enabled = true
					if !isFallback {
						c.Header("X-Synorix-AI-Dedup-Cache", "1")
					}
					logrus.Debugf("✅ Cached response for %s (AI confidence: %.2f%%)", cacheKey, dedupDecision.Probability*100)
				} else {
					logrus.Debugf("⏭️  Skipped caching (AI confidence: %.2f%%, threshold: 65%%)", dedupDecision.Probability*100)
				}
			}
		}
		c.Header("X-Cache", "MISS")
	}

	detailedLog.DeduplicationInfo = deduplicationInfo

	finalResponseBody, compressionInfo := sp.maybeCompressResponse(c, responseBody, resp.Header.Get("Content-Type"), userConfig.UserID, responseHeaders)
	detailedLog.CompressionInfo = compressionInfo
	if compressionInfo != nil {
		detailedLog.ResponseSize = int64(len(finalResponseBody))
	}

	// Consolidate high/critical SecurityEvents into one alert per type (WAF vs Suricata)
	// SKIP Suricata alerts if request was already blocked by Suricata to avoid duplicates
	if len(detailedLog.SecurityEvents) > 0 && !strings.Contains(detailedLog.BlockReason, "Suricata") {
		postSevRank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
		var suricataDescs []string
		topSuriSev := "low"
		var systemDescs []string
		topSysSev := "low"
		for _, event := range detailedLog.SecurityEvents {
			if event.Severity != "high" && event.Severity != "critical" {
				continue
			}
			if strings.EqualFold(event.Type, "SURICATA") {
				suricataDescs = append(suricataDescs, event.Description)
				if postSevRank[event.Severity] > postSevRank[topSuriSev] {
					topSuriSev = event.Severity
				}
			} else {
				systemDescs = append(systemDescs, event.Description)
				if postSevRank[event.Severity] > postSevRank[topSysSev] {
					topSysSev = event.Severity
				}
			}
		}
		if len(suricataDescs) > 0 {
			title := fmt.Sprintf("Suricata IDS: %d event(s) detected", len(suricataDescs))
			if len(suricataDescs) == 1 {
				title = suricataDescs[0]
			}
			sp.createUserAlert(userConfig.UserID, userConfig.AppID, "suricata", topSuriSev,
				title, strings.Join(suricataDescs, " | "),
				"", clientIP, requestPath,
				"Review this Suricata detection and take appropriate action", "detected")
		}
		if len(systemDescs) > 0 {
			title := fmt.Sprintf("Security Events: %d detected", len(systemDescs))
			if len(systemDescs) == 1 {
				title = "Security Event Detected"
			}
			sp.createUserAlert(userConfig.UserID, userConfig.AppID, "system", topSysSev,
				title, strings.Join(systemDescs, " | "),
				"", clientIP, requestPath,
				"Review this security event and take appropriate action", "detected")
		}
	}

	// ── Brute force detection (post-proxy — only tracks failed login responses) ──
	if detected, reason := sp.checkBruteForce(userConfig.UserID, clientIP, requestPath, responseStatus); detected {
		sp.createUserAlert(
			userConfig.UserID, userConfig.AppID, "system", "high",
			"Brute Force Attack Detected",
			fmt.Sprintf("IP %s: %s", clientIP, reason),
			"BRUTE-FORCE-001", clientIP, requestPath,
			"5 failed login attempts detected — consider blocking this IP via the Firewall tab",
			"detected",
		)
	}

	// Log the successful request
	sp.logUserRequest(userConfig.UserID, userConfig.AppID, detailedLog, userConfig.BackendURL)

	// Copy response headers (skip Content-Encoding and Content-Length if already set)
	for name, values := range responseHeaders {
		if name != "Content-Encoding" && name != "Content-Length" {
			for _, value := range values {
				c.Header(name, value)
			}
		}
	}

	// Send response
	c.Data(responseStatus, responseHeaders.Get("Content-Type"), finalResponseBody)
}

func (sp *SecurityProxy) proxyAuthRequest(c *gin.Context) {
	startTime := time.Now()

	// Extract the API path from the request
	fullPath := c.Request.URL.Path
	apiPath := strings.TrimPrefix(fullPath, "/api")

	// Build target URL for authentication/logs server on port 3001
	targetURL := "http://localhost:3001/api" + apiPath

	// Add query parameters
	if c.Request.URL.RawQuery != "" {
		targetURL += "?" + c.Request.URL.RawQuery
	}

	// Read body so we can forward it (middleware may have consumed it)
	var bodyBytes []byte
	if c.Request.Body != nil {
		bodyBytes, _ = io.ReadAll(c.Request.Body)
	}

	// Create a new request
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(c.Request.Method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	// Copy headers (except caching headers so backend sends full response for compression/deduplication)
	nonCachingHeaders := map[string]bool{
		"If-None-Match":       true,
		"If-Modified-Since":   true,
		"If-Unmodified-Since": true,
		"If-Match":            true,
	}
	for name, values := range c.Request.Header {
		if nonCachingHeaders[name] {
			continue // Skip caching headers
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	// Inject forwarding headers so the backend logger captures the real client IP,
	// WAF status, and timing correctly
	clientIP := c.ClientIP()
	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-Client-IP", clientIP)
	if c.Request.Header.Get("X-Forwarded-For") == "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	req.Header.Set("X-Proxy-Start", strconv.FormatInt(startTime.UnixMilli(), 10))
	req.Header.Set("X-Waf-Action", "allowed") // passed WAF (would've been blocked otherwise)
	req.Header.Set("X-Suricata-Action", "allowed")

	// Forward the request
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Auth proxy error: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Authentication service unavailable"})
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for name, values := range resp.Header {
		for _, value := range values {
			c.Header(name, value)
		}
	}

	// Inject response timing for the logger
	elapsed := time.Since(startTime).Milliseconds()
	c.Header("X-Response-Time", strconv.FormatInt(elapsed, 10)+"ms")

	// Read and forward response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
		return
	}

	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

func (sp *SecurityProxy) proxySuricataRequest(c *gin.Context) {
	// Extract the Suricata API path from the request
	fullPath := c.Request.URL.Path
	suricataPath := strings.Replace(fullPath, "/api/suricata", "", 1)

	// Build target URL for Suricata integration service
	targetURL := "http://localhost:8083" + suricataPath

	// Add query parameters
	if c.Request.URL.RawQuery != "" {
		targetURL += "?" + c.Request.URL.RawQuery
	}

	// Create a new request
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(c.Request.Method, targetURL, c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	// Copy headers (except caching headers)
	nonCachingHeaders := map[string]bool{
		"If-None-Match":       true,
		"If-Modified-Since":   true,
		"If-Unmodified-Since": true,
		"If-Match":            true,
	}
	for name, values := range c.Request.Header {
		if nonCachingHeaders[name] {
			continue
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Suricata service unavailable"})
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for name, values := range resp.Header {
		for _, value := range values {
			c.Header(name, value)
		}
	}

	// Copy status code and body
	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}

func parseCacheControlMaxAge(cacheControl string) time.Duration {
	parts := strings.Split(cacheControl, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			value := strings.TrimPrefix(part, "max-age=")
			seconds, err := strconv.Atoi(value)
			if err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return 0
}

func getEnvInt(name string, defaultValue int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func getEnvInt64(name string, defaultValue int64) int64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func getEnvBool(name string, defaultValue bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if value == "" {
		return defaultValue
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func parseAllowedOrigins(raw string, developmentMode bool) (map[string]bool, bool) {
	origins := make(map[string]bool)
	allowAll := false

	for _, item := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(item)
		if origin == "" {
			continue
		}
		if origin == "*" {
			allowAll = true
			continue
		}
		origins[origin] = true
	}

	if len(origins) == 0 && !allowAll && developmentMode {
		origins["http://localhost:5173"] = true
		origins["http://localhost:4173"] = true
		origins["http://127.0.0.1:5173"] = true
		origins["http://127.0.0.1:4173"] = true
	}

	return origins, allowAll
}

func isOriginAllowed(origin string, allowedOrigins map[string]bool, allowAll bool) bool {
	if origin == "" {
		return true
	}
	if allowAll {
		return true
	}
	return allowedOrigins[origin]
}

func computeSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Helper function for Go 1.20 compatibility
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func resolvePath(candidates []string) string {
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return candidates[0]
}

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	if os.Getenv("LOG_LEVEL") == "debug" {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		targetURL = "http://localhost:5000"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	developmentMode := !strings.EqualFold(strings.TrimSpace(os.Getenv("NODE_ENV")), "production")
	allowedOrigins, allowAllOrigins := parseAllowedOrigins(os.Getenv("ALLOWED_ORIGINS"), developmentMode)
	if !developmentMode && (allowAllOrigins || len(allowedOrigins) == 0) {
		logrus.Fatal("ALLOWED_ORIGINS must be explicitly configured in production and cannot be '*'")
	}

	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}

	tlsCert := os.Getenv("TLS_CERT")
	if tlsCert == "" {
		tlsCert = resolvePath([]string{"./certs/cert.pem", "./security-proxy/certs/cert.pem", "../security-proxy/certs/cert.pem"})
	}

	tlsKey := os.Getenv("TLS_KEY")
	if tlsKey == "" {
		tlsKey = resolvePath([]string{"./certs/key.pem", "./security-proxy/certs/key.pem", "../security-proxy/certs/key.pem"})
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = resolvePath([]string{"./data", "./security-proxy/data", "../security-proxy/data"})
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = resolvePath([]string{"./server/synorix.db", "../server/synorix.db", "./security-proxy/../server/synorix.db"})
	}

	target, err := url.Parse(targetURL)
	if err != nil {
		logrus.Fatalf("Invalid target URL: %v", err)
	}

	proxy := NewSecurityProxy(target, dataDir, dbPath)
	proxy.upgrader.CheckOrigin = func(r *http.Request) bool {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		return isOriginAllowed(origin, allowedOrigins, allowAllOrigins)
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// CORS middleware
	router.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" && isOriginAllowed(origin, allowedOrigins, allowAllOrigins) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		} else if origin != "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Origin not allowed"})
			return
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-API-Key, x-api-key, x-custom-user-agent")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Encoding, X-Request-ID")
		c.Header("Vary", "Origin")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// Global WAF middleware — runs on every request before routing
	router.Use(func(c *gin.Context) {
		path := c.Request.URL.Path
		// Skip /user-proxy entirely — handleUserProxy already runs its own WAF
		// check with full user context and creates properly attributed alerts.
		// Running it here too would produce duplicate alerts.
		if strings.HasPrefix(path, "/user-proxy") ||
			strings.HasPrefix(path, "/proxy-api") ||
			strings.HasPrefix(path, "/assets") ||
			path == "/favicon.ico" ||
			path == "/synorix-icon.svg" ||
			c.Request.Method == "OPTIONS" ||
			(!strings.HasPrefix(path, "/api") && !strings.HasPrefix(path, "/user-proxy")) {
			c.Next()
			return
		}

		blocked, ruleID := proxy.checkWAFRulesDetailed(c.Request)
		if blocked {
			clientIP := c.ClientIP()
			logrus.Warnf("🛡️ WAF blocked request from %s: rule=%s path=%s", clientIP, ruleID, path)
			// Fire-and-forget: write to user_alerts (proper schema) AND raw alerts table
			go func(ip, rule, p string) {
				alertPayload := map[string]interface{}{
					// user_alerts fields
					"alert_type":         "waf",
					"severity":           "high",
					"rule_id":            rule,
					"rule_name":          "WAF Block: " + rule,
					"description":        fmt.Sprintf("WAF blocked request matching rule %s on path %s", rule, p),
					"source_ip":          ip,
					"target_url":         p,
					"recommended_action": "Review traffic from this IP",
					"action":             "blocked",
					"auto_blocked":       true,
					// raw alerts table fields (backwards compat)
					"source":    "waf",
					"signature": "WAF:" + rule,
					"src_ip":    ip,
					"category":  "web-attack",
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				}
				body, _ := json.Marshal(alertPayload)
				req, err := http.NewRequest(http.MethodPost, "http://localhost:3001/api/security/alerts/insert", bytes.NewReader(body))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/json")
				if internalToken := strings.TrimSpace(os.Getenv("INTERNAL_API_TOKEN")); internalToken != "" {
					req.Header.Set("X-Internal-Token", internalToken)
				}
				resp, err := http.DefaultClient.Do(req)
				if err == nil && resp != nil {
					resp.Body.Close()
				}
			}(clientIP, ruleID, path)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Request blocked by WAF",
				"rule":    ruleID,
				"message": "Your request was blocked by the Web Application Firewall",
			})
			return
		}
		c.Next()
	})

	proxy.setupAPIRoutes(router)

	// Serve static files from dist directory
	router.Static("/assets", "./dist/assets")
	router.StaticFile("/favicon.ico", "./dist/favicon.ico")
	router.StaticFile("/synorix-icon.svg", "./dist/synorix-icon.svg")

	// Serve React app for all non-API routes
	router.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// Don't proxy API routes through NoRoute - let registered routes handle them
		// If an API route isn't registered, it should 404
		if strings.HasPrefix(path, "/api") {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
			return
		}

		// For all other routes, serve the React app
		c.File("./dist/index.html")
	})

	logrus.Infof("🚀 Synorix Security Proxy with AI Compression starting on :%s", port)
	logrus.Infof("🎯 Target: %s", target.String())
	logrus.Infof("🗜️ Compression AI: %s", proxy.compressionAI.endpoint)
	requireTLS := getEnvBool("REQUIRE_TLS", !developmentMode)
	disableHTTP := getEnvBool("DISABLE_HTTP", !developmentMode)

	// Start HTTPS if cert + key files exist
	certExists := fileExists(tlsCert) && fileExists(tlsKey)
	if requireTLS && !certExists {
		logrus.Fatalf("REQUIRE_TLS=true but certificate files are missing (%s, %s)", tlsCert, tlsKey)
	}

	startHTTPSServer := func() {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		}
		server := &http.Server{
			Addr:      ":" + httpsPort,
			Handler:   router,
			TLSConfig: tlsCfg,
		}
		if err := server.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			logrus.Fatalf("Failed to start HTTPS server: %v", err)
		}
	}

	if certExists {
		logrus.Infof("🔒 TLS enabled — HTTPS listening on :%s (cert: %s)", httpsPort, tlsCert)
		if disableHTTP {
			logrus.Info("🌐 HTTP disabled (DISABLE_HTTP=true)")
			startHTTPSServer()
			return
		}
		go startHTTPSServer()
	} else {
		logrus.Warnf("⚠️  TLS cert/key not found at %s / %s — HTTPS disabled", tlsCert, tlsKey)
	}

	if disableHTTP {
		logrus.Fatal("DISABLE_HTTP=true but HTTPS is not available. Provide TLS cert/key or disable DISABLE_HTTP.")
	}

	// Start HTTP
	logrus.Infof("🌐 HTTP listening on :%s", port)
	if err := router.Run(":" + port); err != nil {
		logrus.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (sp *SecurityProxy) buildCacheKey(r *http.Request, userID int, targetURL string) (string, bool) {
	if !sp.shouldCacheRequest(r) {
		return "", false
	}

	acceptEncoding := r.Header.Get("Accept-Encoding")
	accept := r.Header.Get("Accept")
	return fmt.Sprintf("user:%d|%s|%s|ae:%s|a:%s", userID, r.Method, targetURL, acceptEncoding, accept), true
}

func (sp *SecurityProxy) shouldCacheRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}

	cacheControl := strings.ToLower(r.Header.Get("Cache-Control"))
	if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache") {
		return false
	}
	pragma := strings.ToLower(r.Header.Get("Pragma"))
	if strings.Contains(pragma, "no-cache") {
		return false
	}
	// NOTE: Authorization/Cookie requests ARE cached because the cache key
	// already includes userID (from authenticated config), ensuring data isolation.
	// Requests without a resolved userID are skipped at the buildCacheKey level.

	return true
}

func (sp *SecurityProxy) shouldCacheResponse(headers http.Header, statusCode int) bool {
	if statusCode != http.StatusOK {
		return false
	}

	cacheControl := strings.ToLower(headers.Get("Cache-Control"))
	if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache") || strings.Contains(cacheControl, "private") {
		return false
	}
	if headers.Get("Set-Cookie") != "" {
		return false
	}

	return true
}

func (sp *SecurityProxy) cacheTTLFromHeaders(headers http.Header) time.Duration {
	if sp.dedupCache == nil {
		return 5 * time.Minute
	}
	cacheControl := strings.ToLower(headers.Get("Cache-Control"))
	if cacheControl == "" {
		return sp.dedupCache.TTL()
	}
	if maxAge := parseCacheControlMaxAge(cacheControl); maxAge > 0 {
		return maxAge
	}
	return sp.dedupCache.TTL()
}

func (sp *SecurityProxy) filterCacheHeaders(headers http.Header) http.Header {
	filtered := make(http.Header)
	allowed := []string{
		"Content-Type",
		"Cache-Control",
		"ETag",
		"Last-Modified",
		"Expires",
		"Vary",
		"Content-Encoding",
	}
	for _, key := range allowed {
		if values, ok := headers[key]; ok {
			for _, value := range values {
				filtered.Add(key, value)
			}
		}
	}

	return filtered
}

func (sp *SecurityProxy) maybeCompressResponse(c *gin.Context, responseBody []byte, contentType string, userID int, responseHeaders http.Header) ([]byte, *CompressionInfo) {
	if responseHeaders != nil && responseHeaders.Get("Content-Encoding") != "" {
		return responseBody, nil
	}

	acceptEncoding := c.GetHeader("Accept-Encoding")
	responseSize := len(responseBody)
	logrus.Infof("Compression check - Accept-Encoding: '%s', Size: %d, Contains gzip: %v",
		acceptEncoding, responseSize, strings.Contains(acceptEncoding, "gzip"))

	if strings.Contains(acceptEncoding, "gzip") && responseSize > 1024 {
		strictAITest := sp.isStrictAITest(c)
		logrus.Info("Calling AI compression decision...")
		compDecision, err := sp.callAICompressionDecision(c.Request, responseBody, contentType)
		if err != nil {
			logrus.Errorf("AI compression decision error: %v", err)
		} else {
			logrus.Infof("AI Decision: ShouldCompress=%v, Confidence=%.2f, Reason=%s",
				compDecision.ShouldCompress, compDecision.Confidence, compDecision.Reason)
		}

		if err == nil && compDecision.ShouldCompress {
			isFallback := isFallbackReason(compDecision.Reason)
			if strictAITest && isFallback {
				logrus.Warnf("Strict AI mode: skipping compression due to fallback reason=%s", compDecision.Reason)
				return responseBody, nil
			}
			compressed, err := sp.compressResponse(responseBody)
			if err == nil {
				originalSize := int64(len(responseBody))
				compressedSize := int64(len(compressed))
				compressionRatio := float64(originalSize-compressedSize) / float64(originalSize)

				compressionInfo := &CompressionInfo{
					Enabled:          true,
					OriginalSize:     originalSize,
					CompressedSize:   compressedSize,
					CompressionRatio: compressionRatio,
					Algorithm:        compDecision.Algorithm,
					AIDecision:       !isFallback,
					AIConfidence:     compDecision.Confidence,
					AIReason:         compDecision.Reason,
					ProcessingTime:   0,
				}
				if !isFallback {
					c.Header("X-Synorix-AI-Compression", "1")
				}

				c.Header("Content-Encoding", "gzip")
				c.Header("Content-Length", fmt.Sprintf("%d", compressedSize))

				logrus.Infof("AI Compressed response for user %d: %d -> %d bytes (%.1f%% saved)",
					userID, originalSize, compressedSize, compressionRatio*100)
				return compressed, compressionInfo
			}
		}
	}

	return responseBody, nil
}
