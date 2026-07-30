package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/sirupsen/logrus"
)

// Enhanced logging function for detailed request tracking
func (sp *SecurityProxy) logDetailedRequest(r *http.Request, statusCode int, responseTime time.Duration,
	requestSize, responseSize int64, wafChecks []WAFCheckResult, compressionInfo *CompressionInfo,
	idsIPSInfo *IDSIPSInfo, securityEvents []SecurityEvent, blocked bool, blockReason string) {

	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	detailedLog := DetailedRequestLog{
		Timestamp:       time.Now(),
		Method:          r.Method,
		URL:             r.URL.String(),
		IP:              sp.getClientIP(r),
		UserAgent:       r.UserAgent(),
		StatusCode:      statusCode,
		ResponseTime:    responseTime,
		RequestSize:     requestSize,
		ResponseSize:    responseSize,
		WAFChecks:       wafChecks,
		CompressionInfo: compressionInfo,
		IDSIPSInfo:      idsIPSInfo,
		SecurityEvents:  securityEvents,
		Headers:         headers,
		Blocked:         blocked,
		BlockReason:     blockReason,
	}

	select {
	case sp.detailedLogChan <- detailedLog:
	default:
		logrus.Warn("Detailed log channel full")
	}

	// Send to backend API for frontend display
	sp.sendToBackend(detailedLog)
}

// Send detailed logs to backend API
func (sp *SecurityProxy) sendToBackend(log DetailedRequestLog) {
	go func() {
		jsonData, err := json.Marshal(log)
		if err != nil {
			logrus.WithError(err).Error("Failed to marshal detailed log")
			return
		}

		resp, err := http.Post("http://localhost:3001/api/logs/detailed", "application/json",
			bytes.NewBuffer(jsonData))
		if err != nil {
			logrus.WithError(err).Debug("Failed to send log to backend")
			return
		}
		defer resp.Body.Close()
	}()
}

// Enhanced WAF checking with detailed results
func (sp *SecurityProxy) checkWAFWithDetails(r *http.Request) (bool, []WAFCheckResult) {
	var results []WAFCheckResult
	blocked := false

	sp.wafMu.RLock()
	defer sp.wafMu.RUnlock()

	for _, rule := range sp.wafRulesData {
		if !rule.Enabled {
			continue
		}

		result := WAFCheckResult{
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			Pattern:     rule.Pattern,
			Severity:    rule.Severity,
			Action:      rule.Action,
			Description: rule.Description,
			Matched:     false,
		}

		// Check if rule matches
		if sp.matchesWAFRule(r, rule) {
			result.Matched = true
			if rule.Action == "block" {
				blocked = true
			}
		}

		results = append(results, result)
	}

	return blocked, results
}

// Enhanced compression with detailed info
func (sp *SecurityProxy) getCompressionInfo(r *http.Request, responseSize int64, compressed bool, 
	compressedSize int64, algorithm string) *CompressionInfo {
	
	compressionRatio := float64(0)
	if responseSize > 0 && compressed {
		// Calculate percentage saved, not compressed-to ratio
		compressionRatio = float64(responseSize-compressedSize) / float64(responseSize)
	}

	return &CompressionInfo{
		Enabled:          true,
		OriginalSize:     responseSize,
		CompressedSize:   compressedSize,
		CompressionRatio: compressionRatio,
		Algorithm:        algorithm,
		AIDecision:       false, // TODO: Implement AI decision
		ProcessingTime:   0,     // TODO: Measure processing time
	}
}

// Enhanced IDS/IPS checking with detailed results
func (sp *SecurityProxy) checkIDSIPSWithDetails(r *http.Request) *IDSIPSInfo {
	patterns := []DetectedPattern{}
	threatLevel := "low"

	// Check for suspicious patterns
	userAgent := r.UserAgent()
	
	// Check for scanner user agents
	if contains(userAgent, []string{"sqlmap", "nikto", "nmap", "burp", "nessus"}) {
		patterns = append(patterns, DetectedPattern{
			Type:        "scanner_detection",
			Pattern:     userAgent,
			Description: "Potential security scanner detected",
			Severity:    "medium",
		})
		threatLevel = "medium"
	}

	// Check for injection patterns in URL
	url := r.URL.String()
	if contains(url, []string{"'", "\"", "<script", "union", "select"}) {
		patterns = append(patterns, DetectedPattern{
			Type:        "injection_attempt",
			Pattern:     url,
			Description: "Potential injection attempt detected in URL",
			Severity:    "high",
		})
		threatLevel = "high"
	}

	return &IDSIPSInfo{
		Enabled:        true,
		ThreatLevel:    threatLevel,
		Patterns:       patterns,
		ProcessingTime: 0, // TODO: Measure processing time
	}
}

// matchesWAFRule checks if a request matches a WAF rule pattern
func (sp *SecurityProxy) matchesWAFRule(r *http.Request, rule WAFRuleData) bool {
	compiled, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return false
	}

	fullURL := r.URL.String()
	userAgent := r.UserAgent()

	// Check URL
	if compiled.MatchString(fullURL) {
		return true
	}

	// Check User-Agent
	if compiled.MatchString(userAgent) {
		return true
	}

	// Check body if present
	if r.Body != nil {
		body := new(bytes.Buffer)
		body.ReadFrom(r.Body)
		bodyStr := body.String()
		r.Body = io.NopCloser(bytes.NewBuffer(body.Bytes()))
		
		if compiled.MatchString(bodyStr) {
			return true
		}
	}

	return false
}

// Helper function to check if string contains any of the patterns
func contains(str string, patterns []string) bool {
	for _, pattern := range patterns {
		if len(pattern) > 0 && len(str) >= len(pattern) {
			for i := 0; i <= len(str)-len(pattern); i++ {
				if str[i:i+len(pattern)] == pattern {
					return true
				}
			}
		}
	}
	return false
}