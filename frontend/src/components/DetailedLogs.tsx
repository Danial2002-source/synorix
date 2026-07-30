import React, { useState, useEffect } from 'react';
import Navigation from './Navigation';
import './DetailedLogs.css';

interface WAFCheck {
  rule_name: string;
  pattern: string;
  matched: boolean;
  severity: string;
  category: string;
}

interface CompressionInfo {
  enabled: boolean;
  method?: string;
  original_size?: number;
  compressed_size?: number;
  compression_ratio?: number;
  decision_reason?: string;
}

interface IDSIPSInfo {
  alerts: Array<{
    rule_id: string;
    signature: string;
    severity: string;
    category: string;
  }>;
  action: string;
}

interface DetailedRequestLog {
  id: number;
  timestamp: string;
  method: string;
  url: string;
  ip: string;
  user_agent: string;
  status_code: number;
  response_time: number;
  request_size: number;
  response_size: number;
  waf_checks: WAFCheck[];
  compression_info: CompressionInfo;
  ids_ips_info: IDSIPSInfo;
  security_events: any[];
  headers: Record<string, string>;
  blocked: boolean;
  block_reason?: string;
  created_at: string;
}

const DetailedLogs: React.FC = () => {
  const [logs, setLogs] = useState<DetailedRequestLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('');
  const [expandedLogs, setExpandedLogs] = useState<Set<number>>(new Set());

  useEffect(() => {
    fetchDetailedLogs();
    const interval = setInterval(fetchDetailedLogs, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, [filter]);

  const fetchDetailedLogs = async () => {
    try {
      const url = filter ? `/api/logs/detailed?filter=${filter}` : `/api/logs/detailed`;
      const response = await fetch(url);
      const data = await response.json();
      setLogs(data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching detailed logs:', error);
      setLoading(false);
    }
  };

  const toggleExpanded = (logId: number) => {
    const newExpanded = new Set(expandedLogs);
    if (newExpanded.has(logId)) {
      newExpanded.delete(logId);
    } else {
      newExpanded.add(logId);
    }
    setExpandedLogs(newExpanded);
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const getStatusBadge = (blocked: boolean, statusCode: number) => {
    if (blocked) {
      return <span className="status-badge blocked">BLOCKED</span>;
    }
    if (statusCode >= 400) {
      return <span className="status-badge error">ERROR</span>;
    }
    if (statusCode >= 300) {
      return <span className="status-badge warning">REDIRECT</span>;
    }
    return <span className="status-badge success">SUCCESS</span>;
  };

  const renderWAFChecks = (wafChecks: WAFCheck[]) => {
    if (!wafChecks || wafChecks.length === 0) {
      return <div className="waf-info">No WAF rules triggered</div>;
    }

    return (
      <div className="waf-info">
        <h4>WAF Analysis</h4>
        {wafChecks.map((check, index) => (
          <div key={index} className={`waf-rule ${check.matched ? 'matched' : 'not-matched'}`}>
            <div className="rule-name">{check.rule_name}</div>
            <div className="rule-pattern">{check.pattern}</div>
            <div className="rule-details">
              <span className={`severity ${check.severity}`}>{check.severity}</span>
              <span className="category">{check.category}</span>
              <span className={`match-status ${check.matched ? 'matched' : 'not-matched'}`}>
                {check.matched ? '✓ MATCHED' : '✗ NOT MATCHED'}
              </span>
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderCompressionInfo = (compressionInfo: CompressionInfo) => {
    return (
      <div className="compression-info">
        <h4>Compression Analysis</h4>
        <div className="compression-details">
          <div className={`compression-status ${compressionInfo.enabled ? 'enabled' : 'disabled'}`}>
            {compressionInfo.enabled ? '✓ ENABLED' : '✗ DISABLED'}
          </div>
          {compressionInfo.enabled && (
            <>
              <div>Method: {compressionInfo.method || 'N/A'}</div>
              <div>Original Size: {compressionInfo.original_size || 0} bytes</div>
              <div>Compressed Size: {compressionInfo.compressed_size || 0} bytes</div>
              <div>Compression Ratio: {compressionInfo.compression_ratio ? 
                (compressionInfo.compression_ratio * 100).toFixed(1) + '%' : 'N/A'}</div>
              <div>Decision: {compressionInfo.decision_reason || 'N/A'}</div>
            </>
          )}
        </div>
      </div>
    );
  };

  const renderIDSIPSInfo = (idsInfo: IDSIPSInfo) => {
    return (
      <div className="ids-info">
        <h4>IDS/IPS Analysis</h4>
        <div className="ids-details">
          <div className={`ids-action ${idsInfo.action}`}>
            Action: {idsInfo.action.toUpperCase()}
          </div>
          {idsInfo.alerts && idsInfo.alerts.length > 0 ? (
            <div className="alerts">
              {idsInfo.alerts.map((alert, index) => (
                <div key={index} className="alert">
                  <div className="alert-signature">{alert.signature}</div>
                  <div className="alert-details">
                    <span className={`severity ${alert.severity}`}>{alert.severity}</span>
                    <span className="category">{alert.category}</span>
                    <span className="rule-id">Rule ID: {alert.rule_id}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div>No IDS/IPS alerts triggered</div>
          )}
        </div>
      </div>
    );
  };

  if (loading) {
    return <div className="loading">Loading detailed logs...</div>;
  }

  return (
    <>
      <Navigation />
      <div className="page-container">
        <div className="detailed-logs">
          <div className="detailed-logs-header">
            <h3>Detailed Request Analysis</h3>
            <div className="filters">
              <select value={filter} onChange={(e) => setFilter(e.target.value)}>
                <option value="">All Requests</option>
                <option value="blocked">Blocked Only</option>
                <option value="compressed">Compressed Only</option>
                <option value="waf_triggered">WAF Triggered</option>
              </select>
            </div>
          </div>

          {logs.length === 0 ? (
            <div className="no-logs">No detailed logs available</div>
          ) : (
            <div className="logs-list">
              {logs.map((log) => (
                <div key={log.id} className="log-entry">
                  <div className="log-summary" onClick={() => toggleExpanded(log.id)}>
                    <div className="log-basic-info">
                      <span className="timestamp">{formatTimestamp(log.timestamp)}</span>
                      <span className={`method method-${log.method.toLowerCase()}`}>{log.method}</span>
                      <span className="url">{log.url}</span>
                      <span className="ip">{log.ip}</span>
                      {getStatusBadge(log.blocked, log.status_code)}
                      <span className="response-time">{log.response_time}ms</span>
                    </div>
                    <div className="expand-icon">
                      {expandedLogs.has(log.id) ? '▼' : '▶'}
                    </div>
                  </div>

                  {expandedLogs.has(log.id) && (
                    <div className="log-details">
                      <div className="details-grid">
                        <div className="details-column">
                          {renderWAFChecks(log.waf_checks)}
                        </div>
                        <div className="details-column">
                          {renderCompressionInfo(log.compression_info)}
                        </div>
                        <div className="details-column">
                          {renderIDSIPSInfo(log.ids_ips_info)}
                        </div>
                      </div>
                      
                      {log.blocked && log.block_reason && (
                        <div className="block-reason">
                          <strong>Block Reason:</strong> {log.block_reason}
                        </div>
                      )}

                      <div className="additional-info">
                        <div className="info-row">
                          <strong>User Agent:</strong> {log.user_agent}
                        </div>
                        <div className="info-row">
                          <strong>Request Size:</strong> {log.request_size} bytes
                        </div>
                        <div className="info-row">
                          <strong>Response Size:</strong> {log.response_size} bytes
                        </div>
                        {log.security_events && log.security_events.length > 0 && (
                          <div className="info-row">
                            <strong>Security Events:</strong> {log.security_events.length}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
};

export default DetailedLogs;