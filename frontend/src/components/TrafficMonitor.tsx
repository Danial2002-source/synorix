import React, { useState, useEffect, useRef } from 'react';
import Navigation from './Navigation';
import './TrafficMonitor.css';

interface RequestLog {
  id: number;
  timestamp: string;
  method: string;
  url: string;
  client_ip: string;
  response_status: number;
  response_time: number;
  response_size: number;
  compressed: number;
  compression_saved: number;
  waf_action: string;
  waf_rule?: string | null;
  suricata_action: string;
  suricata_alert?: string | null;
  user_agent: string;
  headers: string;
  request_body: string;
  referer: string;
  content_type: string;
  created_at: string;
}

interface RequestStats {
  totalRequests: number;
  blockedRequests: number;
  wafBlocked: number;
  suricataBlocked: number;
  compressedRequests: number;
  avgResponseTime: number;
  totalBandwidth: number;
  uniqueIPs: number;
  errorRate: string;
  compressionRate: string;
  timeframe: string;
}

interface FilterOptions {
  method: string;
  status: string;
  blocked: boolean;
  compressed: boolean;
  wafOnly: boolean;
  suricataOnly: boolean;
  clientIP: string;
}

const TrafficMonitor: React.FC = () => {
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [stats, setStats] = useState<RequestStats | null>(null);
  const [filters, setFilters] = useState<FilterOptions>({
    method: '',
    status: '',
    blocked: false,
    compressed: false,
    wafOnly: false,
    suricataOnly: false,
    clientIP: ''
  });
  const [isRealTime, setIsRealTime] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'disconnected' | 'connecting' | 'connected'>('disconnected');
  const eventSourceRef = useRef<EventSource | null>(null);

  // Connect to Server-Sent Events
  useEffect(() => {
    if (isRealTime) {
      connectToEventStream();
    } else {
      disconnectFromEventStream();
    }

    return () => {
      disconnectFromEventStream();
    };
  }, [isRealTime]);

  // Load initial data
  useEffect(() => {
    loadRequestLogs();
    loadStats();
  }, [filters]);

  // Connect to Server-Sent Events
  const connectToEventStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    setConnectionStatus('connecting');
    
    // Use the proxy URL for API calls
    const eventSource = new EventSource(`/api/events`);
    eventSourceRef.current = eventSource;

    eventSource.onopen = () => {
      setConnectionStatus('connected');
      console.log('Connected to real-time event stream');
    };

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.type === 'request') {
          const newLog: RequestLog = {
            id: data.id,
            timestamp: data.timestamp,
            method: data.method,
            url: data.url,
            client_ip: data.client_ip,
            response_status: data.response_status,
            response_time: data.response_time,
            response_size: data.response_size || 0,
            compressed: data.compressed,
            compression_saved: data.compression_saved || 0,
            waf_action: data.waf_action,
            waf_rule: data.waf_rule,
            suricata_action: data.suricata_action,
            suricata_alert: data.suricata_alert,
            user_agent: data.user_agent,
            headers: data.headers || '',
            request_body: data.request_body || '',
            referer: data.referer || '',
            content_type: data.content_type || '',
            created_at: data.created_at
          };

          setLogs(prevLogs => {
            const updated = [newLog, ...prevLogs];
            return updated.slice(0, 1000); // Keep only last 1000 entries
          });

          // Update stats periodically
          if (Math.random() < 0.1) { // Update stats on ~10% of requests
            loadStats();
          }
        }
      } catch (error) {
        console.error('Error parsing SSE data:', error);
      }
    };

    eventSource.onerror = () => {
      setConnectionStatus('disconnected');
      console.error('EventSource connection error');
      
      // Retry connection after 5 seconds
      setTimeout(() => {
        if (isRealTime) {
          connectToEventStream();
        }
      }, 5000);
    };
  };

  const disconnectFromEventStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setConnectionStatus('disconnected');
  };

  const loadRequestLogs = async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      
      if (filters.method) params.append('method', filters.method);
      if (filters.status) params.append('status', filters.status);
      if (filters.blocked) params.append('blocked', 'true');
      if (filters.compressed) params.append('compressed', 'true');
      if (filters.clientIP) params.append('clientIP', filters.clientIP);
      
      // Use cache for real-time, database for historical
      params.append('source', isRealTime ? 'cache' : 'db');
      params.append('limit', '100');

      const response = await fetch(`/api/logs?${params}`);
      const data = await response.json();
      
      if (data.data) {
        setLogs(data.data);
      }
    } catch (error) {
      console.error('Error loading request logs:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const response = await fetch(`/api/logs/stats?timeframe=1h`);
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const getStatusColor = (statusCode: number): string => {
    if (statusCode >= 200 && statusCode < 300) return 'success';
    if (statusCode >= 300 && statusCode < 400) return 'warning';
    if (statusCode >= 400 && statusCode < 500) return 'error';
    if (statusCode >= 500) return 'critical';
    return 'default';
  };

  const getSecurityStatus = (wafAction: string, suricataAction: string): string => {
    if (wafAction === 'blocked' || suricataAction === 'blocked') return 'blocked';
    if (wafAction === 'alert' || suricataAction === 'alert') return 'alert';
    return 'allowed';
  };

  const formatTimestamp = (timestamp: string): string => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const formatResponseTime = (time: number): string => {
    return `${(time * 1000).toFixed(0)}ms`;
  };

  const formatFileSize = (bytes: number): string => {
    if (!bytes) return '-';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    
    return `${size.toFixed(1)}${units[unitIndex]}`;
  };

  const handleFilterChange = (key: keyof FilterOptions, value: string | boolean) => {
    setFilters(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const clearFilters = () => {
    setFilters({
      method: '',
      status: '',
      blocked: false,
      compressed: false,
      wafOnly: false,
      suricataOnly: false,
      clientIP: ''
    });
  };

  const filteredLogs = logs.filter(log => {
    if (filters.method && log.method !== filters.method) return false;
    if (filters.status && !log.response_status.toString().startsWith(filters.status)) return false;
    if (filters.blocked && log.waf_action === 'allowed' && log.suricata_action === 'allowed') return false;
    if (filters.compressed && !log.compressed) return false;
    if (filters.wafOnly && log.waf_action === 'allowed') return false;
    if (filters.suricataOnly && log.suricata_action === 'allowed' && !log.suricata_alert) return false;
    if (filters.clientIP && !log.client_ip.includes(filters.clientIP)) return false;
    return true;
  });

  return (
    <>
      <Navigation />
      <div className="traffic-monitor">
        <div className="traffic-monitor-header">
        <h1>Traffic Monitor</h1>
        <div className="header-controls">
          <div className="connection-status">
            <span className={`status-indicator ${connectionStatus}`}></span>
            <span>{connectionStatus === 'connected' ? 'Live' : connectionStatus === 'connecting' ? 'Connecting...' : 'Disconnected'}</span>
          </div>
          <label className="realtime-toggle">
            <input
              type="checkbox"
              checked={isRealTime}
              onChange={(e) => setIsRealTime(e.target.checked)}
            />
            Real-time updates
          </label>
        </div>
      </div>

      {/* Stats Dashboard */}
      {stats && (
        <div className="stats-dashboard">
          <div className="stat-card">
            <h3>Total Requests</h3>
            <div className="stat-value">{stats.totalRequests}</div>
            <div className="stat-timeframe">Last hour</div>
          </div>
          <div className="stat-card">
            <h3>Blocked</h3>
            <div className="stat-value error">{stats.blockedRequests}</div>
            <div className="stat-detail">WAF: {stats.wafBlocked} | Suricata: {stats.suricataBlocked}</div>
          </div>
          <div className="stat-card">
            <h3>Compressed</h3>
            <div className="stat-value success">{stats.compressedRequests}</div>
            <div className="stat-detail">{stats.compressionRate}% rate</div>
          </div>
          <div className="stat-card">
            <h3>Avg Response Time</h3>
            <div className="stat-value">{formatResponseTime(stats.avgResponseTime)}</div>
            <div className="stat-detail">Error rate: {stats.errorRate}%</div>
          </div>
          <div className="stat-card">
            <h3>Bandwidth</h3>
            <div className="stat-value">{formatFileSize(stats.totalBandwidth)}</div>
            <div className="stat-detail">{stats.uniqueIPs} unique IPs</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="filters">
        <div className="filter-group">
          <select
            value={filters.method}
            onChange={(e) => handleFilterChange('method', e.target.value)}
          >
            <option value="">All Methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
          </select>

          <select
            value={filters.status}
            onChange={(e) => handleFilterChange('status', e.target.value)}
          >
            <option value="">All Status</option>
            <option value="200">200 OK</option>
            <option value="201">201 Created</option>
            <option value="400">400 Bad Request</option>
            <option value="401">401 Unauthorized</option>
            <option value="403">403 Forbidden</option>
            <option value="404">404 Not Found</option>
            <option value="500">500 Internal Error</option>
          </select>

          <input
            type="text"
            placeholder="Filter by IP"
            value={filters.clientIP}
            onChange={(e) => handleFilterChange('clientIP', e.target.value)}
          />
        </div>

        <div className="filter-toggles">
          <label>
            <input
              type="checkbox"
              checked={filters.blocked}
              onChange={(e) => handleFilterChange('blocked', e.target.checked)}
            />
            Blocked only
          </label>
          <label>
            <input
              type="checkbox"
              checked={filters.compressed}
              onChange={(e) => handleFilterChange('compressed', e.target.checked)}
            />
            Compressed only
          </label>
          <label>
            <input
              type="checkbox"
              checked={filters.wafOnly}
              onChange={(e) => handleFilterChange('wafOnly', e.target.checked)}
            />
            WAF alerts
          </label>
          <label>
            <input
              type="checkbox"
              checked={filters.suricataOnly}
              onChange={(e) => handleFilterChange('suricataOnly', e.target.checked)}
            />
            Suricata alerts
          </label>
        </div>

        <button onClick={clearFilters} className="clear-filters-btn">
          Clear Filters
        </button>
      </div>

      {/* Request Logs Table */}
      <div className="logs-container">
        {isLoading && <div className="loading">Loading...</div>}
        
        <table className="logs-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Method</th>
              <th>URL</th>
              <th>IP</th>
              <th>Status</th>
              <th>Response Time</th>
              <th>Size</th>
              <th>Security</th>
              <th>Compression</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map((log) => {
              const securityStatus = getSecurityStatus(log.waf_action, log.suricata_action);
              
              return (
                <tr key={log.id} className={`log-row ${securityStatus}`}>
                  <td>{formatTimestamp(log.timestamp)}</td>
                  <td>
                    <span className={`method-badge ${log.method.toLowerCase()}`}>
                      {log.method}
                    </span>
                  </td>
                  <td className="url-cell" title={log.url}>
                    {log.url.length > 50 ? `${log.url.substring(0, 47)}...` : log.url}
                  </td>
                  <td>{log.client_ip}</td>
                  <td>
                    <span className={`status-badge ${getStatusColor(log.response_status)}`}>
                      {log.response_status}
                    </span>
                  </td>
                  <td>{formatResponseTime(log.response_time)}</td>
                  <td>{formatFileSize(log.response_size || 0)}</td>
                  <td>
                    <div className="security-indicators">
                      {log.waf_action === 'blocked' && (
                        <span className="security-badge waf-blocked" title={`WAF Blocked: ${log.waf_rule || 'Security rule triggered'}`}>
                          WAF BLOCKED
                        </span>
                      )}
                      {log.waf_action === 'warned' && (
                        <span className="security-badge waf-warned" title={`WAF Warning: ${log.waf_rule || 'Suspicious pattern'}`}>
                          WAF WARN
                        </span>
                      )}
                      {log.waf_action === 'allowed' && (
                        <span className="security-badge waf-allowed" title="WAF: Request passed security checks">
                          WAF OK
                        </span>
                      )}
                      <br/>
                      {log.suricata_action === 'blocked' && (
                        <span className="security-badge suricata-blocked" title={`Suricata Blocked: ${log.suricata_alert || 'IDS rule triggered'}`}>
                          IDS BLOCK
                        </span>
                      )}
                      {log.suricata_alert && log.suricata_action !== 'blocked' && (
                        <span className="security-badge suricata-alert" title={`Suricata Alert: ${log.suricata_alert}`}>
                          IDS ALERT
                        </span>
                      )}
                      {log.suricata_action === 'allowed' && !log.suricata_alert && (
                        <span className="security-badge suricata-allowed" title="IDS: No threats detected">
                          IDS OK
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    {log.compressed ? (
                      <span className="compression-badge compressed" title={`GZIP compressed, saved ${log.compression_saved || 0} bytes`}>
                        GZIP {log.compression_saved > 0 ? `↓${log.compression_saved}B` : ''}
                      </span>
                    ) : (
                      <span className="compression-badge not-compressed" title="No compression applied">
                        NONE
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {filteredLogs.length === 0 && !isLoading && (
          <div className="no-data">No requests match the current filters</div>
        )}
      </div>
    </div>
    </>
  );
};

export default TrafficMonitor;