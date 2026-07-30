import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, Filter, RefreshCw, ChevronDown, ChevronUp, AlertTriangle, Shield, Eye, Clock, Globe } from 'lucide-react';
import Navigation from './Navigation';
import axios from 'axios';
import './Dashboard.css';
import './UserDashboard.css';
import './UserTrafficLogs.css';

interface TrafficLog {
  id: number;
  timestamp: string;
  method: string;
  url: string;
  backend_url: string;
  client_ip: string;
  user_agent: string;
  status_code: number;
  response_time: number;
  request_size: number;
  response_size: number;
  threat_level: 'none' | 'low' | 'medium' | 'high' | 'critical';
  waf_triggered: boolean;
  suricata_triggered: boolean;
  compressed: boolean;
  deduplicated: boolean;
  compression_ratio: number;
  original_size: number;
  compressed_size: number;
  dedup_size: number;
  dedup_ratio: number;
}

const UserTrafficLogs: React.FC = () => {
  const [logs, setLogs] = useState<TrafficLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [filters, setFilters] = useState({
    threat_level: '',
    waf_triggered: '',
    suricata_triggered: ''
  });

  useEffect(() => {
    fetchLogs();
    
    if (autoRefresh) {
      const interval = setInterval(fetchLogs, 5000); // Refresh every 5 seconds
      return () => clearInterval(interval);
    }
  }, [autoRefresh, filters]);

  const fetchLogs = async () => {
    try {
      const params = new URLSearchParams();
      if (filters.threat_level) params.append('threat_level', filters.threat_level);
      if (filters.waf_triggered) params.append('waf_triggered', filters.waf_triggered);
      if (filters.suricata_triggered) params.append('suricata_triggered', filters.suricata_triggered);
      
      const response = await axios.get(`/api/user/logs?${params.toString()}`);
      setLogs(response.data.logs);
    } catch (error) {
      console.error('Error fetching logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const getThreatLevelColor = (level: string) => {
    const colors = {
      none: '#00ff88',
      low: '#00bfff',
      medium: '#ffaa00',
      high: '#ff6b6b',
      critical: '#ff4444'
    };
    return colors[level as keyof typeof colors] || '#94a3b8';
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return '#00ff88';
    if (status >= 300 && status < 400) return '#00bfff';
    if (status >= 400 && status < 500) return '#ffaa00';
    return '#ff4444';
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  return (
    <div className="dashboard-container">
      <Navigation />
      <div className="dashboard-content">
        {/* Header */}
        <motion.div
          className="dashboard-hero"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="hero-content">
            <Activity className="hero-icon" size={60} />
            <div>
              <h1 className="hero-title">Traffic Logs</h1>
              <p className="hero-subtitle">Monitor all requests passing through your proxy in real-time</p>
            </div>
          </div>
        </motion.div>

        {/* Controls */}
        <div className="traffic-controls">
          <div className="control-group">
            <button
              className={`control-btn ${autoRefresh ? 'active' : ''}`}
              onClick={() => setAutoRefresh(!autoRefresh)}
            >
              <RefreshCw size={18} className={autoRefresh ? 'spinning' : ''} />
              {autoRefresh ? 'Auto-Refresh ON' : 'Auto-Refresh OFF'}
            </button>
            <button className="control-btn" onClick={fetchLogs}>
              <RefreshCw size={18} />
              Refresh Now
            </button>
          </div>

          <div className="filter-group">
            <Filter size={18} />
            <select
              className="filter-select"
              value={filters.threat_level}
              onChange={(e) => setFilters({ ...filters, threat_level: e.target.value })}
            >
              <option value="">All Threat Levels</option>
              <option value="none">None</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>

            <select
              className="filter-select"
              value={filters.waf_triggered}
              onChange={(e) => setFilters({ ...filters, waf_triggered: e.target.value })}
            >
              <option value="">WAF: All</option>
              <option value="true">WAF: Triggered</option>
              <option value="false">WAF: Clean</option>
            </select>

            <select
              className="filter-select"
              value={filters.suricata_triggered}
              onChange={(e) => setFilters({ ...filters, suricata_triggered: e.target.value })}
            >
              <option value="">IDS: All</option>
              <option value="true">IDS: Triggered</option>
              <option value="false">IDS: Clean</option>
            </select>
          </div>
        </div>

        {/* Logs Table */}
        <div className="traffic-table-container">
          {loading ? (
            <div className="loading-state">
              <RefreshCw className="spinning" size={32} />
              <p>Loading traffic logs...</p>
            </div>
          ) : logs.length === 0 ? (
            <div className="empty-state">
              <Activity size={48} />
              <h3>No Traffic Logs Yet</h3>
              <p>Traffic logs will appear here once requests pass through your proxy</p>
            </div>
          ) : (
            <div className="traffic-table-wrapper">
              <table className="traffic-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Method</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Response Time</th>
                    <th>Original Size</th>
                    <th>Compressed</th>
                    <th>Compressed Size</th>
                    <th>Deduplicated</th>
                    <th>Dedup Size</th>
                    <th>Threat Level</th>
                    <th>Security</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <AnimatePresence>
                    {logs.map((log) => (
                      <React.Fragment key={log.id}>
                        <motion.tr
                          className={`log-row ${expandedRow === log.id ? 'expanded' : ''}`}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          exit={{ opacity: 0 }}
                          style={{ borderLeft: `4px solid ${getThreatLevelColor(log.threat_level)}` }}
                        >
                          <td className="timestamp-cell">
                            <Clock size={14} />
                            {formatTimestamp(log.timestamp)}
                          </td>
                          <td>
                            <span className={`method-badge method-${log.method.toLowerCase()}`}>
                              {log.method}
                            </span>
                          </td>
                          <td className="url-cell">{log.url}</td>
                          <td>
                            <span
                              className="status-badge"
                              style={{ backgroundColor: getStatusColor(log.status_code) }}
                            >
                              {log.status_code}
                            </span>
                          </td>
                          <td>{log.response_time.toFixed(2)}ms</td>
                          <td>{log.original_size ? formatBytes(log.original_size) : '-'}</td>
                          <td>
                            <span style={{ color: log.compressed ? '#00ff88' : '#666', fontSize: '18px' }}>
                              {log.compressed ? '✓' : '✗'}
                              {log.compressed && log.compression_ratio > 0 && (
                                <span style={{ fontSize: '12px', marginLeft: '4px', color: '#00bfff' }}>
                                  {(log.compression_ratio * 100).toFixed(0)}%
                                </span>
                              )}
                            </span>
                          </td>
                          <td>{log.compressed && log.compressed_size ? formatBytes(log.compressed_size) : '-'}</td>
                          <td>
                            <span style={{ color: log.deduplicated ? '#00ff88' : '#666', fontSize: '18px' }}>
                              {log.deduplicated ? '✓' : '✗'}
                              {log.deduplicated && log.dedup_ratio > 0 && (
                                <span style={{ fontSize: '12px', marginLeft: '4px', color: '#00bfff' }}>
                                  {(log.dedup_ratio * 100).toFixed(0)}%
                                </span>
                              )}
                            </span>
                          </td>
                          <td>{log.deduplicated && log.dedup_size ? formatBytes(log.dedup_size) : '-'}</td>
                          <td>
                            <span
                              className="threat-badge"
                              style={{ color: getThreatLevelColor(log.threat_level) }}
                            >
                              {log.threat_level}
                            </span>
                          </td>
                          <td className="security-indicators">
                            {log.waf_triggered && (
                              <span className="security-icon waf" title="WAF Triggered">
                                <Shield size={16} />
                              </span>
                            )}
                            {log.suricata_triggered && (
                              <span className="security-icon ids" title="IDS Triggered">
                                <Eye size={16} />
                              </span>
                            )}
                          </td>
                          <td>
                            <button
                              className="expand-btn"
                              onClick={() => setExpandedRow(expandedRow === log.id ? null : log.id)}
                            >
                              {expandedRow === log.id ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                            </button>
                          </td>
                        </motion.tr>
                        
                        {expandedRow === log.id && (
                          <motion.tr
                            className="expanded-details"
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                          >
                            <td colSpan={13}>
                              <div className="details-content">
                                <div className="details-grid">
                                  <div className="detail-section">
                                    <h4><Globe size={18} /> Request Details</h4>
                                    <div className="detail-row">
                                      <span className="detail-label">Backend URL:</span>
                                      <span className="detail-value">{log.backend_url}</span>
                                    </div>
                                    <div className="detail-row">
                                      <span className="detail-label">Client IP:</span>
                                      <span className="detail-value">{log.client_ip}</span>
                                    </div>
                                    <div className="detail-row">
                                      <span className="detail-label">User Agent:</span>
                                      <span className="detail-value">{log.user_agent}</span>
                                    </div>
                                  </div>

                                  <div className="detail-section">
                                    <h4><Activity size={18} /> Performance</h4>
                                    <div className="detail-row">
                                      <span className="detail-label">Response Time:</span>
                                      <span className="detail-value">{log.response_time.toFixed(2)}ms</span>
                                    </div>
                                    <div className="detail-row">
                                      <span className="detail-label">Request Size:</span>
                                      <span className="detail-value">{formatBytes(log.request_size)}</span>
                                    </div>
                                    <div className="detail-row">
                                      <span className="detail-label">Response Size:</span>
                                      <span className="detail-value">{formatBytes(log.response_size)}</span>
                                    </div>
                                    
                                    {log.original_size > 0 && (
                                      <div className="detail-row">
                                        <span className="detail-label">Original Size:</span>
                                        <span className="detail-value" style={{ color: '#fbbf24' }}>{formatBytes(log.original_size)}</span>
                                      </div>
                                    )}
                                    
                                    <div className="detail-row">
                                      <span className="detail-label">Compressed:</span>
                                      <span className="detail-value" style={{ color: log.compressed ? '#00ff88' : '#666' }}>
                                        {log.compressed ? '✓ Yes' : '✗ No'}
                                      </span>
                                    </div>
                                    
                                    {log.compressed && log.compressed_size > 0 && (
                                      <>
                                        <div className="detail-row">
                                          <span className="detail-label">→ Compressed Size:</span>
                                          <span className="detail-value" style={{ color: '#00ff88' }}>{formatBytes(log.compressed_size)}</span>
                                        </div>
                                        <div className="detail-row">
                                          <span className="detail-label">→ Compression Ratio:</span>
                                          <span className="detail-value" style={{ color: '#00bfff' }}>
                                            {(log.compression_ratio * 100).toFixed(1)}% saved ({formatBytes(log.original_size - log.compressed_size)})
                                          </span>
                                        </div>
                                      </>
                                    )}
                                    
                                    <div className="detail-row">
                                      <span className="detail-label">Deduplicated:</span>
                                      <span className="detail-value" style={{ color: log.deduplicated ? '#00ff88' : '#666' }}>
                                        {log.deduplicated ? '✓ Yes' : '✗ No'}
                                      </span>
                                    </div>
                                    
                                    {log.deduplicated && log.dedup_size > 0 && (
                                      <>
                                        <div className="detail-row">
                                          <span className="detail-label">→ Dedup Size:</span>
                                          <span className="detail-value" style={{ color: '#00ff88' }}>{formatBytes(log.dedup_size)}</span>
                                        </div>
                                        <div className="detail-row">
                                          <span className="detail-label">→ Dedup Ratio:</span>
                                          <span className="detail-value" style={{ color: '#00bfff' }}>
                                            {(log.dedup_ratio * 100).toFixed(1)}% saved ({formatBytes((log.compressed_size || log.original_size) - log.dedup_size)})
                                          </span>
                                        </div>
                                      </>
                                    )}
                                    
                                    {(log.compressed || log.deduplicated) && (
                                      <div className="detail-row">
                                        <span className="detail-label">Total Savings:</span>
                                        <span className="detail-value" style={{ color: '#10b981', fontWeight: 'bold' }}>
                                          {formatBytes(log.original_size - (log.dedup_size || log.compressed_size || log.original_size))} 
                                          {' '}({(((log.original_size - (log.dedup_size || log.compressed_size || log.original_size)) / log.original_size) * 100).toFixed(1)}%)
                                        </span>
                                      </div>
                                    )}
                                  </div>

                                  <div className="detail-section">
                                    <h4><AlertTriangle size={18} /> Security Status</h4>
                                    <div className="detail-row">
                                      <span className="detail-label">Threat Level:</span>
                                      <span
                                        className="detail-value"
                                        style={{ color: getThreatLevelColor(log.threat_level) }}
                                      >
                                        {log.threat_level.toUpperCase()}
                                      </span>
                                    </div>
                                    <div className="detail-row">
                                      <span className="detail-label">WAF Status:</span>
                                      <span className={`detail-value ${log.waf_triggered ? 'triggered' : 'clean'}`}>
                                        {log.waf_triggered ? 'Triggered' : 'Clean'}
                                      </span>
                                    </div>
                                    <div className="detail-row">
                                      <span className="detail-label">IDS/IPS Status:</span>
                                      <span className={`detail-value ${log.suricata_triggered ? 'triggered' : 'clean'}`}>
                                        {log.suricata_triggered ? 'Triggered' : 'Clean'}
                                      </span>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </motion.tr>
                        )}
                      </React.Fragment>
                    ))}
                  </AnimatePresence>
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserTrafficLogs;
