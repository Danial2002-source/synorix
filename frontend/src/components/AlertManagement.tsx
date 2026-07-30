import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  AlertTriangle, Shield, CheckCircle, XCircle, MessageSquare, 
  Filter, RefreshCw, Bell, TrendingUp, Activity, Database,
  ExternalLink, Info, Clock, User, ChevronDown, ChevronUp
} from 'lucide-react';
import Navigation from './Navigation';
import axios from 'axios';
import './AlertManagement.css';

interface Alert {
  id: number;
  alert_type: 'waf' | 'suricata' | 'system';
  severity: 'low' | 'medium' | 'high' | 'critical';
  rule_id: string;
  rule_name: string;
  description: string;
  source_ip: string;
  target_url: string;
  recommended_action: string;
  status: 'open' | 'acknowledged' | 'resolved' | 'dismissed';
  acknowledged_by?: string;
  acknowledged_at?: string;
  resolved_at?: string;
  comment?: string;
  auto_blocked: boolean;
  correlation_id?: string;
  timestamp: string;
  is_read: boolean;
}

interface Correlation {
  id: number;
  correlation_id: string;
  alert_pattern: string;
  source_ip: string;
  alert_count: number;
  severity: string;
  first_seen: string;
  last_seen: string;
  auto_action_taken?: string;
  alert_descriptions?: string;
  related_alerts: number;
}

interface AutomatedResponse {
  id: number;
  action_type: 'ip_block' | 'rate_limit' | 'notification';
  target: string;
  reason: string;
  threshold_exceeded?: string;
  is_active: boolean;
  expires_at?: string;
  created_at: string;
}

const AlertManagement: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [automatedResponses, setAutomatedResponses] = useState<AutomatedResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'alerts' | 'correlation' | 'automated'>('alerts');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [expandedAlert, setExpandedAlert] = useState<number | null>(null);
  const [comment, setComment] = useState('');
  const [filters, setFilters] = useState({
    status: '',
    severity: '',
    alert_type: ''
  });

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, [filters]);

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('token');
      const headers = { Authorization: `Bearer ${token}` };

      const [alertsRes, correlationsRes, responsesRes] = await Promise.all([
        axios.get(`/api/security/alerts`, { 
          headers,
          params: filters
        }),
        axios.get(`/api/security/correlation`, { headers }),
        axios.get(`/api/security/automated-responses`, { headers })
      ]);

      setAlerts(alertsRes.data.alerts || []);
      setCorrelations(correlationsRes.data.correlations || []);
      setAutomatedResponses(responsesRes.data.responses || []);
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAcknowledge = async (alertId: number) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `/api/security/alerts/${alertId}/acknowledge`,
        { comment },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setComment('');
      fetchData();
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    }
  };

  const handleResolve = async (alertId: number) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `/api/security/alerts/${alertId}/resolve`,
        { comment },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setComment('');
      fetchData();
    } catch (error) {
      console.error('Error resolving alert:', error);
    }
  };

  const handleDismiss = async (alertId: number) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `/api/security/alerts/${alertId}/dismiss`,
        { comment },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setComment('');
      fetchData();
    } catch (error) {
      console.error('Error dismissing alert:', error);
    }
  };

  const handleAddComment = async (alertId: number) => {
    if (!comment.trim()) return;
    
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `/api/security/alerts/${alertId}/comment`,
        { comment },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setComment('');
      fetchData();
    } catch (error) {
      console.error('Error adding comment:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors = {
      low: '#00bfff',
      medium: '#ffaa00',
      high: '#ff6b6b',
      critical: '#ff4444'
    };
    return colors[severity as keyof typeof colors] || '#94a3b8';
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'acknowledged':
        return <CheckCircle size={18} />;
      case 'resolved':
        return <CheckCircle size={18} />;
      case 'dismissed':
        return <XCircle size={18} />;
      default:
        return <AlertTriangle size={18} />;
    }
  };

  const stats = {
    total: alerts.length,
    open: alerts.filter(a => a.status === 'open').length,
    critical: alerts.filter(a => a.severity === 'critical').length,
    autoBlocked: alerts.filter(a => a.auto_blocked).length
  };

  return (
    <div className="alert-management-container">
      <Navigation />
      
      <div className="alert-management-content">
        {/* Header */}
        <motion.div
          className="alert-header"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="header-left">
            <Shield className="header-icon" size={32} />
            <div>
              <h1>Security Alert Management</h1>
              <p>Monitor, acknowledge, and respond to security incidents</p>
            </div>
          </div>
          <button className="refresh-btn" onClick={fetchData}>
            <RefreshCw size={18} />
            Refresh
          </button>
        </motion.div>

        {/* Stats Cards */}
        <div className="stats-grid">
          <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
            <AlertTriangle className="stat-icon" />
            <div className="stat-info">
              <span className="stat-value">{stats.total}</span>
              <span className="stat-label">Total Alerts</span>
            </div>
          </motion.div>
          <motion.div className="stat-card warning" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>
            <Bell className="stat-icon" />
            <div className="stat-info">
              <span className="stat-value">{stats.open}</span>
              <span className="stat-label">Open Alerts</span>
            </div>
          </motion.div>
          <motion.div className="stat-card danger" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
            <Activity className="stat-icon" />
            <div className="stat-info">
              <span className="stat-value">{stats.critical}</span>
              <span className="stat-label">Critical</span>
            </div>
          </motion.div>
          <motion.div className="stat-card success" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}>
            <Shield className="stat-icon" />
            <div className="stat-info">
              <span className="stat-value">{stats.autoBlocked}</span>
              <span className="stat-label">Auto-Blocked</span>
            </div>
          </motion.div>
        </div>

        {/* Tabs */}
        <div className="alert-tabs">
          <button
            className={`tab-btn ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => setActiveTab('alerts')}
          >
            <AlertTriangle size={18} />
            Alerts ({stats.total})
          </button>
          <button
            className={`tab-btn ${activeTab === 'correlation' ? 'active' : ''}`}
            onClick={() => setActiveTab('correlation')}
          >
            <TrendingUp size={18} />
            Correlation ({correlations.length})
          </button>
          <button
            className={`tab-btn ${activeTab === 'automated' ? 'active' : ''}`}
            onClick={() => setActiveTab('automated')}
          >
            <Activity size={18} />
            Automated Responses ({automatedResponses.length})
          </button>
        </div>

        {/* Filters (for alerts tab) */}
        {activeTab === 'alerts' && (
          <div className="filters-bar">
            <Filter size={18} />
            <select
              className="filter-select"
              value={filters.status}
              onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            >
              <option value="">All Status</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
              <option value="dismissed">Dismissed</option>
            </select>
            <select
              className="filter-select"
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            >
              <option value="">All Severity</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
            <select
              className="filter-select"
              value={filters.alert_type}
              onChange={(e) => setFilters({ ...filters, alert_type: e.target.value })}
            >
              <option value="">All Types</option>
              <option value="waf">WAF</option>
              <option value="suricata">Suricata IPS</option>
              <option value="system">System</option>
            </select>
          </div>
        )}

        {/* Content */}
        <div className="tab-content">
          {activeTab === 'alerts' && (
            <div className="alerts-list">
              {loading ? (
                <div className="loading-state">
                  <RefreshCw className="spinning" size={32} />
                  <p>Loading alerts...</p>
                </div>
              ) : alerts.length === 0 ? (
                <div className="empty-state">
                  <Shield size={48} />
                  <h3>No Alerts Found</h3>
                  <p>All clear! No security alerts match your filters.</p>
                </div>
              ) : (
                <div className="alerts-table">
                  {alerts.map((alert) => (
                    <motion.div
                      key={alert.id}
                      className={`alert-card ${alert.status}`}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      style={{ borderLeftColor: getSeverityColor(alert.severity) }}
                    >
                      <div className="alert-header-row" onClick={() => setExpandedAlert(expandedAlert === alert.id ? null : alert.id)}>
                        <div className="alert-main-info">
                          <div className="alert-icon">
                            {getStatusIcon(alert.status)}
                          </div>
                          <div className="alert-details">
                            <h3>{alert.rule_name}</h3>
                            <p className="alert-description">{alert.description}</p>
                            <div className="alert-meta">
                              <span className={`badge severity-${alert.severity}`}>{alert.severity}</span>
                              <span className={`badge type-${alert.alert_type}`}>{alert.alert_type}</span>
                              <span className="badge">{alert.source_ip}</span>
                              <span className="timestamp">
                                <Clock size={14} />
                                {new Date(alert.timestamp).toLocaleString()}
                              </span>
                              {alert.auto_blocked && (
                                <span className="badge auto-blocked">Auto-Blocked</span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="alert-actions-quick">
                          <span className={`status-badge status-${alert.status}`}>
                            {alert.status}
                          </span>
                          {expandedAlert === alert.id ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                        </div>
                      </div>

                      <AnimatePresence>
                        {expandedAlert === alert.id && (
                          <motion.div
                            className="alert-expanded"
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                          >
                            <div className="alert-details-grid">
                              <div className="detail-section">
                                <h4><Info size={16} /> Details</h4>
                                <div className="detail-row">
                                  <span>Rule ID:</span>
                                  <span>{alert.rule_id}</span>
                                </div>
                                <div className="detail-row">
                                  <span>Target URL:</span>
                                  <span>{alert.target_url}</span>
                                </div>
                                {alert.correlation_id && (
                                  <div className="detail-row">
                                    <span>Correlation ID:</span>
                                    <span className="correlation-id">{alert.correlation_id}</span>
                                  </div>
                                )}
                                {alert.acknowledged_by && (
                                  <div className="detail-row">
                                    <span>Acknowledged By:</span>
                                    <span>{alert.acknowledged_by} at {new Date(alert.acknowledged_at!).toLocaleString()}</span>
                                  </div>
                                )}
                              </div>

                              <div className="detail-section">
                                <h4><Shield size={16} /> Recommended Action</h4>
                                <p>{alert.recommended_action}</p>
                              </div>
                            </div>

                            {alert.comment && (
                              <div className="alert-comments">
                                <h4><MessageSquare size={16} /> Comments</h4>
                                <div className="comment-text">{alert.comment}</div>
                              </div>
                            )}

                            {alert.status === 'open' && (
                              <div className="alert-actions">
                                <div className="comment-input-group">
                                  <input
                                    type="text"
                                    placeholder="Add comment..."
                                    value={comment}
                                    onChange={(e) => setComment(e.target.value)}
                                    className="comment-input"
                                  />
                                  <button
                                    className="action-btn comment"
                                    onClick={() => handleAddComment(alert.id)}
                                    disabled={!comment.trim()}
                                  >
                                    <MessageSquare size={16} />
                                    Add Comment
                                  </button>
                                </div>
                                <div className="action-buttons">
                                  <button
                                    className="action-btn acknowledge"
                                    onClick={() => handleAcknowledge(alert.id)}
                                  >
                                    <CheckCircle size={16} />
                                    Acknowledge
                                  </button>
                                  <button
                                    className="action-btn resolve"
                                    onClick={() => handleResolve(alert.id)}
                                  >
                                    <CheckCircle size={16} />
                                    Resolve
                                  </button>
                                  <button
                                    className="action-btn dismiss"
                                    onClick={() => handleDismiss(alert.id)}
                                  >
                                    <XCircle size={16} />
                                    Dismiss
                                  </button>
                                </div>
                              </div>
                            )}
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'correlation' && (
            <div className="correlation-list">
              {correlations.length === 0 ? (
                <div className="empty-state">
                  <TrendingUp size={48} />
                  <h3>No Correlated Alerts</h3>
                  <p>No attack patterns detected yet.</p>
                </div>
              ) : (
                <div className="correlation-grid">
                  {correlations.map((corr) => (
                    <motion.div
                      key={corr.id}
                      className="correlation-card"
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                    >
                      <div className="correlation-header">
                        <TrendingUp size={24} />
                        <div>
                          <h3>{corr.alert_pattern}</h3>
                          <p className="correlation-source">{corr.source_ip}</p>
                        </div>
                      </div>
                      <div className="correlation-stats">
                        <div className="correlation-stat">
                          <span className="stat-label">Alert Count</span>
                          <span className="stat-value">{corr.alert_count}</span>
                        </div>
                        <div className="correlation-stat">
                          <span className="stat-label">Severity</span>
                          <span className={`severity-badge severity-${corr.severity}`}>{corr.severity}</span>
                        </div>
                        <div className="correlation-stat">
                          <span className="stat-label">Duration</span>
                          <span className="stat-value">
                            {new Date(corr.first_seen).toLocaleDateString()} - {new Date(corr.last_seen).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                      {corr.auto_action_taken && (
                        <div className="auto-action-badge">
                          <Shield size={14} />
                          Auto Action: {corr.auto_action_taken}
                        </div>
                      )}
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'automated' && (
            <div className="automated-responses-list">
              {automatedResponses.length === 0 ? (
                <div className="empty-state">
                  <Activity size={48} />
                  <h3>No Automated Responses</h3>
                  <p>No automated security actions have been taken yet.</p>
                </div>
              ) : (
                <div className="responses-table">
                  <table>
                    <thead>
                      <tr>
                        <th>Action Type</th>
                        <th>Target</th>
                        <th>Reason</th>
                        <th>Threshold</th>
                        <th>Created</th>
                        <th>Expires</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {automatedResponses.map((response) => (
                        <motion.tr
                          key={response.id}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                        >
                          <td>
                            <span className={`action-badge action-${response.action_type}`}>
                              {response.action_type}
                            </span>
                          </td>
                          <td className="target-cell">{response.target}</td>
                          <td className="reason-cell">{response.reason}</td>
                          <td>{response.threshold_exceeded || 'N/A'}</td>
                          <td>{new Date(response.created_at).toLocaleString()}</td>
                          <td>{response.expires_at ? new Date(response.expires_at).toLocaleString() : 'Never'}</td>
                          <td>
                            <span className={`status-indicator ${response.is_active ? 'active' : 'inactive'}`}>
                              {response.is_active ? 'Active' : 'Inactive'}
                            </span>
                          </td>
                        </motion.tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertManagement;
