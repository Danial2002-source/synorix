import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Shield, Eye, AlertCircle, CheckCircle, Filter, RefreshCw, Clock, ChevronDown, ChevronUp, Trash2 } from 'lucide-react';
import Navigation from './Navigation';
import axios from 'axios';
import './Dashboard.css';
import './UserDashboard.css';
import './UserAlerts.css';

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
  action?: 'detected' | 'allowed' | 'blocked' | 'dropped' | 'rejected' | 'prevented';
  auto_blocked: boolean;
  is_read: boolean;
  timestamp: string;
  source?: string; // Added source field to track IDS/IPS/WAF
}

const UserAlerts: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [filters, setFilters] = useState({
    severity: '',
    alert_type: '',
    is_read: ''
  });

  useEffect(() => {
    fetchAlerts();
    
    // Auto-refresh alerts every 5 seconds for real-time updates
    const interval = setInterval(() => {
      fetchAlerts();
    }, 5000);
    
    return () => clearInterval(interval);
  }, [filters]);

  const fetchAlerts = async () => {
    try {
      const token = localStorage.getItem('token');
      const authHeaders = { 
        Authorization: `Bearer ${token}`,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      };
      // Only fetch user-specific alerts to avoid showing other users' data
      // Add timestamp query param to force fresh data
      const cacheKey = `t=${Date.now()}`;
      const userAlertsRes = await axios
        .get(`/api/user/alerts?${cacheKey}`, { 
          headers: authHeaders,
          validateStatus: () => true  // Accept any status code
        })
        .catch(() => ({ data: { alerts: [] } }));

      const userAlerts = userAlertsRes.data.alerts || [];

      // Apply filters
      let filtered = userAlerts;
      if (filters.severity) {
        filtered = filtered.filter((a: Alert) => a.severity === filters.severity);
      }
      if (filters.alert_type) {
        filtered = filtered.filter((a: Alert) => a.alert_type === filters.alert_type);
      }
      if (filters.is_read) {
        const isReadBool = filters.is_read === 'true';
        filtered = filtered.filter((a: Alert) => a.is_read === isReadBool);
      }

      // Always sort newest first regardless of backend order
      filtered.sort((a: Alert, b: Alert) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      setAlerts(filtered);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const markAsRead = async (alertId: number) => {
    try {
      const token = localStorage.getItem('token');
      await axios.put(`/api/user/alerts/${alertId}/read`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAlerts(alerts.map(alert => 
        alert.id === alertId ? { ...alert, is_read: true } : alert
      ));
    } catch (error) {
      console.error('Error marking alert as read:', error);
    }
  };

  const deleteAlert = async (alertId: number) => {
    if (!window.confirm('Are you sure you want to delete this alert?')) return;
    
    try {
      setDeletingId(alertId);
      const token = localStorage.getItem('token');
      await axios.delete(`/api/user/alerts/${alertId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAlerts(alerts.filter(alert => alert.id !== alertId));
      setExpandedRows(prev => {
        const newSet = new Set(prev);
        newSet.delete(alertId);
        return newSet;
      });
    } catch (error) {
      console.error('Error deleting alert:', error);
      alert('Failed to delete alert');
    } finally {
      setDeletingId(null);
    }
  };

  const toggleExpandRow = (alertId: number) => {
    setExpandedRows(prev => {
      const newSet = new Set(prev);
      if (newSet.has(alertId)) {
        newSet.delete(alertId);
      } else {
        newSet.add(alertId);
      }
      return newSet;
    });
  };

  const markAllAsRead = async () => {
    try {
      const token = localStorage.getItem('token');
      await axios.put(`/api/user/alerts/read-all`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAlerts(alerts.map(alert => ({ ...alert, is_read: true })));
    } catch (error) {
      console.error('Error marking all alerts as read:', error);
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

  const getSeverityIcon = (severity: string) => {
    if (severity === 'critical' || severity === 'high') return AlertTriangle;
    return AlertCircle;
  };

  const getAlertTypeIcon = (type: string) => {
    const icons = {
      waf: Shield,
      suricata: Eye,
      system: AlertCircle
    };
    return icons[type as keyof typeof icons] || AlertCircle;
  };

  const getActionBadge = (action?: string, auto_blocked?: boolean, alert_type?: string, source?: string) => {
    // Determine source and action for proper labeling
    const isWAF = alert_type === 'waf' || source?.toLowerCase().includes('waf');
    const isBlocked = action === 'blocked' || action === 'dropped' || action === 'rejected' || action === 'prevented' || auto_blocked;
    
    if (isWAF) {
      return {
        label: 'BLOCKED BY WAF',
        color: '#ff4444',
        icon: Shield,
        description: 'Web Application Firewall - Threat blocked'
      };
    }
    
    if (isBlocked) {
      return {
        label: 'BLOCKED BY IPS',
        color: '#ff4444', 
        icon: Shield,
        description: 'Intrusion Prevention System - Threat blocked inline'
      };
    }
    
    return {
      label: 'DETECTED BY IDS',
      color: '#ffaa00',
      icon: Eye,
      description: 'Intrusion Detection System - Threat detected and logged'
    };
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return date.toLocaleDateString();
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
            <AlertTriangle className="hero-icon" size={60} />
            <div>
              <h1 className="hero-title">Security Alerts</h1>
              <p className="hero-subtitle">Monitor WAF and IDS/IPS security alerts for your backend</p>
            </div>
          </div>
        </motion.div>

        {/* Controls */}
        <div className="alerts-controls">
          <div className="filter-group">
            <Filter size={18} />
            <select
              className="filter-select"
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            >
              <option value="">All Severities</option>
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
              <option value="waf">WAF Alerts</option>
              <option value="suricata">IDS/IPS Alerts</option>
              <option value="system">System Alerts</option>
            </select>

            <select
              className="filter-select"
              value={filters.is_read}
              onChange={(e) => setFilters({ ...filters, is_read: e.target.value })}
            >
              <option value="">All Alerts</option>
              <option value="false">Unread Only</option>
              <option value="true">Read Only</option>
            </select>
          </div>

          <button className="control-btn" onClick={fetchAlerts}>
            <RefreshCw size={18} />
            Refresh
          </button>
          {alerts.some(a => !a.is_read) && (
            <button className="control-btn" onClick={markAllAsRead} style={{ background: 'rgba(0,255,136,0.1)', borderColor: '#00ff88', color: '#00ff88' }}>
              <CheckCircle size={18} />
              Mark All Read
            </button>
          )}
        </div>

        {/* Alerts Table */}
        <div className="alerts-container">
          {loading ? (
            <div className="loading-state">
              <RefreshCw className="spinning" size={32} />
              <p>Loading alerts...</p>
            </div>
          ) : alerts.length === 0 ? (
            <div className="empty-state">
              <CheckCircle size={48} />
              <h3>No Alerts Found</h3>
              <p>Your backend is secure! No security alerts have been triggered.</p>
            </div>
          ) : (
            <div className="alerts-table-wrapper">
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th style={{ width: '50px' }}></th>
                    <th>Alert Type</th>
                    <th>Severity</th>
                    <th>Rule Name</th>
                    <th>Source IP</th>
                    <th>Time</th>
                    <th>Status</th>
                    <th style={{ width: '80px', textAlign: 'center' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert, index) => {
                    const SeverityIcon = getSeverityIcon(alert.severity);
                    const TypeIcon = getAlertTypeIcon(alert.alert_type);
                    const actionBadge = getActionBadge(alert.action, alert.auto_blocked, alert.alert_type, alert.source);
                    const isExpanded = expandedRows.has(alert.id);
                    
                    return (
                      <React.Fragment key={alert.id}>
                        <motion.tr
                          className={`alert-row severity-${alert.severity} ${alert.is_read ? 'read' : 'unread'} ${isExpanded ? 'expanded' : ''}`}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ delay: index * 0.05 }}
                          onClick={() => toggleExpandRow(alert.id)}
                        >
                          <td className="expand-cell">
                            <button className="expand-btn">
                              {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                            </button>
                          </td>
                          <td>
                            <div className="alert-type-badge" style={{ backgroundColor: getSeverityColor(alert.severity), display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 8px', borderRadius: '4px' }}>
                              <TypeIcon size={14} />
                              <span>{alert.alert_type.toUpperCase()}</span>
                            </div>
                          </td>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: getSeverityColor(alert.severity), fontWeight: 'bold' }}>
                              <SeverityIcon size={16} />
                              {alert.severity.toUpperCase()}
                            </div>
                          </td>
                          <td>
                            <div className="rule-name-cell">
                              {alert.rule_name || `Alert #${alert.rule_id}`}
                            </div>
                          </td>
                          <td>
                            <code className="mono-text">{alert.source_ip}</code>
                          </td>
                          <td>
                            <span className="timestamp">{formatTimestamp(alert.timestamp)}</span>
                          </td>
                          <td>
                            {alert.is_read ? (
                              <span className="status-badge read">
                                <CheckCircle size={14} />
                                Read
                              </span>
                            ) : (
                              <span className="status-badge unread">Unread</span>
                            )}
                          </td>
                          <td style={{ textAlign: 'center' }}>
                            <button
                              className="delete-btn"
                              onClick={(e) => {
                                e.stopPropagation();
                                deleteAlert(alert.id);
                              }}
                              disabled={deletingId === alert.id}
                              title="Delete alert"
                            >
                              <Trash2 size={16} />
                            </button>
                          </td>
                        </motion.tr>
                        
                        {/* Expanded Detail Row */}
                        {isExpanded && (
                          <tr className="detail-row">
                            <td colSpan={8}>
                              <motion.div
                                className="alert-details-expanded"
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                              >
                                <div className="detail-grid">
                                  <div className="detail-section">
                                    <h4>Alert Information</h4>
                                    {alert.rule_id && (
                                      <div className="detail-row-item">
                                        <span className="label">{alert.rule_id.includes(',') ? 'Rules Triggered:' : 'Rule ID:'}</span>
                                        <span className="value mono">
                                          {alert.rule_id.includes(',') ? (
                                            <ul style={{ margin: '4px 0 0 0', paddingLeft: '16px', listStyle: 'disc' }}>
                                              {alert.rule_id.split(',').map((r, i) => (
                                                <li key={i} style={{ marginBottom: '2px' }}>{r.trim()}</li>
                                              ))}
                                            </ul>
                                          ) : alert.rule_id}
                                        </span>
                                      </div>
                                    )}
                                    {alert.target_url && (
                                      <div className="detail-row-item">
                                        <span className="label">Target URL:</span>
                                        <span className="value mono">{alert.target_url}</span>
                                      </div>
                                    )}
                                  </div>
                                  
                                  <div className="detail-section">
                                    <h4>Description</h4>
                                    {alert.description.includes(' | ') ? (
                                      <ul className="description-list">
                                        {alert.description.split(' | ').map((d, i) => (
                                          <li key={i}>{d.trim()}</li>
                                        ))}
                                      </ul>
                                    ) : (
                                      <p className="description-text">{alert.description}</p>
                                    )}
                                  </div>
                                  
                                  <div className="detail-section">
                                    <h4>Action & Status</h4>
                                    <div className="detail-row-item">
                                      <span className="label">Action Badge:</span>
                                      <span className="action-badge" style={{ backgroundColor: actionBadge.color + '20', color: actionBadge.color, display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 8px', borderRadius: '4px', border: `1px solid ${actionBadge.color}` }}>
                                        {actionBadge.label}
                                      </span>
                                    </div>
                                    <div className="detail-row-item">
                                      <span className="label">Description:</span>
                                      <span className="value">{actionBadge.description}</span>
                                    </div>
                                  </div>
                                  
                                  {alert.recommended_action && (
                                    <div className="detail-section full-width">
                                      <h4>Recommended Action</h4>
                                      <div className="action-box">
                                        {alert.recommended_action}
                                      </div>
                                    </div>
                                  )}
                                  
                                  {!alert.is_read && (
                                    <div className="detail-section full-width">
                                      <button
                                        className="mark-read-btn-expanded"
                                        onClick={() => markAsRead(alert.id)}
                                      >
                                        <CheckCircle size={16} />
                                        Mark as Read
                                      </button>
                                    </div>
                                  )}
                                </div>
                              </motion.div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserAlerts;
