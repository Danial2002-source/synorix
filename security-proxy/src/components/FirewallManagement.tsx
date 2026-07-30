import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Activity, AlertTriangle, RefreshCw, Eye, Filter, Ban, Lock, Globe, Play, Pause, Edit, Trash2, Plus, X, Save } from 'lucide-react';
import Navigation from './Navigation';
import './FirewallManagement.css';

interface WAFRule {
  id: number;
  pattern: string;
  message: string;
  tags: string;
  severity: number;
  enabled: boolean;
}

interface BlockedRequest {
  id: number;
  timestamp: string;
  method: string;
  url: string;
  client_ip: string;
  response_status: number;
  waf_action: string;
  waf_rule: string | null;
  suricata_action: string;
  suricata_alert: string | null;
  user_agent: string;
}

interface WAFStats {
  totalRequests: number;
  blockedRequests: number;
  wafBlocks: number;
  sqliAttempts: number;
  xssAttempts: number;
}

const FirewallManagement: React.FC = () => {
  const [wafRules, setWafRules] = useState<WAFRule[]>([]);
  const [blockedRequests, setBlockedRequests] = useState<BlockedRequest[]>([]);
  const [stats, setStats] = useState<WAFStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'rules' | 'blocked'>('overview');
  const [showAddRuleModal, setShowAddRuleModal] = useState(false);
  const [editingRule, setEditingRule] = useState<WAFRule | null>(null);
  const [newRule, setNewRule] = useState<Partial<WAFRule>>({
    pattern: '',
    message: '',
    tags: '',
    severity: 1,
    enabled: true
  });

  // Fetch WAF statistics
  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/stats');
      if (!response.ok) throw new Error('Failed to fetch stats');
      const data = await response.json();
      setStats({
        totalRequests: data.totalRequests || 0,
        blockedRequests: data.blockedRequests || 0,
        wafBlocks: data.wafBlocks || 0,
        sqliAttempts: data.sqliAttempts || 0,
        xssAttempts: data.xssAttempts || 0
      });
    } catch (err) {
      console.error('Error fetching stats:', err);
      setError('Failed to load statistics');
    }
  };

  // Fetch WAF rules
  const fetchWAFRules = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/waf/rules');
      if (!response.ok) throw new Error('Failed to fetch WAF rules');
      const data = await response.json();
      setWafRules(data.rules || []);
    } catch (err) {
      console.error('Error fetching WAF rules:', err);
      setError('Failed to load WAF rules');
    }
  };

  // Fetch blocked requests
  const fetchBlockedRequests = async (limit: number = 50) => {
    try {
      const response = await fetch(`http://localhost:8080/api/logs?limit=${limit}`);
      if (!response.ok) throw new Error('Failed to fetch logs');
      const data = await response.json();
      
      const blocked = data.data?.filter((log: any) => 
        log.waf_action === 'blocked' || 
        log.response_status >= 400 ||
        log.suricata_action === 'blocked' ||
        /sqlmap|nikto|nmap|burp/i.test(log.user_agent)
      ) || [];
      
      setBlockedRequests(blocked);
    } catch (err) {
      console.error('Error fetching blocked requests:', err);
      setError('Failed to load blocked requests');
    }
  };

  // Initialize data
  useEffect(() => {
    const initializeData = async () => {
      setIsLoading(true);
      await Promise.all([
        fetchStats(),
        fetchWAFRules(),
        fetchBlockedRequests()
      ]);
      setIsLoading(false);
    };

    initializeData();

    // Refresh data every 30 seconds
    const interval = setInterval(() => {
      fetchStats();
      fetchBlockedRequests();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  // Toggle WAF rule
  const toggleWafRule = async (id: number) => {
    try {
      const response = await fetch(`http://localhost:8080/api/waf/rules/${id}/toggle`, {
        method: 'POST'
      });
      if (!response.ok) throw new Error('Failed to toggle rule');
      await fetchWAFRules();
    } catch (err) {
      console.error('Error toggling rule:', err);
    }
  };

  // Add/Edit WAF rule
  const saveWafRule = async () => {
    try {
      const url = editingRule 
        ? `http://localhost:8080/api/waf/rules/${editingRule.id}`
        : 'http://localhost:8080/api/waf/rules';
      
      const response = await fetch(url, {
        method: editingRule ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newRule)
      });

      if (!response.ok) throw new Error('Failed to save rule');
      
      await fetchWAFRules();
      setShowAddRuleModal(false);
      setEditingRule(null);
      setNewRule({ pattern: '', message: '', tags: '', severity: 1, enabled: true });
    } catch (err) {
      console.error('Error saving rule:', err);
    }
  };

  // Delete WAF rule
  const deleteWafRule = async (id: number) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    
    try {
      const response = await fetch(`http://localhost:8080/api/waf/rules/${id}`, {
        method: 'DELETE'
      });
      if (!response.ok) throw new Error('Failed to delete rule');
      await fetchWAFRules();
    } catch (err) {
      console.error('Error deleting rule:', err);
    }
  };

  // Get block reason
  const getBlockReason = (request: BlockedRequest) => {
    if (request.waf_action === 'blocked') {
      return { icon: '🛡️', text: `WAF Block: ${request.waf_rule || 'Security rule'}`, color: '#ff4444' };
    } else if (request.suricata_action === 'blocked') {
      return { icon: '🚨', text: `IDS Block: ${request.suricata_alert || 'Threat detected'}`, color: '#ff4444' };
    } else if (/sqlmap/i.test(request.user_agent)) {
      return { icon: '🔍', text: 'SQL Injection Scanner', color: '#ff8800' };
    } else if (/nikto/i.test(request.user_agent)) {
      return { icon: '🔍', text: 'Security Scanner', color: '#ff8800' };
    } else if (/nmap/i.test(request.user_agent)) {
      return { icon: '🔍', text: 'Port Scanner', color: '#ff8800' };
    } else if (request.response_status === 404) {
      return { icon: '❓', text: 'Not Found', color: '#ffaa00' };
    } else if (request.response_status === 403) {
      return { icon: '⛔', text: 'Forbidden', color: '#ff8800' };
    } else if (request.response_status === 401) {
      return { icon: '🔒', text: 'Unauthorized', color: '#ff8800' };
    } else if (request.response_status >= 500) {
      return { icon: '💥', text: 'Server Error', color: '#ff4444' };
    }
    return { icon: '⚠️', text: 'Suspicious Request', color: '#ffaa00' };
  };

  if (isLoading) {
    return (
      <div className="firewall-container">
        <Navigation />
        <div className="loading-container">
          <RefreshCw className="spinning" size={48} />
          <p>Loading firewall management...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="firewall-container">
      <Navigation />
      
      <div className="firewall-content">
        <motion.div
          className="firewall-header"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="header-left">
            <Shield className="header-icon" size={32} />
            <div>
              <h1>Firewall Management</h1>
              <p>Web Application Firewall & Request Monitoring</p>
            </div>
          </div>
          <button className="refresh-btn" onClick={() => {
            fetchStats();
            fetchWAFRules();
            fetchBlockedRequests();
          }}>
            <RefreshCw size={18} />
            Refresh
          </button>
        </motion.div>

        {/* Stats Overview */}
        {stats && (
          <div className="stats-grid">
            <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <Activity className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.totalRequests.toLocaleString()}</span>
                <span className="stat-label">Total Requests</span>
              </div>
            </motion.div>
            <motion.div className="stat-card blocked" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>
              <Ban className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.blockedRequests.toLocaleString()}</span>
                <span className="stat-label">Blocked Requests</span>
              </div>
            </motion.div>
            <motion.div className="stat-card waf" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
              <Shield className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.wafBlocks.toLocaleString()}</span>
                <span className="stat-label">WAF Blocks</span>
              </div>
            </motion.div>
            <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}>
              <AlertTriangle className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{((stats.blockedRequests / Math.max(stats.totalRequests, 1)) * 100).toFixed(1)}%</span>
                <span className="stat-label">Block Rate</span>
              </div>
            </motion.div>
          </div>
        )}

        {/* Tabs */}
        <div className="firewall-tabs">
          <button
            className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <Eye size={18} />
            Overview
          </button>
          <button
            className={`tab-btn ${activeTab === 'rules' ? 'active' : ''}`}
            onClick={() => setActiveTab('rules')}
          >
            <Filter size={18} />
            WAF Rules ({wafRules.length})
          </button>
          <button
            className={`tab-btn ${activeTab === 'blocked' ? 'active' : ''}`}
            onClick={() => setActiveTab('blocked')}
          >
            <Ban size={18} />
            Blocked Requests ({blockedRequests.length})
          </button>
        </div>

        {/* Tab Content */}
        <div className="tab-content">
          {activeTab === 'overview' && (
            <div className="overview-tab">
              <div className="overview-grid">
                <div className="overview-card">
                  <h3>Attack Prevention</h3>
                  <div className="attack-stats">
                    <div className="attack-stat">
                      <span className="attack-label">SQL Injection:</span>
                      <span className="attack-value">{stats?.sqliAttempts || 0}</span>
                    </div>
                    <div className="attack-stat">
                      <span className="attack-label">XSS Attempts:</span>
                      <span className="attack-value">{stats?.xssAttempts || 0}</span>
                    </div>
                  </div>
                </div>
                <div className="overview-card">
                  <h3>Quick Actions</h3>
                  <div className="quick-actions">
                    <button onClick={() => setActiveTab('rules')} className="action-btn">
                      <Filter size={16} />
                      Manage Rules
                    </button>
                    <button onClick={() => setActiveTab('blocked')} className="action-btn">
                      <Eye size={16} />
                      View Blocked
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'rules' && (
            <div className="rules-tab">
              <div className="rules-header">
                <h3>WAF Rules Configuration</h3>
                <button className="add-rule-btn" onClick={() => {
                  setEditingRule(null);
                  setNewRule({ pattern: '', message: '', tags: '', severity: 1, enabled: true });
                  setShowAddRuleModal(true);
                }}>
                  <Plus size={18} />
                  Add Rule
                </button>
              </div>

              <div className="rules-list">
                {wafRules.map((rule) => (
                  <motion.div
                    key={rule.id}
                    className={`rule-card ${!rule.enabled ? 'disabled' : ''}`}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                  >
                    <div className="rule-info">
                      <div className="rule-header">
                        <span className={`severity-badge severity-${rule.severity}`}>
                          Severity {rule.severity}
                        </span>
                        {rule.tags && <span className="rule-tags">{rule.tags}</span>}
                      </div>
                      <div className="rule-message">{rule.message}</div>
                      <code className="rule-pattern">{rule.pattern}</code>
                    </div>
                    <div className="rule-actions">
                      <button
                        className="toggle-btn"
                        onClick={() => toggleWafRule(rule.id)}
                        title={rule.enabled ? 'Disable' : 'Enable'}
                      >
                        {rule.enabled ? <Pause size={16} /> : <Play size={16} />}
                      </button>
                      <button
                        className="edit-btn"
                        onClick={() => {
                          setEditingRule(rule);
                          setNewRule(rule);
                          setShowAddRuleModal(true);
                        }}
                      >
                        <Edit size={16} />
                      </button>
                      <button
                        className="delete-btn"
                        onClick={() => deleteWafRule(rule.id)}
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </motion.div>
                ))}
              </div>

              {wafRules.length === 0 && (
                <div className="empty-state">
                  <Shield size={48} />
                  <p>No WAF rules configured</p>
                  <button onClick={() => setShowAddRuleModal(true)}>Add Your First Rule</button>
                </div>
              )}
            </div>
          )}

          {activeTab === 'blocked' && (
            <div className="blocked-tab">
              <div className="blocked-header">
                <h3>Blocked & Suspicious Requests</h3>
                <button className="refresh-btn" onClick={() => fetchBlockedRequests()}>
                  <RefreshCw size={16} />
                  Refresh
                </button>
              </div>

              {blockedRequests.length > 0 ? (
                <div className="blocked-table-container">
                  <table className="blocked-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>IP Address</th>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Reason</th>
                        <th>User Agent</th>
                      </tr>
                    </thead>
                    <tbody>
                      {blockedRequests.map((request, index) => {
                        const reason = getBlockReason(request);
                        const statusColor = request.waf_action === 'blocked' || request.suricata_action === 'blocked' 
                          ? '#ff4444' 
                          : request.response_status >= 500 
                            ? '#ff8800' 
                            : request.response_status >= 400 
                              ? '#ffaa00' 
                              : '#00ff88';
                        
                        return (
                          <motion.tr
                            key={request.id}
                            initial={{ opacity: 0, x: -20 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: index * 0.02 }}
                          >
                            <td>{new Date(request.timestamp).toLocaleString()}</td>
                            <td className="ip-cell">{request.client_ip}</td>
                            <td><span className="method-badge">{request.method}</span></td>
                            <td className="url-cell" title={request.url}>{request.url}</td>
                            <td>
                              <span className="status-badge" style={{ backgroundColor: `${statusColor}22`, color: statusColor }}>
                                {request.response_status}
                              </span>
                            </td>
                            <td style={{ color: reason.color }}>
                              {reason.icon} {reason.text}
                            </td>
                            <td className="agent-cell" title={request.user_agent}>
                              {request.user_agent}
                            </td>
                          </motion.tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty-state">
                  <Shield size={48} />
                  <p>No blocked requests</p>
                  <small>All requests are passing through successfully</small>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Add/Edit Rule Modal */}
      {showAddRuleModal && (
        <div className="modal-overlay" onClick={() => setShowAddRuleModal(false)}>
          <motion.div
            className="modal-content"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <h3>{editingRule ? 'Edit WAF Rule' : 'Add New WAF Rule'}</h3>
              <button className="close-btn" onClick={() => setShowAddRuleModal(false)}>
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Pattern (Regex)</label>
                <input
                  type="text"
                  value={newRule.pattern || ''}
                  onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })}
                  placeholder="(?i)select.*from.*where"
                />
              </div>
              <div className="form-group">
                <label>Message</label>
                <input
                  type="text"
                  value={newRule.message || ''}
                  onChange={(e) => setNewRule({ ...newRule, message: e.target.value })}
                  placeholder="SQL Injection Attempt"
                />
              </div>
              <div className="form-group">
                <label>Tags</label>
                <input
                  type="text"
                  value={newRule.tags || ''}
                  onChange={(e) => setNewRule({ ...newRule, tags: e.target.value })}
                  placeholder="attack-sqli"
                />
              </div>
              <div className="form-group">
                <label>Severity (1-10)</label>
                <select
                  value={newRule.severity || 1}
                  onChange={(e) => setNewRule({ ...newRule, severity: parseInt(e.target.value) })}
                >
                  {[...Array(10)].map((_, i) => (
                    <option key={i + 1} value={i + 1}>
                      {i + 1} - {i < 3 ? 'Low' : i < 7 ? 'Medium' : 'High'}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button className="cancel-btn" onClick={() => setShowAddRuleModal(false)}>
                Cancel
              </button>
              <button className="save-btn" onClick={saveWafRule}>
                <Save size={16} />
                {editingRule ? 'Update Rule' : 'Add Rule'}
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
};

export default FirewallManagement;
