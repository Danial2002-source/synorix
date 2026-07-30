import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Activity, AlertTriangle, RefreshCw, Eye, Filter, Ban, Lock, Globe, Play, Pause, Edit, Trash2, Plus, X, Save } from 'lucide-react';
import Navigation from './Navigation';
import './FirewallManagement.css';

interface WAFRule {
  id: string;
  name: string;
  description: string;
  pattern: string;
  action: string;
  enabled: boolean;
  severity: string;
  category: string;
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

interface AllPhaseRules {
  id: number;
  pattern: string;
  message: string;
  severity: number;
  enabled: boolean;
  phase: string;
  tags?: string;
}

const FirewallManagement: React.FC = () => {
  const [wafRules, setWafRules] = useState<WAFRule[]>([]);
  const [allPhaseRules, setAllPhaseRules] = useState<AllPhaseRules[]>([]);
  const [blockedRequests, setBlockedRequests] = useState<BlockedRequest[]>([]);
  const [stats, setStats] = useState<WAFStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'rules' | 'all-phases' | 'blocked'>('overview');
  const [showAddRuleModal, setShowAddRuleModal] = useState(false);
  const [editingRule, setEditingRule] = useState<WAFRule | null>(null);
  const [newRule, setNewRule] = useState<Partial<WAFRule>>({
    name: '',
    description: '',
    pattern: '',
    category: '',
    severity: 'medium',
    enabled: true,
    action: 'block'
  });

  // Fetch WAF statistics
  const fetchStats = async () => {
    try {
      const response = await fetch(`/api/logs/stats?timeframe=24h`);
      if (!response.ok) throw new Error('Failed to fetch stats');
      const data = await response.json();
      setStats({
        totalRequests: data.totalRequests || 0,
        blockedRequests: (data.wafBlocked || 0) + (data.suricataBlocked || 0),
        wafBlocks: data.wafBlocked || 0,
        sqliAttempts: 0, // Not tracked in database yet
        xssAttempts: 0   // Not tracked in database yet
      });
    } catch (err) {
      console.error('Error fetching stats:', err);
      setError('Failed to load statistics');
    }
  };

  // Fetch WAF rules
  const fetchWAFRules = async () => {
    try {
      const response = await fetch(`/api/waf/rules`);
      if (!response.ok) throw new Error('Failed to fetch WAF rules');
      const data = await response.json();
      setWafRules(data.rules || []);
    } catch (err) {
      console.error('Error fetching WAF rules:', err);
      setError('Failed to load WAF rules');
    }
  };

  // Fetch all phase WAF rules
  const fetchAllPhaseRules = async () => {
    try {
      // Try authenticated endpoint first, fallback to test endpoint
      const token = localStorage.getItem('token');
      let response = await fetch(`/api/admin/waf/rules/all-phases`, {
        headers: {
          'Authorization': `Bearer ${token || ''}`
        }
      }).catch(() => null);

      // If authenticated fails, try test endpoint
      if (!response || !response.ok) {
        response = await fetch(`/api/test/waf/rules/all-phases`);
      }

      if (!response?.ok) throw new Error('Failed to fetch all phase rules');
      const data = await response.json();
      setAllPhaseRules(data.rules || []);
    } catch (err) {
      console.error('Error fetching all phase rules:', err);
    }
  };

  // Fetch blocked requests
  const fetchBlockedRequests = async (limit: number = 50) => {
    try {
      const response = await fetch(`/api/logs?limit=${limit}`);
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
        fetchAllPhaseRules(),
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
  const toggleWafRule = async (id: string) => {
    try {
      const response = await fetch(`/api/waf/rules/${id}/toggle`, {
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
        ? `/api/waf/rules/${editingRule.id}`
        : `/api/waf/rules`;
      
      const response = await fetch(url, {
        method: editingRule ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newRule)
      });

      if (!response.ok) throw new Error('Failed to save rule');
      
      await fetchWAFRules();
      setShowAddRuleModal(false);
      setEditingRule(null);
      setNewRule({ name: '', description: '', pattern: '', category: '', severity: 'medium', enabled: true, action: 'block' });
    } catch (err) {
      console.error('Error saving rule:', err);
    }
  };

  // Delete WAF rule
  const deleteWafRule = async (id: string) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    
    try {
      const response = await fetch(`/api/waf/rules/${id}`, {
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
            className={`tab-btn ${activeTab === 'all-phases' ? 'active' : ''}`}
            onClick={() => setActiveTab('all-phases')}
          >
            <Shield size={18} />
            All Phase Rules ({allPhaseRules.length})
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
                  setNewRule({ name: '', description: '', pattern: '', category: '', severity: 'medium', enabled: true, action: 'block' });
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
                        <span className={`severity-badge severity-${rule.severity === 'high' ? '8' : rule.severity === 'medium' ? '5' : '2'}`}>
                          {rule.severity.toUpperCase()}
                        </span>
                        {rule.category && <span className="rule-tags">{rule.category}</span>}
                      </div>
                      <div className="rule-message">{rule.name}</div>
                      <div className="rule-description" style={{fontSize: '0.85rem', color: '#94a3b8', marginBottom: '0.5rem'}}>{rule.description}</div>
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

          {activeTab === 'all-phases' && (
            <div className="all-phases-tab">
              <div className="rules-header">
                <h3>All WAF Phase Rules ({allPhaseRules.length})</h3>
                <button className="refresh-btn" onClick={fetchAllPhaseRules}>
                  <RefreshCw size={18} />
                  Refresh
                </button>
              </div>

              {allPhaseRules.length > 0 ? (
                <div className="rules-table-container">
                  <table className="rules-table">
                    <thead>
                      <tr>
                        <th>Rule ID</th>
                        <th>Phase</th>
                        <th>Message</th>
                        <th>Pattern</th>
                        <th>Severity</th>
                        <th>Tags</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {allPhaseRules.map((rule, idx) => (
                        <motion.tr
                          key={`${rule.phase}-${idx}`}
                          initial={{ opacity: 0, y: 10 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: idx * 0.02 }}
                        >
                          <td className="rule-id">{rule.id}</td>
                          <td><span className="phase-badge">{rule.phase}</span></td>
                          <td className="rule-msg">{rule.message}</td>
                          <td className="rule-pattern" title={rule.pattern}>
                            <code>{rule.pattern.substring(0, 50)}{rule.pattern.length > 50 ? '...' : ''}</code>
                          </td>
                          <td>
                            <span className={`severity-badge severity-${rule.severity >= 4 ? '8' : rule.severity === 3 ? '5' : '2'}`}>
                              {['Low', 'Low', 'Medium', 'High', 'Critical'][rule.severity] || 'Unknown'}
                            </span>
                          </td>
                          <td className="rule-tags">{rule.tags || '—'}</td>
                          <td>
                            <span className={`status-badge ${rule.enabled ? 'enabled' : 'disabled'}`}>
                              {rule.enabled ? '✓ Active' : '✗ Inactive'}
                            </span>
                          </td>
                        </motion.tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty-state">
                  <Shield size={48} />
                  <p>No phase rules loaded</p>
                  <button onClick={fetchAllPhaseRules}>Reload Rules</button>
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
                <label>Rule Name</label>
                <input
                  type="text"
                  value={newRule.name || ''}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  placeholder="SQL Injection Protection"
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <input
                  type="text"
                  value={newRule.description || ''}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  placeholder="Blocks common SQL injection patterns"
                />
              </div>
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
                <label>Category</label>
                <select
                  value={newRule.category || 'injection'}
                  onChange={(e) => setNewRule({ ...newRule, category: e.target.value })}
                >
                  <option value="injection">Injection</option>
                  <option value="xss">Cross-Site Scripting</option>
                  <option value="rce">Remote Code Execution</option>
                  <option value="lfi">Local File Inclusion</option>
                  <option value="traversal">Path Traversal</option>
                  <option value="scanner">Security Scanner</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div className="form-group">
                <label>Severity</label>
                <select
                  value={newRule.severity || 'medium'}
                  onChange={(e) => setNewRule({ ...newRule, severity: e.target.value })}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div className="form-group">
                <label>Action</label>
                <select
                  value={newRule.action || 'block'}
                  onChange={(e) => setNewRule({ ...newRule, action: e.target.value })}
                >
                  <option value="block">Block</option>
                  <option value="log">Log Only</option>
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
