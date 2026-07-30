import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Copy, TrendingDown, BarChart, RefreshCw, Activity, FileText, Settings, Database } from 'lucide-react';
import Navigation from './Navigation';
import './DeduplicationManagement.css';

interface DeduplicationStats {
  totalDeduplicated: number;
  totalSavings: number;
  hitRate: number;
  cacheSize: number;
  cacheEntries: number;
  evictions: number;
}

interface DeduplicationLog {
  timestamp: string;
  original_size: number;
  deduplicated_size: number;
  dedup_ratio: number;
  url: string;
  status: string;
  content_type: string;
  hit: boolean;
}

const DeduplicationManagement: React.FC = () => {
  const [stats, setStats] = useState<DeduplicationStats | null>(null);
  const [logs, setLogs] = useState<DeduplicationLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'logs' | 'settings'>('overview');
  const [dedupEnabled, setDedupEnabled] = useState(true);

  const fetchStats = async () => {
    try {
      const response = await fetch(`/api/deduplication/stats`);
      if (!response.ok) throw new Error('Failed to fetch stats');
      const data = await response.json();
      setStats({
        totalDeduplicated: data.totalDeduplicated || 0,
        totalSavings: data.totalSavings || 0,
        hitRate: data.hitRate || 0,
        cacheSize: data.cacheSize || 0,
        cacheEntries: data.cacheEntries || 0,
        evictions: data.evictions || 0
      });
    } catch (err) {
      console.error('Error fetching deduplication stats:', err);
    }
  };

  const fetchLogs = async () => {
    try {
      const response = await fetch(`/api/deduplication/logs?limit=50`);
      if (!response.ok) throw new Error('Failed to fetch logs');
      const data = await response.json();
      setLogs(data.logs || []);
    } catch (err) {
      console.error('Error fetching deduplication logs:', err);
    }
  };

  useEffect(() => {
    const initializeData = async () => {
      setIsLoading(true);
      await Promise.all([fetchStats(), fetchLogs()]);
      setIsLoading(false);
    };

    initializeData();

    const interval = setInterval(() => {
      fetchStats();
      fetchLogs();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const formatRatio = (ratio: number): string => {
    return `${(ratio * 100).toFixed(1)}%`;
  };

  if (isLoading) {
    return (
      <div className="deduplication-container">
        <Navigation />
        <div className="loading-container">
          <RefreshCw className="spinning" size={48} />
          <p>Loading deduplication data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="deduplication-container">
      <Navigation />
      
      <div className="deduplication-content">
        <motion.div
          className="deduplication-header"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="header-left">
            <Copy className="header-icon" size={32} />
            <div>
              <h1>AI Deduplication Management</h1>
              <p>Intelligent content deduplication and caching</p>
            </div>
          </div>
          <button className="refresh-btn" onClick={() => {
            fetchStats();
            fetchLogs();
          }}>
            <RefreshCw size={18} />
            Refresh
          </button>
        </motion.div>

        {stats && (
          <div className="stats-grid">
            <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <FileText className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.totalDeduplicated.toLocaleString()}</span>
                <span className="stat-label">Total Deduplicated</span>
              </div>
            </motion.div>
            <motion.div className="stat-card savings" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>
              <TrendingDown className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{formatBytes(stats.totalSavings)}</span>
                <span className="stat-label">Total Savings</span>
              </div>
            </motion.div>
            <motion.div className="stat-card ratio" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
              <BarChart className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{formatRatio(stats.hitRate)}</span>
                <span className="stat-label">Cache Hit Rate</span>
              </div>
            </motion.div>
            <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}>
              <Database className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{formatBytes(stats.cacheSize)}</span>
                <span className="stat-label">Cache Memory</span>
              </div>
            </motion.div>
            <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 }}>
              <Database className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.cacheEntries.toLocaleString()}</span>
                <span className="stat-label">Cache Entries</span>
              </div>
            </motion.div>
            <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }}>
              <Activity className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.evictions.toLocaleString()}</span>
                <span className="stat-label">Evictions</span>
              </div>
            </motion.div>
          </div>
        )}

        <div className="deduplication-tabs">
          <button
            className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <BarChart size={18} />
            Overview
          </button>
          <button
            className={`tab-btn ${activeTab === 'logs' ? 'active' : ''}`}
            onClick={() => setActiveTab('logs')}
          >
            <FileText size={18} />
            Deduplication Logs ({logs.length})
          </button>
          <button
            className={`tab-btn ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            <Settings size={18} />
            Settings
          </button>
        </div>

        <div className="tab-content">
          {activeTab === 'overview' && (
            <div className="overview-tab">
              <div className="overview-grid">
                <div className="overview-card">
                  <h3>Deduplication Performance</h3>
                  <div className="performance-metrics">
                    <div className="metric">
                      <span className="metric-label">Best Hit Rate:</span>
                      <span className="metric-value">
                        {logs.length > 0 
                          ? formatRatio(Math.max(...logs.map(l => l.dedup_ratio)))
                          : '0%'}
                      </span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Total Requests:</span>
                      <span className="metric-value">{logs.length}</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Cache Hits:</span>
                      <span className="metric-value">
                        {logs.filter(l => l.hit).length}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="overview-card">
                  <h3>Bandwidth Savings</h3>
                  <div className="savings-chart">
                    <div className="chart-bar">
                      <div 
                        className="chart-fill" 
                        style={{ 
                          width: `${stats ? Math.min((stats.hitRate * 100), 100) : 0}%` 
                        }}
                      />
                    </div>
                    <p className="chart-label">
                      {stats ? formatRatio(stats.hitRate) : '0%'} cache hit rate
                    </p>
                  </div>
                </div>
              </div>

              <div className="overview-card model-info">
                <h3>AI Model Information</h3>
                <div className="model-details">
                  <div className="model-row">
                    <span className="model-label">Model Type:</span>
                    <span className="model-value">XGBoost Classifier</span>
                  </div>
                  <div className="model-row">
                    <span className="model-label">Decision Threshold:</span>
                    <span className="model-value">0.5 (Shadow Mode) / 0.6 (Production)</span>
                  </div>
                  <div className="model-row">
                    <span className="model-label">Features:</span>
                    <span className="model-value">17 total (8 numeric, 5 categorical, 4 boolean)</span>
                  </div>
                  <div className="model-row">
                    <span className="model-label">Endpoint:</span>
                    <span className="model-value">http://localhost:8082/predict_dedup</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="logs-tab">
              <div className="logs-header">
                <h3>Recent Deduplication Operations</h3>
                <button className="refresh-btn" onClick={fetchLogs}>
                  <RefreshCw size={16} />
                  Refresh
                </button>
              </div>

              {logs.length > 0 ? (
                <div className="logs-table-container">
                  <table className="logs-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>URL</th>
                        <th>Content Type</th>
                        <th>Original Size</th>
                        <th>Deduplicated Size</th>
                        <th>Ratio</th>
                        <th>Cache Hit</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logs.map((log, index) => (
                        <motion.tr
                          key={index}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: index * 0.02 }}
                        >
                          <td>{new Date(log.timestamp).toLocaleString()}</td>
                          <td className="url-cell" title={log.url}>{log.url}</td>
                          <td><span className="content-type-badge">{log.content_type}</span></td>
                          <td>{formatBytes(log.original_size)}</td>
                          <td>{formatBytes(log.deduplicated_size)}</td>
                          <td>
                            <span className="ratio-badge" style={{
                              backgroundColor: log.dedup_ratio > 0.5 
                                ? 'rgba(0, 255, 136, 0.2)' 
                                : log.dedup_ratio > 0.3 
                                  ? 'rgba(255, 170, 0, 0.2)' 
                                  : 'rgba(255, 68, 68, 0.2)',
                              color: log.dedup_ratio > 0.5 
                                ? '#00ff88' 
                                : log.dedup_ratio > 0.3 
                                  ? '#ffaa00' 
                                  : '#ff4444'
                            }}>
                              {formatRatio(log.dedup_ratio)}
                            </span>
                          </td>
                          <td>
                            <span className={`hit-badge ${log.hit ? 'hit' : 'miss'}`}>
                              {log.hit ? 'HIT' : 'MISS'}
                            </span>
                          </td>
                          <td>
                            <span className={`status-badge ${log.status === 'success' ? 'success' : 'error'}`}>
                              {log.status}
                            </span>
                          </td>
                        </motion.tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty-state">
                  <Copy size={48} />
                  <p>No deduplication logs yet</p>
                  <small>Logs will appear as content is deduplicated</small>
                </div>
              )}
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="settings-tab">
              <div className="settings-card">
                <h3>Deduplication Settings</h3>
                <div className="setting-row">
                  <div className="setting-info">
                    <span className="setting-label">Enable AI Deduplication</span>
                    <span className="setting-description">
                      Use AI-powered deduplication for optimal cache management
                    </span>
                  </div>
                  <label className="toggle">
                    <input
                      type="checkbox"
                      checked={dedupEnabled}
                      onChange={() => setDedupEnabled(!dedupEnabled)}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
                <div className="setting-row">
                  <div className="setting-info">
                    <span className="setting-label">Decision Threshold</span>
                    <span className="setting-description">
                      Higher threshold means more conservative deduplication
                    </span>
                  </div>
                  <select className="setting-select">
                    <option value="0.4">Low (0.4 - Aggressive)</option>
                    <option value="0.5" selected>Medium (0.5 - Balanced)</option>
                    <option value="0.6">High (0.6 - Conservative)</option>
                  </select>
                </div>
                <div className="setting-row">
                  <div className="setting-info">
                    <span className="setting-label">Cache Size Limit</span>
                    <span className="setting-description">
                      Maximum cache size in MB
                    </span>
                  </div>
                  <input type="number" className="setting-input" defaultValue="100" />
                </div>
                <div className="setting-row">
                  <div className="setting-info">
                    <span className="setting-label">Cache TTL</span>
                    <span className="setting-description">
                      Time to live for cached content (seconds)
                    </span>
                  </div>
                  <input type="number" className="setting-input" defaultValue="3600" />
                </div>
              </div>

              <div className="settings-card">
                <h3>Advanced Settings</h3>
                <div className="setting-row">
                  <div className="setting-info">
                    <span className="setting-label">CPU Load Threshold</span>
                    <span className="setting-description">
                      Skip deduplication when CPU load exceeds this value (0-1)
                    </span>
                  </div>
                  <input type="number" className="setting-input" defaultValue="0.80" step="0.05" min="0" max="1" />
                </div>
                <div className="setting-row">
                  <div className="setting-info">
                    <span className="setting-label">Queue Depth Limit</span>
                    <span className="setting-description">
                      Skip deduplication when queue depth exceeds this value
                    </span>
                  </div>
                  <input type="number" className="setting-input" defaultValue="30" />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DeduplicationManagement;
