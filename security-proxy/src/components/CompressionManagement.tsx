import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Archive, Zap, TrendingDown, RefreshCw, Activity, FileText, BarChart, Settings } from 'lucide-react';
import Navigation from './Navigation';
import './CompressionManagement.css';

interface CompressionStats {
  totalCompressed: number;
  totalSavings: number;
  averageRatio: number;
  activeConnections: number;
}

interface CompressionLog {
  timestamp: string;
  original_size: number;
  compressed_size: number;
  compression_ratio: number;
  method: string;
  url: string;
  status: string;
}

const CompressionManagement: React.FC = () => {
  const [stats, setStats] = useState<CompressionStats | null>(null);
  const [logs, setLogs] = useState<CompressionLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'logs' | 'settings'>('overview');
  const [compressionEnabled, setCompressionEnabled] = useState(true);

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/compression/stats');
      if (!response.ok) throw new Error('Failed to fetch stats');
      const data = await response.json();
      setStats({
        totalCompressed: data.totalCompressed || 0,
        totalSavings: data.totalSavings || 0,
        averageRatio: data.averageRatio || 0,
        activeConnections: data.activeConnections || 0
      });
    } catch (err) {
      console.error('Error fetching compression stats:', err);
    }
  };

  const fetchLogs = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/compression/logs?limit=50');
      if (!response.ok) throw new Error('Failed to fetch logs');
      const data = await response.json();
      setLogs(data.logs || []);
    } catch (err) {
      console.error('Error fetching compression logs:', err);
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
      <div className="compression-container">
        <Navigation />
        <div className="loading-container">
          <RefreshCw className="spinning" size={48} />
          <p>Loading compression data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="compression-container">
      <Navigation />
      
      <div className="compression-content">
        <motion.div
          className="compression-header"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="header-left">
            <Archive className="header-icon" size={32} />
            <div>
              <h1>AI Compression Management</h1>
              <p>Intelligent content compression and optimization</p>
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
                <span className="stat-value">{stats.totalCompressed.toLocaleString()}</span>
                <span className="stat-label">Total Compressed</span>
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
              <Zap className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{formatRatio(stats.averageRatio)}</span>
                <span className="stat-label">Average Ratio</span>
              </div>
            </motion.div>
            <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}>
              <Activity className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.activeConnections}</span>
                <span className="stat-label">Active Connections</span>
              </div>
            </motion.div>
          </div>
        )}

        <div className="compression-tabs">
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
            Compression Logs ({logs.length})
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
                  <h3>Compression Performance</h3>
                  <div className="performance-metrics">
                    <div className="metric">
                      <span className="metric-label">Best Ratio:</span>
                      <span className="metric-value">
                        {logs.length > 0 
                          ? formatRatio(Math.max(...logs.map(l => l.compression_ratio)))
                          : '0%'}
                      </span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Total Requests:</span>
                      <span className="metric-value">{logs.length}</span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Compression Methods:</span>
                      <span className="metric-value">
                        {[...new Set(logs.map(l => l.method))].length}
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
                          width: `${stats ? Math.min((stats.averageRatio * 100), 100) : 0}%` 
                        }}
                      />
                    </div>
                    <p className="chart-label">
                      Average {stats ? formatRatio(stats.averageRatio) : '0%'} reduction in bandwidth
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="logs-tab">
              <div className="logs-header">
                <h3>Recent Compression Operations</h3>
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
                        <th>Original Size</th>
                        <th>Compressed Size</th>
                        <th>Ratio</th>
                        <th>Method</th>
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
                          <td>{formatBytes(log.original_size)}</td>
                          <td>{formatBytes(log.compressed_size)}</td>
                          <td>
                            <span className="ratio-badge" style={{
                              backgroundColor: log.compression_ratio > 0.5 
                                ? 'rgba(0, 255, 136, 0.2)' 
                                : log.compression_ratio > 0.3 
                                  ? 'rgba(255, 170, 0, 0.2)' 
                                  : 'rgba(255, 68, 68, 0.2)',
                              color: log.compression_ratio > 0.5 
                                ? '#00ff88' 
                                : log.compression_ratio > 0.3 
                                  ? '#ffaa00' 
                                  : '#ff4444'
                            }}>
                              {formatRatio(log.compression_ratio)}
                            </span>
                          </td>
                          <td><span className="method-badge">{log.method}</span></td>
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
                  <Archive size={48} />
                  <p>No compression logs yet</p>
                  <small>Logs will appear as requests are compressed</small>
                </div>
              )}
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="settings-tab">
              <div className="settings-card">
                <h3>Compression Settings</h3>
                <div className="setting-row">
                  <div className="setting-info">
                    <span className="setting-label">Enable AI Compression</span>
                    <span className="setting-description">
                      Use AI-powered compression for optimal results
                    </span>
                  </div>
                  <label className="toggle">
                    <input
                      type="checkbox"
                      checked={compressionEnabled}
                      onChange={() => setCompressionEnabled(!compressionEnabled)}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
                <div className="setting-row">
                  <div className="setting-info">
                    <span className="setting-label">Compression Level</span>
                    <span className="setting-description">
                      Higher levels provide better compression but use more CPU
                    </span>
                  </div>
                  <select className="setting-select">
                    <option value="1">Low (Fast)</option>
                    <option value="5">Medium (Balanced)</option>
                    <option value="9">High (Best Compression)</option>
                  </select>
                </div>
                <div className="setting-row">
                  <div className="setting-info">
                    <span className="setting-label">Minimum Size</span>
                    <span className="setting-description">
                      Only compress responses larger than this size
                    </span>
                  </div>
                  <input type="number" className="setting-input" defaultValue="1024" />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CompressionManagement;
