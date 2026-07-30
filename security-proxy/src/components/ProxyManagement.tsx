import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Server, Activity, TrendingUp, RefreshCw, Globe, Zap, Clock, AlertCircle } from 'lucide-react';
import Navigation from './Navigation';
import './ProxyManagement.css';

interface ProxyStats {
  totalRequests: number;
  activeConnections: number;
  averageLatency: number;
  requestsPerSecond: number;
  uptime: number;
  errorRate: number;
}

interface ProxyLog {
  timestamp: string;
  method: string;
  url: string;
  status: number;
  latency: number;
  client_ip: string;
  user_agent: string;
}

interface LatencyData {
  timestamp: string;
  latency: number;
}

const ProxyManagement: React.FC = () => {
  const [stats, setStats] = useState<ProxyStats | null>(null);
  const [logs, setLogs] = useState<ProxyLog[]>([]);
  const [latencyData, setLatencyData] = useState<LatencyData[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'logs' | 'performance'>('overview');

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/proxy/stats');
      if (!response.ok) throw new Error('Failed to fetch stats');
      const data = await response.json();
      setStats({
        totalRequests: data.totalRequests || 0,
        activeConnections: data.activeConnections || 0,
        averageLatency: data.averageLatency || 0,
        requestsPerSecond: data.requestsPerSecond || 0,
        uptime: data.uptime || 0,
        errorRate: data.errorRate || 0
      });
    } catch (err) {
      console.error('Error fetching proxy stats:', err);
    }
  };

  const fetchLogs = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/logs?limit=50');
      if (!response.ok) throw new Error('Failed to fetch logs');
      const data = await response.json();
      setLogs(data.data || []);
    } catch (err) {
      console.error('Error fetching proxy logs:', err);
    }
  };

  const fetchLatencyData = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/proxy/latency');
      if (!response.ok) throw new Error('Failed to fetch latency data');
      const data = await response.json();
      setLatencyData(data.data || []);
    } catch (err) {
      console.error('Error fetching latency data:', err);
    }
  };

  useEffect(() => {
    const initializeData = async () => {
      setIsLoading(true);
      await Promise.all([fetchStats(), fetchLogs(), fetchLatencyData()]);
      setIsLoading(false);
    };

    initializeData();

    const interval = setInterval(() => {
      fetchStats();
      fetchLogs();
      fetchLatencyData();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const getStatusColor = (status: number): string => {
    if (status >= 200 && status < 300) return '#00ff88';
    if (status >= 300 && status < 400) return '#00bfff';
    if (status >= 400 && status < 500) return '#ffaa00';
    return '#ff4444';
  };

  if (isLoading) {
    return (
      <div className="proxy-container">
        <Navigation />
        <div className="loading-container">
          <RefreshCw className="spinning" size={48} />
          <p>Loading proxy data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="proxy-container">
      <Navigation />
      
      <div className="proxy-content">
        <motion.div
          className="proxy-header"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="header-left">
            <Server className="header-icon" size={32} />
            <div>
              <h1>Proxy Management</h1>
              <p>Real-time proxy monitoring and analytics</p>
            </div>
          </div>
          <button className="refresh-btn" onClick={() => {
            fetchStats();
            fetchLogs();
            fetchLatencyData();
          }}>
            <RefreshCw size={18} />
            Refresh
          </button>
        </motion.div>

        {stats && (
          <div className="stats-grid">
            <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <Activity className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.totalRequests.toLocaleString()}</span>
                <span className="stat-label">Total Requests</span>
              </div>
            </motion.div>
            <motion.div className="stat-card active" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>
              <Globe className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.activeConnections}</span>
                <span className="stat-label">Active Connections</span>
              </div>
            </motion.div>
            <motion.div className="stat-card latency" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
              <Clock className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.averageLatency.toFixed(0)}ms</span>
                <span className="stat-label">Avg Latency</span>
              </div>
            </motion.div>
            <motion.div className="stat-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}>
              <Zap className="stat-icon" />
              <div className="stat-info">
                <span className="stat-value">{stats.requestsPerSecond.toFixed(1)}</span>
                <span className="stat-label">Requests/sec</span>
              </div>
            </motion.div>
          </div>
        )}

        <div className="proxy-tabs">
          <button
            className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <Activity size={18} />
            Overview
          </button>
          <button
            className={`tab-btn ${activeTab === 'logs' ? 'active' : ''}`}
            onClick={() => setActiveTab('logs')}
          >
            <Server size={18} />
            Request Logs ({logs.length})
          </button>
          <button
            className={`tab-btn ${activeTab === 'performance' ? 'active' : ''}`}
            onClick={() => setActiveTab('performance')}
          >
            <TrendingUp size={18} />
            Performance
          </button>
        </div>

        <div className="tab-content">
          {activeTab === 'overview' && stats && (
            <div className="overview-tab">
              <div className="overview-grid">
                <div className="overview-card">
                  <h3>System Health</h3>
                  <div className="health-metrics">
                    <div className="health-metric">
                      <span className="health-label">Uptime:</span>
                      <span className="health-value">{formatUptime(stats.uptime)}</span>
                    </div>
                    <div className="health-metric">
                      <span className="health-label">Error Rate:</span>
                      <span className="health-value" style={{ 
                        color: stats.errorRate > 5 ? '#ff4444' : stats.errorRate > 1 ? '#ffaa00' : '#00ff88' 
                      }}>
                        {stats.errorRate.toFixed(2)}%
                      </span>
                    </div>
                    <div className="health-metric">
                      <span className="health-label">Status:</span>
                      <span className="health-value" style={{ color: '#00ff88' }}>
                        ✓ Healthy
                      </span>
                    </div>
                  </div>
                </div>

                <div className="overview-card">
                  <h3>Recent Activity</h3>
                  <div className="activity-summary">
                    <div className="activity-item">
                      <span className="activity-icon success">✓</span>
                      <span className="activity-text">
                        {logs.filter(l => l.status >= 200 && l.status < 300).length} successful requests
                      </span>
                    </div>
                    <div className="activity-item">
                      <span className="activity-icon warning">⚠</span>
                      <span className="activity-text">
                        {logs.filter(l => l.status >= 400 && l.status < 500).length} client errors
                      </span>
                    </div>
                    <div className="activity-item">
                      <span className="activity-icon error">✗</span>
                      <span className="activity-text">
                        {logs.filter(l => l.status >= 500).length} server errors
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="logs-tab">
              <div className="logs-header">
                <h3>Recent Proxy Requests</h3>
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
                        <th>IP Address</th>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Latency</th>
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
                          <td className="ip-cell">{log.client_ip}</td>
                          <td><span className="method-badge">{log.method}</span></td>
                          <td className="url-cell" title={log.url}>{log.url}</td>
                          <td>
                            <span 
                              className="status-badge" 
                              style={{ 
                                backgroundColor: `${getStatusColor(log.status)}22`,
                                color: getStatusColor(log.status)
                              }}
                            >
                              {log.status}
                            </span>
                          </td>
                          <td className="latency-cell">
                            {log.latency ? `${log.latency.toFixed(0)}ms` : '-'}
                          </td>
                        </motion.tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty-state">
                  <Server size={48} />
                  <p>No proxy logs yet</p>
                  <small>Logs will appear as requests are processed</small>
                </div>
              )}
            </div>
          )}

          {activeTab === 'performance' && (
            <div className="performance-tab">
              <div className="performance-grid">
                <div className="performance-card">
                  <h3>Latency Statistics</h3>
                  {stats && (
                    <div className="latency-stats">
                      <div className="latency-stat">
                        <span className="latency-label">Average:</span>
                        <span className="latency-value">{stats.averageLatency.toFixed(0)}ms</span>
                      </div>
                      <div className="latency-stat">
                        <span className="latency-label">Min:</span>
                        <span className="latency-value">
                          {logs.length > 0 
                            ? Math.min(...logs.filter(l => l.latency).map(l => l.latency)).toFixed(0)
                            : 0}ms
                        </span>
                      </div>
                      <div className="latency-stat">
                        <span className="latency-label">Max:</span>
                        <span className="latency-value">
                          {logs.length > 0 
                            ? Math.max(...logs.filter(l => l.latency).map(l => l.latency)).toFixed(0)
                            : 0}ms
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                <div className="performance-card">
                  <h3>Throughput</h3>
                  <div className="throughput-stats">
                    <div className="throughput-stat">
                      <span className="throughput-label">Current RPS:</span>
                      <span className="throughput-value">
                        {stats?.requestsPerSecond.toFixed(1) || 0}
                      </span>
                    </div>
                    <div className="throughput-stat">
                      <span className="throughput-label">Total Processed:</span>
                      <span className="throughput-value">
                        {stats?.totalRequests.toLocaleString() || 0}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ProxyManagement;
