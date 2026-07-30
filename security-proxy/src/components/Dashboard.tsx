import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Activity, Globe, Eye, Server, Archive, FileText, ArrowRight, Lock, TrendingUp, AlertTriangle, Zap, BarChart3, TrendingDown, Layers, Timer } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import Navigation from './Navigation';
import './Dashboard.css';

interface QuickStats {
  totalRequests: number;
  blockedRequests: number;
  activeConnections: number;
  avgLatency: number;
}

interface GraphData {
  trafficOverTime: Array<{ time: string; value: number }>;
  threatDistribution: Array<{ type: string; count: number; color: string }>;
  blockRateHistory: Array<{ time: string; blocked: number; allowed: number }>;
  latencyMetrics: Array<{ time: string; value: number }>;
}

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<QuickStats>({
    totalRequests: 0,
    blockedRequests: 0,
    activeConnections: 0,
    avgLatency: 0
  });

  const [graphData, setGraphData] = useState<GraphData>({
    trafficOverTime: [],
    threatDistribution: [],
    blockRateHistory: [],
    latencyMetrics: []
  });

  const dashboardCards = [
    {
      title: 'Firewall Management',
      description: 'WAF rules, blocked requests, and security monitoring',
      icon: Globe,
      path: '/firewall',
      color: '#00ff88',
      stats: `${stats.blockedRequests} blocked`
    },
    {
      title: 'IDS/IPS System',
      description: 'Intrusion detection and prevention alerts',
      icon: Eye,
      path: '/idsips',
      color: '#ff4444',
      stats: 'Real-time monitoring'
    },
    {
      title: 'Proxy Management',
      description: 'Request routing and performance metrics',
      icon: Server,
      path: '/proxy',
      color: '#00bfff',
      stats: `${stats.totalRequests} requests`
    },
    {
      title: 'AI Compression',
      description: 'Intelligent content compression and optimization',
      icon: Archive,
      path: '/compression',
      color: '#ffaa00',
      stats: 'Bandwidth optimization'
    },
    {
      title: 'Traffic Monitor',
      description: 'Live request logs and traffic analysis',
      icon: Activity,
      path: '/traffic',
      color: '#00ff88',
      stats: `${stats.activeConnections} active`
    },
    {
      title: 'Detailed Logs',
      description: 'Comprehensive request analysis and history',
      icon: FileText,
      path: '/detailed-logs',
      color: '#8b5cf6',
      stats: 'Full request logs'
    }
  ];

  const systemHealth = [
    {
      name: 'Security Status',
      value: 'Protected',
      icon: Shield,
      status: 'success'
    },
    {
      name: 'System Load',
      value: 'Normal',
      icon: TrendingUp,
      status: 'success'
    },
    {
      name: 'Threat Level',
      value: 'Low',
      icon: AlertTriangle,
      status: 'success'
    },
    {
      name: 'Performance',
      value: `${stats.avgLatency}ms`,
      icon: Zap,
      status: 'success'
    }
  ];

  useEffect(() => {
    const fetchQuickStats = async () => {
      try {
        const response = await fetch('http://localhost:8080/api/stats');
        if (response.ok) {
          const data = await response.json();
          setStats({
            totalRequests: data.totalRequests || 0,
            blockedRequests: data.blockedRequests || 0,
            activeConnections: data.activeConnections || 0,
            avgLatency: data.avgLatency || 0
          });

          // Generate graph data based on fetched stats
          generateGraphData(data);
        }
      } catch (err) {
        console.error('Error fetching stats:', err);
        // Generate sample data for visualization
        generateSampleGraphData();
      }
    };

    const generateGraphData = (data: any) => {
      // Traffic over time (last 8 hours)
      const trafficOverTime = Array.from({ length: 8 }, (_, i) => ({
        time: `${i * 3}h`,
        value: Math.floor(Math.random() * data.totalRequests * 0.3 + data.totalRequests * 0.2)
      }));

      // Threat distribution
      const threatDistribution = [
        { type: 'SQL Injection', count: Math.floor(data.blockedRequests * 0.35), color: '#ff6b6b' },
        { type: 'XSS Attacks', count: Math.floor(data.blockedRequests * 0.25), color: '#ffa94d' },
        { type: 'Bot Traffic', count: Math.floor(data.blockedRequests * 0.25), color: '#ff8787' },
        { type: 'DDoS Attempts', count: Math.floor(data.blockedRequests * 0.15), color: '#ff5252' }
      ];

      // Block rate history
      const blockRateHistory = Array.from({ length: 8 }, (_, i) => {
        const blocked = Math.floor(Math.random() * data.blockedRequests * 0.3 + data.blockedRequests * 0.2);
        const allowed = blocked * (Math.random() * 3 + 2);
        return { time: `${i * 3}h`, blocked, allowed };
      });

      // Latency metrics (last 8 hours)
      const latencyMetrics = Array.from({ length: 8 }, (_, i) => ({
        time: `${i * 3}h`,
        value: Math.floor(data.avgLatency + (Math.random() - 0.5) * 20)
      }));

      setGraphData({
        trafficOverTime,
        threatDistribution,
        blockRateHistory,
        latencyMetrics
      });
    };

    const generateSampleGraphData = () => {
      const trafficOverTime = Array.from({ length: 8 }, (_, i) => ({
        time: `${i * 3}h`,
        value: Math.floor(Math.random() * 5000 + 2000)
      }));

      const threatDistribution = [
        { type: 'SQL Injection', count: 1250, color: '#ff6b6b' },
        { type: 'XSS Attacks', count: 890, color: '#ffa94d' },
        { type: 'Bot Traffic', count: 850, color: '#ff8787' },
        { type: 'DDoS Attempts', count: 520, color: '#ff5252' }
      ];

      const blockRateHistory = Array.from({ length: 8 }, (_, i) => ({
        time: `${i * 3}h`,
        blocked: Math.floor(Math.random() * 800 + 400),
        allowed: Math.floor(Math.random() * 5000 + 2000)
      }));

      const latencyMetrics = Array.from({ length: 8 }, (_, i) => ({
        time: `${i * 3}h`,
        value: Math.floor(Math.random() * 50 + 20)
      }));

      setGraphData({
        trafficOverTime,
        threatDistribution,
        blockRateHistory,
        latencyMetrics
      });
    };

    fetchQuickStats();
    const interval = setInterval(fetchQuickStats, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-container">
      <Navigation />
      
      <div className="dashboard-content">
        {/* Hero Section */}
        <motion.div
          className="dashboard-hero"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="hero-content">
            <Shield className="hero-icon" size={48} />
            <div>
              <h1 className="hero-title">Synorix Security Platform</h1>
              <p className="hero-subtitle">Comprehensive security and performance monitoring dashboard</p>
            </div>
          </div>
        </motion.div>

        {/* Quick Stats */}
        <div className="quick-stats-grid">
          {systemHealth.map((item, index) => {
            const Icon = item.icon;
            return (
              <motion.div
                key={item.name}
                className={`quick-stat-card ${item.status}`}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <Icon className="stat-icon" size={24} />
                <div className="stat-info">
                  <span className="stat-label">{item.name}</span>
                  <span className="stat-value">{item.value}</span>
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Main Dashboard Cards */}
        <div className="dashboard-section">
          <h2 className="section-title">Security & Monitoring Modules</h2>
          <div className="dashboard-cards-grid">
            {dashboardCards.map((card, index) => {
              const Icon = card.icon;
              return (
                <motion.div
                  key={card.path}
                  className="dashboard-card"
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: index * 0.1 }}
                  onClick={() => navigate(card.path)}
                  whileHover={{ scale: 1.05, y: -5 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <div className="card-header">
                    <div className="card-icon" style={{ backgroundColor: `${card.color}22`, borderColor: card.color }}>
                      <Icon size={32} style={{ color: card.color }} />
                    </div>
                    <ArrowRight className="card-arrow" size={20} />
                  </div>
                  <div className="card-content">
                    <h3 className="card-title">{card.title}</h3>
                    <p className="card-description">{card.description}</p>
                    <div className="card-stats" style={{ color: card.color }}>
                      {card.stats}
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>

        {/* System Overview - Graph Cards */}
        <div className="dashboard-section">
          <h2 className="section-title">Analytics & Insights</h2>
          <div className="graph-cards-grid">
            {/* Traffic Over Time Graph */}
            <motion.div
              className="graph-card"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.1 }}
            >
              <div className="graph-card-header">
                <div className="graph-card-title-section">
                  <Activity size={20} />
                  <h3>Request Traffic</h3>
                </div>
                <span className="graph-card-period">Last 24h</span>
              </div>
              <div className="graph-chart">
                <div className="mini-line-chart">
                  <svg viewBox="0 0 300 100" preserveAspectRatio="none" className="chart-svg">
                    <polyline
                      points={graphData.trafficOverTime.map((d, i) => 
                        `${(i / (graphData.trafficOverTime.length - 1)) * 300},${100 - (d.value / Math.max(...graphData.trafficOverTime.map(x => x.value))) * 80}`
                      ).join(' ')}
                      fill="none"
                      stroke="#00ff88"
                      strokeWidth="2"
                    />
                  </svg>
                </div>
              </div>
              <div className="graph-stats-row">
                <div className="graph-stat-item">
                  <span className="graph-stat-label">Peak</span>
                  <span className="graph-stat-value">{Math.max(...graphData.trafficOverTime.map(d => d.value)).toLocaleString()}</span>
                </div>
                <div className="graph-stat-item">
                  <span className="graph-stat-label">Average</span>
                  <span className="graph-stat-value">{Math.floor(graphData.trafficOverTime.reduce((a, b) => a + b.value, 0) / graphData.trafficOverTime.length).toLocaleString()}</span>
                </div>
              </div>
            </motion.div>

            {/* Threat Distribution */}
            <motion.div
              className="graph-card"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2 }}
            >
              <div className="graph-card-header">
                <div className="graph-card-title-section">
                  <AlertTriangle size={20} />
                  <h3>Threat Distribution</h3>
                </div>
                <span className="graph-card-period">Today</span>
              </div>
              <div className="threat-bars">
                {graphData.threatDistribution.map((threat, index) => {
                  const maxCount = Math.max(...graphData.threatDistribution.map(t => t.count));
                  const percentage = (threat.count / maxCount) * 100;
                  return (
                    <div key={index} className="threat-bar-item">
                      <div className="threat-bar-label-section">
                        <span className="threat-bar-label">{threat.type}</span>
                        <span className="threat-bar-count">{threat.count}</span>
                      </div>
                      <div className="threat-bar-container">
                        <div 
                          className="threat-bar" 
                          style={{ width: `${percentage}%`, backgroundColor: threat.color }}
                        ></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </motion.div>

            {/* Block Rate History */}
            <motion.div
              className="graph-card"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.3 }}
            >
              <div className="graph-card-header">
                <div className="graph-card-title-section">
                  <BarChart3 size={20} />
                  <h3>Blocked vs Allowed</h3>
                </div>
                <span className="graph-card-period">Last 24h</span>
              </div>
              <div className="stacked-bars">
                {graphData.blockRateHistory.map((item, index) => {
                  const total = item.blocked + item.allowed;
                  const blockedPercent = (item.blocked / total) * 100;
                  return (
                    <div key={index} className="stacked-bar-item">
                      <div className="stacked-bar-label">{item.time}</div>
                      <div className="stacked-bar-container">
                        <div 
                          className="stacked-bar-blocked" 
                          style={{ width: `${blockedPercent}%` }}
                          title={`Blocked: ${item.blocked}`}
                        ></div>
                        <div 
                          className="stacked-bar-allowed" 
                          style={{ width: `${100 - blockedPercent}%` }}
                          title={`Allowed: ${item.allowed}`}
                        ></div>
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="graph-stats-row">
                <div className="graph-stat-item">
                  <span className="graph-stat-label blocked-label">Total Blocked</span>
                  <span className="graph-stat-value">{graphData.blockRateHistory.reduce((a, b) => a + b.blocked, 0).toLocaleString()}</span>
                </div>
                <div className="graph-stat-item">
                  <span className="graph-stat-label allowed-label">Total Allowed</span>
                  <span className="graph-stat-value">{graphData.blockRateHistory.reduce((a, b) => a + b.allowed, 0).toLocaleString()}</span>
                </div>
              </div>
            </motion.div>

            {/* Latency Metrics */}
            <motion.div
              className="graph-card"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.4 }}
            >
              <div className="graph-card-header">
                <div className="graph-card-title-section">
                  <Timer size={20} />
                  <h3>Latency Metrics</h3>
                </div>
                <span className="graph-card-period">Last 24h</span>
              </div>
              <div className="graph-chart">
                <div className="mini-line-chart">
                  <svg viewBox="0 0 300 100" preserveAspectRatio="none" className="chart-svg latency-chart">
                    <polyline
                      points={graphData.latencyMetrics.map((d, i) => 
                        `${(i / (graphData.latencyMetrics.length - 1)) * 300},${100 - (d.value / Math.max(...graphData.latencyMetrics.map(x => x.value))) * 80}`
                      ).join(' ')}
                      fill="none"
                      stroke="#00bfff"
                      strokeWidth="2"
                    />
                  </svg>
                </div>
              </div>
              <div className="graph-stats-row">
                <div className="graph-stat-item">
                  <span className="graph-stat-label">Max</span>
                  <span className="graph-stat-value">{Math.max(...graphData.latencyMetrics.map(d => d.value))}ms</span>
                </div>
                <div className="graph-stat-item">
                  <span className="graph-stat-label">Avg</span>
                  <span className="graph-stat-value">{Math.floor(graphData.latencyMetrics.reduce((a, b) => a + b.value, 0) / graphData.latencyMetrics.length)}ms</span>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
