import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Activity, Globe, Eye, Server, Archive, Copy, ArrowRight, Lock, TrendingUp, AlertTriangle, Zap, BarChart3, PieChart, RefreshCw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import Navigation from './Navigation';
import './Dashboard.css';

interface QuickStats {
  totalRequests: number;
  blockedRequests: number;
  activeConnections: number;
  avgLatency: number;
}

interface ActivityData {
  day: string;
  allowed: number;
  blocked: number;
}

interface ThreatData {
  type: string;
  count: number;
  percentage: number;
  color?: string;
}

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<QuickStats>({
    totalRequests: 0,
    blockedRequests: 0,
    activeConnections: 0,
    avgLatency: 0
  });
  const [loading, setLoading] = useState(false);
  const [activityData, setActivityData] = useState<ActivityData[]>([]);
  const [threatData, setThreatData] = useState<ThreatData[]>([]);

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
      title: 'AI Deduplication',
      description: 'Smart content deduplication and caching',
      icon: Copy,
      path: '/deduplication',
      color: '#4f46e5',
      stats: 'Cache optimization'
    },
    {
      title: 'Traffic Monitor',
      description: 'Live request logs and traffic analysis',
      icon: Activity,
      path: '/traffic',
      color: '#00ff88',
      stats: `${stats.activeConnections} active`
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
    const fetchDashboardData = async () => {
      setLoading(true);
      try {
        const token = localStorage.getItem('token');
        
        // Fetch quick stats
        try {
          const statsResponse = await fetch(`/api/user/logs/stats`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          if (statsResponse.ok) {
            const data = await statsResponse.json();
            setStats({
              totalRequests: data.stats?.total_requests || 0,
              blockedRequests: (data.stats?.waf_blocks || 0) + (data.stats?.suricata_alerts || 0),
              activeConnections: data.stats?.total_requests || 0,
              avgLatency: Math.round(data.stats?.avg_response_time || 0)
            });
          }
        } catch (err) {
          console.error('Error fetching stats:', err);
        }

        // Fetch activity data (request trends)
        try {
          const activityResponse = await fetch(`/api/user/logs?limit=30`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          if (activityResponse.ok) {
            const data = await activityResponse.json();
            // Group logs by day and calculate allowed/blocked
            const grouped: { [key: string]: ActivityData } = {};
            if (Array.isArray(data)) {
              data.forEach((log: any) => {
                const date = new Date(log.timestamp).toLocaleDateString('en-US', { weekday: 'short' });
                if (!grouped[date]) {
                  grouped[date] = { day: date, allowed: 0, blocked: 0 };
                }
                if (log.waf_triggered || log.suricata_triggered) {
                  grouped[date].blocked++;
                } else {
                  grouped[date].allowed++;
                }
              });
            }
            setActivityData(Object.values(grouped).slice(-7));
          }
        } catch (err) {
          console.error('Error fetching activity data:', err);
        }

        // Fetch threat data
        try {
          const alertsResponse = await fetch(`/api/user/alerts?limit=100`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          if (alertsResponse.ok) {
            const alertsData = await alertsResponse.json();
            // Group alerts by type
            const threatCount: { [key: string]: number } = {};
            const total = alertsData.alerts?.length || 0;
            
            if (Array.isArray(alertsData.alerts)) {
              alertsData.alerts.forEach((alert: any) => {
                const type = alert.alert_type || 'Unknown';
                threatCount[type] = (threatCount[type] || 0) + 1;
              });
            }

            const threats = Object.entries(threatCount)
              .map(([type, count], idx) => ({
                type,
                count,
                percentage: total > 0 ? Math.round((count / total) * 100) : 0,
                color: ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6'][idx % 5]
              }))
              .sort((a, b) => b.count - a.count)
              .slice(0, 5);
            
            setThreatData(threats);
          }
        } catch (err) {
          console.error('Error fetching threat data:', err);
        }
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchDashboardData, 30000);
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
              <div
                key={item.name}
                className={`quick-stat-card ${item.status}`}
              >
                <Icon className="stat-icon" size={24} />
                <div className="stat-info">
                  <span className="stat-label">{item.name}</span>
                  <span className="stat-value">{item.value}</span>
                </div>
              </div>
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

        {/* Recent Activity Summary */}
        <div className="dashboard-section">
          <h2 className="section-title">System Overview</h2>
          <div className="overview-grid">
            <div className="overview-card">
              <h3>Security Summary</h3>
              <div className="overview-stats">
                <div className="overview-stat">
                  <span className="overview-label">Total Requests:</span>
                  <span className="overview-value">{stats.totalRequests.toLocaleString()}</span>
                </div>
                <div className="overview-stat">
                  <span className="overview-label">Blocked Threats:</span>
                  <span className="overview-value">{stats.blockedRequests.toLocaleString()}</span>
                </div>
                <div className="overview-stat">
                  <span className="overview-label">Block Rate:</span>
                  <span className="overview-value">
                    {stats.totalRequests > 0 
                      ? ((stats.blockedRequests / stats.totalRequests) * 100).toFixed(1) 
                      : 0}%
                  </span>
                </div>
              </div>
            </div>

            <div className="overview-card">
              <h3>Performance Metrics</h3>
              <div className="overview-stats">
                <div className="overview-stat">
                  <span className="overview-label">Average Latency:</span>
                  <span className="overview-value">{stats.avgLatency}ms</span>
                </div>
                <div className="overview-stat">
                  <span className="overview-label">Active Connections:</span>
                  <span className="overview-value">{stats.activeConnections}</span>
                </div>
                <div className="overview-stat">
                  <span className="overview-label">System Status:</span>
                  <span className="overview-value status-healthy">Healthy</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Activity and Threat Charts */}
        <div className="dashboard-section">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <h2 className="section-title">Security Analytics</h2>
            <button
              onClick={() => window.location.reload()}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 16px',
                backgroundColor: '#00ff88',
                color: '#000',
                border: 'none',
                borderRadius: '6px',
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.6 : 1,
              }}
            >
              <RefreshCw size={16} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
              Refresh
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            {/* Activity Chart */}
            <div style={{
              backgroundColor: 'rgba(0, 0, 0, 0.9)',
              border: '1px solid rgba(0, 255, 136, 0.3)',
              borderRadius: '8px',
              padding: '20px'
            }}>
              <div style={{ marginBottom: '20px' }}>
                <h3 style={{ color: '#00ff88', margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <BarChart3 size={20} /> Request Activity
                </h3>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-around', height: '200px', gap: '8px' }}>
                {activityData && activityData.length > 0 ? (
                  activityData.map((item, idx) => {
                    const maxTotal = Math.max(...activityData.map(d => (d.allowed || 0) + (d.blocked || 0)), 1);
                    const total = (item.allowed || 0) + (item.blocked || 0);
                    const blockedPercent = total > 0 ? (item.blocked / total) * 100 : 0;
                    const height = (total / maxTotal) * 180;
                    return (
                      <div key={idx} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'flex-end' }}>
                        <div style={{ 
                          width: '100%', 
                          height: `${height}px`,
                          backgroundColor: '#4f46e5',
                          borderRadius: '4px 4px 0 0',
                          position: 'relative',
                          boxShadow: '0 0 10px rgba(79, 70, 229, 0.5)'
                        }}>
                          <div style={{
                            position: 'absolute',
                            bottom: 0,
                            width: '100%',
                            height: `${blockedPercent}%`,
                            backgroundColor: '#ef4444',
                            borderRadius: '4px 4px 0 0',
                            boxShadow: '0 0 8px rgba(239, 68, 68, 0.5)'
                          }} />
                        </div>
                        <span style={{ marginTop: '8px', fontSize: '12px', color: '#888' }}>{item.day}</span>
                      </div>
                    );
                  })
                ) : (
                  <div style={{ color: '#666', textAlign: 'center', width: '100%' }}>No data available</div>
                )}
              </div>
              <div style={{ marginTop: '16px', display: 'flex', gap: '20px', justifyContent: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
                  <div style={{ width: '12px', height: '12px', backgroundColor: '#4f46e5', borderRadius: '2px' }}></div>
                  <span>Allowed</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
                  <div style={{ width: '12px', height: '12px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
                  <span>Blocked</span>
                </div>
              </div>
            </div>

            {/* Threat Distribution */}
            <div style={{
              backgroundColor: 'rgba(0, 0, 0, 0.9)',
              border: '1px solid rgba(79, 70, 229, 0.3)',
              borderRadius: '8px',
              padding: '20px'
            }}>
              <div style={{ marginBottom: '20px' }}>
                <h3 style={{ color: '#4f46e5', margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <PieChart size={20} /> Threat Distribution
                </h3>
              </div>
              <div style={{ height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {threatData && threatData.length > 0 ? (
                  <div style={{ width: '100%', height: '100%', display: 'flex' }}>
                    {threatData.map((threat, idx) => {
                      const total = threatData.reduce((sum, t) => sum + t.count, 0);
                      const percentage = total > 0 ? (threat.count / total) * 100 : 0;
                      return (
                        <div
                          key={idx}
                          style={{
                            flex: percentage,
                            backgroundColor: threat.color,
                            borderRadius: idx === 0 ? '4px 0 0 4px' : idx === threatData.length - 1 ? '0 4px 4px 0' : '0',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            minWidth: '30px',
                            cursor: 'pointer',
                            transition: 'opacity 0.2s',
                            opacity: 0.8,
                            fontSize: '11px',
                            fontWeight: 'bold',
                            color: '#fff'
                          }}
                          title={`${threat.type}: ${threat.count} (${percentage.toFixed(0)}%)`}
                        >
                          {percentage > 8 && `${percentage.toFixed(0)}%`}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div style={{ color: '#666' }}>No threat data available</div>
                )}
              </div>
              <div style={{ marginTop: '16px', fontSize: '12px' }}>
                {threatData && threatData.length > 0 ? (
                  <div>
                    {threatData.map((threat, idx) => (
                      <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                        <div style={{ width: '12px', height: '12px', backgroundColor: threat.color, borderRadius: '2px' }}></div>
                        <span>{threat.type}: {threat.count} ({threat.percentage}%)</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: '#666' }}>No threats detected</div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
