import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Users, Shield, Ban, RefreshCw, CheckCircle, XCircle, Settings, Trash2, Eye } from 'lucide-react';
import Navigation from './Navigation';
import axios from 'axios';
import './Dashboard.css';
import './UserDashboard.css';
import './AdminUserManagement.css';

interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  created_at: string;
  last_login: string;
  is_active: boolean;
  is_banned: boolean;
  backend_url: string;
  is_configured: boolean;
  connectivity_status: string;
}

const AdminUserManagement: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<number | null>(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await axios.get(`/api/admin/users`);
      setUsers(response.data.users);
    } catch (error) {
      console.error('Error fetching users:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleBanUser = async (userId: number, currentBanStatus: boolean) => {
    if (!window.confirm(`Are you sure you want to ${currentBanStatus ? 'unban' : 'ban'} this user?`)) {
      return;
    }

    setActionLoading(userId);
    try {
      await axios.put(`/api/admin/users/${userId}/ban`, {
        is_banned: !currentBanStatus
      });
      await fetchUsers();
    } catch (error) {
      console.error('Error banning user:', error);
      window.alert('Failed to update user ban status');
    } finally {
      setActionLoading(null);
    }
  };

  const handleResetConfig = async (userId: number) => {
    if (!window.confirm('Are you sure you want to reset this user\'s configuration? They will need to go through setup again.')) {
      return;
    }

    setActionLoading(userId);
    try {
      await axios.delete(`/api/admin/users/${userId}/config`);
      await fetchUsers();
      window.alert('User configuration reset successfully');
    } catch (error) {
      console.error('Error resetting config:', error);
      window.alert('Failed to reset user configuration');
    } finally {
      setActionLoading(null);
    }
  };

  const getStatusColor = (status: string) => {
    if (status === 'success') return '#00ff88';
    if (status === 'failed') return '#ff4444';
    return '#94a3b8';
  };

  const formatDate = (dateString: string) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleString();
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
            <Users className="hero-icon" size={60} />
            <div>
              <h1 className="hero-title">User Management</h1>
              <p className="hero-subtitle">Manage all users, configurations, and access permissions</p>
            </div>
          </div>
        </motion.div>

        {/* Stats */}
        <div className="quick-stats-grid">
          <div className="quick-stat-card success">
            <Users className="stat-icon" size={32} />
            <div className="stat-info">
              <div className="stat-label">Total Users</div>
              <div className="stat-value">{users.length}</div>
            </div>
          </div>
          <div className="quick-stat-card">
            <CheckCircle className="stat-icon" size={32} />
            <div className="stat-info">
              <div className="stat-label">Active Users</div>
              <div className="stat-value">{users.filter(u => u.is_active && !u.is_banned).length}</div>
            </div>
          </div>
          <div className="quick-stat-card">
            <Ban className="stat-icon" size={32} />
            <div className="stat-info">
              <div className="stat-label">Banned Users</div>
              <div className="stat-value">{users.filter(u => u.is_banned).length}</div>
            </div>
          </div>
          <div className="quick-stat-card">
            <Settings className="stat-icon" size={32} />
            <div className="stat-info">
              <div className="stat-label">Configured</div>
              <div className="stat-value">{users.filter(u => u.is_configured).length}</div>
            </div>
          </div>
        </div>

        {/* Controls */}
        <div className="admin-controls">
          <button className="control-btn" onClick={fetchUsers}>
            <RefreshCw size={18} />
            Refresh Users
          </button>
        </div>

        {/* Users Table */}
        <div className="users-table-container">
          {loading ? (
            <div className="loading-state">
              <RefreshCw className="spinning" size={32} />
              <p>Loading users...</p>
            </div>
          ) : users.length === 0 ? (
            <div className="empty-state">
              <Users size={48} />
              <h3>No Users Found</h3>
              <p>No users have signed up yet</p>
            </div>
          ) : (
            <div className="users-table-wrapper">
              <table className="users-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Backend Status</th>
                    <th>Created</th>
                    <th>Last Login</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <motion.tr
                      key={user.id}
                      className={`user-row ${user.is_banned ? 'banned' : ''}`}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                    >
                      <td>
                        <div className="user-info">
                          <div className="user-avatar">
                            {user.username.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div className="user-name">{user.username}</div>
                            <div className="user-email">{user.email}</div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className={`role-badge role-${user.role}`}>
                          {user.role === 'admin' ? <Shield size={14} /> : <Users size={14} />}
                          {user.role}
                        </span>
                      </td>
                      <td>
                        {user.is_configured ? (
                          <div className="backend-status">
                            <div className="backend-url">{user.backend_url || 'Not configured'}</div>
                            <span
                              className="status-indicator"
                              style={{ color: getStatusColor(user.connectivity_status) }}
                            >
                              {user.connectivity_status}
                            </span>
                          </div>
                        ) : (
                          <span className="not-configured">Not configured</span>
                        )}
                      </td>
                      <td className="date-cell">{formatDate(user.created_at)}</td>
                      <td className="date-cell">{formatDate(user.last_login)}</td>
                      <td>
                        {user.is_banned ? (
                          <span className="status-badge banned">
                            <Ban size={14} />
                            Banned
                          </span>
                        ) : user.is_active ? (
                          <span className="status-badge active">
                            <CheckCircle size={14} />
                            Active
                          </span>
                        ) : (
                          <span className="status-badge inactive">
                            <XCircle size={14} />
                            Inactive
                          </span>
                        )}
                      </td>
                      <td>
                        <div className="action-buttons">
                          <button
                            className={`action-btn ${user.is_banned ? 'unban' : 'ban'}`}
                            onClick={() => handleBanUser(user.id, user.is_banned)}
                            disabled={actionLoading === user.id || user.role === 'admin'}
                            title={user.role === 'admin' ? 'Cannot ban admin users' : ''}
                          >
                            {actionLoading === user.id ? (
                              <RefreshCw size={16} className="spinning" />
                            ) : user.is_banned ? (
                              <>
                                <CheckCircle size={16} />
                                Unban
                              </>
                            ) : (
                              <>
                                <Ban size={16} />
                                Ban
                              </>
                            )}
                          </button>
                          {user.is_configured && (
                            <button
                              className="action-btn reset"
                              onClick={() => handleResetConfig(user.id)}
                              disabled={actionLoading === user.id}
                            >
                              {actionLoading === user.id ? (
                                <RefreshCw size={16} className="spinning" />
                              ) : (
                                <>
                                  <Trash2 size={16} />
                                  Reset Config
                                </>
                              )}
                            </button>
                          )}
                          <button
                            className="action-btn view"
                            onClick={() => window.open(`/admin/user-logs?user_id=${user.id}`, '_blank')}
                          >
                            <Eye size={16} />
                            View Logs
                          </button>
                        </div>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AdminUserManagement;
