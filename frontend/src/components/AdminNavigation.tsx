import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Shield, LogOut, User, Settings, LayoutDashboard } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import './AdminNavigation.css';

const AdminNavigation: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { logout, user } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="admin-top-navbar">
      <div className="admin-navbar-container">
        {/* Logo & Brand */}
        <div className="admin-navbar-brand">
          <img src="/synorix-logo.png" alt="Synorix" className="admin-navbar-logo-img" />
          <span className="admin-brand-subtitle">Admin Panel</span>
        </div>

        {/* Quick Actions */}
        <div className="admin-quick-actions">
          <button 
            className="admin-action-btn"
            onClick={() => navigate('/admin/dashboard')}
            title="Admin Dashboard"
          >
            <LayoutDashboard size={20} />
            <span>Dashboard</span>
          </button>
        </div>

        {/* Right Section - User Menu */}
        <div className="admin-navbar-actions">
          <div className="admin-user-menu-container">
            <button 
              className="admin-user-menu-btn"
              onClick={() => setShowUserMenu(!showUserMenu)}
            >
              <User size={20} />
              <span className="admin-user-name">{user?.username || 'Admin'}</span>
            </button>
            
            {showUserMenu && (
              <>
                <div 
                  className="admin-user-menu-overlay" 
                  onClick={() => setShowUserMenu(false)}
                />
                <div className="admin-user-menu-dropdown">
                  <div className="admin-user-info">
                    <div className="admin-user-avatar">
                      <User size={24} />
                    </div>
                    <div className="admin-user-details">
                      <div className="admin-user-name-text">{user?.username}</div>
                      <div className="admin-user-role">Administrator</div>
                    </div>
                  </div>
                  
                  <div className="admin-menu-divider" />
                  
                  <button className="admin-menu-item" onClick={() => {
                    setShowUserMenu(false);
                    navigate('/admin/dashboard');
                  }}>
                    <LayoutDashboard size={18} />
                    <span>Admin Dashboard</span>
                  </button>
                  
                  <button className="admin-menu-item" onClick={() => {
                    setShowUserMenu(false);
                    // Add settings navigation when implemented
                  }}>
                    <Settings size={18} />
                    <span>Settings</span>
                  </button>
                  
                  <div className="admin-menu-divider" />
                  
                  <button 
                    className="admin-menu-item logout"
                    onClick={handleLogout}
                  >
                    <LogOut size={18} />
                    <span>Logout</span>
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default AdminNavigation;
