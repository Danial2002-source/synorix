import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Home, Activity, Eye, Menu, X, Copy, Globe, Archive, Server, LogOut, User, Bell, Settings, Users, Shield } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import './Navigation.css';

const Navigation: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { logout, user, isAdmin } = useAuth();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  const adminNavItems = [
    {
      path: '/dashboard',
      icon: Home,
      label: 'Dashboard'
    },
    {
      path: '/admin/dashboard',
      icon: Settings,
      label: 'Admin Panel'
    },
    {
      path: '/firewall',
      icon: Globe,
      label: 'Firewall'
    },
    {
      path: '/idsips',
      icon: Eye,
      label: 'IDS/IPS'
    },
    {
      path: '/proxy',
      icon: Server,
      label: 'Proxy'
    },
    {
      path: '/compression',
      icon: Archive,
      label: 'Compression'
    },
    {
      path: '/deduplication',
      icon: Copy,
      label: 'Deduplication'
    },
    {
      path: '/traffic',
      icon: Activity,
      label: 'Traffic'
    },
    {
      path: '/admin/users',
      icon: Users,
      label: 'Users'
    }
  ];

  const userNavItems = [
    {
      path: '/user/dashboard',
      icon: Home,
      label: 'Dashboard'
    },
    {
      path: '/user/traffic',
      icon: Activity,
      label: 'Traffic Logs'
    },
    {
      path: '/user/alerts',
      icon: Bell,
      label: 'Alerts'
    },
    {
      path: '/user/setup',
      icon: Settings,
      label: 'Setup'
    }
  ];

  const navItems = isAdmin ? adminNavItems : userNavItems;

  const handleNavigation = (path: string) => {
    navigate(path);
    setIsMobileMenuOpen(false);
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <>
      {/* Fixed Top Navbar */}
      <nav className="top-navbar">
        <div className="navbar-container">
          {/* Logo & Brand */}
          <div className="navbar-brand">
            <img src="/synorix-logo.png" alt="Synorix" className="navbar-logo-img" />
          </div>

          {/* Desktop Navigation Links */}
          <div className="navbar-links">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              
              return (
                <button
                  key={item.path}
                  className={`nav-link ${isActive ? 'active' : ''}`}
                  onClick={() => handleNavigation(item.path)}
                >
                  <Icon size={18} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>

          {/* Right Section - Actions */}
          <div className="navbar-actions">
            <button className="action-btn" title="Notifications">
              <Bell size={20} />
              <span className="notification-badge">3</span>
            </button>
            <button className="action-btn" title="Settings">
              <Settings size={20} />
            </button>
            
            {/* User Menu */}
            <div className="user-menu-container">
              <button 
                className="user-menu-btn"
                onClick={() => setShowUserMenu(!showUserMenu)}
              >
                <User size={20} />
                <span className="user-name">{user?.username || 'User'}</span>
              </button>
              
              {showUserMenu && (
                <>
                  <div 
                    className="user-menu-overlay" 
                    onClick={() => setShowUserMenu(false)}
                  />
                  <div className="user-menu-dropdown">
                    <div className="user-menu-header">
                      <User size={24} />
                      <div>
                        <div className="user-menu-name">{user?.username || 'User'}</div>
                        <div className="user-menu-email">{user?.email || ''}</div>
                        {user?.role && (
                          <div className={`user-menu-role role-${user.role}`}>
                            {user.role === 'admin' ? <Shield size={12} /> : <User size={12} />}
                            {user.role}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="user-menu-divider" />
                    <button className="user-menu-item" onClick={handleLogout}>
                      <LogOut size={18} />
                      <span>Logout</span>
                    </button>
                  </div>
                </>
              )}
            </div>

            {/* Mobile Menu Toggle */}
            <button 
              className="mobile-menu-toggle"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            >
              {isMobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
            </button>
          </div>
        </div>
      </nav>

      {/* Mobile Sidebar Menu */}
      {isMobileMenuOpen && (
        <>
          <div 
            className="mobile-overlay" 
            onClick={() => setIsMobileMenuOpen(false)}
          />
          <div className="mobile-sidebar">
            <div className="mobile-sidebar-header">
              <img src="/synorix-logo.png" alt="Synorix" className="navbar-logo-img" style={{ height: '64px' }} />
            </div>
            <div className="mobile-nav-items">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = location.pathname === item.path;
                
                return (
                  <button
                    key={item.path}
                    className={`mobile-nav-item ${isActive ? 'active' : ''}`}
                    onClick={() => handleNavigation(item.path)}
                  >
                    <Icon size={20} />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
            <div className="mobile-sidebar-footer">
              <button className="mobile-logout-btn" onClick={handleLogout}>
                <LogOut size={20} />
                <span>Logout</span>
              </button>
            </div>
          </div>
        </>
      )}
    </>
  );
};

export default Navigation;