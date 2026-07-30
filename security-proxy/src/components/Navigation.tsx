import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Home, Shield, Activity, Eye, Menu, X, FileText, Globe, Archive, Server, LogOut, User, Bell, Settings } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import './Navigation.css';

const Navigation: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  const navItems = [
    {
      path: '/dashboard',
      icon: Home,
      label: 'Dashboard'
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
      path: '/traffic',
      icon: Activity,
      label: 'Traffic'
    },
    {
      path: '/detailed-logs',
      icon: FileText,
      label: 'Logs'
    }
  ];

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
            <Shield className="brand-icon" size={28} />
            <div className="brand-text">
              <span className="brand-name">Synorix</span>
              <span className="brand-subtitle">Security Platform</span>
            </div>
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
                <span className="user-name">Admin</span>
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
                        <div className="user-menu-name">Administrator</div>
                        <div className="user-menu-email">admin@synorix.com</div>
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
              <Shield className="brand-icon" size={24} />
              <span className="brand-name">Synorix</span>
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