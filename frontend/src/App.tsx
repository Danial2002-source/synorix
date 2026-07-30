import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Homepage from './components/Homepage';
import Login from './components/Login';
import Signup from './components/Signup';
import Dashboard from './components/Dashboard';
import AdminDashboard from './components/AdminDashboard';
import IDSIPSManagement from './components/IDSIPSManagement';
import FirewallManagement from './components/FirewallManagement';
import CompressionManagement from './components/CompressionManagement';
import DeduplicationManagement from './components/DeduplicationManagement';
import ProxyManagement from './components/ProxyManagement';
import TrafficMonitor from './components/TrafficMonitor';
import DetailedLogs from './components/DetailedLogs';
import UserDashboard from './components/UserDashboard';
import AdminUserManagement from './components/AdminUserManagement';
import { AuthProvider, useAuth } from './context/AuthContext';
import './App.css';

// Protected Route Component
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
};

// Admin Only Route Component
const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, user } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" />;
  if (user?.role !== 'admin') return <Navigate to="/user/dashboard" />;
  return <>{children}</>;
};

// User Only Route Component
const UserRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, user } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" />;
  if (user?.role === 'admin') return <Navigate to="/admin/dashboard" />;
  return <>{children}</>;
};

// Public Route Component (redirect if authenticated)
const PublicRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, user } = useAuth();
  if (!isAuthenticated) return <>{children}</>;
  // Redirect based on role
  return user?.role === 'admin' ? <Navigate to="/admin/dashboard" /> : <Navigate to="/user/dashboard" />;
};

function App() {
  return (
    <AuthProvider>
      <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <div className="app">
          <Routes>
            <Route 
              path="/login" 
              element={
                <PublicRoute>
                  <Login />
                </PublicRoute>
              } 
            />
            <Route 
              path="/signup" 
              element={
                <PublicRoute>
                  <Signup />
                </PublicRoute>
              } 
            />
            {/* Admin Routes */}
            <Route 
              path="/dashboard" 
              element={
                <AdminRoute>
                  <Dashboard />
                </AdminRoute>
              } 
            />
            <Route 
              path="/admin/dashboard" 
              element={
                <AdminRoute>
                  <AdminDashboard />
                </AdminRoute>
              } 
            />
            <Route 
              path="/idsips" 
              element={
                <AdminRoute>
                  <IDSIPSManagement />
                </AdminRoute>
              } 
            />
            <Route 
              path="/firewall" 
              element={
                <AdminRoute>
                  <FirewallManagement />
                </AdminRoute>
              } 
            />
            <Route 
              path="/compression" 
              element={
                <AdminRoute>
                  <CompressionManagement />
                </AdminRoute>
              } 
            />
            <Route 
              path="/deduplication" 
              element={
                <AdminRoute>
                  <DeduplicationManagement />
                </AdminRoute>
              } 
            />
            <Route 
              path="/proxy" 
              element={
                <AdminRoute>
                  <ProxyManagement />
                </AdminRoute>
              } 
            />
            <Route 
              path="/traffic" 
              element={
                <AdminRoute>
                  <TrafficMonitor />
                </AdminRoute>
              } 
            />
            <Route 
              path="/detailed-logs" 
              element={
                <AdminRoute>
                  <DetailedLogs />
                </AdminRoute>
              } 
            />
            <Route 
              path="/admin/users" 
              element={
                <AdminRoute>
                  <AdminUserManagement />
                </AdminRoute>
              } 
            />

            {/* User Routes */}
            <Route 
              path="/user/dashboard" 
              element={
                <UserRoute>
                  <UserDashboard />
                </UserRoute>
              } 
            />
            <Route path="/user/setup" element={<Navigate to="/user/dashboard" replace />} />
            <Route path="/user/traffic" element={<Navigate to="/user/dashboard" replace />} />
            <Route path="/user/alerts" element={<Navigate to="/user/dashboard" replace />} />

            {/* Legacy route redirects */}
            <Route path="/setup-wizard" element={<Navigate to="/user/dashboard" replace />} />

            {/* Homepage */}
            <Route path="/" element={<Homepage />} />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
