import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Signup from './components/Signup';
import Dashboard from './components/Dashboard';
import IDSIPSManagement from './components/IDSIPSManagement';
import FirewallManagement from './components/FirewallManagement';
import CompressionManagement from './components/CompressionManagement';
import ProxyManagement from './components/ProxyManagement';
import TrafficMonitor from './components/TrafficMonitor';
import DetailedLogs from './components/DetailedLogs';
import { AuthProvider, useAuth } from './context/AuthContext';
import './App.css';

// Protected Route Component
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
};

// Public Route Component (redirect if authenticated)
const PublicRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  return !isAuthenticated ? <>{children}</> : <Navigate to="/dashboard" />;
};

function App() {
  return (
    <AuthProvider>
      <Router>
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
            <Route 
              path="/dashboard" 
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/idsips" 
              element={
                <ProtectedRoute>
                  <IDSIPSManagement />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/firewall" 
              element={
                <ProtectedRoute>
                  <FirewallManagement />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/compression" 
              element={
                <ProtectedRoute>
                  <CompressionManagement />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/proxy" 
              element={
                <ProtectedRoute>
                  <ProxyManagement />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/traffic" 
              element={
                <ProtectedRoute>
                  <TrafficMonitor />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/detailed-logs" 
              element={
                <ProtectedRoute>
                  <DetailedLogs />
                </ProtectedRoute>
              } 
            />
            <Route path="/" element={<Navigate to="/login" />} />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
