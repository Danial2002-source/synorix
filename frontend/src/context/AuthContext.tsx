import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import axios from 'axios';

// Configure axios base URL for API calls
// Use window.location.hostname so the frontend works from any machine (VM, remote, etc.)
const API_BASE_URL = '';
axios.defaults.baseURL = API_BASE_URL;

// Enable credentials (cookies) for all axios requests
axios.defaults.withCredentials = true;

// Disable caching globally for all axios GET requests
axios.interceptors.request.use((config) => {
  // Add cache-busting and no-cache headers to all API calls
  config.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate';
  config.headers['Pragma'] = 'no-cache';
  config.headers['Expires'] = '0';
  
  // Add authorization header with access token from state (not localStorage)
  const accessToken = localStorage.getItem('accessToken') || localStorage.getItem('token');
  if (accessToken) {
    config.headers['Authorization'] = `Bearer ${accessToken}`;
  }
  
  // For GET requests, add timestamp to bypass cache
  if (config.method === 'get' && config.url) {
    // Handle both URL query string and config.params
    const separator = config.url.includes('?') ? '&' : '?';
    config.url = `${config.url}${separator}_t=${Date.now()}`;
  }
  return config;
});

// Response interceptor to handle token refresh on 401
axios.interceptors.response.use(
  response => response,
  async error => {
    const originalRequest = error.config;
    
    // If we get 401 or 403 and haven't retried yet, try to refresh the token
    if ((error.response?.status === 401 || error.response?.status === 403) && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        // Call refresh endpoint to get new access token
        const response = await axios.post('/api/auth/refresh');
        const { accessToken } = response.data;
        
        // Store new access token in localStorage
        localStorage.setItem('accessToken', accessToken);
        localStorage.setItem('token', accessToken);
        
        // Update authorization header
        originalRequest.headers['Authorization'] = `Bearer ${accessToken}`;
        
        // Retry original request
        return axios(originalRequest);
      } catch (refreshError) {
        // Refresh failed, clear tokens and redirect to login
        localStorage.removeItem('accessToken');
        localStorage.removeItem('token');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

interface User {
  id: string;
  email: string;
  username: string;
  role: 'user' | 'admin';
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; message: string }>;
  signup: (username: string, email: string, password: string) => Promise<{ success: boolean; message: string }>;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Check if user is already logged in on app start
  useEffect(() => {
    const accessToken = localStorage.getItem('accessToken') || localStorage.getItem('token');
    if (accessToken) {
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('token', accessToken);
      // Set authorization header and verify token with backend
      axios.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
      fetchUser();
    } else {
      setLoading(false);
    }
  }, []);

  const fetchUser = async () => {
    try {
      const response = await axios.get('/api/auth/me');
      setUser(response.data.user);
    } catch (error) {
      // Silently clear invalid tokens - this is expected on first load
      localStorage.removeItem('accessToken');
      localStorage.removeItem('token');
      delete axios.defaults.headers.common['Authorization'];
      console.log('No valid session found, redirecting to login');
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string): Promise<{ success: boolean; message: string }> => {
    try {
      const response = await axios.post('/api/auth/login', {
        email,
        password,
      });

      const accessToken = response.data?.accessToken || response.data?.token;
      const userData = response.data?.user;
      
      // Store access token in sessionStorage (cleared on browser close) for better security
      // Refresh token is automatically stored in httpOnly cookie by backend
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('token', accessToken);
      axios.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
      setUser(userData);

      return { success: true, message: 'Login successful' };
    } catch (error: any) {
      const message = error.response?.data?.message || 'Login failed';
      return { success: false, message };
    }
  };

  const signup = async (username: string, email: string, password: string): Promise<{ success: boolean; message: string }> => {
    try {
      const response = await axios.post('/api/auth/signup', {
        username,
        email,
        password,
      });

      const accessToken = response.data?.accessToken || response.data?.token;
      const userData = response.data?.user;
      
      // Store access token (refresh token in httpOnly cookie handled automatically)
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('token', accessToken);
      axios.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
      setUser(userData);

      return { success: true, message: 'Account created successfully' };
    } catch (error: any) {
      const message = error.response?.data?.message || 'Signup failed';
      return { success: false, message };
    }
  };

  const logout = async () => {
    try {
      // Call logout endpoint to clear refresh token cookie
      await axios.post('/api/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear local state regardless of server response
      localStorage.removeItem('accessToken');
      localStorage.removeItem('token');
      delete axios.defaults.headers.common['Authorization'];
      setUser(null);
    }
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isAdmin: user?.role === 'admin',
    login,
    signup,
    logout,
    loading,
  };

  // Show loading state while checking authentication
  if (loading) {
    // Add animation styles
    const styleSheet = document.createElement('style');
    styleSheet.textContent = `
      @keyframes gradientShift {
        0%, 100% { background: linear-gradient(135deg, #0D47A1 0%, #0D47A1 100%); }
        50% { background: linear-gradient(135deg, #0D47A1 0%, #0D47A1 100%); }
      }
      @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
      }
      @keyframes float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
      }
      .loading-screen {
        animation: gradientShift 3s ease-in-out infinite;
      }
      .loading-logo {
        animation: float 2s ease-in-out infinite;
      }
      .loading-text {
        animation: pulse 2s ease-in-out infinite;
      }
    `;
    document.head.appendChild(styleSheet);

    return (
      <div className="loading-screen" style={{ 
        display: 'flex', 
        flexDirection: 'column',
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        background: 'linear-gradient(135deg, #0D47A1 0%, #0D47A1 100%)',
        color: '#FFFFFF',
        fontFamily: 'Orbitron, monospace',
        gap: '30px',
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Logo */}
        <div className="loading-logo" style={{
          width: '100px',
          height: '100px',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          background: 'rgba(255, 255, 255, 0.1)',
          borderRadius: '50%',
          border: '2px solid rgba(255, 255, 255, 0.3)',
          backdropFilter: 'blur(10px)'
        }}>
          <img 
            src="/synorix-logo.png" 
            alt="Synorix Logo" 
            style={{ width: '70px', height: '70px', filter: 'drop-shadow(0 0 8px rgba(255, 255, 255, 0.3))' }} 
          />
        </div>

        {/* Text Content */}
        <div style={{
          textAlign: 'center'
        }}>
          <div style={{ 
            fontSize: '2.5rem',
            fontWeight: '700',
            marginBottom: '15px',
            letterSpacing: '2px',
            textShadow: '0 4px 15px rgba(0, 0, 0, 0.2)'
          }}>
            SYNORIX
          </div>
          <div className="loading-text" style={{ 
            fontSize: '1rem',
            opacity: 0.9,
            letterSpacing: '1px',
            fontWeight: '500'
          }}>
            Initializing Security Systems...
          </div>
        </div>

        {/* Loading Bar */}
        <div style={{
          width: '120px',
          height: '3px',
          background: 'rgba(255, 255, 255, 0.2)',
          borderRadius: '2px',
          overflow: 'hidden'
        }}>
          <div style={{
            height: '100%',
            background: 'linear-gradient(90deg, transparent, #FFFFFF, transparent)',
            animation: 'pulse 1.5s ease-in-out infinite',
            width: '100%'
          }} />
        </div>
      </div>
    );
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
