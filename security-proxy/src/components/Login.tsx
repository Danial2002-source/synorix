import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Eye, EyeOff, Lock, Mail, Shield, Zap } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import './Login.css';

const Login: React.FC = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const { login } = useAuth();

  const validateForm = () => {
    const newErrors: { [key: string]: string } = {};

    // Email validation
    if (!formData.email) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Email format is invalid';
    }

    // Password validation
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) return;

    setLoading(true);
    setMessage('');

    try {
      const result = await login(formData.email, formData.password);
      if (!result.success) {
        setMessage(result.message);
      }
    } catch (error) {
      setMessage('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  return (
    <div className="login-container">
      <div className="login-content">
        {/* Header Section */}
        <motion.div
          className="login-header"
          initial={{ opacity: 0, y: -50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          <div className="logo-section">
            <h1 className="logo-text glow-text">SYNORIX</h1>
          </div>
          <p className="tagline">Smart AI-Driven Proxy</p>
        </motion.div>

        <div className="content-sections">
          {/* Matrix-like Terminal Preview */}
          <motion.div
            className="terminal-preview"
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.5 }}
          >
            <div className="terminal-header">
              <div className="terminal-controls">
                <span className="control-dot red"></span>
                <span className="control-dot yellow"></span>
                <span className="control-dot green"></span>
              </div>
              <span className="terminal-title">synorix@proxy:~$</span>
            </div>
            <div className="terminal-body">
              <div className="terminal-line">
                <span className="prompt">$</span> synorix --status
              </div>
              <div className="terminal-line success">
                ✓ AI Engine: Active
              </div>
              <div className="terminal-line success">
                ✓ Security Layer: Protected
              </div>
              <div className="terminal-line warning">
                ⚡ Optimization: Real-time
              </div>
              <div className="terminal-line">
                <span className="prompt">$</span> <span className="cursor">_</span>
              </div>
            </div>
          </motion.div>
          
          {/* Login Form */}
          <motion.div
            className="login-form-container"
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          >
          <form className="login-form" onSubmit={handleSubmit}>
            <h2 className="form-title">Access Terminal</h2>
            
            {message && (
              <motion.div
                className={`message ${message.includes('success') ? 'success' : 'error'}`}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
              >
                {message}
              </motion.div>
            )}

            <div className="form-group">
              <label htmlFor="email" className="form-label">
                <Mail className="label-icon" />
                Email Address
              </label>
              <div className="input-container">
                <input
                  type="email"
                  id="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  className={`form-input ${errors.email ? 'error' : ''}`}
                  placeholder="user@synorix.ai"
                  required
                />
                <div className="input-glow"></div>
              </div>
              {errors.email && <span className="error-text">{errors.email}</span>}
            </div>

            <div className="form-group">
              <label htmlFor="password" className="form-label">
                <Lock className="label-icon" />
                Password
              </label>
              <div className="input-container">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  className={`form-input ${errors.password ? 'error' : ''}`}
                  placeholder="Enter your password"
                  required
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
                <div className="input-glow"></div>
              </div>
              {errors.password && <span className="error-text">{errors.password}</span>}
            </div>

            <motion.button
              type="submit"
              className="login-button cyber-button"
              disabled={loading}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {loading ? (
                <div className="loading-spinner"></div>
              ) : (
                <>
                  <Lock className="button-icon" />
                  Initialize Connection
                </>
              )}
            </motion.button>

            <div className="form-footer">
              <p className="signup-link">
                New to Synorix?{' '}
                <Link to="/signup" className="link-accent">
                  Create Account
                </Link>
              </p>
            </div>
          </form>
        </motion.div>
        </div>
      </div>
    </div>
  );
};

export default Login;
