import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Eye, EyeOff, Lock, Mail, User } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import './Login.css';
import './Signup.css';

const Signup: React.FC = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [ripples, setRipples] = useState<{ id: number; x: number; y: number }[]>([]);

  const { signup } = useAuth();

  const validateForm = () => {
    const newErrors: { [key: string]: string } = {};

    if (!formData.username) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    } else if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) {
      newErrors.username = 'Username can only contain letters, numbers, and underscores';
    }

    if (!formData.email) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Email format is invalid';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters';
    } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(formData.password)) {
      newErrors.password = 'Password must contain uppercase, lowercase, number, and special character';
    }

    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your password';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
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
      const result = await signup(formData.username, formData.email, formData.password);
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
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const addRipple = (e: React.MouseEvent<HTMLButtonElement>) => {
    const btn = e.currentTarget;
    const rect = btn.getBoundingClientRect();
    const id = Date.now();
    setRipples(prev => [...prev, { id, x: e.clientX - rect.left, y: e.clientY - rect.top }]);
    setTimeout(() => setRipples(prev => prev.filter(r => r.id !== id)), 650);
  };

  const getPasswordStrength = (password: string) => {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[@$!%*?&]/.test(password)) strength++;
    return strength;
  };

  const passwordStrength = getPasswordStrength(formData.password);
  const strengthLabel = passwordStrength <= 1 ? 'Weak' : passwordStrength <= 2 ? 'Fair' : passwordStrength <= 3 ? 'Good' : passwordStrength <= 4 ? 'Strong' : 'Very Strong';
  const strengthColors = ['#EF4444', '#EF4444', '#F97316', '#EAB308', '#22C55E', '#16A34A'];

  return (
    <div className="auth-page-bg">
      <motion.div
        className="auth-card signup-card"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: 'easeOut' }}
      >
        {/* ── LEFT: Form Panel ── */}
        <div className="auth-left">
          {/* Form Area */}
          <div className="auth-form-area">
            <div className="auth-form-inner">
              <h2 className="auth-form-title">Sign up</h2>
              <p className="auth-form-subtitle">Create your free account in seconds.</p>

              {message && (
                <motion.div
                  className={`auth-alert ${message.toLowerCase().includes('success') ? 'success' : 'error'}`}
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                >
                  {message}
                </motion.div>
              )}

              <form onSubmit={handleSubmit} className="auth-form">
                {/* Username */}
                <div className="auth-field">
                  <div className={`auth-input-wrap ${errors.username ? 'has-error' : ''}`}>
                    <User className="auth-input-icon" size={17} />
                    <div className="auth-float-field">
                      <input
                        type="text"
                        id="signup-username"
                        name="username"
                        value={formData.username}
                        onChange={handleChange}
                        className="auth-input"
                        autoComplete="username"
                        placeholder=" "
                      />
                      <label htmlFor="signup-username" className="auth-float-label">Username</label>
                    </div>
                  </div>
                  {errors.username && <span className="auth-error">{errors.username}</span>}
                </div>

                {/* Email */}
                <div className="auth-field">
                  <div className={`auth-input-wrap ${errors.email ? 'has-error' : ''}`}>
                    <Mail className="auth-input-icon" size={17} />
                    <div className="auth-float-field">
                      <input
                        type="email"
                        id="signup-email"
                        name="email"
                        value={formData.email}
                        onChange={handleChange}
                        className="auth-input"
                        autoComplete="email"
                        placeholder=" "
                      />
                      <label htmlFor="signup-email" className="auth-float-label">Email address</label>
                    </div>
                  </div>
                  {errors.email && <span className="auth-error">{errors.email}</span>}
                </div>

                {/* Password */}
                <div className="auth-field">
                  <div className={`auth-input-wrap ${errors.password ? 'has-error' : ''}`}>
                    <Lock className="auth-input-icon" size={17} />
                    <div className="auth-float-field">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        id="signup-password"
                        name="password"
                        value={formData.password}
                        onChange={handleChange}
                        className="auth-input"
                        autoComplete="new-password"
                        placeholder=" "
                      />
                      <label htmlFor="signup-password" className="auth-float-label">Password</label>
                    </div>
                    <button
                      type="button"
                      className="auth-eye-btn"
                      onClick={() => setShowPassword(!showPassword)}
                      tabIndex={-1}
                    >
                      <AnimatePresence mode="wait" initial={false}>
                        {showPassword ? (
                          <motion.span key="off" initial={{ rotate: -90, opacity: 0, scale: 0.5 }} animate={{ rotate: 0, opacity: 1, scale: 1 }} exit={{ rotate: 90, opacity: 0, scale: 0.5 }} transition={{ duration: 0.15 }} style={{ display: 'flex' }}>
                            <EyeOff size={17} />
                          </motion.span>
                        ) : (
                          <motion.span key="on" initial={{ rotate: 90, opacity: 0, scale: 0.5 }} animate={{ rotate: 0, opacity: 1, scale: 1 }} exit={{ rotate: -90, opacity: 0, scale: 0.5 }} transition={{ duration: 0.15 }} style={{ display: 'flex' }}>
                            <Eye size={17} />
                          </motion.span>
                        )}
                      </AnimatePresence>
                    </button>
                  </div>
                  {formData.password && (
                    <div className="signup-strength-row">
                      <div className="signup-strength-bar">
                        <div
                          className="signup-strength-fill"
                          style={{
                            width: `${(passwordStrength / 5) * 100}%`,
                            background: strengthColors[passwordStrength]
                          }}
                        />
                      </div>
                      <span className="signup-strength-label" style={{ color: strengthColors[passwordStrength] }}>
                        {strengthLabel}
                      </span>
                    </div>
                  )}
                  {errors.password && <span className="auth-error">{errors.password}</span>}
                </div>

                {/* Confirm Password */}
                <div className="auth-field">
                  <div className={`auth-input-wrap ${errors.confirmPassword ? 'has-error' : ''}`}>
                    <Lock className="auth-input-icon" size={17} />
                    <div className="auth-float-field">
                      <input
                        type={showConfirmPassword ? 'text' : 'password'}
                        id="signup-confirm"
                        name="confirmPassword"
                        value={formData.confirmPassword}
                        onChange={handleChange}
                        className="auth-input"
                        autoComplete="new-password"
                        placeholder=" "
                      />
                      <label htmlFor="signup-confirm" className="auth-float-label">Confirm password</label>
                    </div>
                    <button
                      type="button"
                      className="auth-eye-btn"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      tabIndex={-1}
                    >
                      <AnimatePresence mode="wait" initial={false}>
                        {showConfirmPassword ? (
                          <motion.span key="off" initial={{ rotate: -90, opacity: 0, scale: 0.5 }} animate={{ rotate: 0, opacity: 1, scale: 1 }} exit={{ rotate: 90, opacity: 0, scale: 0.5 }} transition={{ duration: 0.15 }} style={{ display: 'flex' }}>
                            <EyeOff size={17} />
                          </motion.span>
                        ) : (
                          <motion.span key="on" initial={{ rotate: 90, opacity: 0, scale: 0.5 }} animate={{ rotate: 0, opacity: 1, scale: 1 }} exit={{ rotate: -90, opacity: 0, scale: 0.5 }} transition={{ duration: 0.15 }} style={{ display: 'flex' }}>
                            <Eye size={17} />
                          </motion.span>
                        )}
                      </AnimatePresence>
                    </button>
                  </div>
                  {errors.confirmPassword && <span className="auth-error">{errors.confirmPassword}</span>}
                </div>

                {/* Submit */}
                <motion.button
                  type="submit"
                  className="auth-btn-primary"
                  disabled={loading}
                  onClick={addRipple}
                >
                  {ripples.map(r => (
                    <span key={r.id} className="auth-ripple" style={{ left: r.x, top: r.y }} />
                  ))}
                  {loading ? <div className="auth-spinner" /> : 'Create Account'}
                </motion.button>

                {/* Login prompt */}
                <p className="auth-redirect">
                  Already have an account?{' '}
                  <Link to="/login" className="auth-redirect-link">Log in</Link>
                </p>
              </form>
            </div>
          </div>
        </div>

        {/* ── RIGHT: Visual Panel ── */}
        <div className="auth-right">
          <div className="auth-right-bg" />

          <motion.div
            className="auth-blob auth-blob-1"
            animate={{ y: [0, -24, 0], x: [0, 12, 0] }}
            transition={{ duration: 7, repeat: Infinity, ease: 'easeInOut' }}
          />
          <motion.div
            className="auth-blob auth-blob-2"
            animate={{ y: [0, 20, 0], x: [0, -16, 0] }}
            transition={{ duration: 9, repeat: Infinity, ease: 'easeInOut', delay: 1 }}
          />
          <motion.div
            className="auth-blob auth-blob-3"
            animate={{ y: [0, 16, 0], x: [0, 10, 0] }}
            transition={{ duration: 6, repeat: Infinity, ease: 'easeInOut', delay: 2 }}
          />
          <motion.div
            className="auth-blob auth-blob-4"
            animate={{ y: [0, -18, 0] }}
            transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut', delay: 0.5 }}
          />

          <div className="auth-ring auth-ring-1" />
          <div className="auth-ring auth-ring-2" />
          <div className="auth-ring auth-ring-3" />

          <div className="auth-right-content">
            <motion.div
              className="auth-right-logo-wrap"
              initial={{ opacity: 0, scale: 0.75, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.25, ease: [0.34, 1.56, 0.64, 1] }}
            >
              {/* Glow halo layers */}
              <motion.div
                className="auth-logo-halo auth-logo-halo-outer"
                animate={{ scale: [1, 1.18, 1], opacity: [0.3, 0.55, 0.3] }}
                transition={{ duration: 3.5, repeat: Infinity, ease: 'easeInOut' }}
              />
              <motion.div
                className="auth-logo-halo auth-logo-halo-inner"
                animate={{ scale: [1, 1.25, 1], opacity: [0.45, 0.75, 0.45] }}
                transition={{ duration: 3.5, repeat: Infinity, ease: 'easeInOut', delay: 0.4 }}
              />
              {/* Floating logo */}
              <motion.img
                src="/synorix-logo.png"
                alt="Synorix"
                className="auth-right-logo"
                animate={{ y: [0, -14, 0] }}
                transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
              />
            </motion.div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default Signup;
