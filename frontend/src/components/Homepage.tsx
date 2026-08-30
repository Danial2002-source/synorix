import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Zap, Lock, Menu, X, ArrowRight, Activity, Database, Cpu, Network, CheckCircle, Plug, Settings, Eye, TrendingUp, Star } from 'lucide-react';
import './Homepage.css';

const Homepage: React.FC = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const features = [
    {
      icon: <Shield size={24} />,
      title: "IDS/IPS Protection",
      description: "Advanced threat detection with real-time blocking. Signatures are updated continuously to catch zero-day exploits and emerging attack vectors before they ever reach your services."
    },
    {
      icon: <Lock size={24} />,
      title: "Smart Firewall",
      description: "AI-powered filtering with custom rules. Define granular allow/block policies per endpoint and let the ML engine auto-tune thresholds over time to stay ahead of evolving threats."
    },
    {
      icon: <Cpu size={24} />,
      title: "AI Compression",
      description: "Reduce bandwidth usage by up to 70%. Adaptive models analyze payload structure on the fly, compressing responses intelligently without compromising data integrity or increasing latency."
    },
    {
      icon: <Database size={24} />,
      title: "Deduplication",
      description: "Intelligent traffic optimization at the proxy layer. Cache-aware fingerprinting eliminates redundant requests before they hit your origin, cutting server load and speeding up response times."
    },
    {
      icon: <Activity size={24} />,
      title: "Live Monitoring",
      description: "Real-time analytics and instant alerts. Interactive dashboards surface traffic trends, anomaly scores, and security events with sub-second latency so your team can respond before damage occurs."
    },
    {
      icon: <Network size={24} />,
      title: "Zero-Trust",
      description: "Multi-layer security architecture built on zero implicit trust. Every request is verified and every connection authenticated — no internal or external traffic is ever trusted by default."
    }
  ];

  const steps = [
    {
      number: "01",
      icon: <Plug size={28} />,
      title: "Connect",
      description: "Seamlessly integrate Synorix with your existing infrastructure. Deploy via Docker, Kubernetes, or direct API integration in minutes.",
      features: ["One-click deployment", "API integration", "Zero downtime setup"]
    },
    {
      number: "02",
      icon: <Settings size={28} />,
      title: "Configure",
      description: "Customize security rules, firewall policies, and detection parameters to match your organization's unique security requirements.",
      features: ["Custom rule engine", "Policy templates", "Role-based access"]
    },
    {
      number: "03",
      icon: <Eye size={28} />,
      title: "Protect",
      description: "Monitor threats in real-time with AI-powered detection, automated responses, and instant alerts keeping your network secure 24/7.",
      features: ["Real-time monitoring", "Instant alerts", "Automated response"]
    }
  ];

  return (
    <div className="homepage">
      {/* Navbar */}
      <nav className={`navbar ${isScrolled ? 'scrolled' : ''}`}>
        <div className="container">
          <Link to="/" className="logo">
            <img src="/synorix-logo.png" alt="Synorix" />
            <span>SYNORIX</span>
          </Link>

          <button 
            className="menu-toggle"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          >
            {isMobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>

          <div className={`nav-links ${isMobileMenuOpen ? 'active' : ''}`}>
            <a href="#about">About</a>
            <a href="#features">Features</a>
            <a href="#how-it-works">How It Works</a>
            <a href="#pricing">Pricing</a>
            <Link to="/login" className="btn-signin">
              Sign In
              <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="hero">
        <div className="hero-bg-gradient"></div>
        <div className="hero-bg-grid"></div>
        <div className="hero-blob blob-1"></div>
        <div className="hero-blob blob-2"></div>

        <div className="container hero-inner">
          <motion.div
            className="hero-content-centered"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7 }}
          >
            <motion.div
              className="hero-eyebrow"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <span className="eyebrow-dot"></span>
              <span>⚡ FYP-1 MILESTONE (45% COMPLETED) | PHASE 2 IN PROGRESS</span>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              Smart AI-Driven Proxy,<br />
              <span className="gradient-text">Unified Defense & Optimization.</span>
            </motion.h1>

            <motion.p
              className="hero-desc"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4 }}
            >
              Synorix combines AI-assisted compression, Web Application Firewall (WAF), and Suricata IDS threat monitoring into a high-concurrency reverse proxy architecture.
            </motion.p>

            <motion.div
              className="hero-buttons"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
            >
              <Link to="/signup" className="btn-primary">
                Start Free Trial
                <ArrowRight size={18} />
              </Link>
              <Link to="/login" className="btn-secondary">
                View Dashboard
              </Link>
            </motion.div>

            <motion.div
              className="hero-trust"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.6 }}
            >
              <div className="trust-avatars">
                <div className="avatar avatar-1"></div>
                <div className="avatar avatar-2"></div>
                <div className="avatar avatar-3"></div>
                <div className="avatar avatar-4"></div>
              </div>
              <div className="trust-text">
                <div className="trust-stars">
                  <Star size={14} fill="#fbbf24" stroke="#fbbf24" />
                  <Star size={14} fill="#fbbf24" stroke="#fbbf24" />
                  <Star size={14} fill="#fbbf24" stroke="#fbbf24" />
                  <Star size={14} fill="#fbbf24" stroke="#fbbf24" />
                  <Star size={14} fill="#fbbf24" stroke="#fbbf24" />
                </div>
                <span>Trusted by 10,000+ companies</span>
              </div>
            </motion.div>
          </motion.div>

          {/* Dashboard Preview */}
          <motion.div
            className="hero-dashboard"
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.7, duration: 0.8 }}
          >
            <div className="dashboard-mockup">
              <div className="mockup-header">
                <div className="mockup-dots">
                  <span></span><span></span><span></span>
                </div>
                <div className="mockup-url">synorix.security/dashboard</div>
              </div>
              <div className="mockup-content">
                <div className="mockup-stats">
                  <div className="mockup-stat">
                    <div className="mockup-stat-label">Threats Blocked</div>
                    <div className="mockup-stat-value">50.2M</div>
                    <div className="mockup-stat-change positive">
                      <TrendingUp size={12} /> +12.5%
                    </div>
                  </div>
                  <div className="mockup-stat">
                    <div className="mockup-stat-label">Network Uptime</div>
                    <div className="mockup-stat-value">99.99%</div>
                    <div className="mockup-stat-bar">
                      <div className="mockup-stat-bar-fill" style={{ width: '99%' }}></div>
                    </div>
                  </div>
                </div>
                <div className="mockup-chart">
                  <div className="chart-header">
                    <div className="chart-title">
                      <span className="chart-title-main">Traffic Analysis</span>
                      <span className="chart-title-sub">Last 24h · Real-time</span>
                    </div>
                    <div className="chart-legend">
                      <span className="legend-item">
                        <span className="legend-dot blocked"></span>Blocked
                      </span>
                      <span className="legend-item">
                        <span className="legend-dot allowed"></span>Allowed
                      </span>
                    </div>
                  </div>
                  <div className="chart-body">
                    <div className="chart-yaxis">
                      <span>100</span>
                      <span>75</span>
                      <span>50</span>
                      <span>25</span>
                      <span>0</span>
                    </div>
                    <div className="chart-plot">
                      <div className="chart-grid">
                        <span></span><span></span><span></span><span></span><span></span>
                      </div>
                      <div className="chart-bars">
                        {[
                          { a: 45, b: 30 }, { a: 70, b: 40 }, { a: 55, b: 35 },
                          { a: 85, b: 55 }, { a: 75, b: 45 }, { a: 95, b: 65 },
                          { a: 88, b: 58 }, { a: 65, b: 40 }, { a: 78, b: 50 }
                        ].map((h, i) => (
                          <div className="chart-bar-group" key={i}>
                            <div className="chart-bar-stack">
                              <div className="chart-bar-allowed" style={{ height: `${h.a}%` }}></div>
                              <div className="chart-bar-blocked" style={{ height: `${h.b}%` }}></div>
                            </div>
                          </div>
                        ))}
                      </div>
                      <svg className="chart-trendline" viewBox="0 0 100 100" preserveAspectRatio="none">
                        <defs>
                          <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#1976D2" stopOpacity="0.4" />
                            <stop offset="100%" stopColor="#1976D2" stopOpacity="0" />
                          </linearGradient>
                          <linearGradient id="lineGrad" x1="0" y1="0" x2="1" y2="0">
                            <stop offset="0%" stopColor="#1976D2" />
                            <stop offset="50%" stopColor="#1976D2" />
                            <stop offset="100%" stopColor="#42A5F5" />
                          </linearGradient>
                        </defs>
                        <path
                          d="M 0,65 C 6,55 9,45 16,42 C 22,40 26,52 32,48 C 38,44 42,22 50,25 C 58,28 58,12 66,14 C 74,16 76,32 84,36 C 90,39 95,28 100,25 L 100,100 L 0,100 Z"
                          fill="url(#trendGrad)"
                        />
                        <path
                          d="M 0,65 C 6,55 9,45 16,42 C 22,40 26,52 32,48 C 38,44 42,22 50,25 C 58,28 58,12 66,14 C 74,16 76,32 84,36 C 90,39 95,28 100,25"
                          fill="none"
                          stroke="url(#lineGrad)"
                          strokeWidth="1.8"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                      </svg>
                      <div className="chart-peak">
                        <div className="peak-label">PEAK · 14:20</div>
                        <div className="peak-value">9.2K req/s</div>
                      </div>
                    </div>
                  </div>
                  <div className="chart-xaxis">
                    <span>00:00</span>
                    <span>06:00</span>
                    <span>12:00</span>
                    <span>18:00</span>
                    <span>24:00</span>
                  </div>
                </div>
                <div className="mockup-activity">
                  <div className="activity-row">
                    <span className="activity-dot green"></span>
                    <span className="activity-text">Blocked SQL injection from 203.0.113.42</span>
                    <span className="activity-time">2s</span>
                  </div>
                  <div className="activity-row">
                    <span className="activity-dot purple"></span>
                    <span className="activity-text">Rule update deployed to 12 nodes</span>
                    <span className="activity-time">14s</span>
                  </div>
                  <div className="activity-row">
                    <span className="activity-dot green"></span>
                    <span className="activity-text">DDoS mitigated &mdash; 48k req/s absorbed</span>
                    <span className="activity-time">1m</span>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* About */}
      <section id="about" className="about">
        <div className="about-bg-grid"></div>
        <div className="container">
          <div className="about-grid">
            {/* Left: Animation */}
            <motion.div
              className="about-visual"
              initial={{ opacity: 0, x: -40 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.7 }}
            >
              <div className="about-orbit">
                <div className="orbit-ring ring-1"></div>
                <div className="orbit-ring ring-2"></div>
                <div className="orbit-ring ring-3"></div>

                <div className="orbit-core">
                  <img src="/synorix-logo.png" alt="Synorix" className="orbit-core-logo" />
                  
                </div>

                <div className="orbit-node node-1">
                  <Cpu size={18} />
                  <span>AI Engine</span>
                </div>
                <div className="orbit-node node-2">
                  <Lock size={18} />
                  <span>WAF</span>
                </div>
                <div className="orbit-node node-3">
                  <Database size={18} />
                  <span>Dedup</span>
                </div>
                <div className="orbit-node node-4">
                  <Network size={18} />
                  <span>Proxy</span>
                </div>
                <div className="orbit-node node-5">
                  <Activity size={18} />
                  <span>IDS/IPS</span>
                </div>
                <div className="orbit-node node-6">
                  <Zap size={18} />
                  <span>Realtime</span>
                </div>

                {/* Connecting lines */}
                <svg className="orbit-lines" viewBox="0 0 400 400" preserveAspectRatio="none">
                  <defs>
                    <linearGradient id="lineGrad" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#1976D2" stopOpacity="0.6" />
                      <stop offset="100%" stopColor="#1976D2" stopOpacity="0.1" />
                    </linearGradient>
                  </defs>
                  <circle cx="200" cy="200" r="1" fill="none" stroke="url(#lineGrad)" strokeWidth="1" strokeDasharray="4 4" />
                </svg>

                {/* Floating packets */}
                <span className="packet p1"></span>
                <span className="packet p2"></span>
                <span className="packet p3"></span>
              </div>
            </motion.div>

            {/* Right: Content */}
            <motion.div
              className="about-content"
              initial={{ opacity: 0, x: 40 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.7, delay: 0.1 }}
            >
              <div className="section-kicker about-kicker">
                <span className="kicker-line"></span>
                <span className="kicker-text">ABOUT SYNORIX</span>
              </div>
              <h2 className="about-title">
                Not Just Another <span className="heading-accent">Reverse Proxy.</span>
              </h2>
              <p className="about-lead">
                Synorix is the first reverse proxy that fuses AI-driven traffic intelligence,
                a learning WAF, and real-time deduplication into one unified control plane &mdash;
                purpose-built for teams who need enterprise-grade protection without enterprise-grade complexity.
              </p>

              <div className="about-pillars">
                <div className="about-pillar">
                  <div className="pillar-icon">
                    <Cpu size={20} />
                  </div>
                  <div className="pillar-body">
                    <h3>AI-Native Architecture</h3>
                    <p>Embedded ML models classify, compress, and deduplicate traffic inline &mdash; no sidecars, no round-trips.</p>
                  </div>
                </div>

                <div className="about-pillar">
                  <div className="pillar-icon">
                    <Shield size={20} />
                  </div>
                  <div className="pillar-body">
                    <h3>Adaptive WAF + IDS/IPS</h3>
                    <p>Suricata-powered detection layered with custom rule engines that auto-tune to your traffic patterns.</p>
                  </div>
                </div>

                <div className="about-pillar">
                  <div className="pillar-icon">
                    <Zap size={20} />
                  </div>
                  <div className="pillar-body">
                    <h3>Sub-Millisecond Overhead</h3>
                    <p>Go-native core with zero-copy forwarding delivers line-rate performance even under full inspection.</p>
                  </div>
                </div>

                <div className="about-pillar">
                  <div className="pillar-icon">
                    <Eye size={20} />
                  </div>
                  <div className="pillar-body">
                    <h3>One Pane of Glass</h3>
                    <p>Rules, logs, alerts, compression stats &mdash; every signal in a single dashboard, not ten disconnected tools.</p>
                  </div>
                </div>
              </div>

              <div className="about-stats">
                <div className="about-stat">
                  <span className="about-stat-value">70<i>%</i></span>
                  <span className="about-stat-label">Bandwidth saved</span>
                </div>
                <div className="about-stat-divider"></div>
                <div className="about-stat">
                  <span className="about-stat-value">&lt;1<i>ms</i></span>
                  <span className="about-stat-label">Added latency</span>
                </div>
                <div className="about-stat-divider"></div>
                <div className="about-stat">
                  <span className="about-stat-value">99.99<i>%</i></span>
                  <span className="about-stat-label">Uptime SLA</span>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="how-it-works">
        <div className="container">
          <div className="section-header section-header-fancy">
            <motion.div
              className="section-kicker"
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              <span className="kicker-line"></span>
              <span className="kicker-text">PROCESS</span>
              <span className="kicker-line"></span>
            </motion.div>
            <motion.h2
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              Get Started in <span className="heading-accent">3 Simple Steps</span>
            </motion.h2>
            <p>From setup to full protection in under 10 minutes &mdash; no complex configuration required.</p>
          </div>

          <div className="steps-container">
            {steps.map((step, index) => (
              <motion.div
                key={index}
                className="step-card"
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.15, duration: 0.5 }}
              >
                <div className="step-number">{step.number}</div>
                <div className="step-icon">{step.icon}</div>
                <h3>{step.title}</h3>
                <p>{step.description}</p>
                <ul className="step-features">
                  {step.features.map((feature, i) => (
                    <li key={i}>
                      <CheckCircle size={14} />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>
                {index < steps.length - 1 && (
                  <div className="step-connector">
                    <ArrowRight size={24} />
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="features">
        <div className="container">
          <div className="section-header section-header-fancy">
            <motion.div
              className="section-kicker"
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              <span className="kicker-line"></span>
              <span className="kicker-text">CAPABILITIES</span>
              <span className="kicker-line"></span>
            </motion.div>
            <motion.h2
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              Complete <span className="heading-accent">Security Suite</span>
            </motion.h2>
            <p>Everything you need to protect your network &mdash; all in one unified platform.</p>
          </div>

          <div className="features-grid">
            {features.map((feature, index) => (
              <motion.div
                key={index}
                className="feature-card"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.1 }}
              >
                <div className="feature-icon">{feature.icon}</div>
                <h3>{feature.title}</h3>
                <p>{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="pricing">
        <div className="container">
          <div className="section-header section-header-fancy">
            <motion.div
              className="section-kicker"
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              <span className="kicker-line"></span>
              <span className="kicker-text">PRICING</span>
              <span className="kicker-line"></span>
            </motion.div>
            <motion.h2
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              Simple, <span className="heading-accent">Transparent Pricing</span>
            </motion.h2>
            <p>Choose the plan that fits your organization. Upgrade or downgrade at any time.</p>
          </div>

          <div className="pricing-grid">
            {/* Starter */}
            <motion.div
              className="pricing-card"
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0, duration: 0.5 }}
            >
              <div className="pricing-card-header">
                <span className="pricing-tier">Starter</span>
                <div className="pricing-price">
                  <span className="pricing-amount">$0</span>
                  <span className="pricing-period">/mo</span>
                </div>
                <p className="pricing-desc">Ideal for developers and side projects that need solid baseline protection.</p>
              </div>
              <ul className="pricing-features-list">
                <li><CheckCircle size={15} /><span>5 proxied services</span></li>
                <li><CheckCircle size={15} /><span>Basic WAF &amp; rate limiting</span></li>
                <li><CheckCircle size={15} /><span>5 GB/month bandwidth</span></li>
                <li><CheckCircle size={15} /><span>Real-time traffic dashboard</span></li>
                <li><CheckCircle size={15} /><span>Community support</span></li>
              </ul>
              <Link to="/signup" className="pricing-cta pricing-cta-outline">Get Started Free</Link>
            </motion.div>

            {/* Pro */}
            <motion.div
              className="pricing-card pricing-card-featured"
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.15, duration: 0.5 }}
            >
              <div className="pricing-badge">Most Popular</div>
              <div className="pricing-card-header">
                <span className="pricing-tier">Pro</span>
                <div className="pricing-price">
                  <span className="pricing-amount">$29</span>
                  <span className="pricing-period">/mo</span>
                </div>
                <p className="pricing-desc">For teams that need AI-driven threat detection and full traffic control.</p>
              </div>
              <ul className="pricing-features-list">
                <li><CheckCircle size={15} /><span>Unlimited proxied services</span></li>
                <li><CheckCircle size={15} /><span>AI WAF + IDS/IPS engine</span></li>
                <li><CheckCircle size={15} /><span>100 GB/month bandwidth</span></li>
                <li><CheckCircle size={15} /><span>AI compression &amp; deduplication</span></li>
                <li><CheckCircle size={15} /><span>Custom firewall rules</span></li>
                <li><CheckCircle size={15} /><span>Priority support</span></li>
              </ul>
              <Link to="/signup" className="pricing-cta pricing-cta-primary">Start Free Trial</Link>
            </motion.div>

            {/* Enterprise */}
            <motion.div
              className="pricing-card"
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.3, duration: 0.5 }}
            >
              <div className="pricing-card-header">
                <span className="pricing-tier">Enterprise</span>
                <div className="pricing-price">
                  <span className="pricing-amount">$99</span>
                  <span className="pricing-period">/mo</span>
                </div>
                <p className="pricing-desc">Built for large teams with high-traffic infrastructure and compliance needs.</p>
              </div>
              <ul className="pricing-features-list">
                <li><CheckCircle size={15} /><span>Everything in Pro</span></li>
                <li><CheckCircle size={15} /><span>1 TB/month bandwidth</span></li>
                <li><CheckCircle size={15} /><span>Dedicated infrastructure</span></li>
                <li><CheckCircle size={15} /><span>99.99% uptime SLA</span></li>
                <li><CheckCircle size={15} /><span>SSO &amp; role-based access</span></li>
                <li><CheckCircle size={15} /><span>24/7 dedicated support</span></li>
              </ul>
              <Link to="/signup" className="pricing-cta pricing-cta-outline">Start Free Trial</Link>
            </motion.div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section id="cta" className="cta">
        <div className="container">
          <h2>Ready to Secure Your Network?</h2>
          <p>Join thousands of organizations protecting their infrastructure</p>
          <div className="cta-buttons">
            <Link to="/signup" className="btn-primary large">
              Start Free Trial
              <ArrowRight size={20} />
            </Link>
            <Link to="/login" className="btn-secondary large">
              Sign In
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <div className="container">
          <div className="footer-content">
            <div className="footer-col footer-col-brand">
              <div className="footer-logo">
                <img src="/synorix-logo.png" alt="Synorix" />
                <span>SYNORIX</span>
              </div>
              <p className="footer-tagline">
                Enterprise-grade security proxy built for modern infrastructure. Protect your network with AI-powered threat detection, intelligent firewall rules, and real-time monitoring &mdash; all from a single unified platform trusted by thousands of organizations worldwide.
              </p>
            </div>
            <div className="footer-col">
              <h4>Product</h4>
              <a href="#features">Features</a>
              <a href="#how-it-works">How It Works</a>
              <a href="#pricing">Pricing</a>
              <Link to="/signup">Get Started</Link>
            </div>
            <div className="footer-col">
              <h4>Resources</h4>
              <a href="#">Documentation</a>
              <a href="#">API Reference</a>
              <a href="#">Blog</a>
              <a href="#">Changelog</a>
              <Link to="/login">Sign In</Link>
            </div>
            <div className="footer-col">
              <h4>Company</h4>
              <a href="#">About</a>
              <a href="#">Careers</a>
              <a href="#">Privacy</a>
              <a href="#">Terms</a>
              <a href="#">Contact</a>
            </div>
          </div>
          <div className="footer-bottom">
            <p>&copy; 2026 Synorix Security Systems. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Homepage;
