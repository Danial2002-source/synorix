# Synorix — FYP Phase 2 Roadmap (Aug–Dec 2026)

> This branch contains ongoing development work for FYP Phase 2.  
> Phase 1 (Mar–Jul 2026) is complete on the `main` branch.

## Planned Features

### 🤖 AI Model Improvements (Daniyal Shahid)
- [ ] Retrain XGBoost compression model with real traffic data (10,000+ samples)
- [ ] Improve deduplication model accuracy (current threshold: 0.00001)
- [ ] ROC curve analysis for optimal threshold tuning
- [ ] Model versioning and A/B testing framework
- [ ] Document AI pipeline and retraining strategy

### 🔒 Security Enhancements (Hamnah Waseem)
- [ ] Expand Suricata ruleset with custom application-specific signatures
- [ ] Alert acknowledgment workflow (mark as read, resolve, dismiss)
- [ ] Automated IP blocking after threshold violations
- [ ] Advanced alert correlation engine
- [ ] Validate WAF/IPS under multi-vector stress attacks
- [ ] Compile final WAF/IDS/IPS evaluation reports

### ⚙️ Backend Optimization (Isra Abbas)
- [ ] Implement actual Redis/LRU caching layer for deduplication
- [ ] Content hash storage (SHA-256) with cache hit detection
- [ ] Cache eviction policies (LRU, TTL-based)
- [ ] Optimize backend throughput and latency
- [ ] Containerize all services with Docker
- [ ] System handover and core documentation

### 🎨 Frontend Polish (Maria Khan)
- [ ] Metrics dashboard with advanced visualizations
- [ ] Cache statistics dashboard (hit rate, memory usage)
- [ ] Mobile-responsive design and PWA support
- [ ] Export functionality for compliance reports (PDF/CSV)
- [ ] Run beta deployment with selected users
- [ ] Deploy complete web-based management platform

## Timeline

| Month | Focus |
|-------|-------|
| Aug 2026 | Redis cache implementation, advanced Suricata rules |
| Sep 2026 | Model retraining, security hardening |
| Oct 2026 | Performance optimization, UI polish |
| Nov 2026 | Beta deployment, stress testing |
| Dec 2026 | Final integration, documentation, handover |
