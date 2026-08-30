import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';
import {
  Shield,
  Users,
  Globe,
  Activity,
  LogOut,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Search,
  Filter,
  RefreshCw,
  Edit,
  Save,
  X,
  Eye,
  Clock,
  TrendingUp,
  TrendingDown,
  Database,
  BarChart3,
  PieChart,
  Zap,
  Target,
  ArrowUp,
  ArrowDown,
  RotateCcw,
  Trash2,
  UserCheck,
  ShieldCheck,
  Crosshair,
  ShieldX,
  ChevronDown
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import PhaseNotice from './PhaseNotice';
import './AdminDashboard.css';

interface DashboardStats {
  totalUsers: number;
  totalWebsites: number;
  totalRequestsToday: number;
  activeWafRules: number;
  activeSuricataRules: number;
  activeAlerts: number;
  totalBlockedRequests: number;
  blockedRequestsToday: number;
}

interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  created_at: string;
  last_login: string;
  is_active: number;
  is_banned: number;
  backend_url: string;
  is_configured: number;
  connectivity_status: string;
  total_requests: number;
  open_alerts: number;
}

interface Website {
  id: number;
  user_id: number;
  username: string;
  email: string;
  backend_url: string;
  proxy_api_key: string;
  is_configured: number;
  connectivity_status: string;
  last_test_at: string;
  created_at: string;
  total_requests: number;
  blocked_requests: number;
}

interface WafRule {
  id: number;
  pattern: string;
  message: string;
  tags: string;
  severity: number;
  enabled: boolean;
  phase?: string;
}

interface WafRulesConfig {
  enabled: boolean;
  rules: WafRule[];
}

interface SuricataRule {
  id: number;
  sid: number;
  action?: string;
  protocol: string;
  source_ip?: string;
  source_port?: string;
  direction?: string;
  dest_ip?: string;
  dest_port?: string;
  msg?: string;
  message?: string;
  flow?: string | null;
  content?: string | null;
  http_uri?: boolean;
  http_method?: boolean;
  http_header?: boolean;
  http_request_body?: boolean;
  nocase?: boolean;
  pcre?: string | null;
  classtype?: string;
  rev?: number;
  priority?: number;
  enabled?: boolean;
  category?: string;
  filename?: string;
  phase?: string;
  raw?: string;
}

interface ActiveUser {
  id: number;
  username: string;
  email: string;
  request_count: number;
  last_activity: string;
  blocked_count: number;
}

interface ActivityData {
  day: string;
  allowed: number;
  blocked: number;
  total: number;
}

interface ThreatDistribution {
  type: string;
  count: number;
  percentage: number;
  color: string;
}

interface SecurityEvent {
  id: number;
  alert_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  source_ip: string;
  action: string;
  timestamp: string;
  status: string;
}

interface SystemHealth {
  component: string;
  status: 'healthy' | 'warning' | 'error';
  uptime: number;
  message: string;
}

interface MetricTrend {
  requestsTrend: number;
  blockedTrend: number;
  alertsTrend: number;
  detectionRate: number;
}

const AdminDashboard: React.FC = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'websites' | 'waf' | 'suricata' | 'alerts'>('overview');
  const [stats, setStats] = useState<DashboardStats>({
    totalUsers: 0,
    totalWebsites: 0,
    totalRequestsToday: 0,
    activeWafRules: 0,
    activeSuricataRules: 0,
    activeAlerts: 0,
    totalBlockedRequests: 0,
    blockedRequestsToday: 0
  });
  const [users, setUsers] = useState<User[]>([]);
  const [websites, setWebsites] = useState<Website[]>([]);
  const [activeUsers, setActiveUsers] = useState<ActiveUser[]>([]);
  const [wafConfig, setWafConfig] = useState<WafRule[]>([]);
  const [suricataRules, setSuricataRules] = useState<SuricataRule[]>([]);
  const [loading, setLoading] = useState(false);

  // Admin alerts state
  const [adminAlerts, setAdminAlerts] = useState<any[]>([]);
  const [adminAlertsTotal, setAdminAlertsTotal] = useState(0);
  const [adminAlertsLoading, setAdminAlertsLoading] = useState(false);
  const [adminAlertsWindow, setAdminAlertsWindow] = useState<'1h'|'24h'|'7d'|'30d'>('24h');
  const [adminAlertsSeverity, setAdminAlertsSeverity] = useState('high_critical');
  const [adminAlertsType, setAdminAlertsType] = useState('suricata');
  const [adminAlertsOffset, setAdminAlertsOffset] = useState(0);
  const ADMIN_ALERTS_PAGE = 50;
  const [searchTerm, setSearchTerm] = useState('');
  const [editingWaf, setEditingWaf] = useState(false);
  const [editingSuricata, setEditingSuricata] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  
  // Modal states
  const [showEditUserModal, setShowEditUserModal] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showAddWafRuleModal, setShowAddWafRuleModal] = useState(false);
  const [showEditWafRuleModal, setShowEditWafRuleModal] = useState(false);
  const [showAddSuricataRuleModal, setShowAddSuricataRuleModal] = useState(false);
  const [showEditSuricataRuleModal, setShowEditSuricataRuleModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [selectedWafRule, setSelectedWafRule] = useState<WafRule | null>(null);
  const [selectedSuricataRule, setSelectedSuricataRule] = useState<SuricataRule | null>(null);
  const [userToDelete, setUserToDelete] = useState<number | null>(null);
  const [wafRuleToDelete, setWafRuleToDelete] = useState<number | null>(null);
  const [suricataRuleToDelete, setSuricataRuleToDelete] = useState<number | null>(null);
  const [expandedWafRules, setExpandedWafRules] = useState<Set<number>>(new Set());
  const [expandedSuricataRules, setExpandedSuricataRules] = useState<Set<number>>(new Set());

  // Overview dashboard data
  const [activityData, setActivityData] = useState<ActivityData[]>([]);
  const [activityTimeframe, setActivityTimeframe] = useState<'7d' | '30d' | '90d'>('30d');
  const [activityLoading, setActivityLoading] = useState(false);
  const [threatDistribution, setThreatDistribution] = useState<ThreatDistribution[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [systemHealth, setSystemHealth] = useState<SystemHealth[]>([]);
  const [attackStats, setAttackStats] = useState({ wafBlocked: 0, suricataBlocked: 0, highThreats: 0, wafToday: 0, suricataToday: 0 });
  const [topSourceIPs, setTopSourceIPs] = useState<Array<{ip: string; hits: number; blocked: boolean; lastSeen?: string}>>([]);
  const [severityOverTime, setSeverityOverTime] = useState<Array<{day:string;critical:number;high:number;medium:number;low:number}>>([]);
  const [metricTrends, setMetricTrends] = useState<MetricTrend>({
    requestsTrend: 0,
    blockedTrend: 0,
    alertsTrend: 0,
    detectionRate: 0
  });

  const API_BASE = '/api';

  useEffect(() => {
    // Load data on mount
    loadDashboardData();
    
    // Set up auto-refresh every 30 seconds
    const interval = setInterval(loadDashboardData, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      await Promise.all([
        fetchStats(),
        fetchUsers(),
        fetchWebsites(),
        fetchActiveUsers(),
        fetchWafRules(),
        fetchSuricataRules(),
        fetchActivityData('30d'),
        fetchThreatDistribution(),
        fetchSecurityEvents(),
        fetchSystemHealth(),
        fetchMetricTrends(),
        fetchAttackStats(),
        fetchSeverityOverTime()
      ]);
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/dashboard/stats`);
      console.log('Dashboard stats received:', data);
      setStats(data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const fetchUsers = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/users`);
      console.log('Users data received:', data);
      setUsers(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching users:', error);
      setUsers([]);
    }
  };

  const fetchWebsites = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/websites`);
      setWebsites(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching websites:', error);
      setWebsites([]);
    }
  };

  const fetchActiveUsers = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/active-users`);
      setActiveUsers(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching active users:', error);
      setActiveUsers([]);
    }
  };

  const fetchWafRules = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/waf/rules/all-phases`);
      console.log('WAF rules data total:', data?.total, 'rules count:', data?.rules?.length);
      setWafConfig(Array.isArray(data.rules) ? data.rules : []);
    } catch (error) {
      console.error('Error fetching WAF rules:', error);
      setWafConfig([]);
    }
  };

  const fetchSuricataRules = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/suricata/rules/all-phases`);
      if (true) {
        console.log('Suricata rules data total:', data?.total, 'rules count:', data?.rules?.length);
        
        // Transform all-phases response to match interface
        const transformedRules = (data.rules || []).map((rule: any) => ({
          id: rule.id,
          sid: rule.sid,
          protocol: rule.protocol,
          msg: rule.msg || rule.message,
          message: rule.message,
          action: rule.action || 'alert',
          source_ip: rule.source_ip || 'any',
          source_port: rule.source_port || 'any',
          direction: rule.direction || '->',
          dest_ip: rule.dest_ip || 'any',
          dest_port: rule.dest_port || 'any',
          flow: rule.flow || null,
          content: rule.content || null,
          classtype: rule.classtype || null,
          priority: rule.priority || 1,
          rev: rule.rev || 1,
          category: rule.category || null,
          filename: rule.filename || null,
          enabled: rule.enabled !== false,
          phase: rule.type,
          raw: rule.raw
        }));
        setSuricataRules(transformedRules);
      }
    } catch (error) {
      console.error('Error fetching Suricata rules:', error);
    }
  };

  const fetchAdminAlerts = async (opts?: { window?: string; severity?: string; type?: string; offset?: number }) => {
    setAdminAlertsLoading(true);
    try {
      const w = opts?.window ?? adminAlertsWindow;
      const s = opts?.severity ?? adminAlertsSeverity;
      const t = opts?.type ?? adminAlertsType;
      const o = opts?.offset ?? adminAlertsOffset;
      const params = new URLSearchParams({ window: w, limit: String(ADMIN_ALERTS_PAGE), offset: String(o) });
      if (s) params.append('severity', s);
      params.append('alert_type', t || 'suricata');
      const { data } = await axios.get(`${API_BASE}/admin/alerts/aggregated?${params}`);
      if (true) {
        const filteredAlerts = (data.alerts || []).filter((a: any) => (a.alert_type || '').toLowerCase() === 'suricata');
        setAdminAlerts(filteredAlerts);
        setAdminAlertsTotal(filteredAlerts.length);
      }
    } catch (e) {
      console.error('Admin alerts fetch error:', e);
    } finally {
      setAdminAlertsLoading(false);
    }
  };

  const blockIpFromAlert = async (ip: string, signature: string) => {
    try {
      await axios.post(`${API_BASE.replace('/api', '')}/api/security/block-ip`, { ip, reason: `Admin block: ${signature}`, duration: 3600 });
      setMessage({ type: 'success', text: `IP ${ip} blocked for 1 hour.` });
      setTimeout(() => setMessage(null), 3000);
    } catch (e) {
      setMessage({ type: 'error', text: `Failed to block ${ip}.` });
    }
  };
  const fetchActivityData = async (timeframe: '7d' | '30d' | '90d' = '7d') => {
    setActivityLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/admin/dashboard/activity?timeframe=${timeframe}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setActivityData(Array.isArray(data) ? data : []);
        setActivityTimeframe(timeframe);
      }
    } catch (error) {
      console.error('Error fetching activity data:', error);
      setActivityData([]);
    } finally {
      setActivityLoading(false);
    }
  };

  const fetchThreatDistribution = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/dashboard/threats`);
      if (true) {
        // Use byType data and transform it
        // Exclude WAF — it is per-user/application, not a global network-level threat
        const threats = (data.byType || []).filter((t: any) => (t.alert_type || '').toLowerCase() !== 'waf');
        const total = threats.reduce((sum: number, t: any) => sum + (t.count || 0), 0);
        
        const typeLabels: Record<string, string> = {
          'suricata-ids': 'IDS Alerts',
          'suricata-ips': 'IPS Drops',
          'suricata':     'IDS Alerts',
          'system':       'System'
        };
        const colors: Record<string, string> = {
          'IDS Alerts': '#1976D2',
          'IPS Drops':  '#0D47A1',
        };
        // Merge rows with the same label (e.g. 'suricata' + 'suricata-ids' both → 'IDS Alerts')
        const merged: Record<string, number> = {};
        threats.forEach((threat: any) => {
          const label = typeLabels[threat.alert_type] || threat.alert_type || 'Unknown';
          merged[label] = (merged[label] || 0) + (threat.count || 0);
        });
        const transformed = Object.entries(merged)
          .map(([label, count]) => ({
            type:  label,
            count,
            percentage: total > 0 ? Math.round((count / total) * 100) : 0,
            color: colors[label] || '#42A5F5'
          }))
          .sort((a: ThreatDistribution, b: ThreatDistribution) => b.count - a.count);
        
        setThreatDistribution(transformed);

        // Store top source IPs from threats response
        const AUTO_BAN_THRESHOLD = 5;
        const sources = (data.topSources || []).map((s: any) => ({
          ip: s.source_ip || s.src_ip || s.ip || '—',
          hits: s.count || 0,
          blocked: (s.count || 0) >= AUTO_BAN_THRESHOLD,
          lastSeen: s.last_seen || undefined
        }));
        setTopSourceIPs(sources);
      }
    } catch (error) {
      console.error('Error fetching threat distribution:', error);
      setThreatDistribution([]);
    }
  };

  const fetchAttackStats = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/dashboard/attack-stats`);
      setAttackStats(data);
    } catch (e) { console.error('Error fetching attack stats:', e); }
  };

  const fetchSeverityOverTime = async () => {
    try {
      const tzOffset = -new Date().getTimezoneOffset();
      const { data } = await axios.get(`${API_BASE}/admin/dashboard/severity-over-time?tzOffset=${tzOffset}`);
      setSeverityOverTime(data);
    } catch (e) { console.error('Error fetching severity over time:', e); }
  };

  const fetchSecurityEvents = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/dashboard/events`);
      setSecurityEvents(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching security events:', error);
      setSecurityEvents([]);
    }
  };

  const fetchSystemHealth = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/dashboard/health`);
      setSystemHealth(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching system health:', error);
      setSystemHealth([]);
    }
  };

  const fetchMetricTrends = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/admin/dashboard/trends`);
      setMetricTrends(data);
    } catch (error) {
      console.error('Error fetching metric trends:', error);
      setMetricTrends({
        requestsTrend: 0,
        blockedTrend: 0,
        alertsTrend: 0,
        detectionRate: 0
      });
    }
  };

  const saveWafRules = async () => {
    try {
      await axios.post(`${API_BASE}/admin/waf/rules`, wafConfig);
      setMessage({ type: 'success', text: 'WAF rules updated successfully' });
      setTimeout(() => setMessage(null), 3000);
    } catch (error) {
      console.error('Error saving WAF rules:', error);
      setMessage({ type: 'error', text: 'Error saving WAF rules' });
    }
  };

  const saveSuricataRule = async (filename: string, content: string) => {
    try {
      await axios.post(`${API_BASE}/admin/suricata/rules/${filename}`, { content });
      setMessage({ type: 'success', text: 'Suricata rule updated successfully' });
      setEditingSuricata(false);
      fetchSuricataRules();
      setTimeout(() => setMessage(null), 3000);
    } catch (error) {
      console.error('Error saving Suricata rule:', error);
      setMessage({ type: 'error', text: 'Error saving Suricata rule' });
    }
  };

  // ============================================
  // Suricata Rules CRUD Operations
  // ============================================

  const handleAddSuricataRule = async (e: React.FormEvent) => {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const formData = new FormData(form);

    try {
      await axios.post(`${API_BASE}/admin/suricata/rules/add`, {
          sid: parseInt(formData.get('sid') as string),
          action: formData.get('action'),
          protocol: formData.get('protocol'),
          source_ip: formData.get('source_ip'),
          source_port: formData.get('source_port'),
          direction: formData.get('direction'),
          dest_ip: formData.get('dest_ip'),
          dest_port: formData.get('dest_port'),
          msg: formData.get('msg'),
          flow: formData.get('flow') || null,
          content: formData.get('content') || null,
          http_uri: formData.get('http_uri') === 'on',
          http_method: formData.get('http_method') === 'on',
          http_header: formData.get('http_header') === 'on',
          http_request_body: formData.get('http_request_body') === 'on',
          nocase: formData.get('nocase') === 'on',
          pcre: formData.get('pcre') || null,
          classtype: formData.get('classtype'),
          rev: parseInt(formData.get('rev') as string) || 1,
          priority: parseInt(formData.get('priority') as string),
          enabled: formData.get('enabled') === 'on',
          category: formData.get('category'),
          filename: formData.get('filename')
        });

      setMessage({ type: 'success', text: 'Suricata rule added successfully' });
      setShowAddSuricataRuleModal(false);
      fetchSuricataRules();
      form.reset();
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error('Error adding Suricata rule:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error adding Suricata rule' });
    }
  };

  const handleEditSuricataRule = (rule: SuricataRule) => {
    setSelectedSuricataRule(rule);
    setShowEditSuricataRuleModal(true);
  };

  const handleUpdateSuricataRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSuricataRule) return;

    try {
      await axios.put(`${API_BASE}/admin/suricata/rules/${selectedSuricataRule.id}`, selectedSuricataRule);
      setMessage({ type: 'success', text: 'Suricata rule updated successfully' });
      setShowEditSuricataRuleModal(false);
      fetchSuricataRules();
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error('Error updating Suricata rule:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error updating Suricata rule' });
    }
  };

  const reloadSuricata = async () => {
    setLoading(true);
    try {
      const { data: result } = await axios.post(`${API_BASE}/admin/suricata/reload`);
      setMessage({ type: 'success', text: result.message || 'Suricata reload initiated successfully!' });
      setTimeout(() => setMessage(null), 5000);
      setTimeout(() => { fetchSuricataRules(); }, 3000);
    } catch (error: any) {
      console.error('Error reloading Suricata:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error reloading Suricata services' });
      setTimeout(() => setMessage(null), 5000);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteSuricataRule = async () => {
    if (!suricataRuleToDelete) return;

    try {
      await axios.delete(`${API_BASE}/admin/suricata/rules/${suricataRuleToDelete}`);
      setMessage({ type: 'success', text: 'Suricata rule deleted successfully' });
      setSuricataRuleToDelete(null);
      fetchSuricataRules();
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error('Error deleting Suricata rule:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error deleting Suricata rule' });
    }
  };

  const toggleSuricataRule = (ruleId: number) => {
    setSuricataRules(prev => prev.map(rule =>
      rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule
    ));
  };

  const toggleWafRule = async (ruleId: number) => {
    const updatedConfig = wafConfig.map(rule =>
      rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule
    );
    setWafConfig(updatedConfig);

    // Auto-save the changes
    try {
      await axios.post(`${API_BASE}/admin/waf/rules`, updatedConfig);
      setMessage({ type: 'success', text: 'WAF rule status updated' });
      setTimeout(() => setMessage(null), 2000);
    } catch (error) {
      console.error('Error toggling WAF rule:', error);
      setMessage({ type: 'error', text: 'Error updating WAF rule status' });
      // Revert the change on error
      setWafConfig(wafConfig);
    }
  };

  const toggleWafRuleExpanded = (ruleId: number) => {
    setExpandedWafRules(prev => {
      const newSet = new Set(prev);
      if (newSet.has(ruleId)) {
        newSet.delete(ruleId);
      } else {
        newSet.add(ruleId);
      }
      return newSet;
    });
  };

  const toggleSuricataRuleExpanded = (ruleId: number) => {
    setExpandedSuricataRules(prev => {
      const newSet = new Set(prev);
      if (newSet.has(ruleId)) {
        newSet.delete(ruleId);
      } else {
        newSet.add(ruleId);
      }
      return newSet;
    });
  };

  // ============================================
  // User Management CRUD Operations
  // ============================================

  const handleEditUser = (user: User) => {
    setSelectedUser(user);
    setShowEditUserModal(true);
  };

  const handleUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;

    try {
      await axios.put(`${API_BASE}/admin/users/${selectedUser.id}`, {
          username: selectedUser.username,
          email: selectedUser.email,
          role: selectedUser.role,
          is_active: selectedUser.is_active,
          is_banned: selectedUser.is_banned
        });
      setMessage({ type: 'success', text: 'User updated successfully' });
      setShowEditUserModal(false);
      fetchUsers();
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error('Error updating user:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error updating user' });
    }
  };

  const handleDeleteUser = async () => {
    if (!userToDelete) return;

    try {
      await axios.delete(`${API_BASE}/admin/users/${userToDelete}`);
      setMessage({ type: 'success', text: 'User deleted successfully' });
      setShowDeleteConfirm(false);
      setUserToDelete(null);
      fetchUsers();
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error('Error deleting user:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error deleting user' });
    }
  };

  const handleBanUser = async (userId: number, banned: boolean) => {
    try {
      await axios.post(`${API_BASE}/admin/users/${userId}/ban`, { banned });
      setMessage({ type: 'success', text: `User ${banned ? 'banned' : 'unbanned'} successfully` });
      fetchUsers();
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error('Error updating ban status:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error updating ban status' });
    }
  };

  // ============================================
  // WAF Rules CRUD Operations
  // ============================================

  const handleAddWafRule = async (e: React.FormEvent) => {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const formData = new FormData(form);

    try {
      await axios.post(`${API_BASE}/admin/waf/rules/add`, {
          id: parseInt(formData.get('id') as string),
          pattern: formData.get('pattern'),
          message: formData.get('message'),
          tags: formData.get('tags'),
          severity: parseInt(formData.get('severity') as string),
          enabled: formData.get('enabled') === 'on'
        });
      setMessage({ type: 'success', text: 'WAF rule added successfully' });
      setShowAddWafRuleModal(false);
      fetchWafRules();
      form.reset();
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error('Error adding WAF rule:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error adding WAF rule' });
    }
  };

  const handleEditWafRule = (rule: WafRule) => {
    setSelectedWafRule(rule);
    setShowEditWafRuleModal(true);
  };

  const handleUpdateWafRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedWafRule) return;

    try {
      await axios.put(`${API_BASE}/admin/waf/rules/${selectedWafRule.id}`, selectedWafRule);
      setMessage({ type: 'success', text: 'WAF rule updated successfully' });
      setShowEditWafRuleModal(false);
      fetchWafRules();
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error('Error updating WAF rule:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error updating WAF rule' });
    }
  };

  const handleDeleteWafRule = async () => {
    if (!wafRuleToDelete) return;

    try {
      await axios.delete(`${API_BASE}/admin/waf/rules/${wafRuleToDelete}`);
      setMessage({ type: 'success', text: 'WAF rule deleted successfully' });
      setWafRuleToDelete(null);
      fetchWafRules();
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error('Error deleting WAF rule:', error);
      setMessage({ type: 'error', text: error.response?.data?.error || 'Error deleting WAF rule' });
    }
  };

  const filteredUsers = Array.isArray(users) ? users.filter(user =>
    user.username?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.email?.toLowerCase().includes(searchTerm.toLowerCase())
  ) : [];

  console.log('Users state:', users);
  console.log('Filtered users:', filteredUsers);
  console.log('Search term:', searchTerm);

  const filteredWebsites = Array.isArray(websites) ? websites.filter(website =>
    website.backend_url?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    website.username?.toLowerCase().includes(searchTerm.toLowerCase())
  ) : [];

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="admin-dashboard">
      {/* Sidebar */}
      <aside className="admin-sidebar">
        <div className="sidebar-header">
          <img src="/synorix-logo.png" alt="Synorix" className="ad-sidebar-logo-img" />
        </div>

        <nav className="sidebar-nav">
          <button
            className={`sidebar-nav-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <TrendingUp />
            <span>Overview</span>
          </button>
          <button
            className={`sidebar-nav-item ${activeTab === 'users' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('users');
              if (users.length === 0) fetchUsers();
            }}
          >
            <Users />
            <span>Users</span>
          </button>
          <button
            className={`sidebar-nav-item ${activeTab === 'websites' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('websites');
              if (websites.length === 0) fetchWebsites();
            }}
          >
            <Globe />
            <span>Websites</span>
          </button>
          <button
            className={`sidebar-nav-item ${activeTab === 'waf' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('waf');
              if (wafConfig.length === 0) fetchWafRules();
            }}
          >
            <Shield />
            <span>WAF Rules</span>
          </button>
          <button
            className={`sidebar-nav-item ${activeTab === 'suricata' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('suricata');
              if (suricataRules.length === 0) fetchSuricataRules();
            }}
          >
            <Eye />
            <span>IDS/IPS Rules</span>
          </button>
          <button
            className={`sidebar-nav-item ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('alerts');
              if (adminAlerts.length === 0) fetchAdminAlerts();
            }}
          >
            <AlertTriangle />
            <span>Alerts</span>
          </button>
        </nav>

        <button className="sidebar-footer" onClick={handleLogout}>
          <LogOut size={18} />
          <span>Logout</span>
        </button>
      </aside>

      {/* Main Content */}
      <div className="admin-main-content">
        <div className="admin-content-header">
          <div className="header-info">
            <h1>{activeTab === 'overview' ? 'Dashboard Overview' : 
                activeTab === 'users' ? 'User Management' :
                activeTab === 'websites' ? 'Website Management' :
                activeTab === 'waf' ? 'WAF Rules Configuration' :
                activeTab === 'alerts' ? 'Security Alerts' :
                'IDS/IPS Rules Configuration'}</h1>
            <p>{activeTab === 'overview' ? 'System statistics and monitoring' : 
                activeTab === 'users' ? 'Manage all users and permissions' :
                activeTab === 'websites' ? 'Monitor registered websites' :
                activeTab === 'waf' ? 'Configure Web Application Firewall rules' :
                activeTab === 'alerts' ? 'Aggregated security alerts from all sources' :
                'Configure Intrusion Detection and Prevention rules'}</p>
          </div>
          {activeTab === 'overview' && (
            <button 
              onClick={loadDashboardData}
              disabled={loading}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 16px',
                backgroundColor: '#4f46e5',
                color: '#fff',
                border: 'none',
                borderRadius: '6px',
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.6 : 1,
                fontSize: '14px'
              }}
            >
              <RefreshCw size={16} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
          )}
        </div>

        {message && (
          <motion.div
            className={`message ${message.type}`}
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
          >
            {message.type === 'success' ? <CheckCircle /> : <XCircle />}
            {message.text}
          </motion.div>
        )}

        {/* Stats Cards - Only show on overview tab */}
        {activeTab === 'overview' && (
          <div className="ud-stats-grid">
            <div className="ud-stat-card">
              <div className="ud-stat-icon green">
                <UserCheck size={22} />
              </div>
              <div className="ud-stat-body">
                <div className="ud-stat-value">{stats.totalUsers || 0}</div>
                <div className="ud-stat-label">Total Users</div>
              </div>
            </div>

            <div className="ud-stat-card">
              <div className="ud-stat-icon purple">
                <ShieldCheck size={22} />
              </div>
              <div className="ud-stat-body">
                <div className="ud-stat-value">{stats.activeWafRules || 0}</div>
                <div className="ud-stat-label">Active WAF Rules</div>
              </div>
            </div>

            <div className="ud-stat-card">
              <div className="ud-stat-icon amber">
                <Crosshair size={22} />
              </div>
              <div className="ud-stat-body">
                <div className="ud-stat-value">{stats.activeSuricataRules || 0}</div>
                <div className="ud-stat-label">Active IDS/IPS Rules</div>
              </div>
            </div>

            <div className="ud-stat-card">
              <div className="ud-stat-icon red">
                <ShieldX size={22} />
              </div>
              <div className="ud-stat-body">
                <div className="ud-stat-value">{stats.blockedRequestsToday || 0}</div>
                <div className="ud-stat-label">Blocked Today</div>
              </div>
            </div>
          </div>
        )}

        {/* Tab Content */}
        <div className="tab-content">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <motion.div
              className="overview-section"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              {/* Charts Row 1: Pie Chart */}
              <div className="dashboard-row">
                {/* Pie Chart - Threat Distribution */}
                <div className="dashboard-card chart-card">
                  <div className="card-header">
                    <div className="card-title">
                      <PieChart />
                      <h3>Threat Distribution</h3>
                    </div>
                  </div>
                  <div className="card-body">
                    {(() => {
                      // Only show IDS vs IPS — filter everything else out
                      const all = threatDistribution && threatDistribution.length > 0 ? threatDistribution : [
                        { type: 'IDS Alerts', count: 29, color: '#1976D2' },
                        { type: 'IPS Drops',  count: 22, color: '#0D47A1' }
                      ];
                      const threats = all.filter(t =>
                        t.type === 'IDS Alerts' || t.type === 'IPS Drops' ||
                        t.type === 'IDS/IPS'    || t.type === 'suricata-ids' || t.type === 'suricata-ips'
                      ).slice(0, 2);
                      const display = threats.length > 0 ? threats : all.slice(0, 2);
                      const palette = ['#1976D2', '#0D47A1'];
                      const withColor = display.map((t, i) => ({ ...t, color: t.color || palette[i] }));
                      const totalCount = withColor.reduce((s, t) => s + (t.count || 0), 0);
                      const cx = 100, cy = 100, R = 88, ri = 52;
                      let cumDeg = -90;
                      const paths = withColor.map((t, i) => {
                        const pct = totalCount > 0 ? (t.count / totalCount) * 100 : 50;
                        const sweep = (pct / 100) * 360;
                        const s = (cumDeg * Math.PI) / 180;
                        const e = ((cumDeg + sweep) * Math.PI) / 180;
                        const x1o = cx + R  * Math.cos(s), y1o = cy + R  * Math.sin(s);
                        const x2o = cx + R  * Math.cos(e), y2o = cy + R  * Math.sin(e);
                        const x1i = cx + ri * Math.cos(e), y1i = cy + ri * Math.sin(e);
                        const x2i = cx + ri * Math.cos(s), y2i = cy + ri * Math.sin(s);
                        const lg = sweep > 180 ? 1 : 0;
                        cumDeg += sweep;
                        return <path key={i} d={`M${x1o} ${y1o} A${R} ${R} 0 ${lg} 1 ${x2o} ${y2o} L${x1i} ${y1i} A${ri} ${ri} 0 ${lg} 0 ${x2i} ${y2i}Z`} fill={t.color} stroke="#1a1a2e" strokeWidth="2" />;
                      });
                      return (
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                          <svg viewBox="0 0 200 200" style={{ height: '175px', width: 'auto' }}>
                            {paths}
                            <text x={cx} y={cy - 7} textAnchor="middle" fontSize={20} fontWeight="700" fill="#e2e8f0">{totalCount}</text>
                            <text x={cx} y={cy + 13} textAnchor="middle" fontSize={9} fill="#94a3b8">Total Alerts</text>
                          </svg>
                          <div style={{ display: 'flex', gap: '24px', justifyContent: 'center' }}>
                            {withColor.map((t, i) => (
                              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <span style={{ width: 10, height: 10, borderRadius: '50%', background: t.color, flexShrink: 0, display: 'inline-block' }} />
                                <span style={{ fontSize: '12px', color: '#94a3b8' }}>{t.type}</span>
                                <span style={{ fontSize: '13px', fontWeight: 700, color: '#e2e8f0' }}>{t.count}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                </div>

                {/* Alert Severity Over Time Stacked Bar Chart */}
                <div className="dashboard-card chart-card">
                  <div className="card-header">
                    <div className="card-title">
                      <Activity />
                      <h3>Alert Severity Over Time</h3>
                    </div>
                  </div>
                  <div className="card-body">
                    {(() => {
                      const data = severityOverTime.length > 0 ? severityOverTime : [];
                      const totals = { critical: 0, high: 0, medium: 0, low: 0 };
                      data.forEach(d => { totals.critical += d.critical; totals.high += d.high; totals.medium += d.medium; totals.low += d.low; });
                      const maxVal = Math.max(...data.map(d => d.critical + d.high + d.medium + d.low), 1);
                      const chartH = 130;
                      const padL = 36, padR = 10, padTop = 4;
                      const totalW = 480;
                      const colW = data.length > 0 ? totalW / data.length : 60;
                      const barW = Math.max(colW * 0.55, 12);
                      const colors = { critical: '#0D47A1', high: '#1976D2', medium: '#B5179E', low: '#42A5F5' };
                      const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
                      return (
                        <div style={{ width: '100%', position: 'relative' }}>
                          {/* Legend */}
                          <div style={{ display: 'flex', gap: '16px', marginBottom: '12px', flexWrap: 'wrap' }}>
                            {(['critical','high','medium','low'] as const).map(s => (
                              <span key={s} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '12px', color: '#64748b' }}>
                                <span style={{ width: 10, height: 10, borderRadius: 2, background: colors[s], display: 'inline-block' }} />
                                {labels[s]}
                              </span>
                            ))}
                          </div>
                          {/* SVG stacked bars */}
                          <svg viewBox={`0 0 ${padL + totalW + padR} ${chartH + padTop + 20}`} style={{ width: '100%', overflow: 'visible' }}>
                            <defs>
                              {(['critical','high','medium','low'] as const).map(s => (
                                <linearGradient key={s} id={`sev-grad-${s}`} x1="0" y1="0" x2="0" y2="1">
                                  <stop offset="0%" stopColor={colors[s]} stopOpacity="1" />
                                  <stop offset="100%" stopColor={colors[s]} stopOpacity="0.75" />
                                </linearGradient>
                              ))}
                            </defs>
                            {/* Y-axis gridlines */}
                            {[0, 0.25, 0.5, 0.75, 1].map((pct, i) => (
                              <g key={i}>
                                <line x1={padL} y1={padTop + chartH - chartH * pct} x2={padL + totalW} y2={padTop + chartH - chartH * pct} stroke="#e2e8f0" strokeWidth={0.5} strokeDasharray={pct === 0 ? 'none' : '3 3'} />
                                <text x={padL - 4} y={padTop + chartH - chartH * pct + 4} textAnchor="end" fontSize={9} fill="#94a3b8">{Math.round(maxVal * pct)}</text>
                              </g>
                            ))}
                            {data.map((d, i) => {
                              const cx = padL + i * colW + colW / 2;
                              const x = cx - barW / 2;
                              const total = d.critical + d.high + d.medium + d.low;
                              const segments: { s: 'critical'|'high'|'medium'|'low'; h: number; y: number }[] = [];
                              let curY = padTop + chartH;
                              (['low','medium','high','critical'] as const).forEach(s => {
                                const h = total > 0 ? (d[s] / maxVal) * chartH : 0;
                                curY -= h;
                                segments.push({ s, h, y: curY });
                              });
                              return (
                                <g key={d.day} style={{ cursor: 'pointer' }}>
                                  {/* Background column */}
                                  <rect x={x} y={padTop} width={barW} height={chartH} fill="#0D47A1" opacity={0.05} rx={3} />
                                  {/* Stacked segments with CSS grow animation */}
                                  {segments.map(({ s, h, y }) => h > 0 ? (
                                    <rect
                                      key={s}
                                      x={x} y={y} width={barW} height={h}
                                      fill={`url(#sev-grad-${s})`}
                                      rx={s === 'critical' ? 3 : 1}
                                      style={{
                                        transformOrigin: `${cx}px ${padTop + chartH}px`,
                                        animation: 'sevBarGrow 0.6s cubic-bezier(.4,0,.2,1) both',
                                        animationDelay: `${i * 60}ms`,
                                        transition: 'opacity 0.15s',
                                      }}
                                    >
                                      <title>{d.day} — {labels[s]}: {d[s].toLocaleString()}</title>
                                    </rect>
                                  ) : null)}
                                  {/* Hover highlight overlay */}
                                  <rect x={x} y={padTop} width={barW} height={chartH} fill="white" opacity={0} rx={3}
                                    onMouseEnter={e => { (e.currentTarget as SVGRectElement).style.opacity = '0.08'; }}
                                    onMouseLeave={e => { (e.currentTarget as SVGRectElement).style.opacity = '0'; }}
                                  />
                                  <text x={cx} y={padTop + chartH + 14} textAnchor="middle" fontSize={10} fill="#64748b">{d.day}</text>
                                  {/* Value label on top */}
                                  {total > 0 && (
                                    <text x={cx} y={segments[segments.length - 1].y - 3} textAnchor="middle" fontSize={8} fill="#0D47A1" fontWeight={600}>
                                      {total >= 1000 ? `${(total/1000).toFixed(1)}k` : total}
                                    </text>
                                  )}
                                </g>
                              );
                            })}
                          </svg>
                          <style>{`
                            @keyframes sevBarGrow {
                              from { transform: scaleY(0); opacity: 0; }
                              to   { transform: scaleY(1); opacity: 1; }
                            }
                          `}</style>
                          {/* Summary badges */}
                          <div style={{ display: 'flex', gap: '8px', marginTop: '8px', flexWrap: 'wrap' }}>
                            {(['critical','high','medium','low'] as const).map(s => (
                              <span key={s} style={{ padding: '3px 10px', borderRadius: 12, background: colors[s] + '22', border: `1px solid ${colors[s]}`, color: colors[s], fontSize: 12, fontWeight: 500 }}>
                                {totals[s].toLocaleString()} {labels[s]}
                              </span>
                            ))}
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                </div>


              </div>

              {/* Charts Row 2: Recent Alerts — full width */}
              <div className="dashboard-row">
                <div className="dashboard-card chart-card full-width" style={{ gridColumn: '1 / -1' }}>
                  <div className="card-header">
                    <div className="card-title">
                      <Activity />
                      <h3>Recent Alerts</h3>
                    </div>
                  </div>
                  <div className="card-body" style={{ padding: '0', overflow: 'hidden' }}>
                    {securityEvents.length === 0 ? (
                      <div style={{ padding: '32px', textAlign: 'center', color: '#6c2d7d', fontSize: '13px' }}>No recent alerts</div>
                    ) : (
                      securityEvents.slice(0, 5).map((evt, i) => {
                        const sevConfig: Record<string, { dot: string; bg: string; border: string; label: string }> = {
                          critical: { dot: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.30)', label: 'CRITICAL' },
                          high:     { dot: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.30)', label: 'HIGH' },
                          medium:   { dot: '#1976D2', bg: 'rgba(157,78,221,0.12)', border: 'rgba(157,78,221,0.30)', label: 'MEDIUM' },
                          low:      { dot: '#22c55e', bg: 'rgba(34,197,94,0.12)',  border: 'rgba(34,197,94,0.30)',  label: 'LOW' },
                        };
                        const cfg = sevConfig[evt.severity] || sevConfig.low;
                        const rawDesc = evt.description || evt.alert_type || '';
                        const cleanDesc = rawDesc
                          .replace(/^Suricata\s+\w+\s*\([^)]+\):\s*/i, '')
                          .replace(/^SYNORIX\s+\w+:\s*/i, '')
                          .replace(/\s+from\s+[\d.:]+\s+to\s+[\d.:]+.*$/i, '')
                          .replace(/\s*\[Action:[^\]]*\]/gi, '')
                          .trim() || rawDesc;
                        const timeStr = evt.timestamp ? (() => {
                          const d = new Date(evt.timestamp);
                          const diff = Date.now() - d.getTime();
                          if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
                          if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
                          return `${Math.floor(diff / 86400000)}d ago`;
                        })() : '';
                        return (
                          <div key={evt.id} style={{
                            display: 'flex', alignItems: 'center', gap: '14px',
                            padding: '13px 16px',
                            borderBottom: i < 4 ? '1px solid rgba(157,78,221,0.10)' : 'none',
                          }}>
                            <span style={{ width: 9, height: 9, borderRadius: '50%', background: cfg.dot, boxShadow: `0 0 8px ${cfg.dot}`, flexShrink: 0 }} />
                            <span style={{
                              fontSize: '9px', fontWeight: 800, letterSpacing: '0.06em',
                              color: cfg.dot, background: cfg.bg, border: `1px solid ${cfg.border}`,
                              borderRadius: '4px', padding: '3px 8px', flexShrink: 0
                            }}>{cfg.label}</span>
                            <span style={{ fontSize: '11px', fontWeight: 500, color: '#1976D2', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {cleanDesc}
                            </span>
                            <span style={{ fontSize: '10px', fontFamily: 'monospace', color: '#42A5F5', fontWeight: 600, flexShrink: 0 }}>{evt.source_ip || '—'}</span>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* Users Tab */}
          {activeTab === 'users' && (
            <motion.div
              className="users-section"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              <div className="section-header">
                <h2>All Users</h2>
                <div className="search-box">
                  <Search />
                  <input
                    type="text"
                    placeholder="Search users..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
              </div>

              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Username</th>
                      <th>Email</th>
                      <th>Role</th>
                      <th>Status</th>
                      <th>Website</th>
                      <th>Requests</th>
                      <th>Alerts</th>
                      <th>Created</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredUsers.map(user => (
                      <tr key={user.id}>
                        <td>{user.username}</td>
                        <td>{user.email}</td>
                        <td>
                          <span className={`badge ${user.role === 'admin' ? 'admin' : 'user'}`}>
                            {user.role}
                          </span>
                        </td>
                        <td>
                          {user.is_banned ? (
                            <span className="badge error">Banned</span>
                          ) : user.is_active ? (
                            <span className="badge success">Active</span>
                          ) : (
                            <span className="badge warning">Inactive</span>
                          )}
                        </td>
                        <td>
                          {user.backend_url ? (
                            <span className="badge success">
                              {user.is_configured ? '✓' : '⚠'} Configured
                            </span>
                          ) : (
                            <span className="badge secondary">Not Set</span>
                          )}
                        </td>
                        <td>{user.total_requests || 0}</td>
                        <td>
                          {user.open_alerts > 0 ? (
                            <span className="badge warning">{user.open_alerts}</span>
                          ) : (
                            <span className="badge success">0</span>
                          )}
                        </td>
                        <td>{new Date(user.created_at).toLocaleDateString()}</td>
                        <td>
                          <div className="action-buttons-group">
                            <button 
                              className="action-btn-small edit"
                              onClick={() => handleEditUser(user)}
                              title="Edit User"
                            >
                              <Edit size={14} />
                            </button>
                            <button 
                              className={`action-btn-small ${user.is_banned ? 'success' : 'warning'}`}
                              onClick={() => handleBanUser(user.id, !user.is_banned)}
                              title={user.is_banned ? 'Unban User' : 'Ban User'}
                            >
                              {user.is_banned ? '✓' : '🚫'}
                            </button>
                            <button 
                              className="action-btn-small delete"
                              onClick={() => {
                                setUserToDelete(user.id);
                                setShowDeleteConfirm(true);
                              }}
                              title="Delete User"
                            >
                              <X size={14} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {/* Websites Tab */}
          {activeTab === 'websites' && (
            <motion.div
              className="websites-section"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              <div className="section-header">
                <h2>Registered Websites</h2>
                <div className="search-box">
                  <Search />
                  <input
                    type="text"
                    placeholder="Search websites..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
              </div>

              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Website URL</th>
                      <th>Owner</th>
                      <th>Email</th>
                      <th>Status</th>
                      <th>Requests</th>
                      <th>Blocked</th>
                      <th>Last Test</th>
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredWebsites.map(website => (
                      <tr key={website.id}>
                        <td className="website-url">{website.backend_url}</td>
                        <td>{website.username}</td>
                        <td>{website.email}</td>
                        <td>
                          {website.connectivity_status === 'success' ? (
                            <span className="badge success">Connected</span>
                          ) : website.connectivity_status === 'error' ? (
                            <span className="badge error">Error</span>
                          ) : (
                            <span className="badge secondary">Untested</span>
                          )}
                        </td>
                        <td>
                          <span className="badge info">{website.total_requests || 0}</span>
                        </td>
                        <td>
                          <span className={`badge ${website.blocked_requests > 0 ? 'warning' : 'success'}`}>
                            {website.blocked_requests || 0}
                          </span>
                        </td>
                        <td>
                          {website.last_test_at ? (
                            new Date(website.last_test_at).toLocaleString()
                          ) : (
                            'Never'
                          )}
                        </td>
                        <td>{new Date(website.created_at).toLocaleDateString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {/* WAF Rules Tab */}
          {activeTab === 'waf' && (
            <motion.div
              className="waf-section"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              <div className="section-header">
                <h2>Web Application Firewall (WAF) Rules</h2>
                <div className="action-buttons">
                  <button className="add-button" onClick={() => setShowAddWafRuleModal(true)}>
                    <Shield /> Add Rule
                  </button>
                  <button className="refresh-button small" onClick={fetchWafRules}>
                    <RefreshCw /> Refresh
                  </button>
                </div>
              </div>

              <PhaseNotice
                statusBadge="45% FYP-1 Prototype"
                phase="Phase 2 In Development (Oct 2026)"
                title="WAF Custom Rule Engine & Hot Reloading"
                description="Phase 1 evaluates static OWASP signature regexes compiled in Go. Dynamic in-memory rule injection, anomaly score thresholding, and user-defined rate limits are scheduled for Phase 2."
                isMockData={false}
              />

              {!wafConfig || wafConfig.length === 0 ? (
                <div className="empty-state">
                  <Shield />
                  <p>No WAF rules found</p>
                  <button className="add-button" onClick={() => setShowAddWafRuleModal(true)}>
                    <Shield /> Add Your First Rule
                  </button>
                </div>
              ) : (
                <div className="table-container">
                  <table className="data-table waf-rules-table">
                    <thead>
                      <tr>
                        <th style={{ width: '60px' }}>ID</th>
                        <th>Message</th>
                        <th style={{ width: '120px' }}>Category</th>
                        <th style={{ width: '100px' }}>Severity</th>
                        <th style={{ width: '100px' }}>Status</th>
                        <th style={{ width: '150px' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Array.isArray(wafConfig) && wafConfig.map((rule) => (
                        <React.Fragment key={rule.id}>
                          <tr 
                            className={`waf-rule-row ${!rule.enabled ? 'rule-disabled' : ''} ${expandedWafRules.has(rule.id) ? 'expanded' : ''}`}
                            onClick={() => toggleWafRuleExpanded(rule.id)}
                          >
                            <td>
                              <span className="rule-id-badge">
                                <Shield size={14} />
                                {rule.id}
                              </span>
                            </td>
                            <td>
                              <span className="rule-message">{rule.message}</span>
                            </td>
                            <td>
                              <span className="rule-category">{rule.tags}</span>
                            </td>
                            <td>
                              <span className={`badge severity sev-${rule.severity}`}>
                                {rule.severity === 5 ? 'Critical' : 
                                 rule.severity === 4 ? 'High' : 
                                 rule.severity === 3 ? 'Medium' : 
                                 rule.severity === 2 ? 'Low' : 'Info'}
                              </span>
                            </td>
                            <td onClick={(e) => e.stopPropagation()}>
                              <span className={`badge ${rule.enabled ? 'success' : 'secondary'}`}>
                                {rule.enabled ? 'Enabled' : 'Disabled'}
                              </span>
                            </td>
                            <td onClick={(e) => e.stopPropagation()}>
                              <div className="action-buttons-inline">
                                <button
                                  className="action-btn-icon edit"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleEditWafRule(rule);
                                  }}
                                  title="Edit Rule"
                                >
                                  <Edit size={16} />
                                </button>
                                <button
                                  className="action-btn-icon delete"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setWafRuleToDelete(rule.id);
                                  }}
                                  title="Delete Rule"
                                >
                                  <Trash2 size={16} />
                                </button>
                              </div>
                            </td>
                          </tr>
                          {expandedWafRules.has(rule.id) && (
                            <tr className="expanded-row">
                              <td colSpan={7}>
                                <div className="expanded-content">
                                  <div className="expanded-section">
                                    <label className="expanded-label">Pattern:</label>
                                    <code className="pattern-display">{rule.pattern}</code>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </motion.div>
          )}

          {/* Suricata Rules Tab */}
          {activeTab === 'suricata' && (
            <motion.div
              className="suricata-section"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              <div className="section-header">
                <h2>IDS/IPS (Suricata) Rules</h2>
                <div className="action-buttons">
                  <button className="add-button" onClick={() => setShowAddSuricataRuleModal(true)}>
                    <Eye /> Add Rule
                  </button>
                  <button 
                    className="reload-button small" 
                    onClick={reloadSuricata}
                    disabled={loading}
                    title="Restart Suricata IDS/IPS services to apply rule changes"
                  >
                    <RotateCcw /> {loading ? 'Reloading...' : 'Reload Suricata'}
                  </button>
                </div>
              </div>

              <PhaseNotice
                statusBadge="45% FYP-1 Prototype"
                phase="Phase 2 In Development (Nov 2026)"
                title="IDS / IPS Signature Rule Management"
                description="Phase 1 monitors network traffic through pre-configured Suricata rule sets and fast.log parsing. Dynamic rule file compilation and active NFQUEUE inline packet dropping are scheduled for Phase 2."
                isMockData={false}
              />

              {!suricataRules || suricataRules.length === 0 ? (
                <div className="empty-state">
                  <Eye />
                  <p>No Suricata rules found</p>
                </div>
              ) : (
                <div className="table-container">
                  <table className="data-table suricata-rules-table">
                    <thead>
                      <tr>
                        <th style={{ width: '80px' }}>SID</th>
                        <th>Message</th>
                        <th style={{ width: '100px' }}>Action</th>
                        <th style={{ width: '100px' }}>Protocol</th>
                        <th style={{ width: '100px' }}>Status</th>
                        <th style={{ width: '150px' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Array.isArray(suricataRules) && suricataRules.map((rule) => {
                        const isExpanded = expandedSuricataRules.has(rule.id);
                        return (
                          <React.Fragment key={rule.id}>
                            <tr 
                              className={`suricata-rule-row ${!rule.enabled ? 'rule-disabled' : ''}`}
                              onClick={() => {
                                const newExpanded = new Set(expandedSuricataRules);
                                if (isExpanded) {
                                  newExpanded.delete(rule.id);
                                } else {
                                  newExpanded.add(rule.id);
                                }
                                setExpandedSuricataRules(newExpanded);
                              }}
                              style={{ cursor: 'pointer' }}
                            >
                              <td>
                                <span className="rule-id-badge ids-badge">
                                  <Activity size={14} />
                                  {rule.sid}
                                </span>
                              </td>
                              <td>
                                <span className="rule-message">{rule.msg || rule.message}</span>
                              </td>
                              <td>
                                <span className={`badge ${
                                  rule.action === 'alert' ? 'warning' : 
                                  rule.action === 'drop' ? 'error' : 
                                  rule.action === 'reject' ? 'error' : 'info'
                                }`}>
                                  {(rule.action || 'alert').toUpperCase()}
                                </span>
                              </td>
                              <td>
                                <span className="rule-category">{rule.protocol?.toUpperCase() || 'HTTP'}</span>
                              </td>
                              <td onClick={(e) => e.stopPropagation()}>
                                <span className={`badge ${rule.enabled ? 'success' : 'secondary'}`}>
                                  {rule.enabled ? 'Enabled' : 'Disabled'}
                                </span>
                              </td>
                              <td onClick={(e) => e.stopPropagation()}>
                                <div className="action-buttons-inline">
                                  <button
                                    className="action-btn-icon edit"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleEditSuricataRule(rule);
                                    }}
                                    title="Edit Rule"
                                  >
                                    <Edit size={16} />
                                  </button>
                                  <button
                                    className="action-btn-icon delete"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setSuricataRuleToDelete(rule.id);
                                    }}
                                    title="Delete Rule"
                                  >
                                    <Trash2 size={16} />
                                  </button>
                                </div>
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr className="suricata-rule-details-row">
                                <td colSpan={7}>
                                  <div className="rule-details-panel">
                                    <div className="details-grid">
                                      <div className="detail-group">
                                        <label>Source IP</label>
                                        <span className="detail-value">{rule.source_ip || 'any'}</span>
                                      </div>
                                      <div className="detail-group">
                                        <label>Source Port</label>
                                        <span className="detail-value">{rule.source_port || 'any'}</span>
                                      </div>
                                      <div className="detail-group">
                                        <label>Direction</label>
                                        <span className="detail-value">{rule.direction || '->'}</span>
                                      </div>
                                      <div className="detail-group">
                                        <label>Dest IP</label>
                                        <span className="detail-value">{rule.dest_ip || 'any'}</span>
                                      </div>
                                      <div className="detail-group">
                                        <label>Dest Port</label>
                                        <span className="detail-value">{rule.dest_port || 'any'}</span>
                                      </div>
                                      <div className="detail-group">
                                        <label>Priority</label>
                                        <span className="detail-value">{rule.priority || 'N/A'}</span>
                                      </div>
                                      <div className="detail-group">
                                        <label>Flow</label>
                                        <span className="detail-value">{rule.flow || 'N/A'}</span>
                                      </div>
                                      <div className="detail-group">
                                        <label>Content</label>
                                        <span className="detail-value" style={{ wordBreak: 'break-word' }}>
                                          {rule.content || 'N/A'}
                                        </span>
                                      </div>
                                      <div className="detail-group">
                                        <label>Classtype</label>
                                        <span className="detail-value">{rule.classtype || 'N/A'}</span>
                                      </div>
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </motion.div>
          )}

          {/* ── Admin Alerts Tab ── */}
          {activeTab === 'alerts' && (
            <div className="alerts-tab-section">

              {/* Controls card */}
              <div className="alerts-filter-card">
                <div className="alerts-filter-card-header">
                  <div className="alerts-filter-card-title">
                    <Filter size={15} />
                    <span>Filter Alerts</span>
                  </div>
                  <span className="alerts-filter-count">
                    {adminAlertsTotal} group{adminAlertsTotal !== 1 ? 's' : ''} matched
                  </span>
                </div>
                <div className="alerts-filter-card-body">
                  <div className="alerts-filter-field">
                    <label className="alerts-filter-label">Time Window</label>
                    <select
                      className="alerts-filter-select"
                      value={adminAlertsWindow}
                      onChange={e => {
                        const v = e.target.value as '1h'|'24h'|'7d'|'30d';
                        setAdminAlertsWindow(v);
                        setAdminAlertsOffset(0);
                        fetchAdminAlerts({ window: v, offset: 0 });
                      }}
                    >
                      <option value="1h">Last 1 Hour</option>
                      <option value="24h">Last 24 Hours</option>
                      <option value="7d">Last 7 Days</option>
                      <option value="30d">Last 30 Days</option>
                    </select>
                  </div>
                  <div className="alerts-filter-field">
                    <label className="alerts-filter-label">Severity</label>
                    <select
                      className="alerts-filter-select"
                      value={adminAlertsSeverity}
                      onChange={e => {
                        setAdminAlertsSeverity(e.target.value);
                        setAdminAlertsOffset(0);
                        fetchAdminAlerts({ severity: e.target.value, offset: 0 });
                      }}
                    >
                      <option value="high_critical">High + Critical</option>
                      <option value="">All Severities</option>
                      <option value="critical">Critical only</option>
                      <option value="high">High only</option>
                      <option value="medium">Medium only</option>
                    </select>
                  </div>
                  <div className="alerts-filter-field">
                    <label className="alerts-filter-label">Type</label>
                    <select
                      className="alerts-filter-select"
                      value={adminAlertsType}
                      onChange={e => {
                        setAdminAlertsType(e.target.value);
                        setAdminAlertsOffset(0);
                        fetchAdminAlerts({ type: e.target.value, offset: 0 });
                      }}
                    >
                      <option value="">All Types</option>
                      <option value="suricata">IDS/IPS</option>
                      <option value="waf">WAF</option>
                    </select>
                  </div>
                  <button
                    className="alerts-refresh-btn"
                    onClick={() => { setAdminAlertsOffset(0); fetchAdminAlerts({ offset: 0 }); }}
                    disabled={adminAlertsLoading}
                  >
                    <RefreshCw size={14} className={adminAlertsLoading ? 'alerts-spin' : ''} />
                    {adminAlertsLoading ? 'Loading…' : 'Refresh'}
                  </button>
                </div>
              </div>

              {adminAlertsLoading ? (
                <div className="empty-state"><RefreshCw style={{ animation: 'spin 1s linear infinite' }} /><p>Loading alerts…</p></div>
              ) : adminAlerts.length === 0 ? (
                <div className="empty-state"><AlertTriangle /><p>No alerts found for the selected filters</p></div>
              ) : (
                <>
                  <div className="table-container">
                    <table className="data-table alerts-data-table">
                      <thead>
                        <tr>
                          <th>Source IP</th>
                          <th>Signature / Rule</th>
                          <th>Type</th>
                          <th>Severity</th>
                          <th className="col-hits">Hits</th>
                          <th>Last Seen</th>
                          <th>Action</th>
                          <th>Block</th>
                        </tr>
                      </thead>
                      <tbody>
                        {adminAlerts.map((a: any, i: number) => {
                          const sevColorMap: Record<string, string> = { critical: '#DC2626', high: '#F97316', medium: '#1976D2', low: '#3B82F6' };
                          const sevColor = sevColorMap[a.severity] || '#9CA3AF';
                          const d = new Date(a.last_seen);
                          const ago = (() => {
                            const diff = Date.now() - d.getTime(), m = Math.floor(diff/60000), h = Math.floor(m/60), days = Math.floor(h/24);
                            if (m < 1) return 'Just now';
                            if (m < 60) return `${m}m ago`;
                            if (h < 24) return `${h}h ago`;
                            return `${days}d ago`;
                          })();
                          const isBlocked = (a.action || '').toLowerCase() === 'blocked';
                          return (
                            <tr key={i} className={isBlocked ? 'alerts-row-blocked' : ''}>
                              <td>
                                <code className="alerts-source-ip">{a.source_ip}</code>
                              </td>
                              <td className="alerts-rule-cell">
                                <span className="alerts-rule-name" title={a.rule_name}>
                                  {a.rule_name || a.rule_id}
                                </span>
                              </td>
                              <td>
                                <span className={`badge info alerts-type-badge alerts-type-${(a.alert_type || '').toLowerCase()}`}>
                                  {(a.alert_type || '').toUpperCase()}
                                </span>
                              </td>
                              <td>
                                <span className="badge alerts-sev-badge" style={{ background: sevColor + '18', color: sevColor, border: `1px solid ${sevColor}50` }}>
                                  {(a.severity || '').toUpperCase()}
                                </span>
                              </td>
                              <td className="col-hits alerts-hits">{a.total_hits || a.row_count}</td>
                              <td className="alerts-time">{ago}</td>
                              <td>
                                <span className={`badge alerts-action-badge ${isBlocked ? 'error' : 'warning'}`}>
                                  {(a.action || '').toUpperCase()}
                                </span>
                              </td>
                              <td>
                                {a.source_ip && a.source_ip !== '0.0.0.0' && (
                                  <button
                                    className="alerts-block-btn"
                                    title={`Block ${a.source_ip} for 1h`}
                                    onClick={() => blockIpFromAlert(a.source_ip, a.rule_name || a.rule_id)}
                                  >
                                    <ShieldX size={12} /> Block
                                  </button>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination */}
                  {adminAlertsTotal > ADMIN_ALERTS_PAGE && (
                    <div className="alerts-pagination">
                      <button
                        className="reload-button small"
                        disabled={adminAlertsOffset === 0 || adminAlertsLoading}
                        onClick={() => {
                          const o = Math.max(0, adminAlertsOffset - ADMIN_ALERTS_PAGE);
                          setAdminAlertsOffset(o);
                          fetchAdminAlerts({ offset: o });
                        }}
                      >← Prev</button>
                      <span className="alerts-page-info">
                        {adminAlertsOffset + 1}–{Math.min(adminAlertsOffset + ADMIN_ALERTS_PAGE, adminAlertsTotal)} of {adminAlertsTotal}
                      </span>
                      <button
                        className="reload-button small"
                        disabled={adminAlertsOffset + ADMIN_ALERTS_PAGE >= adminAlertsTotal || adminAlertsLoading}
                        onClick={() => {
                          const o = adminAlertsOffset + ADMIN_ALERTS_PAGE;
                          setAdminAlertsOffset(o);
                          fetchAdminAlerts({ offset: o });
                        }}
                      >Next →</button>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Edit User Modal */}
      {showEditUserModal && selectedUser && (
        <div className="modal-overlay" onClick={() => setShowEditUserModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Edit User</h3>
              <button className="modal-close" onClick={() => setShowEditUserModal(false)}>
                <X />
              </button>
            </div>
            <form onSubmit={handleUpdateUser}>
              <div className="form-group">
                <label>Username</label>
                <input
                  type="text"
                  value={selectedUser.username}
                  onChange={(e) => setSelectedUser({ ...selectedUser, username: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label>Email</label>
                <input
                  type="email"
                  value={selectedUser.email}
                  onChange={(e) => setSelectedUser({ ...selectedUser, email: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label>Role</label>
                <select
                  value={selectedUser.role}
                  onChange={(e) => setSelectedUser({ ...selectedUser, role: e.target.value })}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div className="form-group checkbox">
                <label>
                  <input
                    type="checkbox"
                    checked={selectedUser.is_active === 1}
                    onChange={(e) => setSelectedUser({ ...selectedUser, is_active: e.target.checked ? 1 : 0 })}
                  />
                  Active
                </label>
              </div>
              <div className="form-group checkbox">
                <label>
                  <input
                    type="checkbox"
                    checked={selectedUser.is_banned === 1}
                    onChange={(e) => setSelectedUser({ ...selectedUser, is_banned: e.target.checked ? 1 : 0 })}
                  />
                  Banned
                </label>
              </div>
              <div className="modal-actions">
                <button type="button" className="cancel-button" onClick={() => setShowEditUserModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="save-button">
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <div className="modal-overlay" onClick={() => setShowDeleteConfirm(false)}>
          <div className="modal-content confirm" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Confirm Delete</h3>
              <button className="modal-close" onClick={() => setShowDeleteConfirm(false)}>
                <X />
              </button>
            </div>
            <p>Are you sure you want to delete this user? This action cannot be undone.</p>
            <div className="modal-actions">
              <button className="cancel-button" onClick={() => setShowDeleteConfirm(false)}>
                Cancel
              </button>
              <button className="delete-button" onClick={handleDeleteUser}>
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add WAF Rule Modal */}
      {showAddWafRuleModal && (
        <div className="modal-overlay" onClick={() => setShowAddWafRuleModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Add WAF Rule</h3>
              <button className="modal-close" onClick={() => setShowAddWafRuleModal(false)}>
                <X />
              </button>
            </div>
            <form onSubmit={handleAddWafRule}>
              <div className="form-group">
                <label>Rule ID</label>
                <input type="number" name="id" required placeholder="e.g., 2001" />
              </div>
              <div className="form-group">
                <label>Message</label>
                <input type="text" name="message" required placeholder="Description of what this rule detects" />
              </div>
              <div className="form-group">
                <label>Pattern (Regex)</label>
                <input type="text" name="pattern" required placeholder="Regular expression pattern" />
              </div>
              <div className="form-group">
                <label>Tags</label>
                <input type="text" name="tags" required placeholder="e.g., attack-sqli, attack-xss" />
              </div>
              <div className="form-group">
                <label>Severity (1-5)</label>
                <select name="severity" required>
                  <option value="1">1 - Low</option>
                  <option value="2">2 - Medium-Low</option>
                  <option value="3">3 - Medium</option>
                  <option value="4">4 - High</option>
                  <option value="5">5 - Critical</option>
                </select>
              </div>
              <div className="form-group checkbox">
                <label>
                  <input type="checkbox" name="enabled" defaultChecked />
                  Enabled
                </label>
              </div>
              <div className="modal-actions">
                <button type="button" className="cancel-button" onClick={() => setShowAddWafRuleModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="save-button">
                  Add Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit WAF Rule Modal */}
      {showEditWafRuleModal && selectedWafRule && (
        <div className="modal-overlay" onClick={() => setShowEditWafRuleModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Edit WAF Rule</h3>
              <button className="modal-close" onClick={() => setShowEditWafRuleModal(false)}>
                <X />
              </button>
            </div>
            <form onSubmit={handleUpdateWafRule}>
              <div className="form-group">
                <label>Rule ID</label>
                <input
                  type="number"
                  value={selectedWafRule.id}
                  onChange={(e) => setSelectedWafRule({ ...selectedWafRule, id: parseInt(e.target.value) })}
                  required
                  disabled
                />
              </div>
              <div className="form-group">
                <label>Message</label>
                <input
                  type="text"
                  value={selectedWafRule.message}
                  onChange={(e) => setSelectedWafRule({ ...selectedWafRule, message: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label>Pattern (Regex)</label>
                <input
                  type="text"
                  value={selectedWafRule.pattern}
                  onChange={(e) => setSelectedWafRule({ ...selectedWafRule, pattern: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label>Tags</label>
                <input
                  type="text"
                  value={selectedWafRule.tags}
                  onChange={(e) => setSelectedWafRule({ ...selectedWafRule, tags: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label>Severity (1-5)</label>
                <select
                  value={selectedWafRule.severity}
                  onChange={(e) => setSelectedWafRule({ ...selectedWafRule, severity: parseInt(e.target.value) })}
                  required
                >
                  <option value="1">1 - Low</option>
                  <option value="2">2 - Medium-Low</option>
                  <option value="3">3 - Medium</option>
                  <option value="4">4 - High</option>
                  <option value="5">5 - Critical</option>
                </select>
              </div>
              <div className="form-group checkbox">
                <label>
                  <input
                    type="checkbox"
                    checked={selectedWafRule.enabled}
                    onChange={(e) => setSelectedWafRule({ ...selectedWafRule, enabled: e.target.checked })}
                  />
                  Enabled
                </label>
              </div>
              <div className="modal-actions">
                <button type="button" className="cancel-button" onClick={() => setShowEditWafRuleModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="save-button">
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete WAF Rule Confirmation */}
      {wafRuleToDelete && (
        <div className="modal-overlay" onClick={() => setWafRuleToDelete(null)}>
          <div className="modal-content confirm" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Confirm Delete</h3>
              <button className="modal-close" onClick={() => setWafRuleToDelete(null)}>
                <X />
              </button>
            </div>
            <p>Are you sure you want to delete this WAF rule? This action cannot be undone.</p>
            <div className="modal-actions">
              <button className="cancel-button" onClick={() => setWafRuleToDelete(null)}>
                Cancel
              </button>
              <button className="delete-button" onClick={handleDeleteWafRule}>
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Suricata Rule Modal */}
      {showAddSuricataRuleModal && (
        <div className="modal-overlay" onClick={() => setShowAddSuricataRuleModal(false)}>
          <div className="modal-content large" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Add Suricata Rule</h3>
              <button className="modal-close" onClick={() => setShowAddSuricataRuleModal(false)}>
                <X />
              </button>
            </div>
            <form onSubmit={handleAddSuricataRule}>
              <div className="form-row">
                <div className="form-group">
                  <label>SID (Signature ID)</label>
                  <input type="number" name="sid" required />
                </div>
                <div className="form-group">
                  <label>Action</label>
                  <select name="action" required>
                    <option value="alert">Alert</option>
                    <option value="drop">Drop</option>
                    <option value="reject">Reject</option>
                    <option value="pass">Pass</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Protocol</label>
                  <select name="protocol" required>
                    <option value="http">HTTP</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="icmp">ICMP</option>
                    <option value="ip">IP</option>
                  </select>
                </div>
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Source IP</label>
                  <input type="text" name="source_ip" defaultValue="any" required />
                </div>
                <div className="form-group">
                  <label>Source Port</label>
                  <input type="text" name="source_port" defaultValue="any" required />
                </div>
                <div className="form-group">
                  <label>Direction</label>
                  <select name="direction" required>
                    <option value="->">→ (to server)</option>
                    <option value="<-">← (to client)</option>
                    <option value="<>">↔ (bidirectional)</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Dest IP</label>
                  <input type="text" name="dest_ip" defaultValue="any" required />
                </div>
                <div className="form-group">
                  <label>Dest Port</label>
                  <input type="text" name="dest_port" defaultValue="any" required />
                </div>
              </div>

              <div className="form-group">
                <label>Message</label>
                <input type="text" name="msg" required placeholder="Rule description" />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Flow</label>
                  <input type="text" name="flow" placeholder="e.g., to_server,established" />
                </div>
                <div className="form-group">
                  <label>Content</label>
                  <input type="text" name="content" placeholder="Pattern to match" />
                </div>
                <div className="form-group">
                  <label>Classtype</label>
                  <input type="text" name="classtype" placeholder="e.g., web-application-attack" />
                </div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Priority (1-5)</label>
                  <select name="priority" required>
                    <option value="1">1 - High</option>
                    <option value="2">2 - Medium</option>
                    <option value="3">3 - Low</option>
                  </select>
                </div>
              </div>

              <div className="form-group checkbox-group">
                <label><input type="checkbox" name="enabled" defaultChecked /> Enabled</label>
              </div>

              <div className="modal-actions">
                <button type="button" className="cancel-button" onClick={() => setShowAddSuricataRuleModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="save-button">
                  Add Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Suricata Rule Modal */}
      {showEditSuricataRuleModal && selectedSuricataRule && (
        <div className="modal-overlay" onClick={() =>setShowEditSuricataRuleModal(false)}>
          <div className="modal-content large" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Edit Suricata Rule</h3>
              <button className="modal-close" onClick={() => setShowEditSuricataRuleModal(false)}>
                <X />
              </button>
            </div>
            <form onSubmit={handleUpdateSuricataRule}>
              <div className="form-row">
                <div className="form-group">
                  <label>SID</label>
                  <input
                    type="number"
                    value={selectedSuricataRule.sid}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, sid: parseInt(e.target.value) })}
                    required
                    disabled
                  />
                </div>
                <div className="form-group">
                  <label>Action</label>
                  <select
                    value={selectedSuricataRule.action}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, action: e.target.value })}
                    required
                  >
                    <option value="alert">Alert</option>
                    <option value="drop">Drop</option>
                    <option value="reject">Reject</option>
                    <option value="pass">Pass</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Protocol</label>
                  <select
                    value={selectedSuricataRule.protocol}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, protocol: e.target.value })}
                    required
                  >
                    <option value="http">HTTP</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="icmp">ICMP</option>
                    <option value="ip">IP</option>
                  </select>
                </div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Source IP</label>
                  <input
                    type="text"
                    value={selectedSuricataRule.source_ip}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, source_ip: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Source Port</label>
                  <input
                    type="text"
                    value={selectedSuricataRule.source_port}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, source_port: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Direction</label>
                  <select
                    value={selectedSuricataRule.direction}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, direction: e.target.value })}
                    required
                  >
                    <option value="->">→ (to server)</option>
                    <option value="<-">← (to client)</option>
                    <option value="<>">↔ (bidirectional)</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Dest IP</label>
                  <input
                    type="text"
                    value={selectedSuricataRule.dest_ip}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, dest_ip: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Dest Port</label>
                  <input
                    type="text"
                    value={selectedSuricataRule.dest_port}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, dest_port: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label>Message</label>
                <input
                  type="text"
                  value={selectedSuricataRule.msg}
                  onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, msg: e.target.value })}
                  required
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Flow</label>
                  <input
                    type="text"
                    value={selectedSuricataRule.flow || ''}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, flow: e.target.value || null })}
                    placeholder="e.g., to_server,established"
                  />
                </div>
                <div className="form-group">
                  <label>Content</label>
                  <input
                    type="text"
                    value={selectedSuricataRule.content || ''}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, content: e.target.value || null })}
                    placeholder="Pattern to match"
                  />
                </div>
                <div className="form-group">
                  <label>Classtype</label>
                  <input
                    type="text"
                    value={selectedSuricataRule.classtype || ''}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, classtype: e.target.value || undefined })}
                    placeholder="e.g., web-application-attack"
                  />
                </div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Priority</label>
                  <select
                    value={selectedSuricataRule.priority}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, priority: parseInt(e.target.value) })}
                    required
                  >
                    <option value="1">1 - High</option>
                    <option value="2">2 - Medium</option>
                    <option value="3">3 - Low</option>
                  </select>
                </div>
              </div>

              <div className="form-group checkbox-group">
                <label>
                  <input
                    type="checkbox"
                    checked={selectedSuricataRule.enabled}
                    onChange={(e) => setSelectedSuricataRule({ ...selectedSuricataRule, enabled: e.target.checked })}
                  />
                  Enabled
                </label>
              </div>

              <div className="modal-actions">
                <button type="button" className="cancel-button" onClick={() => setShowEditSuricataRuleModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="save-button">
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Suricata Rule Confirmation */}
      {suricataRuleToDelete && (
        <div className="modal-overlay" onClick={() => setSuricataRuleToDelete(null)}>
          <div className="modal-content confirm" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Confirm Delete</h3>
              <button className="modal-close" onClick={() => setSuricataRuleToDelete(null)}>
                <X />
              </button>
            </div>
            <p>Are you sure you want to delete this Suricata rule? This action cannot be undone.</p>
            <div className="modal-actions">
              <button className="cancel-button" onClick={() => setSuricataRuleToDelete(null)}>
                Cancel
              </button>
              <button className="delete-button" onClick={handleDeleteSuricataRule}>
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard;
