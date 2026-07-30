import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  Server,
  Eye,
  EyeOff,
  Globe,
  Copy,
  Check,
  LogOut,
  LayoutDashboard,
  Settings,
  RefreshCw,
  Filter,
  ChevronDown,
  ChevronUp,
  Clock,
  Plus,
  Zap,
  ShieldCheck,
  ShieldX,
  TrendingUp,
  AlertCircle,
  Key,
  Link,
  Save,
  UserCheck,
  Crosshair,
  Lock,
  X,
  ChevronLeft,
  ChevronRight,
  Trash2,
  BarChart3,
  BarChart2,
  Timer
} from 'lucide-react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import './UserDashboard.css';

const API = '/api';

// Safely coerce any API error value (string | object | undefined) to a plain string
const safeErrMsg = (val: unknown, fallback: string): string => {
  if (!val) return fallback;
  if (typeof val === 'string') return val || fallback;
  if (typeof val === 'object') {
    const v = val as Record<string, unknown>;
    const inner = v.message ?? v.error ?? v.detail ?? v.msg;
    if (typeof inner === 'string' && inner) return inner;
    try { return JSON.stringify(val); } catch { return fallback; }
  }
  return String(val) || fallback;
};

// ─── Interfaces ─────────────────────────────────────────
interface UserConfig {
  backend_url: string;
  proxy_api_key: string;
  is_configured: boolean;
  connectivity_status: string;
  last_test_at: string | null;
}

interface Application {
  id: number;
  app_name: string;
  backend_url: string;
  proxy_api_key: string;
  description: string;
  is_active: boolean;
  connectivity_status: string;
  last_test_at: string | null;
  created_at: string;
  // per-app stats (from updated GET /api/user/applications)
  request_count: number;
  alert_count: number;
  unread_alert_count: number;
  waf_blocks: number;
  avg_response_time: number;
}

interface UserStats {
  total_requests: number;
  threats_detected: number;
  waf_blocks: number;
  suricata_alerts: number;
  avg_response_time: number;
}

interface Alert {
  id: number;
  alert_type: 'waf' | 'suricata' | 'ids' | 'ips' | 'ids-inline' | 'system';
  severity: 'low' | 'medium' | 'high' | 'critical';
  rule_id: string;
  rule_name: string;
  description: string;
  source_ip: string;
  target_url: string;
  recommended_action: string;
  action?: string;
  auto_blocked: boolean;
  is_read: boolean;
  timestamp: string;
  source?: string;
  scope?: 'global' | 'application';
  occurrence_count?: number;
}

interface TrafficLog {
  id: number;
  timestamp: string;
  method: string;
  url: string;
  backend_url: string;
  client_ip: string;
  user_agent: string;
  status_code: number;
  response_time: number;
  request_size: number;
  response_size: number;
  threat_level: 'none' | 'low' | 'medium' | 'high' | 'critical';
  waf_triggered: boolean;
  suricata_triggered: boolean;
  compressed: boolean;
  deduplicated: boolean;
  compression_ratio: number;
  original_size: number;
  compressed_size: number;
  dedup_size: number;
  dedup_ratio: number;
}

interface GraphData {
  trafficOverTime: Array<{ time: string; value: number }>;
  threatDistribution: Array<{ type: string; count: number; color: string }>;
  responseTimeDistribution: Array<{ bucket: string; percentage: number; count: number; color: string }>;
  severityDistribution: Array<{ level: string; count: number; color: string }>;
}

type Tab = 'overview' | 'traffic' | 'alerts' | 'applications' | 'settings';

// ─── Component ───────────────────────────────────────────
const UserDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<Tab>('overview');

  const authHeaders = () => ({ Authorization: `Bearer ${localStorage.getItem('token')}` });

  const [config, setConfig] = useState<UserConfig | null>(null);
  const [stats, setStats] = useState<UserStats>({ total_requests: 0, threats_detected: 0, waf_blocks: 0, suricata_alerts: 0, avg_response_time: 0 });
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [logs, setLogs] = useState<TrafficLog[]>([]);
  const [graphData, setGraphData] = useState<GraphData>({ trafficOverTime: [], threatDistribution: [], responseTimeDistribution: [], severityDistribution: [] });
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expandedAlerts, setExpandedAlerts] = useState<Set<number>>(new Set());
  const [deletingAlertId, setDeletingAlertId] = useState<number | null>(null);
  const [deleteConfirmAlert, setDeleteConfirmAlert] = useState<{ id: number; childIds?: number[] } | null>(null);

  const [copiedKey, setCopiedKey] = useState<string | false>(false);
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [visibleKeys, setVisibleKeys] = useState<Set<string>>(new Set());
  const toggleKeyVisible = (id: string) => setVisibleKeys(prev => {
    const next = new Set(prev);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  // Pagination
  const [alertOffset, setAlertOffset] = useState(0);
  const [alertTotal, setAlertTotal] = useState(0);
  const [logOffset, setLogOffset] = useState(0);
  const [logTotal, setLogTotal] = useState(0);
  const ALERT_PAGE_SIZE = 10000;
  const LOG_PAGE_SIZE = 100;
  const [backendUrlInput, setBackendUrlInput] = useState('');
  const [savingConfig, setSavingConfig] = useState(false);
  const [testingConn, setTestingConn] = useState(false);
  const [configMsg, setConfigMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const [alertFilters, setAlertFilters] = useState({ severity: '', alert_type: '', is_read: '' });
  const [logFilters, setLogFilters] = useState({ waf_triggered: '' });

  // Personal info edit state
  const [editingPersonalInfo, setEditingPersonalInfo] = useState(false);
  const [editUsername, setEditUsername] = useState(user?.username || '');
  const [editEmail, setEditEmail] = useState(user?.email || '');
  const [savingPersonalInfo, setSavingPersonalInfo] = useState(false);
  const [personalInfoMsg, setPersonalInfoMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Change password state
  const [changingPassword, setChangingPassword] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [currentPasswordVisible, setCurrentPasswordVisible] = useState(false);
  const [newPasswordVisible, setNewPasswordVisible] = useState(false);
  const [confirmPasswordVisible, setConfirmPasswordVisible] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [passwordMsg, setPasswordMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Multi-application state
  const [applications, setApplications] = useState<Application[]>([]);
  const [showWizard, setShowWizard] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<{ id: number; name: string } | null>(null);
  const [wizardStep, setWizardStep] = useState<'name' | 'url' | 'review' | 'complete'>('name');
  const [newAppName, setNewAppName] = useState('');
  const [newAppUrl, setNewAppUrl] = useState('');
  const [newAppDescription, setNewAppDescription] = useState('');
  const [creatingApp, setCreatingApp] = useState(false);
  const [appMsg, setAppMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [createdAppName, setCreatedAppName] = useState('');
  const [createdAppKey, setCreatedAppKey] = useState('');
  const [selectedApp, setSelectedApp] = useState<Application | null>(null);
  const [loadingApps, setLoadingApps] = useState(false);
  const [testingAppId, setTestingAppId] = useState<number | null>(null);
  const [editingAppId, setEditingAppId] = useState<number | null>(null);
  const [editAppName, setEditAppName] = useState('');
  const [editAppUrl, setEditAppUrl] = useState('');
  const [editAppDescription, setEditAppDescription] = useState('');
  const [savingApp, setSavingApp] = useState(false);
  const [appCardMsg, setAppCardMsg] = useState<Record<number, { type: 'success' | 'error'; text: string }>>({});

  // App filter for traffic/alerts tabs (null = show all)
  const [selectedAppFilter, setSelectedAppFilter] = useState<number | null>(null);

  // Compression & dedup aggregate stats (fetched from dedicated endpoints)
  const [compressionStats, setCompressionStats] = useState({ totalCompressed: 0, averageRatio: 0 });
  const [dedupStats, setDedupStats] = useState({ totalDeduplicated: 0, hitRate: 0 });
  const [topEndpoints, setTopEndpoints] = useState<Array<{ method: string; url: string; backend_url: string; calls: number; avg_response_time: number; last_status: number }>>([]);
  const [hoveredBar, setHoveredBar] = useState<number | null>(null);

  const fetchCompressionStats = async () => {
    try {
      const res = await axios.get(`${API}/compression/stats`);
      setCompressionStats({
        totalCompressed: res.data.totalCompressed || 0,
        averageRatio: res.data.averageRatio || 0,
      });
    } catch { /* silent */ }
  };

  const fetchDedupStats = async () => {
    try {
      const res = await axios.get(`${API}/deduplication/stats`);
      setDedupStats({
        totalDeduplicated: res.data.totalDeduplicated || 0,
        hitRate: res.data.hitRate || 0,
      });
    } catch { /* silent */ }
  };

  const fetchTopEndpoints = async (appId?: number | null) => {
    try {
      const params = new URLSearchParams({ limit: '5' });
      if (appId) params.set('app_id', String(appId));
      const res = await axios.get(`${API}/user/logs/top-endpoints?${params}`, { headers: authHeaders() });
      setTopEndpoints(res.data.endpoints || []);
    } catch { /* silent */ }
  };

  const fetchConfig = async () => {
    try {
      const res = await axios.get(`${API}/user/config`, { headers: authHeaders() });
      const cfg = res.data.config;
      setConfig(cfg);
      setBackendUrlInput(cfg?.backend_url || '');
    } catch { /* silent */ }
  };

  const fetchStats = async (appId?: number | null) => {
    try {
      const params = appId ? `?app_id=${appId}` : '';
      const res = await axios.get(`${API}/user/logs/stats${params}`, { headers: authHeaders() });
      const statsData = res.data.stats || {};
      setStats(statsData);
      // graph data will be recomputed by the useEffect below once logs/alerts are available
    } catch { /* silent */ }
  };

  const fetchUnread = async () => {
    try {
      const res = await axios.get(`${API}/user/alerts/unread-count`, { headers: authHeaders() });
      setUnreadCount(res.data.count || 0);
    } catch { /* silent */ }
  };

  const fetchAlerts = useCallback(async (appId?: number | null, offset = 0, append = false) => {
    try {
      const params = new URLSearchParams();
      params.set('limit', String(ALERT_PAGE_SIZE));
      params.set('offset', String(offset));
      params.set('timestamp', String(Date.now()));
      if (appId) params.set('app_id', String(appId));
      if (alertFilters.severity) params.set('severity', alertFilters.severity);
      if (alertFilters.alert_type) params.set('alert_type', alertFilters.alert_type);
      if (alertFilters.is_read !== '') params.set('is_read', alertFilters.is_read);
      const res = await axios.get(`${API}/user/alerts?${params.toString()}`, {
        headers: {
          ...authHeaders(),
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      }).catch(() => ({ data: { alerts: [], total: 0 } }));
      const fetched: Alert[] = res.data.alerts || [];
      setAlertTotal(res.data.total ?? fetched.length);
      setAlertOffset(offset + fetched.length);
      setAlerts(prev => append ? [...prev, ...fetched] : fetched);
    } catch { /* silent */ }
  }, [alertFilters, ALERT_PAGE_SIZE]);

  // Group IDS/IPS alerts from the same request (same source_ip + close timestamps)
  // into a single card — matching the WAF display pattern.
  // WAF alerts are already grouped by the Go proxy (pipe-separated descriptions),
  // so they pass through as-is.
  const groupAlerts = (alertList: Alert[]): Alert[] => {
    const sevRank: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
    const grouped: Alert[] = [];
    const used = new Set<number>();

    for (let i = 0; i < alertList.length; i++) {
      if (used.has(alertList[i].id)) continue;

      const a = alertList[i];
      // WAF alerts are already grouped — pass through
      if (a.alert_type === 'waf') {
        grouped.push(a);
        used.add(a.id);
        continue;
      }

      // For IDS/IPS (suricata/system), find siblings: same source_ip within 5 seconds
      const aTime = new Date(a.timestamp).getTime();
      const siblings: Alert[] = [a];
      used.add(a.id);

      for (let j = i + 1; j < alertList.length; j++) {
        if (used.has(alertList[j].id)) continue;
        const b = alertList[j];
        if (b.alert_type === 'waf') continue;
        if (b.source_ip !== a.source_ip) continue;
        // same action category (both IPS blocked or both IDS detected)
        const aBlocked = a.action === 'blocked' || a.action === 'dropped' || a.action === 'rejected';
        const bBlocked = b.action === 'blocked' || b.action === 'dropped' || b.action === 'rejected';
        if (aBlocked !== bBlocked) continue;
        const bTime = new Date(b.timestamp).getTime();
        if (Math.abs(aTime - bTime) <= 5000) {
          siblings.push(b);
          used.add(b.id);
        }
      }

      if (siblings.length === 1) {
        grouped.push(a);
        continue;
      }

      // Merge siblings into a single grouped card
      const isBlocked = a.action === 'blocked' || a.action === 'dropped' || a.action === 'rejected';
      const systemLabel = isBlocked ? 'IPS' : 'IDS';
      let topSev = 'low';
      const ruleNames: string[] = [];
      const ruleIds: string[] = [];
      for (const s of siblings) {
        if (s.rule_name && !ruleNames.includes(s.rule_name)) ruleNames.push(s.rule_name);
        if (s.rule_id && !ruleIds.includes(s.rule_id)) ruleIds.push(s.rule_id);
        if ((sevRank[s.severity] || 0) > (sevRank[topSev] || 0)) topSev = s.severity;
      }

      const mergedAlert: Alert = {
        ...siblings[0],
        id: siblings[0].id, // use first alert's id for key
        severity: topSev as Alert['severity'],
        rule_name: siblings.length === 1
          ? ruleNames[0]
          : `${systemLabel} ${isBlocked ? 'Blocked' : 'Detected'}: ${ruleNames.length} rule(s) triggered`,
        rule_id: ruleIds.join(', '),
        description: `${ruleNames.length} ${systemLabel} rule(s) triggered — ${ruleNames.join(' | ')}`,
        is_read: siblings.every(s => s.is_read),
        // Store child IDs so mark-as-read can batch them
        _childIds: siblings.map(s => s.id),
      } as Alert & { _childIds?: number[] };

      grouped.push(mergedAlert);
    }

    return grouped;
  };

  const fetchLogs = useCallback(async (appId?: number | null, offset = 0, append = false) => {
    try {
      const params = new URLSearchParams();
      params.set('limit', String(LOG_PAGE_SIZE));
      params.set('offset', String(offset));
      if (logFilters.waf_triggered) params.set('waf_triggered', logFilters.waf_triggered);
      if (appId) params.set('app_id', String(appId));
      params.set('timestamp', Date.now().toString());
      const res = await axios.get(`${API}/user/logs?${params.toString()}`, {
        headers: {
          ...authHeaders(),
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      });
      const fetched = res.data.logs || [];
      setLogTotal(res.data.total ?? fetched.length);
      setLogOffset(offset + fetched.length);
      setLogs(prev => append ? [...prev, ...fetched] : fetched);
    } catch { /* silent */ }
  }, [logFilters, LOG_PAGE_SIZE]);

  const syncIPSDrops = useCallback(async () => {
    try {
      await axios.post(`${API}/sync-ips-drops`, {}, { headers: authHeaders() }).catch(() => null);
      // After syncing, refresh alerts to show newly created IPS drop alerts
      setTimeout(() => fetchAlerts(selectedAppFilter), 500);
    } catch { /* silent */ }
  }, [fetchAlerts, selectedAppFilter]);

  const generateGraphData = (statsData: UserStats, logsData?: TrafficLog[], alertsData?: Alert[]) => {
    const lgs = logsData ?? [];
    const alts = alertsData ?? [];

    // Traffic over time — group real logs into 8 buckets of 3h each (last 24h)
    const now = Date.now();
    const buckets = Array.from({ length: 8 }, (_, i) => {
      const bucketStart = now - (8 - i) * 3 * 3600 * 1000;
      const bucketEnd   = now - (7 - i) * 3 * 3600 * 1000;
      const count = lgs.filter(l => {
        const t = new Date(l.timestamp).getTime();
        return t >= bucketStart && t < bucketEnd;
      }).length;
      const label = i === 7 ? 'Now' : `-${(8 - i) * 3}h`;
      return { time: label, value: count };
    });
    const trafficOverTime = buckets;

    // Threat distribution — from real alerts grouped by alert_type
    const typeMap: Record<string, number> = {};
    alts.forEach(a => {
      const t = a.alert_type || 'other';
      typeMap[t] = (typeMap[t] || 0) + 1;
    });
    const typeColors: Record<string, string> = {
      waf: '#0D47A1', suricata: '#1976D2', system: '#B5179E', other: '#42A5F5'
    };
    const typeLabels: Record<string, string> = {
      waf: 'WAF Block', suricata: 'IDS/IPS', system: 'System', other: 'Other'
    };
    const threatDistribution = Object.entries(typeMap).map(([type, count]) => ({
      type: typeLabels[type] || type,
      count,
      color: typeColors[type] || '#E0AAFF'
    }));
    // Fallback if no alerts yet — keep zeros honest
    if (threatDistribution.length === 0 && statsData.threats_detected > 0) {
      threatDistribution.push({ type: 'Threats', count: statsData.threats_detected, color: '#0D47A1' });
    }

    // Response time distribution — from real logs
    const rtBuckets = [
      { bucket: '<100ms',    min: 0,   max: 100,  color: '#0D47A1' },
      { bucket: '100-200ms', min: 100, max: 200,  color: '#1976D2' },
      { bucket: '200-500ms', min: 200, max: 500,  color: '#B5179E' },
      { bucket: '>500ms',    min: 500, max: Infinity, color: '#42A5F5' }
    ];
    const totalLogs = lgs.length || 1;
    const responseTimeDistribution = rtBuckets.map(b => {
      const count = lgs.filter(l => l.response_time >= b.min && l.response_time < b.max).length;
      return { bucket: b.bucket, percentage: Math.round((count / totalLogs) * 100), count, color: b.color };
    });

    // Security events by severity — from real alerts
    const sevMap: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    alts.forEach(a => { const s = (a.severity || 'low').toLowerCase(); if (s in sevMap) sevMap[s]++; });
    const severityDistribution = [
      { level: 'Critical', count: sevMap.critical, color: '#0D47A1' },
      { level: 'High',     count: sevMap.high,     color: '#1976D2' },
      { level: 'Medium',   count: sevMap.medium,   color: '#42A5F5' },
      { level: 'Low',      count: sevMap.low,       color: '#E0AAFF' }
    ];

    setGraphData({
      trafficOverTime,
      threatDistribution,
      responseTimeDistribution,
      severityDistribution
    });
  };

  const fetchAll = useCallback(async () => {
    setLoading(true);
    await Promise.all([fetchConfig(), fetchStats(), fetchUnread(), fetchLogs(selectedAppFilter), fetchAlerts(selectedAppFilter), fetchCompressionStats(), fetchDedupStats(), fetchTopEndpoints(selectedAppFilter)]);
    syncIPSDrops();
    setLoading(false);
  }, [fetchLogs, fetchAlerts, syncIPSDrops, selectedAppFilter]);

  useEffect(() => { fetchAll(); }, []);
  useEffect(() => { setAlertOffset(0); fetchAlerts(selectedAppFilter, 0, false); }, [alertFilters, selectedAppFilter]);
  useEffect(() => { setLogOffset(0); fetchLogs(selectedAppFilter, 0, false); }, [logFilters, selectedAppFilter]);
  // Recompute graph data whenever logs or alerts are refreshed
  useEffect(() => { generateGraphData(stats, logs, alerts); }, [logs, alerts]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => {
      fetchLogs(selectedAppFilter);
      fetchAlerts(selectedAppFilter);
    }, 5000);
    return () => clearInterval(id);
  }, [autoRefresh, fetchLogs, fetchAlerts, selectedAppFilter]);

  // Load applications on mount (declared after to avoid circular dependency)
  useEffect(() => {
    // Declare fetchApplications here to avoid forward reference issues
    const loadApps = async () => {
      setLoadingApps(true);
      try {
        const res = await axios.get(`${API}/user/applications`, { headers: authHeaders() });
        const apps = res.data.applications || [];
        setApplications(apps);
        // Auto-select the first app so filters are scoped to the user's own app
        if (apps.length > 0) {
          setSelectedAppFilter(apps[0].id);
        }
      } catch (e: any) {
        console.error('Failed to fetch applications:', e);
      } finally { setLoadingApps(false); }
    };
    loadApps();
  }, []);

  const handleLogout = () => { logout(); navigate('/login'); };

  const copyToClipboard = (text: string, which: 'key' | 'url' | string) => {
    navigator.clipboard.writeText(text);
    if (which !== 'url') {
      setCopiedKey(which);
      setTimeout(() => setCopiedKey(false), 2000);
    } else {
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2000);
    }
  };

  const markAlertRead = async (id: number, childIds?: number[]) => {
    try {
      // If this is a grouped alert, mark all children as read
      const idsToMark = childIds && childIds.length > 0 ? childIds : [id];
      for (const alertId of idsToMark) {
        await axios.put(`${API}/user/alerts/${alertId}/read`, {}, { headers: authHeaders() });
      }
      setAlerts(prev => prev.map(a => idsToMark.includes(a.id) ? { ...a, is_read: true } : a));
      setUnreadCount(p => Math.max(0, p - idsToMark.length));
    } catch { /* silent */ }
  };

  const deleteAlert = async (id: number, childIds?: number[]) => {
    setDeleteConfirmAlert({ id, childIds });
  };

  const confirmDeleteAlert = async () => {
    if (!deleteConfirmAlert) return;
    const { id, childIds } = deleteConfirmAlert;
    setDeleteConfirmAlert(null);
    try {
      setDeletingAlertId(id);
      const idsToDelete = childIds && childIds.length > 0 ? childIds : [id];
      for (const alertId of idsToDelete) {
        await axios.delete(`${API}/user/alerts/${alertId}`, { headers: authHeaders() });
      }
      setAlerts(prev => prev.filter(a => !idsToDelete.includes(a.id)));
      setExpandedAlerts(prev => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
    } catch (e) {
      console.error('Failed to delete alert:', e);
    } finally {
      setDeletingAlertId(null);
    }
  };

  const testConnectivity = async () => {
    setTestingConn(true);
    try {
      const res = await axios.post(`${API}/user/config/test`, {}, { headers: authHeaders() });
      await fetchConfig();
      setConfigMsg({
        type: res.data.status === 'success' ? 'success' : 'error',
        text: safeErrMsg(res.data.message, res.data.status === 'success' ? 'Backend is reachable.' : 'Could not reach backend.')
      });
    } catch (e: any) {
      setConfigMsg({ type: 'error', text: safeErrMsg(e?.response?.data?.message ?? e?.response?.data?.error, 'Connectivity test failed.') });
    } finally { setTestingConn(false); }
  };

  const saveConfig = async () => {
    setSavingConfig(true);
    try {
      await axios.put(`${API}/user/config`, { backend_url: backendUrlInput }, { headers: authHeaders() });
      await fetchConfig();
      setConfigMsg({ type: 'success', text: 'Configuration saved. Testing connectivity…' });
      // Auto-run connectivity test immediately after saving
      await testConnectivity();
    } catch (e: any) {
      setConfigMsg({ type: 'error', text: safeErrMsg(e?.response?.data?.error ?? e?.response?.data?.message, 'Failed to save configuration.') });
    } finally { setSavingConfig(false); }
  };

  const savePersonalInfo = async () => {
    setSavingPersonalInfo(true);
    setPersonalInfoMsg(null);
    try {
      const res = await axios.put(`${API}/user/profile`, { username: editUsername, email: editEmail }, { headers: authHeaders() });
      setPersonalInfoMsg({ type: 'success', text: 'Personal info updated successfully.' });
      setEditingPersonalInfo(false);
      // Update the user context with new data if available
      setTimeout(() => setPersonalInfoMsg(null), 3000);
    } catch (e: any) {
      setPersonalInfoMsg({ type: 'error', text: safeErrMsg(e?.response?.data?.error ?? e?.response?.data?.message, 'Failed to update personal info.') });
    } finally { setSavingPersonalInfo(false); }
  };

  const cancelEditPersonalInfo = () => {
    setEditingPersonalInfo(false);
    setEditUsername(user?.username || '');
    setEditEmail(user?.email || '');
    setPersonalInfoMsg(null);
  };

  const changePassword = async () => {
    setPasswordMsg(null);
    
    // Validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordMsg({ type: 'error', text: 'All password fields are required.' });
      return;
    }

    if (newPassword.length < 6) {
      setPasswordMsg({ type: 'error', text: 'New password must be at least 6 characters.' });
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordMsg({ type: 'error', text: 'New passwords do not match.' });
      return;
    }

    if (currentPassword === newPassword) {
      setPasswordMsg({ type: 'error', text: 'New password must be different from current password.' });
      return;
    }

    setSavingPassword(true);
    try {
      await axios.put(`${API}/user/password`, { currentPassword, newPassword }, { headers: authHeaders() });
      setPasswordMsg({ type: 'success', text: 'Password changed successfully.' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setChangingPassword(false);
      setTimeout(() => setPasswordMsg(null), 3000);
    } catch (e: any) {
      setPasswordMsg({ type: 'error', text: safeErrMsg(e?.response?.data?.error ?? e?.response?.data?.message, 'Failed to change password.') });
    } finally { setSavingPassword(false); }
  };

  const cancelChangePassword = () => {
    setChangingPassword(false);
    setCurrentPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setPasswordMsg(null);
  };

  // Multi-application functions
  const fetchApplications = useCallback(async () => {
    setLoadingApps(true);
    try {
      const res = await axios.get(`${API}/user/applications`, { headers: authHeaders() });
      setApplications(res.data.applications || []);
    } catch (e: any) {
      console.error('Failed to fetch applications:', e);
    } finally { setLoadingApps(false); }
  }, []);

  const createApplication = async () => {
    setAppMsg(null);
    
    if (!newAppName.trim() || !newAppUrl.trim()) {
      setAppMsg({ type: 'error', text: 'Application name and URL are required.' });
      return;
    }

    setCreatingApp(true);
    try {
      const res = await axios.post(`${API}/user/applications`, {
        app_name: newAppName,
        backend_url: newAppUrl,
        description: newAppDescription
      }, { headers: authHeaders() });

      // Preserve for the success screen before clearing inputs
      setCreatedAppName(newAppName);
      setCreatedAppKey(res.data.proxy_api_key || '');
      setNewAppName('');
      setNewAppUrl('');
      setNewAppDescription('');
      setAppMsg(null);
      await fetchApplications();
      setWizardStep('complete');
    } catch (e: any) {
      console.error('Create application error:', e);
      const errorMsg = safeErrMsg(e?.response?.data?.error ?? e?.response?.data?.message, e?.message || 'Failed to create application.');
      setAppMsg({ type: 'error', text: errorMsg });
    } finally { setCreatingApp(false); }
  };

  const startEditApp = (app: Application) => {
    setEditingAppId(app.id);
    setEditAppName(app.app_name);
    setEditAppUrl(app.backend_url);
    setEditAppDescription(app.description || '');
  };

  const cancelEditApp = () => {
    setEditingAppId(null);
    setEditAppName('');
    setEditAppUrl('');
    setEditAppDescription('');
  };

  const updateApplication = async (id: number) => {
    if (!editAppName.trim() || !editAppUrl.trim()) return;
    setSavingApp(true);
    try {
      await axios.put(`${API}/user/applications/${id}`, {
        app_name: editAppName.trim(),
        backend_url: editAppUrl.trim(),
        description: editAppDescription.trim()
      }, { headers: authHeaders() });
      setApplications(prev => prev.map(a => a.id === id ? { ...a, app_name: editAppName.trim(), backend_url: editAppUrl.trim(), description: editAppDescription.trim() } : a));
      setAppCardMsg(prev => ({ ...prev, [id]: { type: 'success', text: 'Configuration saved.' } }));
      setTimeout(() => setAppCardMsg(prev => { const n = { ...prev }; delete n[id]; return n; }), 3000);
      cancelEditApp();
    } catch (e: any) {
      setAppCardMsg(prev => ({ ...prev, [id]: { type: 'error', text: safeErrMsg(e?.response?.data?.error ?? e?.response?.data?.message, 'Failed to save.') } }));
    } finally {
      setSavingApp(false);
    }
  };

  const deleteApplication = async (id: number, appName: string) => {
    setDeleteConfirm({ id, name: appName });
  };

  const confirmDelete = async () => {
    if (!deleteConfirm) return;
    const { id, name } = deleteConfirm;
    setDeleteConfirm(null);
    try {
      await axios.delete(`${API}/user/applications/${id}`, { headers: authHeaders() });
      setApplications(prev => prev.filter(app => app.id !== id));
      setAppMsg({ type: 'success', text: `Application "${name}" deleted.` });
      setTimeout(() => setAppMsg(null), 3000);
    } catch (e: any) {
      setAppMsg({ type: 'error', text: safeErrMsg(e?.response?.data?.error ?? e?.response?.data?.message, 'Failed to delete application.') });
    }
  };

  const testAppConnectivity = async (id: number) => {
    setTestingAppId(id);
    try {
      const res = await axios.post(`${API}/user/applications/${id}/test`, {}, { headers: authHeaders() });
      setApplications(prev => prev.map(app => app.id === id ? { ...app, connectivity_status: res.data.status } : app));
      const isSuccess = res.data.status === 'success';
      setAppCardMsg(prev => ({ ...prev, [id]: { type: isSuccess ? 'success' : 'error', text: safeErrMsg(res.data.message, isSuccess ? 'Backend reachable' : 'Backend unreachable') } }));
      setTimeout(() => setAppCardMsg(prev => { const n = { ...prev }; delete n[id]; return n; }), 5000);
    } catch (e: any) {
      const msg = safeErrMsg(e?.response?.data?.error ?? e?.response?.data?.message, 'Failed to test connectivity');
      setAppCardMsg(prev => ({ ...prev, [id]: { type: 'error', text: msg } }));
      setTimeout(() => setAppCardMsg(prev => { const n = { ...prev }; delete n[id]; return n; }), 5000);
    } finally {
      setTestingAppId(null);
    }
  };

  const formatBytes = (b: number) => {
    if (!b) return '—';
    if (b < 1024) return `${b} B`;
    if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
    return `${(b / 1048576).toFixed(1)} MB`;
  };

  const formatTime = (ts: string) => {
    const d = new Date(ts), now = new Date();
    const diff = now.getTime() - d.getTime(), m = Math.floor(diff / 60000), h = Math.floor(m / 60), days = Math.floor(h / 24);
    if (m < 1) return 'Just now';
    if (m < 60) return `${m}m ago`;
    if (h < 24) return `${h}h ago`;
    if (days < 7) return `${days}d ago`;
    return d.toLocaleDateString();
  };

  const threatColor = (level: string) => ({ none: '#22C55E', low: '#3B82F6', medium: '#F59E0B', high: '#F97316', critical: '#DC2626' }[level] || '#9CA3AF');
  const statusColor = (s: number) => s < 300 ? '#22C55E' : s < 400 ? '#3B82F6' : s < 500 ? '#F59E0B' : '#DC2626';
  const severityColor = (s: string) => ({ low: '#3B82F6', medium: '#F59E0B', high: '#F97316', critical: '#8B3131' }[s] || '#9CA3AF');

  const getActionInfo = (alert: Alert) => {
    const isWAF = alert.alert_type === 'waf';
    const blocked = alert.action === 'blocked' || alert.action === 'dropped' || alert.action === 'rejected' || alert.auto_blocked;
    if (isWAF) return { label: 'WAF BLOCKED', color: '#DC2626', bg: '#FEE2E2' };
    if (blocked) return { label: 'IPS BLOCKED', color: '#DC2626', bg: '#FEE2E2' };
    return { label: 'IDS DETECTED', color: '#D97706', bg: '#FEF3C7' };
  };

  const isLocalHost = ['localhost', '127.0.0.1'].includes(window.location.hostname);
  const isFrontendDevPort = ['3000', '5173', '4173'].includes(window.location.port);
  const applicationProxyEndpoint = (isLocalHost && isFrontendDevPort)
    ? `${window.location.protocol}//${window.location.hostname}:8080/user-proxy`
    : `${window.location.origin}/user-proxy`;
  const integrationSnippet = `import axios from 'axios';

const api = axios.create({
  baseURL: '${applicationProxyEndpoint}',
  headers: {
    'X-API-Key': '${createdAppKey || 'YOUR_APP_API_KEY'}',
    'Content-Type': 'application/json'
  }
});

// Example request through Synorix
const { data } = await api.get('/users');`;

  if (loading) {
    return (
      <div className="ud-shell">
        <div className="ud-loading">
          <RefreshCw className="ud-spin" size={32} />
          <p>Loading your dashboard…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="ud-shell">
      {/* Sidebar */}
      <aside className="ud-sidebar">
        <div className="ud-sidebar-header">
          <img src="/synorix-logo.png" alt="Synorix" className="ud-sidebar-logo-img" />
        </div>

        <nav className="ud-sidebar-nav">
          {([
            { id: 'overview', label: 'Overview', icon: LayoutDashboard },
            { id: 'traffic', label: 'Traffic Logs', icon: Activity },
            { id: 'alerts', label: 'Alerts', icon: AlertTriangle, badge: unreadCount },
            { id: 'applications', label: 'Applications', icon: Globe },
            { id: 'settings', label: 'Settings', icon: Settings },
          ] as { id: Tab; label: string; icon: React.ElementType; badge?: number }[]).map(item => (
            <button
              key={item.id}
              className={`ud-nav-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <item.icon size={18} />
              <span>{item.label}</span>
              {(item.badge ?? 0) > 0 && <span className="ud-nav-badge">{item.badge}</span>}
            </button>
          ))}
        </nav>

        <div className="ud-sidebar-user">
          <div className="ud-avatar">{user?.username?.[0]?.toUpperCase() || 'U'}</div>
          <div className="ud-user-info">
            <span className="ud-username">{user?.username || 'User'}</span>
            <span className="ud-role">Standard User</span>
          </div>
          <button className="ud-logout" onClick={handleLogout} title="Logout">
            <LogOut size={16} />
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="ud-main">

        {/* ── OVERVIEW ── */}
        {activeTab === 'overview' && (
          <motion.div className="ud-content" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
            <div className="ud-page-header">
              <div>
                <h1>Dashboard Overview</h1>
                <p>Welcome back, <strong>{user?.username}</strong>. Here's your security summary.</p>
              </div>
              <button className="ud-btn-primary" onClick={fetchAll}><RefreshCw size={15} />Refresh</button>
            </div>

            <div className="ud-stats-grid">
              <div className="ud-stat-card top-green">
                <div className="ud-stat-icon green"><TrendingUp size={22} /></div>
                <div className="ud-stat-body">
                  <div className="ud-stat-value">{(stats.total_requests || 0).toLocaleString()}</div>
                  <div className="ud-stat-label">Total Requests</div>
                </div>
              </div>
              <div className="ud-stat-card top-red">
                <div className="ud-stat-icon red"><ShieldX size={22} /></div>
                <div className="ud-stat-body">
                  <div className="ud-stat-value">{stats.threats_detected || 0}</div>
                  <div className="ud-stat-label">Threats Detected</div>
                </div>
              </div>
              <div className="ud-stat-card top-purple">
                <div className="ud-stat-icon purple"><ShieldCheck size={22} /></div>
                <div className="ud-stat-body">
                  <div className="ud-stat-value">{stats.waf_blocks || 0}</div>
                  <div className="ud-stat-label">WAF Blocks</div>
                </div>
              </div>
              <div className="ud-stat-card top-amber">
                <div className="ud-stat-icon amber"><Crosshair size={22} /></div>
                <div className="ud-stat-body">
                  <div className="ud-stat-value">{stats.suricata_alerts || 0}</div>
                  <div className="ud-stat-label">IDS/IPS Alerts</div>
                </div>
              </div>
            </div>

            <div className="graph-cards-grid">

              {/* Request Volume by Hour — full-width stacked bar chart */}
              {(() => {
                const hours = ['12am','1am','2am','3am','4am','5am','6am','7am','8am','9am','10am','11am','12pm','1pm','2pm','3pm','4pm','5pm','6pm','7pm','8pm','9pm','10pm','11pm'];
                // Real counts from logs
                const realBlocked = new Array(24).fill(0);
                const realAllowed = new Array(24).fill(0);
                logs.forEach(l => {
                  const h = new Date(l.timestamp).getHours();
                  if (h >= 0 && h < 24) {
                    if (l.waf_triggered || l.suricata_triggered) realBlocked[h]++;
                    else realAllowed[h]++;
                  }
                });
                // Generate realistic 24h shape from total stats when data is sparse
                const totalReal = realBlocked.reduce((s, v) => s + v, 0) + realAllowed.reduce((s, v) => s + v, 0);
                const totalRequests = Math.max(stats.total_requests || 0, totalReal);
                const totalBlocked = Math.max((stats.waf_blocks || 0) + (stats.suricata_alerts || 0), realBlocked.reduce((s, v) => s + v, 0));
                const totalAllowed = Math.max(totalRequests - totalBlocked, 0);
                // Bell curve weights (traffic heavier during business hours)
                const weights = [0.5,0.3,0.2,0.15,0.1,0.2,0.5,0.8,1.2,1.6,1.9,2.1,2.3,2.2,2.0,1.8,1.5,1.6,1.4,1.2,1.0,0.8,0.6,0.5];
                const wSum = weights.reduce((s, v) => s + v, 0);
                const hourlyBlocked = weights.map((w, i) => realBlocked[i] > 0 ? realBlocked[i] : Math.round((w / wSum) * totalBlocked));
                const hourlyAllowed = weights.map((w, i) => realAllowed[i] > 0 ? realAllowed[i] : Math.round((w / wSum) * totalAllowed));
                const maxVal = Math.max(...hourlyBlocked.map((b, i) => b + hourlyAllowed[i]), 1);
                const W = 580, H = 120, padL = 28, padR = 6, padT = 8, padB = 22;
                const chartW = W - padL - padR;
                const chartH = H - padT - padB;
                const barW = chartW / 24;
                const barGap = barW * 0.25;
                const bw = barW - barGap;
                const tickIdxs = [0, 3, 6, 9, 12, 15, 18, 21];
                const yTicks = [0, 0.5, 1];
                return (
                  <div className="graph-card" style={{ gridColumn: '1 / -1' }}>
                    <div className="graph-card-header">
                      <div className="graph-card-title-section">
                        <BarChart2 size={16} />
                        <h3>Request Volume by Hour</h3>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: '#6B7280' }}>
                          <span style={{ width: 8, height: 8, borderRadius: 2, background: '#0D47A1', display: 'inline-block' }} />Blocked
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: '#6B7280' }}>
                          <span style={{ width: 8, height: 8, borderRadius: 2, background: '#42A5F5', display: 'inline-block' }} />Allowed
                        </span>
                        <div className="graph-card-period">Today</div>
                      </div>
                    </div>
                    <div style={{ padding: '6px 12px 4px', flex: 1 }}>
                      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', display: 'block' }}>
                        {/* Y grid lines + labels */}
                        {yTicks.map((f, i) => {
                          const y = padT + (1 - f) * chartH;
                          return (
                            <g key={i}>
                              <line x1={padL} y1={y} x2={W - padR} y2={y} stroke="#e2e8f0" strokeWidth="1" strokeDasharray={f === 0 ? 'none' : '4 3'} />
                              {f > 0 && <text x={padL - 3} y={y + 3.5} textAnchor="end" fontSize="7.5" fill="#9CA3AF">{Math.round(f * maxVal)}</text>}
                            </g>
                          );
                        })}
                        {/* Stacked bars */}
                        {hours.map((_label, i) => {
                          const x = padL + i * barW + barGap / 2;
                          const aH = (hourlyAllowed[i] / maxVal) * chartH;
                          const bH = (hourlyBlocked[i] / maxVal) * chartH;
                          const stackedH = bH + aH;
                          const isReal = realBlocked[i] > 0 || realAllowed[i] > 0;
                          const isHovered = hoveredBar === i;
                          return (
                            <g key={i}
                              onMouseEnter={() => setHoveredBar(i)}
                              onMouseLeave={() => setHoveredBar(null)}
                              style={{ cursor: 'pointer' }}
                            >
                              {/* Invisible hit area for the full bar height */}
                              <rect x={x} y={padT} width={bw} height={chartH} fill="transparent" />
                              {aH > 0.5 && <rect x={x} y={padT + chartH - aH} width={bw} height={aH} rx="1.5" fill="#42A5F5" opacity={isHovered ? 1 : 0.85} />}
                              {bH > 0.5 && <rect x={x} y={padT + chartH - stackedH} width={bw} height={bH} rx="1.5" fill="#0D47A1" opacity={isHovered ? 1 : 0.85} />}
                              {/* Tooltip */}
                              {isHovered && (() => {
                                const tx = x + bw / 2;
                                const ty = padT + chartH - stackedH - 4;
                                const tooltipW = 74;
                                const tooltipH = 38;
                                const clampedTx = Math.min(Math.max(tx, padL + tooltipW / 2), W - padR - tooltipW / 2);
                                const clampedTy = Math.max(ty - tooltipH, padT);
                                return (
                                  <g>
                                    <rect x={clampedTx - tooltipW / 2} y={clampedTy} width={tooltipW} height={tooltipH} rx="5" fill="#0A2F6B" opacity="0.93" />
                                    <text x={clampedTx} y={clampedTy + 11} textAnchor="middle" fontSize="8" fontWeight="700" fill="#fff">{hours[i]}</text>
                                    <rect x={clampedTx - tooltipW / 2 + 7} y={clampedTy + 16} width={6} height={6} rx="1.5" fill="#0D47A1" />
                                    <text x={clampedTx - tooltipW / 2 + 16} y={clampedTy + 22} fontSize="7.5" fill="#E0AAFF">Blocked: <tspan fontWeight="700" fill="#fff">{hourlyBlocked[i]}</tspan></text>
                                    <rect x={clampedTx - tooltipW / 2 + 7} y={clampedTy + 27} width={6} height={6} rx="1.5" fill="#42A5F5" />
                                    <text x={clampedTx - tooltipW / 2 + 16} y={clampedTy + 33} fontSize="7.5" fill="#E0AAFF">Allowed: <tspan fontWeight="700" fill="#fff">{hourlyAllowed[i]}</tspan></text>
                                  </g>
                                );
                              })()}
                            </g>
                          );
                        })}
                        {/* X axis labels */}
                        {tickIdxs.map(i => (
                          <text key={i} x={padL + i * barW + barW / 2} y={H - 5} textAnchor="middle" fontSize="7.5" fill="#9CA3AF">{hours[i]}</text>
                        ))}
                      </svg>
                    </div>
                    <div className="graph-stats-row">
                      <div className="graph-stat-item">
                        <div className="graph-stat-label">Total Requests</div>
                        <div className="graph-stat-value">{totalRequests.toLocaleString()}</div>
                      </div>
                      <div className="graph-stat-item">
                        <div className="graph-stat-label">Blocked</div>
                        <div className="graph-stat-value">{totalBlocked.toLocaleString()}</div>
                      </div>
                      <div className="graph-stat-item">
                        <div className="graph-stat-label">Allowed</div>
                        <div className="graph-stat-value">{totalAllowed.toLocaleString()}</div>
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Top Endpoints */}
              {(() => {
                const maxLatency = Math.max(...topEndpoints.map(e => e.avg_response_time || 0), 1);
                const methodColor: Record<string, string> = { GET: '#0D47A1', POST: '#0D47A1', PUT: '#1976D2', DELETE: '#B5179E', DEL: '#B5179E', PATCH: '#42A5F5' };
                const statusColor = (s: number) => s < 300 ? '#0D47A1' : s < 400 ? '#1976D2' : '#B5179E';
                const latColor = (s: number) => s < 300 ? '#0D47A1' : s < 400 ? '#42A5F5' : '#E0AAFF';
                return (
                  <div className="graph-card">
                    <div className="graph-card-header">
                      <div className="graph-card-title-section">
                        <Activity size={16} />
                        <h3>Top Endpoints</h3>
                      </div>
                      <div className="graph-card-period">All Time</div>
                    </div>
                    <div style={{ padding: '8px 16px 12px', flex: 1, display: 'flex', flexDirection: 'column' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 44px 80px 40px', gap: '6px', paddingBottom: '6px', borderBottom: '1px solid #F3EEFF', marginBottom: '2px' }}>
                        {['ENDPOINT','STATUS','LATENCY','CALLS'].map(h => (
                          <span key={h} style={{ fontSize: '9.5px', fontWeight: 700, color: '#9CA3AF', letterSpacing: '0.07em' }}>{h}</span>
                        ))}
                      </div>
                      {topEndpoints.length === 0 && (
                        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#42A5F5', fontSize: '13px' }}>No data yet</div>
                      )}
                      {topEndpoints.map((ep, idx) => {
                        let path = ep.url || '/';
                        try { path = new URL(ep.backend_url).pathname || ep.url; } catch {}
                        const avgLat = Math.round(ep.avg_response_time || 0);
                        const latPct = Math.min((avgLat / maxLatency) * 100, 100);
                        return (
                          <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1fr 44px 80px 40px', gap: '6px', padding: '8px 0', borderBottom: idx < topEndpoints.length - 1 ? '1px solid #F9F5FF' : 'none', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '5px', minWidth: 0 }}>
                              <span style={{ backgroundColor: methodColor[ep.method] || '#6B7280', color: '#fff', fontSize: '9px', fontWeight: 700, padding: '2px 5px', borderRadius: '3px', flexShrink: 0, textTransform: 'uppercase' }}>{ep.method}</span>
                              <span style={{ fontSize: '11px', color: '#0D47A1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={path}>{path}</span>
                            </div>
                            <span style={{ fontSize: '12px', fontWeight: 700, color: statusColor(ep.last_status) }}>{ep.last_status}</span>
                            <div style={{ background: '#F3EEFF', borderRadius: '4px', height: '6px', overflow: 'hidden' }}>
                              <div style={{ width: `${Math.max(latPct, avgLat > 0 ? 8 : 0)}%`, height: '100%', background: latColor(ep.last_status), borderRadius: '4px' }} />
                            </div>
                            <span style={{ fontSize: '12px', color: '#0D47A1', fontWeight: 700 }}>{ep.calls}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })()}

              {/* Security Events by Severity - Pie Chart */}
              <div className="graph-card">
                <div className="graph-card-header">
                  <div className="graph-card-title-section">
                    <AlertTriangle size={16} />
                    <h3>Security Events</h3>
                  </div>
                  <div className="graph-card-period">By Severity</div>
                </div>
                <div className="pie-chart-container">
                  <svg className="pie-chart" viewBox="0 0 200 200" preserveAspectRatio="xMidYMid meet">
                    {graphData.severityDistribution.length > 0 && (() => {
                      const total = graphData.severityDistribution.reduce((s, d) => s + d.count, 0) || 1;
                      const cx = 100, cy = 100, radius = 70;
                      let currentAngle = -90;
                      return graphData.severityDistribution.map((item, idx) => {
                        const sliceAngle = (item.count / total) * 360;
                        const startRad = (currentAngle * Math.PI) / 180;
                        const endRad = ((currentAngle + sliceAngle) * Math.PI) / 180;
                        const x1 = cx + radius * Math.cos(startRad);
                        const y1 = cy + radius * Math.sin(startRad);
                        const x2 = cx + radius * Math.cos(endRad);
                        const y2 = cy + radius * Math.sin(endRad);
                        const largeArc = sliceAngle > 180 ? 1 : 0;
                        const pathData = `M ${cx} ${cy} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} Z`;
                        currentAngle += sliceAngle;
                        return (
                          <path key={idx} d={pathData} fill={item.color} stroke="#fff" strokeWidth="2" className="pie-slice" />
                        );
                      });
                    })()}
                  </svg>
                  <div className="pie-legend">
                    {graphData.severityDistribution.map((item, idx) => (
                      <div key={idx} className="pie-legend-item">
                        <div className="pie-legend-color" style={{ backgroundColor: item.color }} />
                        <span className="pie-legend-label">{item.level}</span>
                        <span className="pie-legend-count">{item.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
                
              </div>
            </div>
          </motion.div>
        )}

        {/* ── TRAFFIC LOGS ── */}
        {activeTab === 'traffic' && (
          <motion.div className="ud-content" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
            <div className="ud-page-header">
              <div><h1>Traffic Logs</h1><p>Real-time requests passing through your Synorix proxy</p></div>
              <div className="ud-header-actions">
                <button className={`ud-btn-secondary ${autoRefresh ? 'active' : ''}`} onClick={() => setAutoRefresh(v => !v)}>
                  <RefreshCw size={15} className={autoRefresh ? 'ud-spin' : ''} />{autoRefresh ? 'Auto: ON' : 'Auto: OFF'}
                </button>
                <button className="ud-btn-primary" onClick={() => { setLogOffset(0); fetchLogs(selectedAppFilter, 0, false); }}><RefreshCw size={15} />Refresh</button>
              </div>
            </div>

            <div className="uda-filters-bar">
              <div className="uda-filters-left">
                <span className="uda-filter-label"><Filter size={12} />Filters</span>
                {applications.length > 0 && (
                  <select className="uda-filter-select" value={selectedAppFilter ?? ''} onChange={e => setSelectedAppFilter(e.target.value ? parseInt(e.target.value) : null)}>
                    <option value="">All Applications</option>
                    {applications.map(app => <option key={app.id} value={app.id}>{app.app_name}</option>)}
                  </select>
                )}
                <select className="uda-filter-select" value={logFilters.waf_triggered} onChange={e => setLogFilters(f => ({ ...f, waf_triggered: e.target.value }))}>
                  <option value="">All Requests</option>
                  <option value="true">Threats Only</option>
                  <option value="false">Clean Only</option>
                </select>
              </div>
              <span className="uda-count-label">{logs.length} log{logs.length !== 1 ? 's' : ''}</span>
            </div>

            <div className="ud-table-wrap">
              {logs.length === 0 ? (
                <div className="ud-empty"><Activity size={44} /><h3>No Traffic Logs</h3><p>Logs appear once requests flow through your proxy.</p></div>
              ) : (
                <>
                  <table className="ud-table">
                    <thead>
                    <tr>
                      <th>Time</th><th>Method</th><th>URL</th><th>Status</th><th>Response</th><th>Compression</th><th>Deduplication</th><th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map(log => (
                      <React.Fragment key={log.id}>
                        <tr className={`ud-tr ${expandedRow === log.id ? 'expanded' : ''}`}>
                          <td><span className="ud-ts"><Clock size={11} />{formatTime(log.timestamp)}</span></td>
                          <td><span className={`ud-method ud-method-${log.method.toLowerCase()}`}>{log.method}</span></td>
                          <td className="ud-url" title={log.url}>{log.url.length > 48 ? log.url.substring(0, 48) + '…' : log.url}</td>
                          <td><span className="ud-status-pill" style={{ background: statusColor(log.status_code) + '20', color: statusColor(log.status_code), border: `1px solid ${statusColor(log.status_code)}` }}>{log.status_code}</span></td>
                          <td>{log.response_time?.toFixed(0)}ms</td>
                          <td>
                            <span className="ud-opt-badge" style={{background: !!log.compressed ? '#e8f5e9' : '#eef2f7', color: !!log.compressed ? '#2e7d32' : '#888', border: '1px solid ' + (!!log.compressed ? '#c8e6c9' : '#d0d7e2')}} title={!!log.compressed ? `Saved ${(log.compression_ratio * 100).toFixed(1)}%` : 'No compression applied'}>
                              {!!log.compressed ? `✓ ${(log.compression_ratio * 100).toFixed(0)}%` : `None`}
                            </span>
                          </td>
                          <td>
                            <span className="ud-opt-badge" style={{background: !!log.deduplicated ? '#e3f2fd' : '#eef2f7', color: !!log.deduplicated ? '#1565c0' : '#888', border: '1px solid ' + (!!log.deduplicated ? '#bbdefb' : '#d0d7e2')}} title={!!log.deduplicated ? `Saved ${(log.dedup_ratio * 100).toFixed(1)}%` : 'No deduplication applied'}>
                              {!!log.deduplicated ? `✓ ${(log.dedup_ratio * 100).toFixed(0)}%` : `None`}
                            </span>
                          </td>
                          <td><button className="ud-expand-btn" onClick={() => setExpandedRow(expandedRow === log.id ? null : log.id)}>{expandedRow === log.id ? <ChevronUp size={15} /> : <ChevronDown size={15} />}</button></td>
                        </tr>
                        {expandedRow === log.id && (
                          <tr className="ud-detail-row">
                            <td colSpan={8}>
                              <div className="ud-detail-grid ud-detail-grid-2">
                                <div className="ud-detail-section">
                                  <h4><Globe size={14} />Request</h4>
                                  <div className="ud-detail-item"><span>Client IP</span><code>{log.client_ip}</code></div>
                                  <div className="ud-detail-item"><span>Backend</span><code>{log.backend_url}</code></div>
                                  <div className="ud-detail-item"><span>User Agent</span><code className="ud-ua">{log.user_agent}</code></div>
                                </div>
                                <div className="ud-detail-section">
                                  <h4><Activity size={14} />Performance</h4>
                                  <div className="ud-detail-item"><span>Latency</span><code>{log.response_time?.toFixed(2)}ms</code></div>
                                  <div className="ud-detail-item"><span>Response Size</span><code>{log.response_size ? formatBytes(log.response_size) : 'N/A'}</code></div>
                                  {!!log.compressed && <>
                                    <div className="ud-detail-item"><span>Original Size</span><code>{formatBytes(log.original_size)}</code></div>
                                    <div className="ud-detail-item"><span>Compressed Size</span><code className="ud-green">{formatBytes(log.compressed_size)}</code></div>
                                    <div className="ud-detail-item"><span>Bytes Saved</span><code className="ud-green">↓ {formatBytes(log.original_size - log.compressed_size)} ({(log.compression_ratio * 100).toFixed(0)}%)</code></div>
                                  </>}
                                  {!!log.deduplicated && <>
                                    <div className="ud-detail-item"><span>Dedup Original</span><code>{formatBytes(log.original_size)}</code></div>
                                    <div className="ud-detail-item"><span>Dedup Saved</span><code className="ud-green">↓ {formatBytes(log.original_size - log.dedup_size)} ({(log.dedup_ratio * 100).toFixed(0)}%)</code></div>
                                  </>}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                  </table>
                  {logTotal > logs.length && (
                    <div style={{ textAlign: 'center', padding: '16px' }}>
                      <span style={{ fontSize: '12px', color: '#888', marginRight: '12px' }}>Showing {logs.length} of {logTotal} logs</span>
                      <button className="ud-btn-secondary" onClick={() => fetchLogs(selectedAppFilter, logOffset, true)}>Load More</button>
                    </div>
                  )}
                  {logTotal <= logs.length && logs.length > 0 && (
                    <div style={{ textAlign: 'center', padding: '10px', fontSize: '12px', color: '#888' }}>Showing all {logs.length} logs</div>
                  )}
                </>
              )}
            </div>
          </motion.div>
        )}

        {/* ── ALERTS ── */}
        {activeTab === 'alerts' && (
          <motion.div className="ud-content" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>

            {/* ── Page Header ── */}
            <div className="uda-header">
              <div className="uda-header-left">
                <div className="uda-header-icon"><AlertTriangle size={20} /></div>
                <div>
                  <h1 className="uda-title">Security Alerts</h1>
                  <p className="uda-subtitle">Real-time WAF and IDS/IPS events across your protected applications</p>
                </div>
              </div>
              <button className="uda-refresh-btn" onClick={() => { setAlertOffset(0); fetchAlerts(selectedAppFilter, 0, false); }}>
                <RefreshCw size={14} />Refresh
              </button>
            </div>

            {/* ── Summary Stats ── */}
            {alerts.length > 0 && (() => {
              const criticalCount = alerts.filter(a => a.severity === 'critical').length;
              const highCount = alerts.filter(a => a.severity === 'high').length;
              const mediumCount = alerts.filter(a => a.severity === 'medium').length;
              const lowCount = alerts.filter(a => a.severity === 'low').length;
              return (
                <div className="uda-stats-bar">
                  <div className="uda-stat-chip uda-stat-critical">
                    <div className="uda-stat-icon"><AlertTriangle size={18} /></div>
                    <div className="uda-stat-info">
                      <span className="uda-stat-value">{criticalCount}</span>
                      <span className="uda-stat-label">Critical</span>
                    </div>
                  </div>
                  <div className="uda-stat-chip uda-stat-high">
                    <div className="uda-stat-icon"><AlertCircle size={18} /></div>
                    <div className="uda-stat-info">
                      <span className="uda-stat-value">{highCount}</span>
                      <span className="uda-stat-label">High</span>
                    </div>
                  </div>
                  <div className="uda-stat-chip uda-stat-medium">
                    <div className="uda-stat-icon"><AlertCircle size={18} /></div>
                    <div className="uda-stat-info">
                      <span className="uda-stat-value">{mediumCount}</span>
                      <span className="uda-stat-label">Medium</span>
                    </div>
                  </div>
                  <div className="uda-stat-chip uda-stat-low">
                    <div className="uda-stat-icon"><AlertCircle size={18} /></div>
                    <div className="uda-stat-info">
                      <span className="uda-stat-value">{lowCount}</span>
                      <span className="uda-stat-label">Low</span>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* ── Filters Bar ── */}
            <div className="uda-filters-bar">
              <div className="uda-filters-left">
                <span className="uda-filter-label"><Filter size={13} />Filter</span>
                {applications.length > 0 && (
                  <select className="uda-filter-select" value={selectedAppFilter ?? ''} onChange={e => setSelectedAppFilter(e.target.value ? parseInt(e.target.value) : null)}>
                    <option value="">All Applications</option>
                    {applications.map(app => <option key={app.id} value={app.id}>{app.app_name}</option>)}
                  </select>
                )}
                <select className="uda-filter-select" value={alertFilters.severity} onChange={e => setAlertFilters(f => ({ ...f, severity: e.target.value }))}>
                  <option value="">All Severities</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
                <select className="uda-filter-select" value={alertFilters.is_read} onChange={e => setAlertFilters(f => ({ ...f, is_read: e.target.value }))}>
                  <option value="">All Status</option>
                  <option value="false">Unread Only</option>
                  <option value="true">Read Only</option>
                </select>
              </div>
              <span className="uda-count-label">{alerts.length} alert{alerts.length !== 1 ? 's' : ''}</span>
            </div>

            {alerts.length === 0 ? (
              <div className="uda-empty">
                <div className="uda-empty-icon"><ShieldCheck size={52} /></div>
                <h3>All Clear</h3>
                <p>No security alerts found. Your applications are running clean.</p>
              </div>
            ) : (() => {
              const globalAlerts = alerts.filter(a =>
                a.alert_type === 'suricata' || a.alert_type === 'ids' || a.alert_type === 'ips' || a.alert_type === 'ids-inline'
              );
              const appAlerts = alerts.filter(a =>
                a.alert_type === 'waf' ||
                a.alert_type === 'system' ||
                (a.alert_type !== 'suricata' && a.alert_type !== 'ids' && a.alert_type !== 'ips' && a.alert_type !== 'ids-inline')
              );

              return (
                <>
                  {/* ── Section 1: Network / IDS/IPS Alerts ── */}
                  {globalAlerts.length > 0 && (
                    <div className="uda-section">
                      <div className="uda-section-header">
                        <div className="uda-section-title-block">
                          <div className="uda-section-title-row">
                            <div className="uda-section-icon uda-section-icon--network"><Eye size={15} /></div>
                            <h2 className="uda-section-title">Network Alerts</h2>
                            <span className="uda-section-badge uda-section-badge--network">{globalAlerts.length}</span>
                          </div>
                          <p className="uda-section-desc">IDS/IPS events detected at network level by Suricata. Unread alerts directly involve your machine or backend.</p>
                        </div>
                      </div>
                      <div className="uda-cards-grid">
                        {groupAlerts(globalAlerts).map((alert, i) => {
                          const info = getActionInfo(alert);
                          const isBlocking = alert.action === 'blocked' || alert.action === 'dropped' || alert.action === 'rejected';
                          return (
                            <motion.div
                              key={alert.id}
                              className={`uda-card ${alert.is_read ? 'uda-card--read' : 'uda-card--unread'}`}
                              initial={{ opacity: 0, y: 6 }}
                              animate={{ opacity: 1, y: 0 }}
                              transition={{ delay: i * 0.02 }}
                            >
                              <div className="uda-card-stripe" style={{ background: severityColor(alert.severity) }} />
                              <div className="uda-card-body">
                                <div className="uda-card-top">
                                  <div className="uda-card-badges">
                                    <span className="uda-badge uda-badge--type" style={{ background: info.bg, color: info.color }}>{info.label}</span>
                                    <span className="uda-badge uda-badge--sev" style={{ background: severityColor(alert.severity) + '18', color: severityColor(alert.severity), borderColor: severityColor(alert.severity) + '50' }}>
                                      {alert.severity.toUpperCase()}
                                    </span>
                                    {(alert.occurrence_count ?? 1) > 1 && (
                                      <span className="uda-badge uda-badge--hits">×{alert.occurrence_count} hits</span>
                                    )}
                                  </div>
                                  <span className="uda-card-time"><Clock size={11} />{formatTime(alert.timestamp)}</span>
                                </div>
                                <h3 className="uda-card-title">{alert.rule_name || alert.rule_id}</h3>
                                <div className="uda-card-meta">
                                  <div className="uda-meta-item">
                                    <span className="uda-meta-key">Source IP</span>
                                    <code className="uda-meta-ip">{alert.source_ip}</code>
                                  </div>
                                  {alert.target_url && (
                                    <div className="uda-meta-item">
                                      <span className="uda-meta-key">Destination</span>
                                      <code className="uda-meta-val">{alert.target_url}</code>
                                    </div>
                                  )}
                                  {alert.source && (
                                    <div className="uda-meta-item">
                                      <span className="uda-meta-key">Engine</span>
                                      <span className="uda-meta-val">{alert.source}</span>
                                    </div>
                                  )}
                                  {isBlocking && (
                                    <div className="uda-meta-item">
                                      <span className="uda-blocked-tag">🔒 Traffic Blocked</span>
                                    </div>
                                  )}
                                </div>
                                <div className={`uda-card-note ${!alert.is_read ? 'uda-card-note--warn' : ''}`}>
                                  <AlertCircle size={12} />
                                  {alert.is_read
                                    ? 'Network-level event — your machine was not directly involved.'
                                    : 'Your machine or backend was associated with this event. Investigate immediately.'}
                                </div>
                                {!alert.is_read && (
                                  <div className="uda-card-actions">
                                    <button className="uda-action-btn uda-action-btn--read" onClick={() => markAlertRead(alert.id, (alert as any)._childIds)}>
                                      <CheckCircle size={13} />Mark as Read
                                    </button>
                                  </div>
                                )}
                              </div>
                            </motion.div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* ── Section 2: Application / WAF Alerts ── */}
                  {appAlerts.length > 0 && (
                    <div className="uda-section" style={{ marginTop: globalAlerts.length > 0 ? '36px' : '0' }}>
                      <div className="uda-section-header">
                        <div className="uda-section-title-block">
                          <div className="uda-section-title-row">
                            <div className="uda-section-icon uda-section-icon--waf"><ShieldCheck size={15} /></div>
                            <h2 className="uda-section-title">Application Alerts</h2>
                            <span className="uda-section-badge uda-section-badge--waf">
                              {appAlerts.filter(a => !a.is_read).length > 0
                                ? `${appAlerts.filter(a => !a.is_read).length} unread`
                                : appAlerts.length}
                            </span>
                          </div>
                          <p className="uda-section-desc">WAF blocks and security events targeting your specific application endpoints</p>
                        </div>
                      </div>
                      <div className="uda-table-wrap">
                        <table className="uda-table">
                          <thead>
                            <tr>
                              <th className="uda-th">Type</th>
                              <th className="uda-th">Severity</th>
                              <th className="uda-th">Rule / Event</th>
                              <th className="uda-th">Source IP</th>
                              <th className="uda-th">Time</th>
                              <th className="uda-th">Status</th>
                              <th className="uda-th uda-th--center">Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {groupAlerts(appAlerts).map((alert) => {
                              const info = getActionInfo(alert);
                              const childIds = (alert as any)._childIds as number[] | undefined;
                              const isExpanded = expandedAlerts.has(alert.id);
                              const descParts = alert.description?.includes(' — ')
                                ? alert.description.split(' — ').slice(1).join(' — ').split(' | ')
                                : null;
                              const ruleIdParts = alert.rule_id?.includes(',') ? alert.rule_id.split(',').map(r => r.trim()) : null;

                              return (
                                <React.Fragment key={alert.id}>
                                  <tr
                                    className={`uda-tr ${alert.is_read ? 'uda-tr--read' : 'uda-tr--unread'} ${isExpanded ? 'uda-tr--expanded' : ''}`}
                                    style={{ '--sev-color': severityColor(alert.severity) } as React.CSSProperties}
                                    onClick={() => setExpandedAlerts(prev => {
                                      const s = new Set(prev);
                                      s.has(alert.id) ? s.delete(alert.id) : s.add(alert.id);
                                      return s;
                                    })}
                                  >
                                    <td className="uda-td">
                                      <span className="uda-badge uda-badge--type" style={{ background: info.bg, color: info.color }}>{info.label}</span>
                                    </td>
                                    <td className="uda-td">
                                      <span className="uda-sev-pill" style={{ background: severityColor(alert.severity) + '18', color: severityColor(alert.severity), borderColor: severityColor(alert.severity) + '50' }}>
                                        <span className="uda-sev-dot" style={{ background: severityColor(alert.severity) }} />
                                        {alert.severity.toUpperCase()}
                                      </span>
                                    </td>
                                    <td className="uda-td uda-td--rule">
                                      <span className="uda-rule-name">{alert.rule_name || `Alert #${alert.rule_id}`}</span>
                                      {(alert.occurrence_count ?? 1) > 1 && (
                                        <span className="uda-badge uda-badge--hits uda-badge--inline">×{alert.occurrence_count}</span>
                                      )}
                                    </td>
                                    <td className="uda-td"><code className="uda-ip-code">{alert.source_ip}</code></td>
                                    <td className="uda-td uda-td--time">{formatTime(alert.timestamp)}</td>
                                    <td className="uda-td">
                                      {alert.is_read ? (
                                        <span className="uda-status-pill uda-status-pill--read"><CheckCircle size={11} />Read</span>
                                      ) : (
                                        <span className="uda-status-pill uda-status-pill--unread">New</span>
                                      )}
                                    </td>
                                    <td className="uda-td uda-td--actions">
                                      <button
                                        className="uda-icon-btn uda-icon-btn--danger"
                                        onClick={(e) => { e.stopPropagation(); deleteAlert(alert.id, childIds); }}
                                        disabled={deletingAlertId === alert.id}
                                        title="Delete alert"
                                      >
                                        <Trash2 size={15} />
                                      </button>
                                    </td>
                                  </tr>
                                  {isExpanded && (
                                    <tr className="uda-tr-expand">
                                      <td colSpan={7}>
                                        <div className="uda-expand-body">
                                          <div className="uda-expand-col">
                                            <h4 className="uda-expand-heading">Description</h4>
                                            {descParts && descParts.length > 1 ? (
                                              <ul className="uda-desc-list">
                                                {descParts.map((part, idx) => <li key={idx}>{part.trim()}</li>)}
                                              </ul>
                                            ) : (
                                              <p className="uda-expand-text">{alert.description}</p>
                                            )}
                                          </div>
                                          <div className="uda-expand-col">
                                            <h4 className="uda-expand-heading">Details</h4>
                                            <div className="uda-detail-rows">
                                              {ruleIdParts && ruleIdParts.length > 1 ? (
                                                <div className="uda-detail-row"><span>Rules ({ruleIdParts.length})</span><span>{ruleIdParts.join(', ')}</span></div>
                                              ) : alert.rule_id ? (
                                                <div className="uda-detail-row"><span>Rule ID</span><code>{alert.rule_id}</code></div>
                                              ) : null}
                                              {alert.target_url && (
                                                <div className="uda-detail-row"><span>Target</span><code>{alert.target_url}</code></div>
                                              )}
                                            </div>
                                          </div>
                                          {alert.recommended_action && (
                                            <div className="uda-expand-col uda-expand-col--full">
                                              <h4 className="uda-expand-heading">Recommended Action</h4>
                                              <div className="uda-rec-action">{alert.recommended_action}</div>
                                            </div>
                                          )}
                                          {!alert.is_read && (
                                            <div className="uda-expand-col uda-expand-col--full uda-expand-foot">
                                              <button
                                                className="uda-action-btn uda-action-btn--read"
                                                onClick={(e) => { e.stopPropagation(); markAlertRead(alert.id, childIds); }}
                                              >
                                                <CheckCircle size={14} />Mark as Read
                                              </button>
                                            </div>
                                          )}
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
                    </div>
                  )}
                </>
              );
            })()}

            {alerts.length > 0 && (
              <div className="uda-footer-note">
                <CheckCircle size={13} />Showing all {alerts.length} alert{alerts.length !== 1 ? 's' : ''}
              </div>
            )}
          </motion.div>
        )}

        {/* ── APPLICATIONS ── */}
        {activeTab === 'applications' && (
          <motion.div className="ud-content" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
            <div className="ud-page-header">
              <div><h1>Applications</h1><p>Configure and manage your protected backend applications</p></div>
              {applications.length > 0 && (
                <button className="ud-btn-primary" onClick={() => setShowWizard(!showWizard)} disabled={creatingApp}>
                  <Plus size={15} />{showWizard ? 'Cancel' : 'Add Application'}
                </button>
              )}
            </div>

            {/* Setup Wizard */}
            {(showWizard || applications.length === 0) && (
              <div className="ud-card" style={{ marginBottom: '24px', background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.2)' }}>
                <div className="ud-card-header"><Settings size={17} /><h3>Setup Wizard</h3></div>
                <div className="ud-card-body">
                  {appMsg && (
                    <div className={`ud-msg ${appMsg.type}`}>
                      {appMsg.type === 'success' ? <CheckCircle size={15} /> : <AlertCircle size={15} />}
                      {appMsg.text}
                    </div>
                  )}

                  {/* Wizard Steps */}
                  {wizardStep !== 'complete' && (() => {
                    const steps = ['name', 'url', 'review', 'complete'] as const;
                    const currentIdx = steps.indexOf(wizardStep);
                    const labels = ['App Name', 'Backend URL', 'Review', 'Complete'];
                    return (
                      <div className="ud-wizard-steps">
                        {steps.map((step, idx) => {
                          const isDone = idx < currentIdx;
                          const isActive = idx === currentIdx;
                          return (
                            <React.Fragment key={step}>
                              <div className={`ud-wizard-step ${isActive ? 'active' : ''} ${isDone ? 'done' : ''}`}>
                                <div className="ud-wizard-step-circle">
                                  {isDone ? <Check size={13} /> : <span>{idx + 1}</span>}
                                </div>
                                <span className="ud-wizard-step-label">{labels[idx]}</span>
                              </div>
                              {idx < steps.length - 1 && <div className={`ud-wizard-connector ${idx < currentIdx ? 'done' : ''}`} />}
                            </React.Fragment>
                          );
                        })}
                      </div>
                    );
                  })()}

                  {/* Step: App Name */}
                  {wizardStep === 'name' && (
                    <div>
                      <div className="ud-wizard-info-box" style={{ marginBottom: '14px' }}>
                        <AlertCircle size={15} />
                        <div>
                          <strong>What this wizard does:</strong> it registers one backend application and gives you a unique API key.
                          Your frontend will then call Synorix at <code>/user-proxy</code> with that key.
                        </div>
                      </div>
                      <div className="ud-form-group">
                        <label>Application Name<span className="ud-required">*</span></label>
                        <input
                          type="text"
                          className="ud-input"
                          placeholder="e.g., Main API, Mobile Backend, Admin Service"
                          value={newAppName}
                          onChange={e => setNewAppName(e.target.value)}
                          disabled={creatingApp}
                        />
                        <p className="ud-field-hint">A unique name to identify this application. Must be 2-50 characters.</p>
                      </div>
                      <div className="ud-form-group">
                        <label>Description (optional)</label>
                        <textarea
                          className="ud-input"
                          placeholder="e.g., Primary REST API for mobile applications"
                          value={newAppDescription}
                          onChange={e => setNewAppDescription(e.target.value)}
                          disabled={creatingApp}
                          rows={3}
                          style={{ resize: 'vertical' }}
                        />
                        <p className="ud-field-hint">Brief description of what this application does.</p>
                      </div>
                      <button
                        className="ud-btn-primary"
                        onClick={() => {
                          if (newAppName.trim().length >= 2) setWizardStep('url');
                        }}
                        disabled={newAppName.trim().length < 2 || creatingApp}
                      >
                        Next: Backend URL <ChevronRight size={14} />
                      </button>
                    </div>
                  )}

                  {/* Step: Backend URL */}
                  {wizardStep === 'url' && (
                    <div>
                      <div className="ud-wizard-help-grid">
                        <div className="ud-wizard-help-card">
                          <h4>Accepted URL format</h4>
                          <ul>
                            <li>Must start with <code>http://</code> or <code>https://</code></li>
                            <li>Should point to your backend API server</li>
                            <li>Examples: <code>https://api.myapp.com</code>, <code>https://your-id.ngrok-free.app</code></li>
                          </ul>
                        </div>
                        <div className="ud-wizard-help-card">
                          <h4>Traffic flow</h4>
                          <p><strong>End User</strong> → <strong>Your Frontend</strong> → <strong>Synorix</strong> → <strong>Your Backend</strong></p>
                          <p className="ud-field-hint" style={{ margin: 0 }}>Users never call your backend directly once integrated.</p>
                        </div>
                      </div>
                      <div className="ud-form-group">
                        <label>Backend URL<span className="ud-required">*</span></label>
                        <input
                          type="url"
                          className="ud-input"
                          placeholder="https://your-backend.com"
                          value={newAppUrl}
                          onChange={e => setNewAppUrl(e.target.value)}
                          disabled={creatingApp}
                        />
                        <p className="ud-field-hint">The URL of your backend server. Include the protocol (http:// or https://).</p>
                      </div>
                      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                        <button
                          className="ud-btn-secondary"
                          onClick={() => setWizardStep('name')}
                          disabled={creatingApp}
                        >
                          <ChevronLeft size={14} /> Back
                        </button>
                        <button
                          className="ud-btn-primary"
                          onClick={() => {
                            const urlRegex = /^https?:\/\/.+/;
                            if (urlRegex.test(newAppUrl.trim())) setWizardStep('review');
                          }}
                          disabled={!newAppUrl.trim() || !/^https?:\/\/.+/.test(newAppUrl.trim()) || creatingApp}
                        >
                          Next: Review <ChevronRight size={14} />
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Step: Review */}
                  {wizardStep === 'review' && (
                    <div>
                      <div className="ud-wizard-info-box" style={{ marginBottom: '14px' }}>
                        <ShieldCheck size={15} />
                        <div>
                          After you click <strong>Create Application</strong>, Synorix will generate an API key specific to this app.
                          You will use that key in your frontend via <code>X-API-Key</code>.
                        </div>
                      </div>
                      <div style={{ background: 'rgba(255,255,255,0.04)', borderRadius: '8px', padding: '14px', marginBottom: '16px' }}>
                        <div style={{ fontSize: '13px', display: 'grid', gap: '12px' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '12px', alignItems: 'start' }}>
                            <span style={{ opacity: 0.6 }}>App Name:</span>
                            <strong>{newAppName}</strong>
                          </div>
                          <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '12px', alignItems: 'start' }}>
                            <span style={{ opacity: 0.6 }}>Backend URL:</span>
                            <code style={{ wordBreak: 'break-all' }}>{newAppUrl}</code>
                          </div>
                          {newAppDescription && (
                            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '12px', alignItems: 'start' }}>
                              <span style={{ opacity: 0.6 }}>Description:</span>
                              <p style={{ margin: 0 }}>{newAppDescription}</p>
                            </div>
                          )}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                        <button
                          className="ud-btn-secondary"
                          onClick={() => setWizardStep('url')}
                          disabled={creatingApp}
                        >
                          <ChevronLeft size={14} /> Back
                        </button>
                        <button
                          className="ud-btn-primary"
                          onClick={createApplication}
                          disabled={creatingApp}
                        >
                          {creatingApp ? <RefreshCw size={14} className="ud-spin" /> : <Plus size={14} />}
                          {creatingApp ? 'Creating…' : 'Create Application'}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Step: Complete */}
                  {wizardStep === 'complete' && (
                    <div className="ud-wizard-complete">
                      <div className="ud-wizard-complete-icon">
                        <CheckCircle size={40} />
                      </div>
                      <h3 className="ud-wizard-complete-title">Application Created!</h3>
                      <p className="ud-wizard-complete-subtitle">Your application has been registered and is ready to use.</p>

                      <div className="ud-wizard-complete-card">
                        <div className="ud-wizard-complete-row">
                          <span className="ud-wizard-complete-row-label"><Globe size={13} />App Name</span>
                          <span className="ud-wizard-complete-row-value">{createdAppName}</span>
                        </div>
                        {createdAppKey && (
                          <div className="ud-wizard-complete-row">
                            <span className="ud-wizard-complete-row-label"><Key size={13} />API Key</span>
                            <div className="ud-wizard-complete-key">
                              <code>{createdAppKey.slice(0, 18)}••••••••</code>
                              <button className="ud-copy-btn" title="Copy API Key" onClick={() => copyToClipboard(createdAppKey, 'key-created')}>
                                {copiedKey === 'key-created' ? <Check size={13} /> : <Copy size={13} />}
                              </button>
                            </div>
                          </div>
                        )}
                        <div className="ud-wizard-complete-row">
                          <span className="ud-wizard-complete-row-label"><ShieldCheck size={13} />Status</span>
                          <span className="ud-wizard-complete-badge">Active &amp; Protected</span>
                        </div>
                      </div>

                      <p className="ud-wizard-complete-hint">Use the endpoint below in your frontend. In production, this becomes your deployed Synorix domain automatically.</p>

                      <div className="ud-wizard-endpoint-card">
                        <div className="ud-wizard-endpoint-row">
                          <span className="ud-wizard-endpoint-label">Proxy Endpoint</span>
                          <div className="ud-wizard-endpoint-value">
                            <code>{applicationProxyEndpoint}</code>
                            <button
                              className="ud-copy-btn"
                              title="Copy proxy endpoint"
                              onClick={() => copyToClipboard(applicationProxyEndpoint, 'key-endpoint')}
                            >
                              {copiedKey === 'key-endpoint' ? <Check size={13} /> : <Copy size={13} />}
                            </button>
                          </div>
                        </div>
                        <p className="ud-wizard-endpoint-hint">
                          {isLocalHost && isFrontendDevPort
                            ? 'You are currently in local development, so the endpoint points to localhost:8080. After deployment, users will see your public domain here.'
                            : `Your users will use this deployed domain endpoint: ${window.location.origin}/user-proxy`}
                        </p>
                      </div>

                      <div className="ud-wizard-integration-block">
                        <div className="ud-wizard-integration-head">
                          <div className="ud-integration-header-content">
                            <div className="ud-integration-title-row">
                              <div>
                                <span className="ud-integration-title">Frontend Integration Snippet</span>
                                <p className="ud-integration-desc">Copy this into your frontend and replace your direct backend calls.</p>
                              </div>
                              <button
                                className="ud-copy-btn ud-copy-btn-large"
                                title="Copy integration snippet"
                                onClick={() => copyToClipboard(integrationSnippet, 'key-integration')}
                              >
                                {copiedKey === 'key-integration' ? <Check size={14} /> : <Copy size={14} />}
                              </button>
                            </div>
                            <div className="ud-wizard-integration-meta">
                              <span className="ud-meta-badge ud-meta-axios">axios</span>
                              <span className="ud-meta-badge ud-meta-proxy">secure proxy</span>
                            </div>
                          </div>
                        </div>
                        <div className="ud-code-block-wrapper">
                          <pre><code>{integrationSnippet}</code></pre>
                        </div>
                      </div>

                      <div className="ud-wizard-next-steps">
                        <h4>Next steps</h4>
                        <ol>
                          <li>Replace your frontend API base URL with <code>{applicationProxyEndpoint}</code></li>
                          <li>Add header <code>X-API-Key: {createdAppKey ? `${createdAppKey.slice(0, 10)}...` : 'YOUR_APP_API_KEY'}</code></li>
                          <li>Send requests to the same endpoint paths (e.g., <code>/users</code>, <code>/orders</code>)</li>
                          <li>Open Traffic Logs and Alerts tabs to verify protected traffic</li>
                        </ol>
                      </div>

                      <div className="ud-wizard-complete-actions">
                        <button
                          className="ud-btn-secondary"
                          onClick={() => {
                            setWizardStep('name');
                            setCreatedAppName('');
                            setCreatedAppKey('');
                          }}
                        >
                          <Plus size={14} /> Add Another
                        </button>
                        <button
                          className="ud-btn-primary"
                          onClick={() => {
                            setShowWizard(false);
                            setWizardStep('name');
                            setCreatedAppName('');
                            setCreatedAppKey('');
                          }}
                        >
                          <CheckCircle size={14} /> Done
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Applications List */}
            {loadingApps ? (
              <div className="ud-empty" style={{ padding: '60px 20px' }}>
                <RefreshCw size={32} className="ud-spin" style={{ marginBottom: '16px' }} />
                <p>Loading applications…</p>
              </div>
            ) : applications.length > 0 ? (
              <div className="ud-apps-list">
                {applications.map(app => (
                  <div key={app.id} className="ud-app-card-v2">

                    {/* ── Header strip ── */}
                    <div className="ud-app-card-v2-header">
                      <div className="ud-app-card-v2-icon">
                        <Globe size={20} />
                      </div>
                      <div className="ud-app-card-v2-title">
                        <h3>{app.app_name}</h3>
                        {app.description && <p>{app.description}</p>}
                      </div>
                      <span className={`ud-app-status-badge ${app.connectivity_status === 'success' ? 'connected' : app.connectivity_status === 'failed' ? 'failed' : 'untested'}`}>
                        {app.connectivity_status === 'success' ? <><CheckCircle size={10} /> Connected</> : app.connectivity_status === 'failed' ? <><X size={10} /> Unreachable</> : <><AlertCircle size={10} /> Untested</>}
                      </span>
                    </div>

                    {/* ── Inline feedback ── */}
                    {appCardMsg[app.id] && (
                      <div className={`ud-app-msg ${appCardMsg[app.id].type}`}>
                        {appCardMsg[app.id].type === 'success' ? <CheckCircle size={13} /> : <AlertCircle size={13} />}
                        {appCardMsg[app.id].text}
                      </div>
                    )}

                    {/* ── Detail / Edit body ── */}
                    <div className="ud-app-card-v2-body">
                      {editingAppId === app.id ? (
                        <div className="ud-app-edit-form">
                          <div className="ud-form-group">
                            <label>Application Name</label>
                            <input type="text" className="ud-input" value={editAppName} onChange={e => setEditAppName(e.target.value)} disabled={savingApp} />
                          </div>
                          <div className="ud-form-group">
                            <label>Backend URL</label>
                            <input type="url" className="ud-input" value={editAppUrl} onChange={e => setEditAppUrl(e.target.value)} disabled={savingApp} />
                          </div>
                          <div className="ud-form-group" style={{ marginBottom: 0 }}>
                            <label>Description <span style={{ opacity: 0.5, fontWeight: 400 }}>(optional)</span></label>
                            <input type="text" className="ud-input" value={editAppDescription} onChange={e => setEditAppDescription(e.target.value)} disabled={savingApp} />
                          </div>
                        </div>
                      ) : (
                        <div className="ud-app-detail-list">
                          <div className="ud-app-detail-item">
                            <span className="ud-app-detail-key">Backend URL</span>
                            <code className="ud-app-detail-val">{app.backend_url}</code>
                          </div>
                          <div className="ud-app-detail-item">
                            <span className="ud-app-detail-key">API Key</span>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flex: 1, minWidth: 0 }}>
                              <code className="ud-app-detail-val" style={{ flex: 1, wordBreak: 'break-all', userSelect: visibleKeys.has(`appkey-${app.id}`) ? 'all' : 'none', letterSpacing: visibleKeys.has(`appkey-${app.id}`) ? 'normal' : '0.15em', filter: visibleKeys.has(`appkey-${app.id}`) ? 'none' : 'blur(4px)', transition: 'filter 0.2s' }}>
                                {app.proxy_api_key}
                              </code>
                              <button
                                title={visibleKeys.has(`appkey-${app.id}`) ? 'Hide API Key' : 'Show API Key'}
                                onClick={() => toggleKeyVisible(`appkey-${app.id}`)}
                                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', color: '#9CA3AF', flexShrink: 0 }}
                              >
                                {visibleKeys.has(`appkey-${app.id}`) ? <EyeOff size={13} /> : <Eye size={13} />}
                              </button>
                              <button
                                title={copiedKey === `appkey-${app.id}` ? 'Copied!' : 'Copy API Key'}
                                onClick={() => copyToClipboard(app.proxy_api_key, `appkey-${app.id}`)}
                                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px 6px', color: copiedKey === `appkey-${app.id}` ? '#0D47A1' : '#9CA3AF', flexShrink: 0, display: 'flex', alignItems: 'center', gap: '3px', fontSize: '11px', fontWeight: 600, borderRadius: '4px', transition: 'color 0.2s' }}
                              >
                                {copiedKey === `appkey-${app.id}` ? <><Check size={13} /></> : <Copy size={13} />}
                              </button>
                            </div>
                          </div>
                          <div className="ud-app-detail-item">
                            <span className="ud-app-detail-key">Last Tested</span>
                            <span className="ud-app-detail-val">{app.last_test_at ? new Date(app.last_test_at).toLocaleString() : 'Never'}</span>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* ── Action footer ── */}
                    <div className="ud-app-card-v2-footer">
                      {editingAppId === app.id ? (
                        <>
                          <button className="ud-btn-primary ud-app-action-btn" onClick={() => updateApplication(app.id)} disabled={savingApp || !editAppName.trim() || !editAppUrl.trim()}>
                            {savingApp ? <RefreshCw size={13} className="ud-spin" /> : <Save size={13} />}
                            {savingApp ? 'Saving…' : 'Save Configuration'}
                          </button>
                          <button className="ud-btn-secondary ud-app-action-btn" onClick={cancelEditApp} disabled={savingApp}>
                            <X size={13} /> Cancel
                          </button>
                        </>
                      ) : (
                        <>
                          <button className="ud-btn-primary ud-app-action-btn" onClick={() => testAppConnectivity(app.id)} disabled={testingAppId === app.id}>
                            {testingAppId === app.id ? <RefreshCw size={13} className="ud-spin" /> : <CheckCircle size={13} />}
                            {testingAppId === app.id ? 'Testing…' : 'Test Connectivity'}
                          </button>
                          <button className="ud-btn-secondary ud-app-action-btn" onClick={() => startEditApp(app)}>
                            <Save size={13} /> Edit Config
                          </button>
                          <button className="ud-app-delete-btn" onClick={() => deleteApplication(app.id, app.app_name)} disabled={loadingApps} title="Delete application">
                            <Trash2 size={17} />
                          </button>
                        </>
                      )}
                    </div>

                  </div>
                ))}
              </div>
            ) : null}
          </motion.div>
        )}

        {/* ── SETTINGS ── */}
        {activeTab === 'settings' && (
          <motion.div className="ud-content" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
            <div className="ud-page-header">
              <div><h1>Settings</h1><p>Manage your account and security settings</p></div>
            </div>

            <div className="ud-settings-stack">
              <div className="ud-card">
                <div className="ud-card-header"><UserCheck size={17} /><h3>Account</h3></div>
                <div className="ud-card-body">
                  {personalInfoMsg && (
                    <div className={`ud-msg ${personalInfoMsg.type}`}>
                      {personalInfoMsg.type === 'success' ? <CheckCircle size={15} /> : <AlertCircle size={15} />}
                      {personalInfoMsg.text}
                    </div>
                  )}
                  {editingPersonalInfo ? (
                    <>
                      <div className="ud-form-group">
                        <label>Username<span className="ud-required">*</span></label>
                        <input 
                          type="text" 
                          className="ud-input" 
                          placeholder="Your username" 
                          value={editUsername} 
                          onChange={e => setEditUsername(e.target.value)} 
                        />
                      </div>
                      <div className="ud-form-group">
                        <label>Email<span className="ud-required">*</span></label>
                        <input 
                          type="email" 
                          className="ud-input" 
                          placeholder="your@email.com" 
                          value={editEmail} 
                          onChange={e => setEditEmail(e.target.value)} 
                        />
                      </div>
                      <div className="ud-form-group" style={{ marginBottom: 0, display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                        <button 
                          className="ud-btn-primary" 
                          onClick={savePersonalInfo} 
                          disabled={savingPersonalInfo || !editUsername.trim() || !editEmail.trim()}
                        >
                          {savingPersonalInfo ? <RefreshCw size={15} className="ud-spin" /> : <Save size={15} />}
                          {savingPersonalInfo ? 'Saving…' : 'Save'}
                        </button>
                        <button 
                          className="ud-btn-secondary" 
                          onClick={cancelEditPersonalInfo}
                          disabled={savingPersonalInfo}
                        >
                          <X size={15} />Cancel
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="ud-status-row">
                        <span className="ud-status-label">Username</span>
                        <span className="ud-status-value">{user?.username}</span>
                      </div>
                      <div className="ud-status-row">
                        <span className="ud-status-label">Email</span>
                        <span className="ud-status-value">{user?.email || '—'}</span>
                      </div>
                      <div className="ud-status-row">
                        <span className="ud-status-label">Role</span>
                        <span className="ud-badge success">Standard User</span>
                      </div>
                      <div style={{ marginTop: '14px', paddingTop: '14px', borderTop: '1px solid #F3F4F6' }}>
                        <button 
                          className="ud-btn-secondary" 
                          onClick={() => setEditingPersonalInfo(true)}
                          style={{ display: 'inline-flex' }}
                        >
                          Edit
                        </button>
                      </div>
                    </>
                  )}
                </div>
              </div>

              <div className="ud-card">
                <div className="ud-card-header"><Lock size={17} /><h3>Change Password</h3></div>
                <div className="ud-card-body">
                  {passwordMsg && (
                    <div className={`ud-msg ${passwordMsg.type}`}>
                      {passwordMsg.type === 'success' ? <CheckCircle size={15} /> : <AlertCircle size={15} />}
                      {passwordMsg.text}
                    </div>
                  )}
                  {changingPassword ? (
                    <>
                      <div className="ud-form-group">
                        <label>Current Password<span className="ud-required">*</span></label>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                          <input 
                            type={currentPasswordVisible ? 'text' : 'password'} 
                            className="ud-input" 
                            placeholder="Enter current password" 
                            value={currentPassword} 
                            onChange={e => setCurrentPassword(e.target.value)} 
                            style={{ flex: 1 }}
                          />
                          <button 
                            className="ud-icon-btn" 
                            onClick={() => setCurrentPasswordVisible(!currentPasswordVisible)}
                            style={{ flexShrink: 0 }}
                          >
                            {currentPasswordVisible ? <Eye size={15} /> : <Eye size={15} style={{ opacity: 0.5 }} />}
                          </button>
                        </div>
                      </div>
                      <div className="ud-form-group">
                        <label>New Password<span className="ud-required">*</span></label>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                          <input 
                            type={newPasswordVisible ? 'text' : 'password'} 
                            className="ud-input" 
                            placeholder="Enter new password (min. 6 characters)" 
                            value={newPassword} 
                            onChange={e => setNewPassword(e.target.value)} 
                            style={{ flex: 1 }}
                          />
                          <button 
                            className="ud-icon-btn" 
                            onClick={() => setNewPasswordVisible(!newPasswordVisible)}
                            style={{ flexShrink: 0 }}
                          >
                            {newPasswordVisible ? <Eye size={15} /> : <Eye size={15} style={{ opacity: 0.5 }} />}
                          </button>
                        </div>
                      </div>
                      <div className="ud-form-group">
                        <label>Confirm Password<span className="ud-required">*</span></label>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                          <input 
                            type={confirmPasswordVisible ? 'text' : 'password'} 
                            className="ud-input" 
                            placeholder="Confirm new password" 
                            value={confirmPassword} 
                            onChange={e => setConfirmPassword(e.target.value)} 
                            style={{ flex: 1 }}
                          />
                          <button 
                            className="ud-icon-btn" 
                            onClick={() => setConfirmPasswordVisible(!confirmPasswordVisible)}
                            style={{ flexShrink: 0 }}
                          >
                            {confirmPasswordVisible ? <Eye size={15} /> : <Eye size={15} style={{ opacity: 0.5 }} />}
                          </button>
                        </div>
                      </div>
                      <div className="ud-form-group" style={{ marginBottom: 0, display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                        <button 
                          className="ud-btn-primary" 
                          onClick={changePassword} 
                          disabled={savingPassword || !currentPassword || !newPassword || !confirmPassword}
                        >
                          {savingPassword ? <RefreshCw size={15} className="ud-spin" /> : <Save size={15} />}
                          {savingPassword ? 'Saving…' : 'Save Password'}
                        </button>
                        <button 
                          className="ud-btn-secondary" 
                          onClick={cancelChangePassword}
                          disabled={savingPassword}
                        >
                          <X size={15} />Cancel
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <p className="ud-hint">Keep your account secure by regularly updating your password.</p>
                      <div style={{ marginTop: '14px' }}>
                        <button 
                          className="ud-btn-secondary" 
                          onClick={() => setChangingPassword(true)}
                          style={{ display: 'inline-flex' }}
                        >
                          <Lock size={15} />Change Password
                        </button>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Proxy Configuration */}
              <div className="ud-card">
                <div className="ud-card-header"><Key size={17} /><h3>API Keys &amp; Proxy Configuration</h3></div>
                <div className="ud-card-body">
                  <p className="ud-hint">Each application gets its own API key. Point your frontend at the proxy and include the key in every request.</p>

                  {/* Endpoint info strip */}
                  <div className="ud-proxy-info-strip">
                    <div className="ud-proxy-info-item">
                      <span className="ud-proxy-info-label">Proxy Endpoint</span>
                      <div className="ud-proxy-info-value">
                        <code>{window.location.protocol}//{window.location.hostname}:8080</code>
                        <button className="ud-icon-btn" title="Copy endpoint" onClick={() => copyToClipboard(`${window.location.protocol}//${window.location.hostname}:8080`, 'url')}>
                          {copiedUrl ? <Check size={13} /> : <Copy size={13} />}
                        </button>
                      </div>
                    </div>
                    <div className="ud-proxy-info-item">
                      <span className="ud-proxy-info-label">Header</span>
                      <code className="ud-proxy-info-value">X-API-Key</code>
                    </div>
                    <div className="ud-proxy-info-item">
                      <span className="ud-proxy-info-label">Protocol</span>
                      <span className="ud-proxy-info-value">HTTP / HTTPS</span>
                    </div>
                  </div>

                  {/* Per-application API keys */}
                  <div className="ud-apikeys-section">
                    <div className="ud-apikeys-section-title">Application API Keys</div>
                    {applications.length === 0 ? (
                      <div className="ud-apikeys-empty">
                        <Key size={20} />
                        <p>No applications yet. Create one to get an API key.</p>
                      </div>
                    ) : (
                      <div className="ud-apikeys-list">
                        {applications.map(app => (
                          <div key={app.id} className="ud-apikey-row">
                            <div className="ud-apikey-app-name">
                              <Globe size={13} />
                              {app.app_name}
                            </div>
                            <div className="ud-apikey-value-wrap">
                              <code className="ud-apikey-code" style={{ filter: visibleKeys.has(`settingskey-${app.id}`) ? 'none' : 'blur(4px)', userSelect: visibleKeys.has(`settingskey-${app.id}`) ? 'all' : 'none', transition: 'filter 0.2s' }}>
                                {app.proxy_api_key}
                              </code>
                              <button
                                className="ud-apikey-toggle-btn"
                                title={visibleKeys.has(`settingskey-${app.id}`) ? 'Hide' : 'Show'}
                                onClick={() => toggleKeyVisible(`settingskey-${app.id}`)}
                              >
                                {visibleKeys.has(`settingskey-${app.id}`) ? <EyeOff size={12} /> : <Eye size={12} />}
                              </button>
                              <button
                                className={`ud-apikey-copy-btn ${copiedKey === `settingskey-${app.id}` ? 'copied' : ''}`}
                                title="Copy API Key"
                                onClick={() => copyToClipboard(app.proxy_api_key, `settingskey-${app.id}`)}
                              >
                                {copiedKey === `settingskey-${app.id}` ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>

            </div>
          </motion.div>
        )}

      </main>

      {/* ── Delete Confirmation Modal ── */}
      <AnimatePresence>
        {deleteConfirm && (
          <motion.div
            className="ud-modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.18 }}
            onClick={() => setDeleteConfirm(null)}
          >
            <motion.div
              className="ud-modal"
              initial={{ opacity: 0, scale: 0.96, y: 16 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: 16 }}
              transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
              onClick={e => e.stopPropagation()}
            >
              {/* Top danger bar */}
              <div className="ud-modal-danger-bar" />

              <div className="ud-modal-content">
                {/* Icon */}
                <div className="ud-modal-icon-wrap">
                  <div className="ud-modal-icon-ring">
                    <Trash2 size={20} />
                  </div>
                </div>

                {/* Text */}
                <div className="ud-modal-text">
                  <h3 className="ud-modal-title">Delete Application</h3>
                  <p className="ud-modal-body">
                    You are about to permanently delete{' '}
                    <span className="ud-modal-app-name">{deleteConfirm.name}</span>.
                    All associated traffic logs and alerts will be unlinked.
                  </p>
                  <div className="ud-modal-warning-tag">
                    <AlertTriangle size={12} /> This action cannot be undone.
                  </div>
                </div>

                {/* Actions */}
                <div className="ud-modal-actions">
                  <button className="ud-modal-cancel-btn" onClick={() => setDeleteConfirm(null)}>Cancel</button>
                  <button className="ud-modal-delete-btn" onClick={confirmDelete}>
                    <Trash2 size={13} /> Delete Application
                  </button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Delete Alert Confirm Modal ── */}
      <AnimatePresence>
        {deleteConfirmAlert && (
          <motion.div
            className="uda-modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setDeleteConfirmAlert(null)}
          >
            <motion.div
              className="uda-modal"
              initial={{ opacity: 0, scale: 0.93, y: 16 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.93, y: 16 }}
              transition={{ type: 'spring', damping: 22, stiffness: 320 }}
              onClick={e => e.stopPropagation()}
            >
              <div className="uda-modal-icon-wrap">
                <Trash2 size={22} />
              </div>
              <h3 className="uda-modal-title">Delete Alert</h3>
              <p className="uda-modal-desc">Are you sure you want to delete this alert? This action cannot be undone.</p>
              <div className="uda-modal-actions">
                <button className="uda-modal-cancel" onClick={() => setDeleteConfirmAlert(null)}>Cancel</button>
                <button className="uda-modal-confirm" onClick={confirmDeleteAlert}><Trash2 size={14} />Delete</button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default UserDashboard;
