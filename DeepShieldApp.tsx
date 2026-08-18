import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Incident, SystemNode, FirewallRule, ChartDataPoint } from './types';
import { StatusBanner } from './components/StatusBanner';
import { NotificationDrawer } from './components/NotificationDrawer';
import { MetricCards } from './components/MetricCards';
import { PulseChart } from './components/PulseChart';
import { IncidentLogs } from './components/IncidentLogs';
import { NodeManager } from './components/NodeManager';
import { FirewallRules } from './components/FirewallRules';
import { DatabaseSync } from './components/DatabaseSync';
import { TargetAnalysisHub } from './components/TargetAnalysisHub';
import { ScanSafetyAnalysis } from './components/ScanSafetyAnalysis';
import { AISecurityBot } from './components/AISecurityBot';
import { SystemHealthSummary } from './components/SystemHealthSummary';
import { ThreatMap } from './components/ThreatMap';
import { SecOpsSuite } from './components/SecOpsSuite';
import { EmergencyLockdownModal } from './components/EmergencyLockdownModal';
import { CommandPaletteModal } from './components/CommandPaletteModal';
import { isSupabaseConfigured } from './lib/supabase';
import { Terminal, Shield, Search, Cpu, Download, FileJson, FileText, ChevronDown, Clock, Filter, Activity } from 'lucide-react';

const tabContainerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
      delayChildren: 0.03,
    }
  },
  exit: {
    opacity: 0,
    transition: {
      duration: 0.15
    }
  }
};

const tabItemVariants = {
  hidden: { opacity: 0, y: 8 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.2 } }
};

export default function App() {
  // --- Core Dashboard Navigation & Theme ---
  const [activeTab, setActiveTab] = useState<'console' | 'ingress' | 'secops'>('console');
  // Enterprise obsidian theme is the only supported visual mode.
  const [theme] = useState<'light' | 'dark'>('dark');

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
      document.body.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
      document.body.classList.remove('dark');
    }
    localStorage.setItem('deepshield-theme', theme);
  }, [theme]);

  const handleToggleTheme = () => {
    /* Locked to the obsidian enterprise theme. */
  };
  
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [activeScanState, setActiveScanState] = useState<any>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);

  const [nodes, setNodes] = useState<SystemNode[]>([
    {
      id: 'NODE-US-EAST',
      name: 'US-EAST-01 (Primary Gateway)',
      region: 'N. Virginia, USA',
      status: 'operational',
      cpuUsage: 18,
      memoryUsage: 26,
      latency: 14,
    },
    {
      id: 'NODE-EU-WEST',
      name: 'EU-WEST-02 (Core Compute)',
      region: 'Dublin, Ireland',
      status: 'operational',
      cpuUsage: 14,
      memoryUsage: 32,
      latency: 28,
    },
    {
      id: 'NODE-AP-SOUTH',
      name: 'AP-SOUTH-01 (Edge Proxy)',
      region: 'Mumbai, India',
      status: 'operational',
      cpuUsage: 8,
      memoryUsage: 14,
      latency: 42,
    }
  ]);

  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [autoContainmentEnabled, setAutoContainmentEnabled] = useState(false);

  const [chartData, setChartData] = useState<ChartDataPoint[]>(() => {
    const data: ChartDataPoint[] = [];
    const now = new Date();
    for (let i = 9; i >= 0; i--) {
      const timePoint = new Date(now.getTime() - i * 5 * 60 * 1000);
      data.push({
        time: timePoint.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }),
        traffic: 1200 + Math.floor(Math.random() * 400),
        threats: Math.floor(Math.random() * 3),
        blocked: Math.floor(Math.random() * 2),
      });
    }
    return data;
  });

  const [threatLevel, setThreatLevel] = useState<'STABLE' | 'ELEVATED' | 'CRITICAL'>('STABLE');
  const [systemState, setSystemState] = useState<string>('DEFCON-5 (OPERATIONAL)');
  const [activeIncidentsCount, setActiveIncidentsCount] = useState<number>(0);
  const [blockedCount, setBlockedCount] = useState<number>(0);
  const [securedNodes, setSecuredNodes] = useState<number>(3);
  const [networkThroughput, setNetworkThroughput] = useState<number>(1420);
  const [dbLinkStatus, setDbLinkStatus] = useState<string>('In-Memory DB Online');

  const [isLockdownActive, setIsLockdownActive] = useState<boolean>(false);
  const [isLockdownModalOpen, setIsLockdownModalOpen] = useState<boolean>(false);
  const [lockdownModalMode, setLockdownModalMode] = useState<'confirm_engage' | 'active_overlay' | 'confirm_disengage'>('confirm_engage');

  const [systemLogs, setSystemLogs] = useState<string[]>([
    '[00:00:00] DEEPSHEILD Security Kernel Initialized.',
    '[00:00:01] Listening for ingress telemetry & threat vectors...'
  ]);
  const [showTerminalTimestamps, setShowTerminalTimestamps] = useState(true);
  const [terminalSeverityFilter, setTerminalSeverityFilter] = useState<'ALL' | 'INFO' | 'WARNING' | 'CRITICAL'>('ALL');

  // --- Command Palette State ---
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // --- Notification Drawer States ---
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [pinnedAlertIds, setPinnedAlertIds] = useState<string[]>([]);

  // --- Export States & Handler ---
  const [isExportDropdownOpen, setIsExportDropdownOpen] = useState(false);
  const exportDropdownRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (exportDropdownRef.current && !exportDropdownRef.current.contains(event.target as Node)) {
        setIsExportDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  // --- Log helper ---
  const logMessage = useCallback((msg: string) => {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    setSystemLogs((prev) => [`[${time}] ${msg}`, ...prev.slice(0, 20)]);
  }, []);

  const handleExportData = (format: 'json' | 'txt') => {
    const exportIsoTime = new Date().toISOString();
    const exportPayload = {
      report_metadata: {
        system: "DEEPSHEILD Enterprise Cyber Ops Platform",
        generated_at: exportIsoTime,
        local_time: new Date().toLocaleString(),
        system_status: threatLevel === 'CRITICAL' ? 'BREACH CONTEXT' : 'OPERATIONAL',
        overall_security_grade: (activeScanState as { grade?: string })?.grade || 'A+'
      },
      telemetry_metrics: {
        threat_level: threatLevel,
        system_state: systemState,
        active_incidents: activeIncidentsCount,
        blocked_threat_signatures: blockedCount,
        network_throughput_bps: networkThroughput,
        active_tunnels: securedNodes,
        db_link_status: dbLinkStatus
      },
      nodes_infrastructure: nodes,
      firewall_policies: rules,
      incident_logs: incidents
    };

    let blob: Blob;
    let filename = `shieldpulse_security_report_${Date.now()}`;

    if (format === 'json') {
      const jsonString = JSON.stringify(exportPayload, null, 2);
      blob = new Blob([jsonString], { type: 'application/json' });
      filename += '.json';
    } else {
      const txtContent = `================================================================================
DEEPSHEILD ENTERPRISE - SECURITY INTELLIGENCE REPORT
Generated: ${exportPayload.report_metadata.local_time} (${exportPayload.report_metadata.generated_at})
System Status: ${exportPayload.report_metadata.system_status}
Security Grade: ${exportPayload.report_metadata.overall_security_grade}
================================================================================

1. TELEMETRY METRICS OVERVIEW
--------------------------------------------------------------------------------
Threat Level:         ${exportPayload.telemetry_metrics.threat_level}
System State:         ${exportPayload.telemetry_metrics.system_state}
Active Incidents:     ${exportPayload.telemetry_metrics.active_incidents}
Blocked Signatures:   ${exportPayload.telemetry_metrics.blocked_threat_signatures}
Network Throughput:   ${exportPayload.telemetry_metrics.network_throughput_bps} B/s
Database Link:        ${exportPayload.telemetry_metrics.db_link_status}

2. INFRASTRUCTURE STATUS
--------------------------------------------------------------------------------
${nodes.map(n => `- [${n.id}] ${n.name} | Region: ${n.region} | Status: ${n.status.toUpperCase()} | CPU: ${n.cpuUsage}% | Latency: ${n.latency}ms`).join('\n')}

3. FIREWALL POLICIES
--------------------------------------------------------------------------------
${rules.length === 0 ? 'No active firewall policies.' : rules.map(r => `- Rule: ${r.id} (${r.isActive ? 'ACTIVE' : 'INACTIVE'}) | Target: ${r.ipRange} | ${r.description}`).join('\n')}

4. LIVE INCIDENT LEDGER
--------------------------------------------------------------------------------
${incidents.length === 0 ? 'No active security incidents.' : incidents.map(i => `[${new Date(i.timestamp).toLocaleTimeString()}] ${i.id} (${i.severity.toUpperCase()}) - ${i.sourceIp} -> ${i.targetService} [${i.status.toUpperCase()}]`).join('\n')}

================================================================================
End of DEEPSHEILD Report
================================================================================
`;
      blob = new Blob([txtContent], { type: 'text/plain' });
      filename += '.txt';
    }

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    logMessage(`REPORT EXPORTED: Successfully downloaded ${filename}`);
  };

  const handleTogglePin = (id: string) => {
    setPinnedAlertIds((prev) =>
      prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id]
    );
  };

  const handleClearAllHistorical = () => {
    setIncidents([]);
    setPinnedAlertIds([]);
    logMessage('AUDIT LEDGER CLEARED: All historical alert records purged.');
  };

  // --- Emergency Lockdown Execution & Prompt Handlers ---
  const handleTriggerLockdownPrompt = useCallback(() => {
    setLockdownModalMode('confirm_engage');
    setIsLockdownModalOpen(true);
  }, []);

  const handleTriggerDisengagePrompt = useCallback(() => {
    setLockdownModalMode('confirm_disengage');
    setIsLockdownModalOpen(true);
  }, []);

  const handleConfirmEngageLockdown = useCallback(() => {
    setIsLockdownActive(true);
    setThreatLevel('CRITICAL');
    setSystemState('DEFCON 1 • SYSTEM EMERGENCY LOCKDOWN');
    setNodes((prev) =>
      prev.map((n) => ({
        ...n,
        status: 'isolated' as const,
        cpuUsage: 0,
        memoryUsage: 0,
        latency: 0,
      }))
    );
    setNetworkThroughput(0);
    setSecuredNodes(0);
    setDbLinkStatus('ISOLATED (Quarantine)');
    setIncidents((prev) =>
      prev.map((i) => (i.status === 'active' ? { ...i, status: 'blocked' as const } : i))
    );
    logMessage('[CRITICAL ACTION] Global perimeter kill-switch engaged. All active ingress ports sealed.');
    fetch('/api/lockdown', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enable: true })
    }).catch(() => {});
    setLockdownModalMode('active_overlay');
  }, [logMessage]);

  const handleConfirmDisengageLockdown = useCallback(() => {
    setIsLockdownActive(false);
    setIsLockdownModalOpen(false);
    setThreatLevel('STABLE');
    setSystemState('DEFCON-5 (ALL SECURE)');
    setNodes([
      {
        id: 'NODE-US-EAST',
        name: 'US-EAST-01 (Primary Gateway)',
        region: 'N. Virginia, USA',
        status: 'operational',
        cpuUsage: 18,
        memoryUsage: 26,
        latency: 14,
      },
      {
        id: 'NODE-EU-WEST',
        name: 'EU-WEST-02 (Core Compute)',
        region: 'Dublin, Ireland',
        status: 'operational',
        cpuUsage: 14,
        memoryUsage: 32,
        latency: 28,
      },
      {
        id: 'NODE-AP-SOUTH',
        name: 'AP-SOUTH-01 (Edge Proxy)',
        region: 'Mumbai, India',
        status: 'operational',
        cpuUsage: 8,
        memoryUsage: 14,
        latency: 42,
      }
    ]);
    setNetworkThroughput(1420);
    setSecuredNodes(3);
    setDbLinkStatus(isSupabaseConfigured ? 'Supabase cloud active' : 'In-Memory DB Online');
    logMessage('[SYSTEM RESTORED] Global perimeter lockdown disengaged. Edge relays re-armed.');
    fetch('/api/lockdown', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enable: false })
    }).catch(() => {});
  }, [logMessage]);

  const handleEmergencyLockdown = useCallback((enable: boolean = true) => {
    if (enable) {
      handleConfirmEngageLockdown();
    } else {
      handleConfirmDisengageLockdown();
    }
  }, [handleConfirmEngageLockdown, handleConfirmDisengageLockdown]);

  // Sync state values with active incident ledger
  useEffect(() => {
    if (isLockdownActive) {
      setThreatLevel('CRITICAL');
      setSystemState('EMERGENCY LOCKDOWN ACTIVE');
      return;
    }

    const activeList = incidents.filter((i) => i.status === 'active');
    setActiveIncidentsCount(activeList.length);

    if (activeList.length === 0) {
      setThreatLevel('STABLE');
      const scanObj = activeScanState as { statusMessage?: string } | null;
      setSystemState(scanObj?.statusMessage || 'DEFCON-5 (OPERATIONAL)');
    } else {
      const criticalCount = activeList.filter((i) => i.severity === 'critical').length;
      const highCount = activeList.filter((i) => i.severity === 'high').length;

      if (criticalCount > 0) {
        setThreatLevel('CRITICAL');
        setSystemState('DEFCON-2 (CRITICAL INCIDENTS DETECTED)');
      } else if (highCount > 0) {
        setThreatLevel('ELEVATED');
        setSystemState('DEFCON-3 (ELEVATED THREAT LEVEL)');
      } else {
        setThreatLevel('STABLE');
        setSystemState('DEFCON-5 (ALL SECURE)');
      }
    }
  }, [incidents, activeScanState, isLockdownActive]);

  useEffect(() => {
    if (isLockdownActive) {
      setBlockedCount(0);
      return;
    }
    const blockedIncidentsCount = incidents.filter((i) => i.status === 'blocked').length;
    setBlockedCount(blockedIncidentsCount);
  }, [incidents, isLockdownActive]);

  useEffect(() => {
    if (isLockdownActive) {
      setSecuredNodes(0);
      return;
    }
    const operationalCount = nodes.filter((n) => n.status !== 'offline' && n.status !== 'isolated').length;
    setSecuredNodes(operationalCount);
  }, [nodes, isLockdownActive]);

  useEffect(() => {
    if (isLockdownActive) {
      setDbLinkStatus('ISOLATED (Quarantine)');
      return;
    }
    setDbLinkStatus(isSupabaseConfigured ? 'Supabase cloud active' : 'In-Memory DB Online');
  }, [isLockdownActive]);

  // --- Manual Threat Injection Engine (Only triggered on button click) ---
  const handleSimulateCriticalAttack = useCallback(() => {
    const threatTemplates = [
      {
        category: 'SQL Injection' as const,
        severity: 'critical' as const,
        targets: ['/api/v1/auth/login', 'PostgreSQL DB Core', '/api/users/profile'],
        ips: ['194.26.29.112', '185.220.101.5', '45.154.255.89'],
        country: 'RU',
        payload: "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --"
      },
      {
        category: 'Port Scan' as const,
        severity: 'medium' as const,
        targets: ['Port 443 (HTTPS Edge)', 'Port 8443 (Kube-API)', 'Port 22 (SSH Gateway)'],
        ips: ['198.51.100.42', '103.203.57.18', '91.240.118.232'],
        country: 'CN',
        payload: 'SYN Stealth Scan detected across ports 20-10000; TCP probe sequence flagged'
      },
      {
        category: 'DDoS' as const,
        severity: 'critical' as const,
        targets: ['Edge Ingress Proxy US-EAST', 'Cloudflare Load Balancer', 'API Gateway Relay'],
        ips: ['185.156.177.34', '193.201.224.23', '45.143.203.111'],
        country: 'NL',
        payload: 'High volume UDP flood: 48,000 req/sec exceeding edge boundary threshold'
      },
      {
        category: 'Brute Force' as const,
        severity: 'high' as const,
        targets: ['OAuth Key Management Service', '/api/v1/checkout/authorize', 'Session Token Broker'],
        ips: ['89.248.163.77', '185.176.27.14', '195.154.122.90'],
        country: 'DE',
        payload: 'Invalid JWT Header: algorithm set to "none" with forged HMAC signature'
      },
      {
        category: 'Brute Force' as const,
        severity: 'high' as const,
        targets: ['SSH Bastion Host', '/admin/portal/sso', 'Vault Secret Manager'],
        ips: ['104.244.76.13', '193.106.191.89', '185.190.141.28'],
        country: 'US',
        payload: 'Repeated authentication failures (42 attempts in 3.2s) with dictionary wordlist'
      },
      {
        category: 'Malware' as const,
        severity: 'critical' as const,
        targets: ['Internal S3 Asset Bucket', 'Build Artifact Staging', '/uploads/media/payload.bin'],
        ips: ['45.133.1.20', '194.36.191.10', '109.237.103.18'],
        country: 'UA',
        payload: 'Binary signature match: Trojan.Linux.Generic.4921 executable upload attempt blocked'
      },
      {
        category: 'Phishing' as const,
        severity: 'high' as const,
        targets: ['/static/..%2f..%2fetc/passwd', 'Web Root File Server', 'Asset Cache Node'],
        ips: ['178.128.240.11', '167.99.145.202', '142.93.180.44'],
        country: 'FR',
        payload: 'GET /static/../../../../etc/passwd HTTP/1.1 (Unicode dot-dot slash bypass attempt)'
      }
    ];

    const template = threatTemplates[Math.floor(Math.random() * threatTemplates.length)];
    const randomIp = template.ips[Math.floor(Math.random() * template.ips.length)];
    const randomTarget = template.targets[Math.floor(Math.random() * template.targets.length)];

    const newIncident: Incident = {
      id: `INC-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      sourceIp: randomIp,
      targetService: randomTarget,
      category: template.category as Incident['category'],
      severity: template.severity,
      status: 'active',
      countryCode: template.country,
      payload: template.payload
    };

    setIncidents((prev) => [newIncident, ...prev.slice(0, 49)]);
    logMessage(`[MANUAL INJECTION] Injected ${newIncident.severity.toUpperCase()} incident ${newIncident.id} (${newIncident.category}) targeting ${newIncident.targetService}`);
  }, [logMessage]);

  const handleScanComplete = useCallback((data: { incidents?: Incident[]; throughput?: number; ssl?: boolean; latency?: number; host?: string; url?: string; grade?: string; headers?: Record<string, string> }) => {
    setIsScanning(false);
    setActiveScanState(data);
    setIncidents(data.incidents || []);
    setNetworkThroughput(data.throughput || 1420);

    setNodes([
      {
        id: 'NODE-US-EAST',
        name: 'US-EAST-01 (Primary Gateway)',
        region: 'N. Virginia, USA',
        status: data.ssl ? 'operational' : 'degraded',
        cpuUsage: Math.min(95, Math.floor((data.throughput || 1200) / 120)),
        memoryUsage: 48,
        latency: data.latency || 25,
      },
      {
        id: 'NODE-EU-WEST',
        name: 'EU-WEST-02 (Core Compute)',
        region: 'Dublin, Ireland',
        status: 'operational',
        cpuUsage: 14,
        memoryUsage: 32,
        latency: (data.latency || 25) + 28,
      },
      {
        id: 'NODE-AP-SOUTH',
        name: 'AP-SOUTH-01 (Edge Proxy)',
        region: 'Mumbai, India',
        status: 'operational',
        cpuUsage: 8,
        memoryUsage: 14,
        latency: 42,
      }
    ]);

    const nextTime = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    const freshPoint: ChartDataPoint = {
      time: nextTime,
      traffic: data.throughput || 1420,
      threats: (data.incidents || []).length,
      blocked: (data.incidents || []).filter((i: Incident) => i.status === 'blocked').length
    };
    setChartData(prev => [...prev.slice(1), freshPoint]);
  }, []);

  const handleFileLoaded = useCallback((
    fileDetails: { name: string; size: number; type: string },
    derivedIncidents: Incident[],
    metrics: { throughput: number; fileSize: number }
  ) => {
    setIsScanning(false);
    setActiveScanState({ fileDetails, derivedIncidents, metrics });
    setIncidents(derivedIncidents);
    setNetworkThroughput(metrics.throughput);

    const nextTime = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    const freshPoint: ChartDataPoint = {
      time: nextTime,
      traffic: metrics.throughput,
      threats: derivedIncidents.length,
      blocked: derivedIncidents.filter(i => i.status === 'blocked').length
    };
    setChartData(prev => [...prev.slice(1), freshPoint]);
  }, []);

  const handleBlockIp = (ip: string, category: string) => {
    const newRuleId = `FW-RULE-${Math.floor(Math.random() * 900) + 100}`;
    const newRule: FirewallRule = {
      id: newRuleId,
      ipRange: `${ip}/32`,
      description: `Automated block from alert: ${category}`,
      action: 'block',
      createdBy: 'sec-ops-bot',
      createdAt: new Date().toISOString(),
      isActive: true,
    };

    setRules((prev) => [newRule, ...prev]);
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.sourceIp === ip && inc.status === 'active') {
          return { ...inc, status: 'blocked' as const };
        }
        return inc;
      })
    );

    logMessage(`POLICY RULE ENFORCED: Blocked ${ip}/32 via rule ${newRuleId}`);
  };

  const handleResolveIncident = (id: string) => {
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id === id) {
          return { ...inc, status: 'resolved' as const };
        }
        return inc;
      })
    );
    logMessage(`ALERT RESOLVED: Incident ticket ${id}`);
  };

  const handleRebootNode = (id: string) => {
    setNodes((prev) =>
      prev.map((node) => {
        if (node.id === id) {
          return {
            ...node,
            status: 'offline' as const,
            cpuUsage: 0,
            memoryUsage: 0,
            latency: 999,
          };
        }
        return node;
      })
    );
    logMessage(`REBOOTING NODE: ${id}...`);

    setTimeout(() => {
      setNodes((prev) =>
        prev.map((node) => {
          if (node.id === id) {
            logMessage(`BOOT COMPLETE: Gateway Node ${node.name} reconnected.`);
            return {
              ...node,
              status: 'operational' as const,
              cpuUsage: 22,
              memoryUsage: 38,
              latency: 18,
            };
          }
          return node;
        })
      );
    }, 3000);
  };

  const handleIsolateNode = (id: string) => {
    setNodes((prev) =>
      prev.map((node) => {
        if (node.id === id) {
          const nextStatus = node.status === 'isolated' ? ('operational' as const) : ('isolated' as const);
          logMessage(`NODE STATUS CHANGED: ${id} set to ${nextStatus.toUpperCase()}.`);
          return {
            ...node,
            status: nextStatus,
            cpuUsage: nextStatus === 'isolated' ? 0 : 25,
            latency: nextStatus === 'isolated' ? 0 : 35,
          };
        }
        return node;
      })
    );
  };

  const handleAddRule = (newRuleData: Omit<FirewallRule, 'id' | 'createdAt' | 'createdBy'>) => {
    const newRule: FirewallRule = {
      ...newRuleData,
      id: `FW-RULE-${Math.floor(Math.random() * 800) + 200}`,
      createdAt: new Date().toISOString(),
      createdBy: 'admin@shieldpulse.enterprise',
    };

    setRules((prev) => [newRule, ...prev]);
    logMessage(`FIREWALL RULE ADDED: ${newRule.id} target ${newRule.ipRange}`);
  };

  const handleToggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((rule) => {
        if (rule.id === id) {
          return { ...rule, isActive: !rule.isActive };
        }
        return rule;
      })
    );
  };

  const handleDeleteRule = (id: string) => {
    setRules((prev) => prev.filter((r) => r.id !== id));
    logMessage(`FIREWALL RULE DELETED: ${id}`);
  };

  const handleForceRefresh = () => {
    if (isLockdownActive) return;
    setChartData((prev) => {
      const nextTime = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
      return [
        ...prev.slice(1),
        {
          time: nextTime,
          traffic: Math.floor(Math.random() * 200) + 1300,
          threats: incidents.filter((i) => i.status === 'active').length,
          blocked: incidents.filter((i) => i.status === 'blocked').length,
        },
      ];
    });
  };

  const isDark = theme === 'dark';

  return (
    <div id="app-viewport" className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 bg-light-mesh dark:bg-deep-mesh flex flex-col font-sans selection:bg-sky-600/30 selection:text-slate-900 dark:selection:text-slate-100 relative transition-colors duration-150">
      {/* 1. Enterprise Header Navigation */}
      <StatusBanner
        activeIncidentsCount={activeIncidentsCount}
        threatLevel={threatLevel}
        systemState={systemState}
        isLockdownActive={isLockdownActive}
        onToggleLockdown={handleTriggerLockdownPrompt}
        onRestoreSystem={handleTriggerDisengagePrompt}
        onOpenDrawer={() => setIsCommandPaletteOpen(true)}
        historicalAlertsCount={incidents.filter(inc => inc.severity === 'critical' || inc.severity === 'high').length}
        pinnedCount={pinnedAlertIds.length}
        onSimulateCriticalAttack={handleSimulateCriticalAttack}
        theme={theme}

      />

      <NotificationDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        incidents={incidents}
        pinnedAlertIds={pinnedAlertIds}
        onTogglePin={handleTogglePin}
        onClearAllHistorical={handleClearAllHistorical}
      />

      {/* 2. Primary Enterprise Top Navigation Bar */}
      <div className="max-w-7xl w-full mx-auto px-4 mt-6">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-slate-200 dark:border-slate-800 pb-4 gap-4">
          <div className="flex items-center gap-2 p-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs dark:shadow-lg">
            <button
              onClick={() => setActiveTab('console')}
              className={`px-4 py-2 text-xs font-bold rounded-lg flex items-center gap-2 transition-all cursor-pointer ${
                activeTab === 'console'
                  ? 'bg-sky-600 text-white dark:text-slate-950 shadow-md font-bold'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60'
              }`}
            >
              <Shield className="w-4 h-4" />
              Threat Console
            </button>
            <button
              onClick={() => setActiveTab('ingress')}
              className={`px-4 py-2 text-xs font-bold rounded-lg flex items-center gap-2 transition-all cursor-pointer ${
                activeTab === 'ingress'
                  ? 'bg-sky-600 text-white dark:text-slate-950 shadow-md font-bold'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60'
              }`}
            >
              <Search className="w-4 h-4" />
              Ingress Scanner
            </button>
            <button
              onClick={() => setActiveTab('secops')}
              className={`px-4 py-2 text-xs font-bold rounded-lg flex items-center gap-2 transition-all cursor-pointer ${
                activeTab === 'secops'
                  ? 'bg-sky-600 text-white dark:text-slate-950 shadow-md font-bold'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60'
              }`}
            >
              <Activity className="w-4 h-4" />
              SecOps Suite
            </button>
          </div>

          {/* Export Telemetry Report Dropdown */}
          <div ref={exportDropdownRef} className="relative">
            <button
              id="export-metrics-btn"
              onClick={() => setIsExportDropdownOpen(!isExportDropdownOpen)}
              className="px-4 py-2 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-800 rounded-xl text-xs font-semibold flex items-center gap-2 transition cursor-pointer shadow-xs"
            >
              <Download className="w-4 h-4 text-sky-500 dark:text-sky-400" />
              <span>Export Report</span>
              <ChevronDown className={`w-3.5 h-3.5 transition-transform ${isExportDropdownOpen ? 'rotate-180' : ''}`} />
            </button>

            <AnimatePresence>
              {isExportDropdownOpen && (
                <motion.div
                  initial={{ opacity: 0, y: 8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: 8, scale: 0.98 }}
                  transition={{ duration: 0.12 }}
                  className="absolute right-0 mt-2 w-56 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xl p-1.5 z-50 text-xs font-sans"
                >
                  <div className="px-3 py-1.5 text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider border-b border-slate-100 dark:border-slate-800">
                    Export Format
                  </div>
                  <button
                    onClick={() => {
                      handleExportData('json');
                      setIsExportDropdownOpen(false);
                    }}
                    className="w-full text-left px-3 py-2 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white rounded-lg flex items-center gap-2 transition cursor-pointer mt-1"
                  >
                    <FileJson className="w-4 h-4 text-sky-500 dark:text-blue-400" />
                    <div>
                      <div className="font-semibold text-slate-800 dark:text-slate-200">Raw Dataset (JSON)</div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400">Full telemetry dump</div>
                    </div>
                  </button>
                  <button
                    onClick={() => {
                      handleExportData('txt');
                      setIsExportDropdownOpen(false);
                    }}
                    className="w-full text-left px-3 py-2 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white rounded-lg flex items-center gap-2 transition cursor-pointer"
                  >
                    <FileText className="w-4 h-4 text-amber-500 dark:text-amber-400" />
                    <div>
                      <div className="font-semibold text-slate-800 dark:text-slate-200">Formatted Brief (TXT)</div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400">Executive summary</div>
                    </div>
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* 3. Tab Views Content */}
      <AnimatePresence mode="wait">
        {/* TAB 1: THREAT CONSOLE */}
        {activeTab === 'console' && (
          <motion.div
            key="console"
            variants={tabContainerVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            className="space-y-6"
          >
            {/* KPI Cards & System Summary */}
            <div className="max-w-7xl w-full mx-auto px-4 mt-6">
              <MetricCards
                networkThroughput={networkThroughput}
                activeTunnels={securedNodes}
                infrastructureIntegrity={99.4}
              />
              <div className="mt-4">
                <SystemHealthSummary
                  isSimulating={false}
                  activeIncidentsCount={activeIncidentsCount}
                />
              </div>
            </div>

            {/* Main Console Grid */}
            <main className="max-w-7xl w-full mx-auto px-4 grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left Column (2/3 width): Graphs, Map & Incident Ledger */}
              <div className="lg:col-span-2 space-y-6 flex flex-col">
                <motion.div variants={tabItemVariants}>
                  <PulseChart
                    data={chartData}
                    isSimulating={false}
                    onRefresh={handleForceRefresh}
                  />
                </motion.div>

                <motion.div variants={tabItemVariants}>
                  <ThreatMap
                    incidents={incidents}
                    nodes={nodes}
                    isLockdownActive={isLockdownActive}
                  />
                </motion.div>

                <motion.div variants={tabItemVariants} className="flex-1">
                  <IncidentLogs
                    incidents={incidents}
                    onBlockIp={handleBlockIp}
                    onResolveIncident={handleResolveIncident}
                  />
                </motion.div>
              </div>

              {/* Right Column (1/3 width): Nodes, Firewall & Database Sync */}
              <div className="space-y-6 flex flex-col">
                <motion.div variants={tabItemVariants}>
                  <NodeManager
                    nodes={nodes}
                    onRebootNode={handleRebootNode}
                    onIsolateNode={handleIsolateNode}
                  />
                </motion.div>

                <motion.div variants={tabItemVariants}>
                  <FirewallRules
                    rules={rules}
                    onAddRule={handleAddRule}
                    onToggleRule={handleToggleRule}
                    onDeleteRule={handleDeleteRule}
                    autoContainmentEnabled={autoContainmentEnabled}
                    onToggleAutoContainment={setAutoContainmentEnabled}
                  />
                </motion.div>

                <motion.div variants={tabItemVariants}>
                  <DatabaseSync
                    isSynced={isSupabaseConfigured}
                  />
                </motion.div>

                {/* Telemetry Log Terminal */}
                <motion.div 
                  variants={tabItemVariants}
                  className="bg-[#161b22] border border-[#30363d] rounded-xl p-4 font-mono text-xs shadow-sm flex-1 min-h-[160px] flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between border-b border-slate-700/60 pb-2 mb-2">
                      <div className="flex items-center gap-2 text-blue-400 font-semibold">
                        <Terminal className="w-4 h-4" />
                        <span>System Telemetry Log</span>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        <Filter className="w-3 h-3 text-slate-400" />
                        <select
                          value={terminalSeverityFilter}
                          onChange={(e) => setTerminalSeverityFilter(e.target.value as any)}
                          className="bg-slate-900 border border-slate-700 text-[10px] text-slate-300 rounded px-2 py-0.5"
                        >
                          <option value="ALL">All</option>
                          <option value="INFO">Info</option>
                          <option value="WARNING">Warning</option>
                          <option value="CRITICAL">Critical</option>
                        </select>
                      </div>
                    </div>
                    
                    <div className="space-y-1 max-h-[140px] overflow-y-auto text-slate-300 text-[11px]">
                      {systemLogs
                        .filter(log => {
                          if (terminalSeverityFilter === 'ALL') return true;
                          const upper = log.toUpperCase();
                          if (terminalSeverityFilter === 'CRITICAL') return upper.includes('CRITICAL') || upper.includes('LOCKDOWN') || upper.includes('BREACH');
                          if (terminalSeverityFilter === 'WARNING') return upper.includes('WARN') || upper.includes('ALERT') || upper.includes('FLAGGED');
                          return !upper.includes('CRITICAL') && !upper.includes('WARN');
                        })
                        .map((log, idx) => (
                          <div key={idx} className="py-0.5 border-b border-slate-800/40 last:border-0 font-mono">
                            {log}
                          </div>
                        ))}
                    </div>
                  </div>
                  <div className="border-t border-slate-800/60 pt-2 mt-2 flex justify-between items-center text-[10px] text-slate-400">
                    <span>Engine: Active</span>
                    <span className="text-emerald-400 font-medium">● Telemetry Live</span>
                  </div>
                </motion.div>
              </div>
            </main>
          </motion.div>
        )}

        {/* TAB 2: INGRESS SCANNER */}
        {activeTab === 'ingress' && (
          <motion.div
            key="ingress"
            variants={tabContainerVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            className="space-y-6 max-w-7xl mx-auto px-4 mt-6"
          >
            <TargetAnalysisHub
              onScanComplete={handleScanComplete}
              onFileLoaded={handleFileLoaded}
              onLogMessage={logMessage}
              onScanStart={() => setIsScanning(true)}
            />

            <ScanSafetyAnalysis
              scanData={activeScanState}
              isScanning={isScanning}
              onClearScan={() => {
                setActiveScanState(null);
                setIsScanning(false);
                logMessage('AUDIT ENGINE: Cleared active scan analysis state.');
              }}
              onIsolateTarget={(targetName) => {
                logMessage(`ZERO-TRUST CONTAINMENT: Quarantining target '${targetName}'.`);
                handleEmergencyLockdown(true);
              }}
              onDownloadReport={() => handleExportData('json')}
            />
          </motion.div>
        )}

        {/* TAB 3: SECOPS SUITE */}
        {activeTab === 'secops' && (
          <motion.div
            key="secops"
            variants={tabContainerVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
          >
            <SecOpsSuite
              incidents={incidents}
              setIncidents={setIncidents}
              onResolveIncident={handleResolveIncident}
              onBlockIp={handleBlockIp}
              nodes={nodes}
              onIsolateNode={handleIsolateNode}
              rules={rules}
              setRules={setRules}
              dbLinkStatus={dbLinkStatus}
              onLogMessage={logMessage}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Emergency Lockdown Modal */}
      <EmergencyLockdownModal
        isOpen={isLockdownModalOpen}
        isLockdownActive={isLockdownActive}
        mode={lockdownModalMode}
        onConfirmEngage={handleConfirmEngageLockdown}
        onConfirmDisengage={handleConfirmDisengageLockdown}
        onClose={() => setIsLockdownModalOpen(false)}
        isolatedNodesCount={nodes.filter((n) => n.status === 'isolated' || n.status === 'offline').length}
        totalNodesCount={nodes.length}
      />

      {/* 4. Minimalist Enterprise Footer */}
      <footer id="footer-panel" className="mt-16 border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 py-5 text-center text-xs text-slate-500 dark:text-slate-400 transition-colors duration-150">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row justify-between items-center gap-2">
          <p>© 2026 DEEPSHEILD Enterprise. Cyber Operations Console.</p>
          <p className="font-mono text-slate-500 dark:text-slate-400">Environment: Operational • TLS 1.3 Encrypted</p>
        </div>
      </footer>

      <AISecurityBot activeState={activeScanState} onLogMessage={logMessage} />

      <CommandPaletteModal
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onSelectTab={(tab) => setActiveTab(tab)}
        onToggleLockdown={isLockdownActive ? handleTriggerDisengagePrompt : handleTriggerLockdownPrompt}
        onIsolateNode={(id) => handleIsolateNode(id)}
        onToggleTheme={handleToggleTheme}
        onSimulateCriticalAttack={handleSimulateCriticalAttack}
        nodes={nodes}
        incidents={incidents}
        theme={theme}
      />
    </div>
  );
}
