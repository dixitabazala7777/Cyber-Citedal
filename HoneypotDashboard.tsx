import React, { useEffect, useState, useRef } from 'react';
import { HoneypotEvent, HoneypotSensor, ActiveBlocklistRule, HoneypotAnalytics, DeceptionTestResult } from '../types/honeypot';
import { HoneypotStreamService } from '../services/honeypotStreamService';
import { LiveTerminalFeed } from './LiveTerminalFeed';
import { HoneypotDecoyBar } from './HoneypotDecoyBar';
import { motion, AnimatePresence } from 'motion/react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import {
  Shield, Play, Pause, Radio, Cpu, AlertTriangle,
  MapPin, ShieldAlert, CheckCircle, Flame, Plus, X, Server
} from 'lucide-react';

interface HoneypotDashboardProps {
  isLockdownActive?: boolean;
  onLogMessage: (msg: string, type?: 'info' | 'success' | 'warn' | 'error') => void;
  onBlockIp?: (ip: string) => void;
}

const COLORS = ['#10b981', '#34d399', '#d29922', '#da3633', '#10b981'];

export const HoneypotDashboard: React.FC<HoneypotDashboardProps> = ({ isLockdownActive = false, onLogMessage, onBlockIp }) => {
  const [events, setEvents] = useState<HoneypotEvent[]>([]);
  const [streamActive, setStreamActive] = useState(true);
  const [blocklist, setBlocklist] = useState<ActiveBlocklistRule[]>([]);
  const [analytics, setAnalytics] = useState<HoneypotAnalytics>({
    topTargetedPorts: [],
    attackerGeoStats: []
  });

  const [sensors, setSensors] = useState<HoneypotSensor[]>([
    { id: 'S-01', name: 'SSH-Cowrie-Decoy-Prod', serviceType: 'Cowrie', status: 'operational', cpu: 1.2, memory: 12, hitCount: 142, port: 22 },
    { id: 'S-02', name: 'DB-Dionaea-Trap-01', serviceType: 'Dionaea', status: 'operational', cpu: 0.8, memory: 8, hitCount: 89, port: 445 },
    { id: 'S-03', name: 'PLC-Conpot-SCADA', serviceType: 'Conpot', status: 'operational', cpu: 2.1, memory: 18, hitCount: 34, port: 502 },
    { id: 'S-04', name: 'Web-ElasticPot-Decoy', serviceType: 'ElasticPot', status: 'operational', cpu: 1.5, memory: 14, hitCount: 104, port: 80 }
  ]);

  const [testPayload, setTestPayload] = useState("SELECT * FROM users WHERE '1'='1' -- AND DROP TABLE credentials;");
  const [testDeceptionResult, setTestDeceptionResult] = useState<DeceptionTestResult | null>(null);
  const [isTestingDeception, setIsTestingDeception] = useState(false);

  const handleRunDeceptionTest = async () => {
    setIsTestingDeception(true);
    setTestDeceptionResult(null);
    try {
      const res = await fetch('/api/v1/shield/process', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer deepshield-secret-token-2026'
        },
        body: JSON.stringify({ prompt: testPayload })
      });
      const data = await res.json();
      setTestDeceptionResult(data);
      onLogMessage(`DECEPT CORE: Processed payload through LLM Sandbox Engine. Status: ${data.status}`, 'warn');
    } catch (e) {
      console.warn("Deception Test Error:", e);
    } finally {
      setIsTestingDeception(false);
    }
  };
  const [manualIp, setManualIp] = useState('');
  const [manualReason, setManualReason] = useState('');
  const [showBlockModal, setShowBlockModal] = useState(false);

  const streamServiceRef = useRef<HoneypotStreamService | null>(null);

  const loadAnalytics = async () => {
    if (!streamServiceRef.current) return;
    const data = await streamServiceRef.current.fetchAnalytics();
    if (data) {
      setAnalytics({
        topTargetedPorts: data.topTargetedPorts || [],
        attackerGeoStats: data.attackerGeoStats || []
      });
      if (data.rules) {
        setBlocklist(data.rules);
      }
    }
  };

  useEffect(() => {
    const service = new HoneypotStreamService();
    streamServiceRef.current = service;

    loadAnalytics();

    if (streamActive) {
      service.connect((event) => {
        setEvents((prev) => {
          const next = [...prev, event];
          return next.slice(-200);
        });

        setSensors((prevSensors) =>
          prevSensors.map((sensor) => {
            if (sensor.serviceType === event.service) {
              const cpuDelta = (Math.random() * 4 - 2);
              const memDelta = (Math.random() * 2 - 1);
              return {
                ...sensor,
                hitCount: sensor.hitCount + 1,
                cpu: Math.max(0.5, Math.min(15, Number((sensor.cpu + cpuDelta).toFixed(1)))),
                memory: Math.max(4, Math.min(32, Number((sensor.memory + memDelta).toFixed(1))))
              };
            }
            return sensor;
          })
        );
      });
    }

    const analyticInterval = setInterval(() => {
      loadAnalytics();
    }, 5000);

    return () => {
      service.disconnect();
      clearInterval(analyticInterval);
    };
  }, [streamActive]);

  const uniqueIps = Array.from(new Set(events.map(e => e.attackerIp)));
  const totalHitCount = events.length;

  const handleBlockIpSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualIp) return;

    if (streamServiceRef.current) {
      await streamServiceRef.current.blockIp(manualIp, manualReason || 'Manual Admin threat quarantine');
      setBlocklist(prev => {
        const exists = prev.some(r => r.ip === manualIp);
        if (exists) return prev;
        return [
          ...prev,
          {
            id: `FR-${Math.floor(1000 + Math.random() * 9000)}`,
            ip: manualIp,
            bannedAt: new Date().toLocaleTimeString(),
            reason: manualReason || 'Manual Admin threat quarantine',
            duration: '24 Hours'
          }
        ];
      });
      onLogMessage(`Threat isolated: Blocklisted attacker IP ${manualIp} successfully!`, 'success');
      setManualIp('');
      setManualReason('');
      setShowBlockModal(false);
    }
  };

  const handleBlockIpQuick = async (ip: string, reason: string) => {
    if (streamServiceRef.current) {
      await streamServiceRef.current.blockIp(ip, reason);
      setBlocklist(prev => {
        if (prev.some(r => r.ip === ip)) return prev;
        return [
          ...prev,
          {
            id: `FR-${Math.floor(1000 + Math.random() * 9000)}`,
            ip,
            bannedAt: new Date().toLocaleTimeString(),
            reason,
            duration: '24 Hours'
          }
        ];
      });
      onLogMessage(`Threat isolated: Banned intruder IP ${ip} across firewall clusters!`, 'success');
    }
  };

  const handleUnblockIp = (ip: string) => {
    setBlocklist(prev => prev.filter(r => r.ip !== ip));
    onLogMessage(`Rule relaxed: Restored egress route for IP ${ip}`, 'info');
  };

  return (
    <div className="space-y-6">
      {/* Upper Status & Control Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 rounded-2xl p-5 gap-4">
        <div>
          <h2 className="text-lg font-sans font-bold text-white tracking-tight flex items-center gap-2">
            <Radio className="w-5 h-5 text-indigo-400 animate-pulse" />
            LIVE HONEYPOT & DECOY TELEMETRY
          </h2>
          <p className="text-xs text-zinc-400 font-sans mt-0.5">
            Active threat replication sensors capturing high-fidelity credential probes, SCADA PLC injections, and malware payloads in real-time.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              setStreamActive(!streamActive);
              onLogMessage(
                streamActive ? 'Honeypot telemetry ingestion PAUSED.' : 'Honeypot socket ingestion STARTED.',
                streamActive ? 'warn' : 'success'
              );
            }}
            className={`px-4 py-2 rounded-full font-mono text-xs font-semibold uppercase transition flex items-center gap-2 cursor-pointer border ${streamActive
              ? 'bg-amber-950/30 text-amber-300 border-amber-800/50 hover:bg-amber-900/30'
              : 'bg-emerald-950/30 text-emerald-300 border-emerald-800/50 hover:bg-emerald-900/30'
              }`}
          >
            {streamActive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            {streamActive ? 'Pause Ingestion' : 'Resume Ingestion'}
          </button>

          <button
            onClick={() => setShowBlockModal(true)}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-full font-mono text-xs font-semibold uppercase transition flex items-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(99,102,241,0.25)] border border-indigo-400/30"
          >
            <Plus className="w-3.5 h-3.5" />
            Manual Block
          </button>
        </div>
      </div>

      {/* Real-time Decoy Activity & Threat Interaction Bar */}
      <HoneypotDecoyBar
        isOffline={!streamActive || isLockdownActive}
        loadLevel={isLockdownActive ? 0 : undefined}
        activeDecoysCount={isLockdownActive ? 0 : sensors.filter(s => s.status === 'operational').length}
        totalDecoysCount={sensors.length}
        onLogMessage={onLogMessage}
      />

      {/* Header Metric Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 p-5 rounded-2xl flex items-center justify-between shadow-2xl">
          <div className="space-y-1">
            <span className="text-[11px] text-zinc-400 font-semibold tracking-wider block uppercase font-sans">TOTAL DECOY ALERTS</span>
            <span className="text-2xl font-sans font-bold text-white tracking-tight">{totalHitCount || 40}</span>
            <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-mono">
              <Flame className="w-3 h-3 animate-bounce" /> Live socket broadcasting
            </span>
          </div>
          <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/20 rounded-xl text-indigo-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        {/* Metric 2 */}
        <div className="bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 p-5 rounded-2xl flex items-center justify-between shadow-2xl">
          <div className="space-y-1">
            <span className="text-[11px] text-zinc-400 font-semibold tracking-wider block uppercase font-sans">UNIQUE INTRUDER IPS</span>
            <span className="text-2xl font-sans font-bold text-white tracking-tight">{uniqueIps.length || 8}</span>
            <span className="text-[10px] text-zinc-400 font-mono">Distinct geographic hosts</span>
          </div>
          <div className="p-2.5 bg-violet-500/10 border border-violet-500/20 rounded-xl text-violet-400">
            <MapPin className="w-5 h-5" />
          </div>
        </div>

        {/* Metric 3 */}
        <div className="bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 p-5 rounded-2xl flex items-center justify-between shadow-2xl">
          <div className="space-y-1">
            <span className="text-[11px] text-zinc-400 font-semibold tracking-wider block uppercase font-sans">TOP TARGETED PORT</span>
            <span className="text-2xl font-sans font-bold text-rose-400 tracking-tight">Port 22 (SSH)</span>
            <span className="text-[10px] text-rose-400/80 font-mono">Cowrie replica matches</span>
          </div>
          <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400">
            <AlertTriangle className="w-5 h-5 animate-pulse" />
          </div>
        </div>

        {/* Metric 4 */}
        <div className="bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 p-5 rounded-2xl flex items-center justify-between shadow-2xl">
          <div className="space-y-1">
            <span className="text-[11px] text-zinc-400 font-semibold tracking-wider block uppercase font-sans">SENSORS IN SERVICE</span>
            <span className="text-2xl font-sans font-bold text-emerald-400 tracking-tight">4 / 4 Active</span>
            <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-mono">
              <CheckCircle className="w-3 h-3 text-emerald-400" /> Operational status 100%
            </span>
          </div>
          <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-400">
            <Server className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Sensors Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {sensors.map((sensor) => (
          <div key={sensor.id} className="bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 rounded-2xl p-5 space-y-4 hover:border-white/20 transition-all duration-200 shadow-2xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-indigo-400 animate-pulse" />
                <span className="text-xs font-mono font-bold text-white">{sensor.name}</span>
              </div>
              <span className="text-[10px] bg-indigo-950/40 border border-indigo-800/40 text-indigo-300 px-2 py-0.5 rounded-full font-mono font-semibold uppercase">
                Port {sensor.port}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-center bg-black/40 rounded-xl py-2 px-1 border border-white/5">
              <div>
                <span className="text-[9px] text-zinc-500 block font-mono">CPU LOAD</span>
                <span className="text-xs font-mono font-bold text-zinc-200">{sensor.cpu}%</span>
              </div>
              <div>
                <span className="text-[9px] text-zinc-500 block font-mono">RAM ALLOC</span>
                <span className="text-xs font-mono font-bold text-zinc-200">{sensor.memory} MB</span>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-zinc-500">Decoy Hits</span>
              <span className="text-indigo-400 font-bold">{sensor.hitCount}</span>
            </div>

            {/* Health Bar */}
            <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-indigo-500 transition-all duration-500"
                style={{ width: `${Math.min(100, Math.max(10, (sensor.hitCount / 200) * 100))}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Targeted Ports */}
        <div className="bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 p-6 rounded-2xl shadow-2xl flex flex-col h-[340px]">
          <h3 className="text-xs font-sans font-bold text-white mb-4 flex items-center gap-2 border-b border-white/5 pb-2 uppercase tracking-wider">
            <Flame className="w-4 h-4 text-rose-500" /> Top Targeted Ports (Hits)
          </h3>
          <div className="flex-1 w-full text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analytics.topTargetedPorts}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="name" stroke="#8b949e" tickLine={false} />
                <YAxis stroke="#8b949e" tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#161b22', borderColor: 'rgba(255,255,255,0.1)', color: '#ffffff', fontFamily: 'monospace' }}
                  cursor={{ fill: 'rgba(99,102,241,0.05)' }}
                />
                <Bar dataKey="hits" fill="#10b981" radius={[4, 4, 0, 0]}>
                  {analytics.topTargetedPorts.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Attacker Geo Breakdowns */}
        <div className="bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 p-6 rounded-2xl shadow-2xl flex flex-col h-[340px]">
          <h3 className="text-xs font-sans font-bold text-white mb-4 flex items-center gap-2 border-b border-white/5 pb-2 uppercase tracking-wider">
            <MapPin className="w-4 h-4 text-cyan-400" /> Attacker Geo-Location Source (Hits)
          </h3>
          <div className="flex-1 w-full text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={analytics.attackerGeoStats}
                  cx="50%"
                  cy="45%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={5}
                  dataKey="hits"
                >
                  {analytics.attackerGeoStats.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#161b22', borderColor: 'rgba(255,255,255,0.1)', color: '#ffffff', fontFamily: 'monospace' }}
                />
                <Legend layout="horizontal" verticalAlign="bottom" align="center" wrapperStyle={{ fontFamily: 'monospace', fontSize: '10px', color: '#8b949e' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Dynamic AI Honeypot & Deception Core Simulator Card (macOS frame) */}
      <div className="bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 rounded-2xl p-6 shadow-2xl space-y-4">
        <div className="flex justify-between items-center border-b border-white/5 pb-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-indigo-400 animate-pulse" />
            <h3 className="text-xs font-bold text-white uppercase font-sans tracking-tight">DYNAMIC AI HONEYPOT & DECEPTION SANDBOX CORE</h3>
          </div>
          <span className="px-2.5 py-0.5 bg-indigo-950/40 text-indigo-300 border border-indigo-800/40 rounded-full text-[10px] font-mono font-semibold">
            [HONEYPOT_DECEPT_TRAP] ACTIVE
          </span>
        </div>

        <p className="text-xs text-zinc-400 font-sans">
          When Gate 4 or Gate 5 detects high-confidence threat vectors (SQLi, XSS, Prompt Injection), incoming payloads are silently rerouted to an isolated LLM Sandbox Engine that synthesizes mock database responses and fake cloud keys.
        </p>

        <div className="space-y-3">
          <div className="flex gap-2">
            <input
              type="text"
              value={testPayload}
              onChange={(e) => setTestPayload(e.target.value)}
              placeholder="Test attack vector (e.g., SELECT * FROM users or system prompt override)..."
              className="bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-xs font-mono text-zinc-200 flex-1 focus:outline-none focus:border-indigo-500"
            />
            <button
              onClick={handleRunDeceptionTest}
              disabled={isTestingDeception}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-mono font-bold cursor-pointer transition flex items-center gap-1.5 shadow-[0_0_20px_rgba(99,102,241,0.3)] disabled:opacity-50"
            >
              {isTestingDeception ? "SIMULATING..." : "SIMULATE TRAP"}
            </button>
          </div>

          {testDeceptionResult && (
            <div className="p-4 bg-black/60 border border-white/10 rounded-xl space-y-2 font-mono">
              <div className="flex justify-between items-center border-b border-white/5 pb-2 text-[10px]">
                <span className="text-zinc-400 font-bold">SANDBOX RESPONSE: <strong className="text-rose-400">{testDeceptionResult.status}</strong></span>
                <span className="text-zinc-500">Execution: {testDeceptionResult.execution_time_ms}ms</span>
              </div>
              <pre className="text-[11px] text-emerald-400/90 whitespace-pre-wrap break-all bg-black/40 p-3 rounded-lg border border-white/5 max-h-48 overflow-y-auto font-mono">
                {testDeceptionResult.deception_payload || testDeceptionResult.ai_response}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* Live Terminal Log Component */}
      <LiveTerminalFeed
        events={events}
        onClear={() => setEvents([])}
        onBlockIp={(ip, reason) => handleBlockIpQuick(ip, reason)}
      />

      {/* Active IP Isolation List */}
      <div className="bg-[#090c10]/80 backdrop-blur-md border border-white/10 ring-1 ring-white/5 rounded-2xl p-6 shadow-2xl space-y-4">
        <h3 className="text-xs font-sans font-bold text-white flex items-center gap-2 border-b border-white/5 pb-2 uppercase tracking-wider">
          <Shield className="w-4 h-4 text-indigo-400" /> Active Threat Blocklist & Mitigation Rules ({blocklist.length})
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-white/5 text-zinc-400 font-semibold text-[10px] uppercase">
                <th className="py-3 px-4">RULE ID</th>
                <th className="py-3 px-4">ATTACKER IP</th>
                <th className="py-3 px-4">BANNED TIMESTAMP</th>
                <th className="py-3 px-4">MITIGATION REASON</th>
                <th className="py-3 px-4">DURATION</th>
                <th className="py-3 px-4 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-zinc-300">
              {blocklist.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-zinc-500 italic font-sans">
                    No active threat blocklists declared. Firewall clusters cleared.
                  </td>
                </tr>
              ) : (
                blocklist.map((rule) => (
                  <tr key={rule.id} className="hover:bg-white/5 transition-colors">
                    <td className="py-3 px-4 font-bold text-zinc-400">{rule.id}</td>
                    <td className="py-3 px-4 text-rose-400 font-bold">{rule.ip}</td>
                    <td className="py-3 px-4 text-zinc-500">{rule.bannedAt}</td>
                    <td className="py-3 px-4 text-zinc-400 max-w-xs truncate">{rule.reason}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 bg-rose-950/40 text-rose-300 border border-rose-800/40 rounded-full text-[9px] uppercase font-bold">
                        {rule.duration}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleUnblockIp(rule.ip)}
                        className="px-2.5 py-1 bg-white/5 hover:bg-white/10 text-zinc-300 hover:text-white border border-white/10 rounded-lg text-[10px] font-bold transition cursor-pointer"
                      >
                        Unblock IP
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manual Block IP Modal */}
      <AnimatePresence>
        {showBlockModal && (
          <div className="fixed inset-0 bg-black/85 backdrop-blur-md flex items-center justify-center z-50 p-4">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-[#090c10] border border-white/10 ring-1 ring-white/10 rounded-2xl w-full max-w-md p-6 relative shadow-2xl space-y-4"
            >
              <button
                onClick={() => setShowBlockModal(false)}
                className="absolute right-4 top-4 text-zinc-500 hover:text-zinc-300 transition cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>

              <div className="space-y-1">
                <h4 className="text-sm font-sans font-bold text-white uppercase flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-500" /> ISOLATE THREAT & BAN IP
                </h4>
                <p className="text-xs text-zinc-400 font-sans">
                  Deploy immediate network route blocking across active border routers, edge proxies, and replica containers.
                </p>
              </div>

              <form onSubmit={handleBlockIpSubmit} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-[10px] font-mono text-zinc-400 block uppercase">ATTACKER IPv4 ADDRESS</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 185.156.177.34"
                    value={manualIp}
                    onChange={(e) => setManualIp(e.target.value)}
                    className="w-full bg-black/60 border border-white/10 hover:border-white/20 focus:border-indigo-500 rounded-xl px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none transition-all"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-mono text-zinc-400 block uppercase">REASON FOR ISOLATION</label>
                  <textarea
                    rows={3}
                    placeholder="Describe specific intrusion activity or indicator of compromise..."
                    value={manualReason}
                    onChange={(e) => setManualReason(e.target.value)}
                    className="w-full bg-black/60 border border-white/10 hover:border-white/20 focus:border-indigo-500 rounded-xl px-3 py-2 text-xs text-zinc-200 font-sans focus:outline-none transition-all"
                  />
                </div>

                <div className="flex justify-end gap-2.5 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowBlockModal(false)}
                    className="px-4 py-2 bg-white/5 hover:bg-white/10 text-zinc-300 border border-white/10 rounded-xl text-xs font-mono uppercase transition cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-mono font-bold uppercase transition cursor-pointer shadow-[0_0_15px_rgba(244,63,94,0.3)]"
                  >
                    Apply Isolation
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};
