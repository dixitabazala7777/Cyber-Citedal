import React, { useState, useEffect, useRef, useMemo } from 'react';
import { SystemNode, FirewallRule, Incident } from '../types';
import { 
  Cpu, RefreshCw, Zap, Play, Terminal, 
  Lock, Users, Volume2, VolumeX, ShieldAlert, CheckCircle2
} from 'lucide-react';

interface SoarPlaybooksProps {
  nodes: SystemNode[];
  onIsolateNode: (id: string) => void;
  rules: FirewallRule[];
  setRules: React.Dispatch<React.SetStateAction<FirewallRule[]>>;
  incidents: Incident[];
  setIncidents: React.Dispatch<React.SetStateAction<Incident[]>>;
  onLogMessage: (msg: string) => void;
}

interface Playbook {
  id: string;
  name: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  category: 'Infrastructure' | 'Network' | 'Identity';
  parameters: {
    name: string;
    type: 'select' | 'text' | 'checkbox';
    options?: string[];
    defaultValue: string;
  }[];
}

export const SoarPlaybooks: React.FC<SoarPlaybooksProps> = ({
  nodes,
  onIsolateNode,
  rules,
  setRules,
  incidents,
  setIncidents,
  onLogMessage
}) => {
  const [reputationList, setReputationList] = useState<Array<{ ip: string; score: number; status: string; reason?: string }>>([]);
  const [quarantineCount, setQuarantineCount] = useState<number>(0);
  const [customSubnet, setCustomSubnet] = useState<string>('185.156.177.0/24');

  // Fetch reputation telemetry periodically
  const fetchSoarTelemetry = async () => {
    try {
      const res = await fetch('/api/v1/soar/reputation');
      if (res.ok) {
        const data = await res.json();
        setReputationList(data.reputations || []);
        setQuarantineCount(data.quarantinedCount || 0);
      }
    } catch {
      // Ignored
    }
  };

  useEffect(() => {
    fetchSoarTelemetry();
    const interval = setInterval(fetchSoarTelemetry, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleBlockSubnet = async () => {
    if (!customSubnet) return;
    try {
      const res = await fetch('/api/v1/soar/block-subnet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subnet: customSubnet, reason: 'SecOps 1-Click Subnet Quarantine' })
      });
      if (res.ok) {
        const data = await res.json();
        onLogMessage(`SOAR ACTION: ${data.message}`);
        playSynthSound('success');
        fetchSoarTelemetry();
      }
    } catch (e) {
      console.warn("Block Subnet Error:", e);
    }
  };

  const handleRevokeJwtSession = async () => {
    try {
      const res = await fetch('/api/v1/soar/revoke-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: 'ALL_SUSPECT_TOKENS' })
      });
      if (res.ok) {
        const data = await res.json();
        onLogMessage(`SOAR ACTION: ${data.message}`);
        playSynthSound('success');
      }
    } catch (e) {
      console.warn("Revoke Session Error:", e);
    }
  };

  const handleFlushKeys = async () => {
    try {
      const res = await fetch('/api/v1/soar/flush-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (res.ok) {
        const data = await res.json();
        onLogMessage(`SOAR ACTION: ${data.message}`);
        playSynthSound('success');
      }
    } catch (e) {
      console.warn("Flush Keys Error:", e);
    }
  };

  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>('node-isolation');
  const [activeParamValues, setActiveParamValues] = useState<Record<string, string>>({});
  const [executionLogs, setExecutionLogs] = useState<string[]>([]);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [executionState, setExecutionState] = useState<'idle' | 'running' | 'success' | 'failed'>('idle');
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);
  
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [executionLogs]);

  const playSynthSound = (type: 'start' | 'success' | 'warn') => {
    if (!soundEnabled) return;
    const AudioContextClass = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AudioContextClass) return;
    try {
      const ctx = new AudioContextClass();
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      
      if (type === 'start') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(350, now);
        osc.frequency.setValueAtTime(700, now + 0.08);
        gain.gain.setValueAtTime(0.015, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
      } else if (type === 'success') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(440, now); // A4
        osc.frequency.setValueAtTime(554.37, now + 0.08); // C#5
        osc.frequency.setValueAtTime(659.25, now + 0.16); // E5
        osc.frequency.setValueAtTime(880, now + 0.24); // A5
        gain.gain.setValueAtTime(0.02, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);
      } else { // warn
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(220, now);
        osc.frequency.linearRampToValueAtTime(80, now + 0.25);
        gain.gain.setValueAtTime(0.04, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
      }
      
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.5);
    } catch (e) {
      console.warn("Playbook Audio Synth Error:", e);
    }
  };

  const playbooks: Playbook[] = useMemo(() => [
    {
      id: 'node-isolation',
      name: 'Isolate Compromised Node',
      icon: Lock,
      description: 'Isolates the targeted production cloud node immediately. Revokes session tokens, deploys localized security group filters, and flags instances inside administrative dashboards.',
      category: 'Infrastructure',
      parameters: [
        {
          name: 'Target Node Instance',
          type: 'select',
          options: nodes.map(n => n.id),
          defaultValue: nodes[0]?.id || 'NODE-US-EAST'
        },
        {
          name: 'Revoke Node IAM Credentials',
          type: 'checkbox',
          defaultValue: 'true'
        },
        {
          name: 'Alert Level',
          type: 'select',
          options: ['Critical Block', 'Heuristic Warning', 'Containment Audit'],
          defaultValue: 'Critical Block'
        }
      ]
    },
    {
      id: 'flush-firewall',
      name: 'Flush Ingress Firewalls',
      icon: RefreshCw,
      description: 'Flushes existing temporary blocklists, audits current IP rules, and regenerates a fresh, cryptographically validated firewall filter baseline.',
      category: 'Network',
      parameters: [
        {
          name: 'Blocklist Scope',
          type: 'select',
          options: ['Clear Custom Blocked IPs', 'Regenerate Base Policy Only', 'Full Ingress Blackout'],
          defaultValue: 'Clear Custom Blocked IPs'
        },
        {
          name: 'Include Quantum IPS Shielding',
          type: 'checkbox',
          defaultValue: 'true'
        }
      ]
    },
    {
      id: 'revoke-identity',
      name: 'Emergency Identity Revocation',
      icon: Users,
      description: 'Forcefully invalidates active sessions of flagged accounts showing anomalous risk scores. Revokes active JSON Web Tokens (JWT) and flags MFA re-verification requirements.',
      category: 'Identity',
      parameters: [
        {
          name: 'Identity Class Scope',
          type: 'select',
          options: ['High-Risk Quarantined Users Only', 'All Active Contractor Roles', 'Global Admin Password Reset'],
          defaultValue: 'High-Risk Quarantined Users Only'
        },
        {
          name: 'Enforce Global Hardware-Key MFA',
          type: 'checkbox',
          defaultValue: 'true'
        }
      ]
    }
  ], [nodes]);

  // Set default parameters
  useEffect(() => {
    const selected = playbooks.find(p => p.id === selectedPlaybookId);
    if (selected) {
      const defaults: Record<string, string> = {};
      selected.parameters.forEach(p => {
        defaults[p.name] = p.defaultValue;
      });
      setActiveParamValues(defaults);
    }
  }, [selectedPlaybookId, playbooks]);

  const handleParamChange = (name: string, value: string) => {
    setActiveParamValues(prev => ({ ...prev, [name]: value }));
  };

  const runPlaybook = () => {
    if (isExecuting) return;
    
    setIsExecuting(true);
    setExecutionState('running');
    playSynthSound('start');
    
    const timestamp = new Date().toLocaleTimeString();
    const activeThreatsCount = incidents.filter(i => i.status === 'active').length;
    setExecutionLogs([
      `[${timestamp}] [INIT] Instantiating SOAR Playbook: ${selectedPlaybookId.toUpperCase()}...`,
      `[${timestamp}] [AUDIT] Live Uncontained Ingress Threats in Buffer: ${activeThreatsCount}`
    ]);

    const delay = (ms: number) => new Promise(res => setTimeout(res, ms));

    const executeSteps = async () => {
      try {
        if (selectedPlaybookId === 'node-isolation') {
          const targetId = activeParamValues['Target Node Instance'] || nodes[0]?.id;
          const revokeCredentials = activeParamValues['Revoke Node IAM Credentials'] === 'true';
          const nodeName = nodes.find(n => n.id === targetId)?.name || targetId;

          await delay(600);
          setExecutionLogs(prev => [...prev, `[INFO] Resolving endpoint routing identifiers for ${targetId}...`]);
          playSynthSound('warn');

          await delay(600);
          setExecutionLogs(prev => [...prev, `[WARN] Isolating node connectivity. Dropping physical and virtual gateway links...`]);
          onIsolateNode(targetId);

          await delay(700);
          if (revokeCredentials) {
            setExecutionLogs(prev => [...prev, `[INFO] IAM Engine: Invalidation request pushed. Access keys associated with ${targetId} revoked.`]);
          }

          await delay(500);
          setExecutionLogs(prev => [...prev, `[SUCCESS] ${nodeName} encapsulated in air-gapped sandboxed zone.`]);
          onLogMessage(`SOAR PLAYBOOK: Isolated and secured cloud gateway node ${targetId}`);

        } else if (selectedPlaybookId === 'flush-firewall') {
          const scope = activeParamValues['Blocklist Scope'];
          const quantumShield = activeParamValues['Include Quantum IPS Shielding'] === 'true';

          await delay(500);
          setExecutionLogs(prev => [...prev, `[INFO] Fetching active firewall policies list... Found ${rules.length} custom rules.`]);

          await delay(600);
          if (scope === 'Clear Custom Blocked IPs') {
            setExecutionLogs(prev => [...prev, `[WARN] Clearing all active block rules in local list...`]);
            setRules([]);
            setIncidents(prev => prev.map(inc => {
              if (inc.status === 'blocked') {
                return { ...inc, status: 'resolved' };
              }
              return inc;
            }));
          } else {
            setExecutionLogs(prev => [...prev, `[WARN] Deploying full ingress blackout. Compiling safety rules...`]);
          }

          await delay(700);
          if (quantumShield) {
            setExecutionLogs(prev => [...prev, `[INFO] Injecting Quantum IPS dynamic telemetry signatures... OK.`]);
          }

          await delay(500);
          setExecutionLogs(prev => [...prev, `[SUCCESS] Ingress firewall interfaces cleared and synchronized with secure baseline.`]);
          onLogMessage(`SOAR PLAYBOOK: Flushed and reset ingress firewall filters`);

        } else if (selectedPlaybookId === 'revoke-identity') {
          const scope = activeParamValues['Identity Class Scope'];
          const mfaHardware = activeParamValues['Enforce Global Hardware-Key MFA'] === 'true';

          await delay(600);
          setExecutionLogs(prev => [...prev, `[INFO] Auditing active identity tokens for security threshold breach...`]);

          await delay(600);
          setExecutionLogs(prev => [...prev, `[WARN] Revoking session tokens. Expelling users associated with ${scope}...`]);

          await delay(800);
          if (mfaHardware) {
            setExecutionLogs(prev => [...prev, `[INFO] Enforcement Mode: Locked all contractor/high-risk accounts. Requiring hardware-key YubiKey/MFA.`]);
          }

          await delay(500);
          setExecutionLogs(prev => [...prev, `[SUCCESS] Identity Access Management bounds updated. Active security breach path severed.`]);
          onLogMessage(`SOAR PLAYBOOK: Expelled high-risk identities and applied administrative lockouts`);
        }

        // Finalize playbook
        await delay(300);
        setExecutionState('success');
        playSynthSound('success');
        setExecutionLogs(prev => [...prev, `[COMPLETE] Playbook execution finalized with SLA exit code 0. Status: SAFE.`]);
        setIsExecuting(false);

      } catch (error) {
        setExecutionState('failed');
        playSynthSound('warn');
        setExecutionLogs(prev => [...prev, `[FATAL] Playbook aborted. Local execution engine failure: ${error}`]);
        setIsExecuting(false);
      }
    };

    executeSteps();
  };

  const selectedPlaybook = playbooks.find(p => p.id === selectedPlaybookId) || playbooks[0];

  return (
    <div id="soar-playbooks-module" className="p-6 bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs dark:shadow-xl relative overflow-hidden min-h-[500px] text-slate-900 dark:text-slate-100">
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />
      
      {/* Header Panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-200 dark:border-slate-800 pb-4 mb-6 gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Zap className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold tracking-widest uppercase">SIEM ORCHESTRATION PANEL</span>
          </div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white font-sans tracking-wide">SOAR Playbooks & Remediation</h2>
          <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 max-w-xl">
            Deploy automated Security Orchestration, Automation, and Response sequences to isolate nodes, clear firewall overflows, or cycle high-risk administrative keys.
          </p>
        </div>

        {/* Audio Toggler */}
        <button
          onClick={() => setSoundEnabled(!soundEnabled)}
          className={`flex items-center gap-2 px-3 py-1.5 border rounded-lg text-[10px] font-mono font-bold transition-all active:scale-95 cursor-pointer ${
            soundEnabled 
              ? 'bg-indigo-50 dark:bg-indigo-950/40 border-indigo-200 dark:border-indigo-800/60 text-indigo-700 dark:text-indigo-300' 
              : 'bg-slate-100 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400'
          }`}
        >
          {soundEnabled ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5" />}
          {soundEnabled ? 'AUDIO READY' : 'AUDIO MUTED'}
        </button>
      </div>

      {/* 1-Click SOAR Remediation Action Bar */}
      <div className="mb-6 p-4 bg-slate-900 text-white border border-slate-800 rounded-xl space-y-3 font-mono shadow-md">
        <div className="flex justify-between items-center border-b border-slate-800 pb-2">
          <span className="text-xs font-bold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-emerald-400" /> AUTO-CONTAINMENT SHIELD & 1-CLICK REMEDIATION
          </span>
          <span className="text-[10px] text-amber-300 font-bold bg-amber-950/80 px-2 py-0.5 rounded border border-amber-700/80">
            {quarantineCount} QUARANTINED HOSTS
          </span>
        </div>

        {/* Active Client Reputation Score Ledger */}
        {reputationList.length > 0 && (
          <div className="pt-2 border-t border-slate-800">
            <div className="text-[10px] font-bold text-slate-300 mb-2 uppercase">SOAR Client Reputation Ledger</div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[10px]">
              {reputationList.map((client) => (
                <div key={client.ip} className="p-2 bg-slate-950 rounded border border-slate-800 flex justify-between items-center text-white">
                  <span className="text-slate-100 font-bold">{client.ip}</span>
                  <span className={`font-bold px-1.5 py-0.5 rounded ${client.score < 30 ? 'bg-rose-950 text-rose-300 border border-rose-700 animate-pulse' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'}`}>
                    {client.score} PTS
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Action 1: Block Subnet */}
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-col justify-between space-y-2 text-white">
            <div className="text-[10px] text-slate-300 uppercase font-bold">1-Click Subnet Quarantine</div>
            <div className="flex gap-2">
              <input 
                type="text" 
                value={customSubnet} 
                onChange={(e) => setCustomSubnet(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-white placeholder-slate-400 flex-1 font-mono focus:border-indigo-400 outline-none"
              />
              <button 
                onClick={handleBlockSubnet}
                className="px-3 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-[10px] font-extrabold cursor-pointer transition border border-rose-500 shadow-xs"
              >
                BLOCK
              </button>
            </div>
          </div>

          {/* Action 2: Revoke JWT Tokens */}
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between text-white">
            <div>
              <div className="text-[10px] text-slate-200 uppercase font-bold">Revoke Active JWT Sessions</div>
              <div className="text-[10px] text-slate-400">Invalidates all Bearer tokens</div>
            </div>
            <button 
              onClick={handleRevokeJwtSession}
              className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded text-[10px] font-extrabold cursor-pointer transition border border-amber-500 shadow-xs"
            >
              REVOKE
            </button>
          </div>

          {/* Action 3: Flush PQC Crypto Keys */}
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between text-white">
            <div>
              <div className="text-[10px] text-slate-200 uppercase font-bold">Flush PQC Kyber Keys</div>
              <div className="text-[10px] text-slate-400">Rotate session keys instantly</div>
            </div>
            <button 
              onClick={handleFlushKeys}
              className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-[10px] font-extrabold cursor-pointer transition border border-indigo-500 shadow-xs"
            >
              FLUSH
            </button>
          </div>
        </div>
      </div>

      {/* Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Playbook List Selection (Left 5 Cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="text-[10px] font-bold text-slate-600 dark:text-slate-300 font-mono tracking-wider border-b border-slate-200 dark:border-slate-800 pb-2 mb-1 uppercase">
            AVAILABLE REMEDIATION SCRIPTS
          </div>
          
          <div className="space-y-2">
            {playbooks.map((pb) => {
              const IconComp = pb.icon;
              const isSelected = pb.id === selectedPlaybookId;
              
              return (
                <div
                  key={pb.id}
                  onClick={() => !isExecuting && setSelectedPlaybookId(pb.id)}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer transition-all ${
                    isSelected 
                      ? 'bg-indigo-50/80 dark:bg-indigo-950/40 border-indigo-500 dark:border-indigo-500 shadow-sm' 
                      : isExecuting 
                        ? 'bg-slate-100/50 dark:bg-slate-950/30 border-slate-200 dark:border-slate-900 opacity-50 cursor-not-allowed' 
                        : 'bg-white dark:bg-slate-950/60 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-900/30'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <div className={`p-2 rounded-lg ${isSelected ? 'bg-indigo-600 text-white' : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300'}`}>
                        <IconComp className="w-4 h-4" />
                      </div>
                      <div>
                        <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase font-sans">
                          {pb.name}
                        </h4>
                        <span className="text-[9px] text-slate-600 dark:text-slate-400 font-mono uppercase bg-slate-100 dark:bg-slate-800 px-1.5 py-0.2 rounded mt-0.5 inline-block font-semibold">
                          {pb.category}
                        </span>
                      </div>
                    </div>
                    {isSelected && (
                      <span className={`w-2 h-2 rounded-full ${isExecuting ? 'bg-amber-500 animate-ping' : 'bg-indigo-600 dark:bg-indigo-400 animate-pulse'}`} />
                    )}
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-300 mt-2.5 font-sans leading-relaxed">
                    {pb.description}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Playbook Parameters & Interactive Console (Right 7 Cols) */}
        <div className="lg:col-span-7 space-y-4 flex flex-col justify-between">
          
          {/* Active Configuration Box */}
          <div className="bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-4 shadow-xs">
            <div className="text-[10px] font-bold text-slate-700 dark:text-slate-300 font-mono tracking-wider border-b border-slate-200 dark:border-slate-800 pb-2 flex items-center gap-2 uppercase">
              <Cpu className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>PLAYBOOK PARAMETER ENGINE: {selectedPlaybook.name.toUpperCase()}</span>
            </div>

            <div className="space-y-3">
              {selectedPlaybook.parameters.map((param) => (
                <div key={param.name} className="flex flex-col gap-1.5">
                  <label className="text-[11px] font-bold text-slate-800 dark:text-slate-200 font-mono">{param.name}</label>
                  
                  {param.type === 'select' && (
                    <select
                      disabled={isExecuting}
                      value={activeParamValues[param.name] || ''}
                      onChange={(e) => handleParamChange(param.name, e.target.value)}
                      className="w-full bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-indigo-500 font-mono font-medium shadow-xs"
                    >
                      {param.options?.map(opt => (
                        <option key={opt} value={opt} className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">{opt}</option>
                      ))}
                    </select>
                  )}

                  {param.type === 'checkbox' && (
                    <div className="flex items-center gap-2 mt-1.5">
                      <input
                        type="checkbox"
                        disabled={isExecuting}
                        id={`chk-${param.name}`}
                        checked={activeParamValues[param.name] === 'true'}
                        onChange={(e) => handleParamChange(param.name, e.target.checked ? 'true' : 'false')}
                        className="rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-indigo-600 focus:ring-0 w-4 h-4 cursor-pointer"
                      />
                      <label htmlFor={`chk-${param.name}`} className="text-xs text-slate-700 dark:text-slate-300 select-none cursor-pointer font-medium">
                        Enforce active parameters cryptographically during process runtime.
                      </label>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Run Button */}
            <div className="pt-2">
              <button
                onClick={runPlaybook}
                disabled={isExecuting}
                className={`w-full py-3 rounded-xl border text-xs font-bold font-mono transition flex items-center justify-center gap-2 cursor-pointer shadow-md ${
                  isExecuting
                    ? 'bg-amber-600/20 border-amber-600/50 text-amber-700 dark:text-amber-300 cursor-not-allowed'
                    : 'bg-indigo-600 hover:bg-indigo-500 border-indigo-600 text-white active:scale-95'
                }`}
              >
                {isExecuting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-amber-500" />
                    EXECUTING ENCAPSULATED RUNTIME...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 text-white fill-white" />
                    DEPLOY SEC-OPS PLAYBOOK
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Interactive Live Output Terminal (Always Crisp Terminal Dark) */}
          <div className="bg-black text-emerald-400 border border-slate-800 rounded-xl overflow-hidden flex flex-col h-[200px] shadow-lg">
            <div className="px-3 py-2 bg-slate-950 border-b border-slate-800 flex justify-between items-center text-[10px] font-mono">
              <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5" />
                ORCHESTRATOR TERMINAL FEED
              </span>
              <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                executionState === 'success' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                executionState === 'running' ? 'bg-amber-950 text-amber-300 border border-amber-800 animate-pulse' :
                executionState === 'failed' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-900 text-slate-400 border border-slate-800'
              }`}>
                {executionState.toUpperCase()}
              </span>
            </div>

            <div className="p-3 overflow-y-auto flex-1 font-mono text-[10px] leading-relaxed text-emerald-400 space-y-1 select-text">
              {executionLogs.length === 0 ? (
                <div className="text-zinc-500 italic py-6 text-center select-none font-mono text-[11px]">
                  Awaiting playbook instancing. Launch script above to dump telemetry logs...
                </div>
              ) : (
                executionLogs.map((log, lIdx) => (
                  <div key={`play-log-${lIdx}`} className={`break-all ${
                    log.includes('[SUCCESS]') ? 'text-emerald-300 font-bold' :
                    log.includes('[WARN]') ? 'text-amber-300 font-semibold' :
                    log.includes('[FATAL]') ? 'text-rose-400 font-bold' : 'text-emerald-400'
                  }`}>
                    {log}
                  </div>
                ))
              )}
              {isExecuting && (
                <div className="text-amber-300 animate-pulse flex items-center gap-1.5 font-bold pt-1">
                  <span>█ SYSTEM ACTIVE • DO NOT ABORT SEQUENCE</span>
                </div>
              )}
              <div ref={terminalEndRef} />
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};

export default SoarPlaybooks;
