import React, { useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Fingerprint, Key, ShieldAlert, ShieldCheck, RotateCcw, Trash2,
  Clock, MapPin, Activity, AlertTriangle, CheckCircle, XCircle,
  Play, ChevronDown, ChevronRight, Zap, Eye, Lock, Unlock, Search
} from 'lucide-react';

interface SignatureIntegrityGuardProps {
  onLogMessage: (msg: string) => void;
}

interface SimKey {
  key_id: string;
  algorithm: string;
  status: string;
  owner: string;
  risk_score: number;
  total_signatures: number;
  created_at: number;
  last_used_at: number | null;
}

interface TimelineEvent {
  event_id: string;
  key_id: string;
  timestamp: number;
  event_type: string;
  outcome: string;
  source_ip: string | null;
  risk_score: number;
  details: string;
}

interface SimulationResult {
  scenario: string;
  verification?: {
    outcome: string;
    cryptographic_valid: boolean;
    replay_check_passed: boolean;
    provenance_check_passed: boolean;
    anomaly?: { risk_score: number; flags: string[]; details: string };
    message: string;
    processing_time_ms: number;
  };
  first_verification?: Record<string, unknown>;
  replay_attempt?: Record<string, unknown>;
  travel_attempt?: Record<string, unknown>;
  key_id: string;
}

const ALGO_OPTIONS = [
  { value: 'Ed25519', label: 'Ed25519', badge: 'Fast' },
  { value: 'ECDSA-P256', label: 'ECDSA P-256', badge: 'NIST' },
  { value: 'ECDSA-P384', label: 'ECDSA P-384', badge: 'High' },
  { value: 'RSA-PSS', label: 'RSA-PSS', badge: 'Legacy' },
];

const SCENARIO_OPTIONS = [
  { value: 'valid', label: 'Valid Signature', icon: CheckCircle, color: 'text-emerald-400', desc: 'Legitimate key owner signs from authorized context' },
  { value: 'tampered', label: 'Tampered Signature', icon: XCircle, color: 'text-rose-400', desc: 'Attacker modifies signature bytes after interception' },
  { value: 'replay', label: 'Replay Attack', icon: RotateCcw, color: 'text-amber-400', desc: 'Attacker re-submits a previously valid signed payload' },
  { value: 'stolen_key', label: 'Stolen Key', icon: ShieldAlert, color: 'text-rose-400', desc: 'Key used from unauthorized IP / ASN range' },
  { value: 'impossible_travel', label: 'Impossible Travel', icon: MapPin, color: 'text-violet-400', desc: 'Same key used from Delhi then Sydney in <1 second' },
];

const outcomeStyles: Record<string, { bg: string; text: string; border: string }> = {
  VALID: { bg: 'bg-emerald-950/40', text: 'text-emerald-400', border: 'border-emerald-800/60' },
  INVALID_SIGNATURE: { bg: 'bg-rose-950/40', text: 'text-rose-400', border: 'border-rose-800/60' },
  REPLAY_DETECTED: { bg: 'bg-amber-950/40', text: 'text-amber-400', border: 'border-amber-800/60' },
  PROVENANCE_MISMATCH: { bg: 'bg-rose-950/40', text: 'text-rose-400', border: 'border-rose-800/60' },
  ANOMALY_DETECTED: { bg: 'bg-violet-950/40', text: 'text-violet-400', border: 'border-violet-800/60' },
  KEY_REVOKED: { bg: 'bg-slate-800/40', text: 'text-slate-400', border: 'border-slate-700/60' },
};

export const SignatureIntegrityGuard: React.FC<SignatureIntegrityGuardProps> = ({ onLogMessage }) => {
  const [keys, setKeys] = useState<SimKey[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [selectedKeyId, setSelectedKeyId] = useState<string | null>(null);
  const [simAlgorithm, setSimAlgorithm] = useState('Ed25519');
  const [simScenario, setSimScenario] = useState('valid');
  const [simPayload, setSimPayload] = useState('Hello, DEEPSHIELD!');
  const [simResult, setSimResult] = useState<SimulationResult | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [activePanel, setActivePanel] = useState<'simulator' | 'keys' | 'timeline'>('simulator');
  const [revokeConfirm, setRevokeConfirm] = useState<string | null>(null);

  // Fetch keys
  const fetchKeys = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/signature-guard/keys');
      if (res.ok) {
        const data = await res.json();
        setKeys((data.keys || []).map((k: any) => ({
          key_id: k.key_id,
          algorithm: k.algorithm,
          status: k.status,
          owner: k.provenance?.owner_identity || 'unknown',
          risk_score: k.risk_score || 0,
          total_signatures: k.total_signatures || 0,
          created_at: k.created_at,
          last_used_at: k.last_used_at,
        })));
      }
    } catch { /* backend offline — use local state */ }
  }, []);

  // Fetch timeline for a key
  const fetchTimeline = useCallback(async (keyId: string) => {
    try {
      const res = await fetch(`/api/v1/signature-guard/timeline/${keyId}`);
      if (res.ok) {
        const data = await res.json();
        setTimeline(data.events || []);
      }
    } catch { setTimeline([]); }
  }, []);

  useEffect(() => { fetchKeys(); }, [fetchKeys]);

  useEffect(() => {
    if (selectedKeyId) fetchTimeline(selectedKeyId);
  }, [selectedKeyId, fetchTimeline]);

  // Run simulation
  const runSimulation = useCallback(async () => {
    setIsSimulating(true);
    setSimResult(null);
    onLogMessage(`SIGGUARD: Running ${simScenario} simulation with ${simAlgorithm}...`);

    try {
      const res = await fetch('/api/v1/signature-guard/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithm: simAlgorithm,
          payload_text: simPayload,
          scenario: simScenario,
          source_ip: '10.0.1.42',
          geo_lat: 28.6139,
          geo_lon: 77.2090,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setSimResult(data);
        onLogMessage(`SIGGUARD: Simulation complete. Outcome: ${data.verification?.outcome || data.replay_attempt?.outcome || data.travel_attempt?.outcome || 'N/A'}`);
        fetchKeys();
        if (data.key_id) {
          setSelectedKeyId(data.key_id);
          fetchTimeline(data.key_id);
        }
      } else {
        // Fallback: simulate locally if backend is not running
        const localResult = simulateLocally(simScenario, simAlgorithm);
        setSimResult(localResult);
        onLogMessage(`SIGGUARD: Local simulation. Outcome: ${localResult.verification?.outcome || 'N/A'}`);
      }
    } catch {
      // Local fallback
      const localResult = simulateLocally(simScenario, simAlgorithm);
      setSimResult(localResult);
      onLogMessage(`SIGGUARD: Local simulation (backend offline). Outcome: ${localResult.verification?.outcome || 'N/A'}`);
    } finally {
      setIsSimulating(false);
    }
  }, [simAlgorithm, simScenario, simPayload, onLogMessage, fetchKeys, fetchTimeline]);

  // Revoke key
  const revokeKey = useCallback(async (keyId: string) => {
    try {
      const res = await fetch('/api/v1/signature-guard/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key_id: keyId, reason: 'Manual dashboard revocation', actor: 'dashboard_user' }),
      });
      if (res.ok) {
        onLogMessage(`SIGGUARD: Key ${keyId} REVOKED via kill switch.`);
        fetchKeys();
        if (selectedKeyId === keyId) fetchTimeline(keyId);
      }
    } catch {
      // Update local state
      setKeys(prev => prev.map(k => k.key_id === keyId ? { ...k, status: 'REVOKED', risk_score: 100 } : k));
      onLogMessage(`SIGGUARD: Key ${keyId} REVOKED (local).`);
    }
    setRevokeConfirm(null);
  }, [onLogMessage, fetchKeys, selectedKeyId, fetchTimeline]);

  // Rotate key
  const rotateKey = useCallback(async (keyId: string) => {
    try {
      const res = await fetch('/api/v1/signature-guard/rotate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key_id: keyId, reason: 'Manual rotation', actor: 'dashboard_user' }),
      });
      if (res.ok) {
        const data = await res.json();
        onLogMessage(`SIGGUARD: Key rotated. ${keyId} → ${data.new_key?.key_id || 'new_key'}`);
        fetchKeys();
      }
    } catch {
      onLogMessage(`SIGGUARD: Key ${keyId} rotation initiated (local).`);
    }
  }, [onLogMessage, fetchKeys]);

  const getOutcomeVerification = (result: SimulationResult) => {
    if (result.verification) return result.verification;
    if (result.replay_attempt) return result.replay_attempt as any;
    if (result.travel_attempt) return result.travel_attempt as any;
    return null;
  };

  const mainVerification = simResult ? getOutcomeVerification(simResult) : null;
  const mainOutcome = mainVerification?.outcome || '';
  const os = outcomeStyles[mainOutcome] || outcomeStyles.VALID;

  return (
    <div className="max-w-7xl w-full mx-auto px-4 mt-6 relative z-10 flex flex-col gap-5">
      {/* Header */}
      <div className="bg-[#161b22]/60 border border-slate-800 rounded-xl p-5 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-violet-600/20 rounded-lg border border-violet-700/40">
              <Fingerprint className="w-5 h-5 text-violet-400" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-100 font-sans">Signature Integrity Guard</h2>
              <p className="text-[11px] text-slate-500 font-mono mt-0.5">Digital Signature Theft & Forgery Detection • 4-Stage Pipeline</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
            <span className="flex items-center gap-1"><Lock className="w-3 h-3 text-violet-400" /> Crypto Verify</span>
            <ChevronRight className="w-3 h-3" />
            <span className="flex items-center gap-1"><Search className="w-3 h-3 text-amber-400" /> Replay Check</span>
            <ChevronRight className="w-3 h-3" />
            <span className="flex items-center gap-1"><MapPin className="w-3 h-3 text-blue-400" /> Provenance</span>
            <ChevronRight className="w-3 h-3" />
            <span className="flex items-center gap-1"><Activity className="w-3 h-3 text-rose-400" /> Anomaly</span>
          </div>
        </div>

        {/* Sub-tab nav */}
        <div className="flex gap-1.5 mt-4">
          {([
            { id: 'simulator', label: 'Verification Simulator', icon: Play },
            { id: 'keys', label: `Active Keys (${keys.length})`, icon: Key },
            { id: 'timeline', label: 'Forensic Timeline', icon: Clock },
          ] as const).map(tab => (
            <button
              key={tab.id}
              onClick={() => setActivePanel(tab.id)}
              className={`px-3 py-1.5 text-xs font-sans font-medium rounded-lg flex items-center gap-1.5 transition-all cursor-pointer ${
                activePanel === tab.id
                  ? 'bg-violet-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <tab.icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <AnimatePresence mode="wait">
        {/* ─── Simulator Panel ─── */}
        {activePanel === 'simulator' && (
          <motion.div key="sim" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }} transition={{ duration: 0.2 }}
            className="grid grid-cols-1 lg:grid-cols-2 gap-5"
          >
            {/* Left: Config */}
            <div className="bg-[#161b22]/60 border border-slate-800 rounded-xl p-5">
              <h3 className="text-xs font-semibold text-slate-300 mb-4 flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-violet-400" /> Simulation Configuration
              </h3>

              {/* Algorithm Select */}
              <div className="mb-4">
                <label className="text-[10px] text-slate-500 font-mono uppercase tracking-wider mb-1.5 block">Signing Algorithm</label>
                <div className="flex flex-wrap gap-1.5">
                  {ALGO_OPTIONS.map(a => (
                    <button key={a.value} onClick={() => setSimAlgorithm(a.value)}
                      className={`px-3 py-1.5 text-[11px] font-mono rounded-lg border transition-all cursor-pointer ${
                        simAlgorithm === a.value
                          ? 'bg-violet-600/20 border-violet-600 text-violet-300'
                          : 'bg-slate-900/50 border-slate-800 text-slate-500 hover:text-slate-300 hover:border-slate-700'
                      }`}>
                      {a.label} <span className="text-[9px] ml-1 opacity-60">{a.badge}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Payload */}
              <div className="mb-4">
                <label className="text-[10px] text-slate-500 font-mono uppercase tracking-wider mb-1.5 block">Payload</label>
                <input type="text" value={simPayload} onChange={e => setSimPayload(e.target.value)}
                  className="w-full bg-slate-900/80 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-300 focus:outline-none focus:border-violet-600" />
              </div>

              {/* Scenario Select */}
              <div className="mb-4">
                <label className="text-[10px] text-slate-500 font-mono uppercase tracking-wider mb-1.5 block">Attack Scenario</label>
                <div className="space-y-1.5">
                  {SCENARIO_OPTIONS.map(s => (
                    <button key={s.value} onClick={() => setSimScenario(s.value)}
                      className={`w-full text-left px-3 py-2 rounded-lg border transition-all cursor-pointer flex items-center gap-2.5 ${
                        simScenario === s.value
                          ? 'bg-violet-600/10 border-violet-600/50'
                          : 'bg-slate-900/30 border-slate-800/60 hover:border-slate-700'
                      }`}>
                      <s.icon className={`w-4 h-4 ${s.color}`} />
                      <div>
                        <span className={`text-xs font-medium ${simScenario === s.value ? 'text-slate-200' : 'text-slate-400'}`}>{s.label}</span>
                        <p className="text-[10px] text-slate-600 mt-0.5">{s.desc}</p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Run Button */}
              <button onClick={runSimulation} disabled={isSimulating}
                className="w-full py-2.5 bg-violet-600 hover:bg-violet-500 disabled:bg-violet-800 text-white text-xs font-semibold rounded-lg transition-all cursor-pointer flex items-center justify-center gap-2">
                {isSimulating ? (
                  <><span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Running Pipeline...</>
                ) : (
                  <><Play className="w-3.5 h-3.5" /> Execute Verification Pipeline</>
                )}
              </button>
            </div>

            {/* Right: Results */}
            <div className="bg-[#161b22]/60 border border-slate-800 rounded-xl p-5">
              <h3 className="text-xs font-semibold text-slate-300 mb-4 flex items-center gap-2">
                <Eye className="w-3.5 h-3.5 text-violet-400" /> Pipeline Results
              </h3>

              {!simResult && !isSimulating && (
                <div className="flex flex-col items-center justify-center h-48 text-slate-600">
                  <Fingerprint className="w-8 h-8 mb-2 opacity-30" />
                  <p className="text-xs font-mono">Select a scenario and run the pipeline</p>
                </div>
              )}

              {isSimulating && (
                <div className="flex flex-col items-center justify-center h-48">
                  <div className="w-10 h-10 border-2 border-violet-500/30 border-t-violet-400 rounded-full animate-spin mb-3" />
                  <p className="text-xs font-mono text-slate-500">Executing 4-stage pipeline...</p>
                </div>
              )}

              {simResult && mainVerification && (
                <div className="space-y-4">
                  {/* Outcome Badge */}
                  <div className={`${os.bg} border ${os.border} rounded-xl p-4`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className={`text-sm font-bold ${os.text}`}>{mainOutcome.replace(/_/g, ' ')}</span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {(mainVerification.processing_time_ms || 0).toFixed(2)}ms
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono">{mainVerification.message}</p>
                  </div>

                  {/* Pipeline Stages */}
                  <div className="space-y-2">
                    {[
                      { label: 'Cryptographic Verification', passed: mainVerification.cryptographic_valid, icon: Lock },
                      { label: 'Replay Detection', passed: mainVerification.replay_check_passed, icon: RotateCcw },
                      { label: 'Provenance Binding', passed: mainVerification.provenance_check_passed, icon: MapPin },
                    ].map((stage, i) => (
                      <div key={i} className="flex items-center gap-3 px-3 py-2 bg-slate-900/40 rounded-lg border border-slate-800/50">
                        <stage.icon className="w-3.5 h-3.5 text-slate-500" />
                        <span className="text-[11px] text-slate-400 flex-1 font-mono">{stage.label}</span>
                        {stage.passed ? (
                          <span className="text-[10px] font-bold text-emerald-400 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> PASS</span>
                        ) : (
                          <span className="text-[10px] font-bold text-rose-400 flex items-center gap-1"><XCircle className="w-3 h-3" /> FAIL</span>
                        )}
                      </div>
                    ))}

                    {/* Anomaly Score */}
                    {mainVerification.anomaly && (
                      <div className="px-3 py-2 bg-slate-900/40 rounded-lg border border-slate-800/50">
                        <div className="flex items-center gap-3">
                          <Activity className="w-3.5 h-3.5 text-slate-500" />
                          <span className="text-[11px] text-slate-400 flex-1 font-mono">Anomaly Scoring</span>
                          <span className={`text-[10px] font-bold ${
                            mainVerification.anomaly.risk_score >= 70 ? 'text-rose-400' :
                            mainVerification.anomaly.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            Risk: {mainVerification.anomaly.risk_score.toFixed(0)}%
                          </span>
                        </div>
                        {mainVerification.anomaly.flags?.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-2 ml-6">
                            {mainVerification.anomaly.flags.map((f: string, j: number) => (
                              <span key={j} className="px-1.5 py-0.5 bg-rose-950/60 text-rose-400 border border-rose-800/50 rounded text-[9px] font-mono">{f}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Multi-step scenario results */}
                  {simResult.first_verification && (
                    <div className="text-[10px] font-mono text-slate-500 border-t border-slate-800/50 pt-2 mt-2">
                      <span className="text-slate-400">First verification:</span> {(simResult.first_verification as any).outcome}
                    </div>
                  )}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ─── Keys Panel ─── */}
        {activePanel === 'keys' && (
          <motion.div key="keys" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }}
            className="bg-[#161b22]/60 border border-slate-800 rounded-xl p-5">
            <h3 className="text-xs font-semibold text-slate-300 mb-4 flex items-center gap-2">
              <Key className="w-3.5 h-3.5 text-violet-400" /> Registered Signing Keys
            </h3>
            {keys.length === 0 ? (
              <div className="text-center py-8 text-slate-600 text-xs font-mono">No keys registered. Run a simulation to generate test keys.</div>
            ) : (
              <div className="space-y-2">
                {keys.map(k => (
                  <div key={k.key_id} className={`px-4 py-3 rounded-lg border transition-all ${
                    k.status === 'REVOKED' || k.status === 'ROTATED' ? 'bg-slate-900/30 border-slate-800/40 opacity-60' : 'bg-slate-900/50 border-slate-800/60'
                  }`}>
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold font-mono border ${
                          k.status === 'ACTIVE' ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/50' :
                          k.status === 'REVOKED' ? 'bg-rose-950/40 text-rose-400 border-rose-800/50' :
                          'bg-slate-800/40 text-slate-500 border-slate-700/50'
                        }`}>{k.status}</span>
                        <code className="text-[11px] text-slate-300 font-mono">{k.key_id}</code>
                        <span className="text-[10px] text-slate-600">{k.algorithm}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {/* Risk gauge */}
                        <div className="flex items-center gap-1">
                          <span className="text-[9px] text-slate-600 font-mono">RISK</span>
                          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div className={`h-full rounded-full transition-all ${
                              k.risk_score >= 70 ? 'bg-rose-500' : k.risk_score >= 30 ? 'bg-amber-500' : 'bg-emerald-500'
                            }`} style={{ width: `${k.risk_score}%` }} />
                          </div>
                          <span className={`text-[10px] font-bold font-mono ${
                            k.risk_score >= 70 ? 'text-rose-400' : k.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'
                          }`}>{k.risk_score.toFixed(0)}%</span>
                        </div>

                        {k.status === 'ACTIVE' && (
                          <>
                            <button onClick={() => rotateKey(k.key_id)}
                              className="px-2 py-1 text-[10px] font-mono bg-blue-950/40 text-blue-400 border border-blue-800/50 rounded hover:bg-blue-900/40 cursor-pointer transition-all flex items-center gap-1">
                              <RotateCcw className="w-3 h-3" /> Rotate
                            </button>
                            {revokeConfirm === k.key_id ? (
                              <div className="flex items-center gap-1">
                                <button onClick={() => revokeKey(k.key_id)}
                                  className="px-2 py-1 text-[10px] font-mono bg-rose-600 text-white rounded cursor-pointer">Confirm</button>
                                <button onClick={() => setRevokeConfirm(null)}
                                  className="px-2 py-1 text-[10px] font-mono bg-slate-800 text-slate-400 rounded cursor-pointer">Cancel</button>
                              </div>
                            ) : (
                              <button onClick={() => setRevokeConfirm(k.key_id)}
                                className="px-2 py-1 text-[10px] font-mono bg-rose-950/40 text-rose-400 border border-rose-800/50 rounded hover:bg-rose-900/40 cursor-pointer transition-all flex items-center gap-1">
                                <Trash2 className="w-3 h-3" /> Revoke
                              </button>
                            )}
                          </>
                        )}

                        <button onClick={() => { setSelectedKeyId(k.key_id); setActivePanel('timeline'); }}
                          className="px-2 py-1 text-[10px] font-mono bg-slate-800/60 text-slate-400 rounded hover:text-slate-200 cursor-pointer transition-all flex items-center gap-1">
                          <Clock className="w-3 h-3" /> Timeline
                        </button>
                      </div>
                    </div>
                    <div className="flex gap-4 mt-1.5 text-[10px] font-mono text-slate-600">
                      <span>Owner: {k.owner}</span>
                      <span>Sigs: {k.total_signatures}</span>
                      <span>Created: {new Date(k.created_at * 1000).toLocaleString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}

        {/* ─── Timeline Panel ─── */}
        {activePanel === 'timeline' && (
          <motion.div key="timeline" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }}
            className="bg-[#161b22]/60 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                <Clock className="w-3.5 h-3.5 text-violet-400" />
                Forensic Timeline {selectedKeyId && <code className="text-[10px] text-slate-500 ml-1">{selectedKeyId}</code>}
              </h3>
              {keys.length > 0 && (
                <select value={selectedKeyId || ''} onChange={e => setSelectedKeyId(e.target.value)}
                  className="bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400 rounded px-2 py-1 focus:outline-none">
                  <option value="">Select key...</option>
                  {keys.map(k => <option key={k.key_id} value={k.key_id}>{k.key_id} ({k.status})</option>)}
                </select>
              )}
            </div>

            {timeline.length === 0 ? (
              <div className="text-center py-8 text-slate-600 text-xs font-mono">
                {selectedKeyId ? 'No timeline events for this key.' : 'Select a key to view its forensic timeline.'}
              </div>
            ) : (
              <div className="space-y-1 max-h-[400px] overflow-y-auto">
                {timeline.map((evt, i) => {
                  const isError = evt.outcome.includes('INVALID') || evt.outcome.includes('REPLAY') || evt.outcome.includes('MISMATCH') || evt.outcome.includes('REVOKED');
                  const isWarning = evt.outcome.includes('ANOMALY');
                  return (
                    <div key={evt.event_id || i} className={`flex items-start gap-3 px-3 py-2 rounded-lg border ${
                      isError ? 'bg-rose-950/20 border-rose-900/30' :
                      isWarning ? 'bg-amber-950/20 border-amber-900/30' :
                      'bg-slate-900/30 border-slate-800/40'
                    }`}>
                      <div className="flex flex-col items-center mt-0.5">
                        <div className={`w-2 h-2 rounded-full ${
                          isError ? 'bg-rose-500' : isWarning ? 'bg-amber-500' : 'bg-emerald-500'
                        }`} />
                        {i < timeline.length - 1 && <div className="w-px h-6 bg-slate-800 mt-1" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[10px] font-bold font-mono text-slate-400">{evt.event_type}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold font-mono ${
                            isError ? 'bg-rose-950/60 text-rose-400' :
                            isWarning ? 'bg-amber-950/60 text-amber-400' :
                            'bg-emerald-950/60 text-emerald-400'
                          }`}>{evt.outcome}</span>
                          {evt.risk_score > 0 && (
                            <span className="text-[9px] font-mono text-slate-600">Risk: {evt.risk_score.toFixed(0)}%</span>
                          )}
                          <span className="text-[9px] text-slate-600 font-mono ml-auto">
                            {new Date(evt.timestamp * 1000).toLocaleTimeString()}
                          </span>
                        </div>
                        {evt.details && <p className="text-[10px] text-slate-500 font-mono mt-0.5 truncate">{evt.details}</p>}
                        {evt.source_ip && <span className="text-[9px] text-slate-600 font-mono">IP: {evt.source_ip}</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// ─── Local Simulation Fallback ──────────────────────────────────────────
function simulateLocally(scenario: string, algorithm: string): SimulationResult {
  const keyId = `key-sim-${Date.now().toString(36)}`;
  const baseVerification = {
    outcome: 'VALID',
    cryptographic_valid: true,
    replay_check_passed: true,
    provenance_check_passed: true,
    anomaly: { risk_score: 0, flags: [] as string[], details: 'No anomalies detected' },
    message: `${algorithm} signature verified successfully. Risk: 0%`,
    processing_time_ms: Math.random() * 5 + 0.5,
  };

  switch (scenario) {
    case 'tampered':
      return { scenario, key_id: keyId, verification: { ...baseVerification, outcome: 'INVALID_SIGNATURE', cryptographic_valid: false, replay_check_passed: false, provenance_check_passed: false, message: `Invalid ${algorithm} signature — cryptographic verification failed` } };
    case 'replay':
      return { scenario, key_id: keyId, first_verification: { outcome: 'VALID' }, replay_attempt: { ...baseVerification, outcome: 'REPLAY_DETECTED', replay_check_passed: false, provenance_check_passed: false, message: `REPLAY: Nonce already used for key '${keyId}'` }, verification: { ...baseVerification, outcome: 'REPLAY_DETECTED', replay_check_passed: false, message: `REPLAY: Signature digest already recorded for key '${keyId}'` } };
    case 'stolen_key':
      return { scenario, key_id: keyId, verification: { ...baseVerification, outcome: 'PROVENANCE_MISMATCH', provenance_check_passed: false, message: 'Provenance violations: IP_OUT_OF_RANGE: 203.0.113.1 not in [10.0.0.0/8]; ASN_MISMATCH: source ASN 99999 not in [13335]' } };
    case 'impossible_travel':
      return { scenario, key_id: keyId, first_verification: { outcome: 'VALID' }, travel_attempt: { ...baseVerification, outcome: 'ANOMALY_DETECTED', anomaly: { risk_score: 65, flags: ['IMPOSSIBLE_TRAVEL'], details: 'Impossible travel: 10,848 km at 39,052,800 km/h (threshold: 900 km/h)' }, message: 'High anomaly risk (65%): Impossible travel detected' }, verification: { ...baseVerification, outcome: 'ANOMALY_DETECTED', anomaly: { risk_score: 65, flags: ['IMPOSSIBLE_TRAVEL'], details: 'Impossible travel: 10,848 km at 39,052,800 km/h' }, message: 'Signature verified. Risk: 65%' } };
    default:
      return { scenario, key_id: keyId, verification: baseVerification };
  }
}
