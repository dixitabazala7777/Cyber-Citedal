import React, { useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Zap, Play, Square, AlertTriangle, CheckCircle, Clock,
  Activity, Shield, BarChart3, X, Flame
} from 'lucide-react';

interface ChaosSimulatorProps {
  onLogMessage: (msg: string) => void;
}

interface AttackVector {
  id: string;
  name: string;
  description: string;
  category: string;
  syntheticPayload: string;
  expectedDetectionMs: number;
  severity: 'critical' | 'high' | 'medium';
}

interface SimulationResult {
  vectorId: string;
  vectorName: string;
  detected: boolean;
  detectionTimeMs: number;
  containmentTimeMs: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  details: string;
  timestamp: string;
}

interface SimulationRun {
  id: string;
  startTime: string;
  endTime: string | null;
  status: 'running' | 'complete' | 'aborted';
  results: SimulationResult[];
  overallGrade: string;
  avgDetectionMs: number;
  avgContainmentMs: number;
}

const ATTACK_VECTORS: AttackVector[] = [
  {
    id: 'syn-flood',
    name: 'SYN Flood Storm',
    description: 'Simulates high-volume TCP SYN packet flood targeting API gateway',
    category: 'DDoS',
    syntheticPayload: '[SYNTHETIC_DEFENSIVE_ASSET] SYN_FLOOD_SIMULATION: 50,000 SYN packets/sec targeting port 443',
    expectedDetectionMs: 500,
    severity: 'critical',
  },
  {
    id: 'sqli-storm',
    name: 'SQL Injection Storm',
    description: 'Batched SQLi payloads including UNION SELECT, boolean-based, and time-based blind injection',
    category: 'SQL Injection',
    syntheticPayload: "[SYNTHETIC_DEFENSIVE_ASSET] SQLI_TEST: ' OR 1=1 UNION SELECT null,table_name FROM information_schema.tables--",
    expectedDetectionMs: 200,
    severity: 'critical',
  },
  {
    id: 'credential-stuff',
    name: 'Credential Stuffing',
    description: 'Simulated brute-force credential stuffing from rotated proxy IPs',
    category: 'Brute Force',
    syntheticPayload: '[SYNTHETIC_DEFENSIVE_ASSET] CRED_STUFF: 1000 login attempts from 50 rotating IPs in 60 seconds',
    expectedDetectionMs: 1000,
    severity: 'high',
  },
  {
    id: 'xss-polyglot',
    name: 'XSS Polyglot Injection',
    description: 'Multi-context XSS payloads targeting HTML, JS, and CSS injection points',
    category: 'XSS',
    syntheticPayload: '[SYNTHETIC_DEFENSIVE_ASSET] XSS_POLY: <img/src=x onerror="alert(document.cookie)"/><svg/onload=eval(atob("YWxlcnQoMSk="))>',
    expectedDetectionMs: 150,
    severity: 'high',
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal Probe',
    description: 'Directory traversal attempts targeting sensitive system files',
    category: 'Path Traversal',
    syntheticPayload: '[SYNTHETIC_DEFENSIVE_ASSET] PATH_TRAV: ../../../../../../etc/passwd%00.jpg',
    expectedDetectionMs: 100,
    severity: 'medium',
  },
  {
    id: 'jwt-forge',
    name: 'JWT Forgery Attack',
    description: 'Attempts to forge JWT with algorithm confusion (none/HS256 vs RS256)',
    category: 'Auth Bypass',
    syntheticPayload: '[SYNTHETIC_DEFENSIVE_ASSET] JWT_FORGE: {"alg":"none","typ":"JWT"}.{"sub":"admin","role":"superuser"}',
    expectedDetectionMs: 50,
    severity: 'critical',
  },
];

function gradeDetectionTime(actual: number, expected: number): SimulationResult['grade'] {
  const ratio = actual / expected;
  if (ratio <= 0.5) return 'A+';
  if (ratio <= 0.8) return 'A';
  if (ratio <= 1.0) return 'B';
  if (ratio <= 1.5) return 'C';
  if (ratio <= 2.0) return 'D';
  return 'F';
}

const gradeColors: Record<string, string> = {
  'A+': 'text-emerald-600 dark:text-emerald-400',
  'A': 'text-emerald-600 dark:text-emerald-400',
  'B': 'text-sky-600 dark:text-sky-400',
  'C': 'text-amber-600 dark:text-amber-400',
  'D': 'text-orange-600 dark:text-orange-400',
  'F': 'text-rose-600 dark:text-rose-400',
};

export const ChaosSimulator: React.FC<ChaosSimulatorProps> = ({ onLogMessage }) => {
  const [selectedVectors, setSelectedVectors] = useState<Set<string>>(new Set(ATTACK_VECTORS.map(v => v.id)));
  const [currentRun, setCurrentRun] = useState<SimulationRun | null>(null);
  const [activeVectorIdx, setActiveVectorIdx] = useState<number>(-1);
  const [history, setHistory] = useState<SimulationRun[]>([]);
  const abortRef = useRef(false);

  const toggleVector = (id: string) => {
    setSelectedVectors(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const runSimulation = useCallback(async () => {
    const vectors = ATTACK_VECTORS.filter(v => selectedVectors.has(v.id));
    if (vectors.length === 0) return;

    abortRef.current = false;
    const run: SimulationRun = {
      id: `run-${Date.now()}`,
      startTime: new Date().toISOString(),
      endTime: null,
      status: 'running',
      results: [],
      overallGrade: '',
      avgDetectionMs: 0,
      avgContainmentMs: 0,
    };
    setCurrentRun(run);
    onLogMessage(`CHAOS RUNNER: Starting simulation with ${vectors.length} attack vectors...`);

    for (let i = 0; i < vectors.length; i++) {
      if (abortRef.current) {
        run.status = 'aborted';
        break;
      }

      const vec = vectors[i];
      setActiveVectorIdx(i);

      // Simulate processing delay
      const jitter = 0.5 + Math.random() * 1.5;
      const detectionMs = Math.round(vec.expectedDetectionMs * jitter);
      const containmentMs = Math.round(detectionMs * (0.8 + Math.random() * 0.6));

      await new Promise(r => setTimeout(r, Math.min(detectionMs + 200, 1500)));

      const grade = gradeDetectionTime(detectionMs, vec.expectedDetectionMs);
      const result: SimulationResult = {
        vectorId: vec.id,
        vectorName: vec.name,
        detected: true,
        detectionTimeMs: detectionMs,
        containmentTimeMs: containmentMs,
        grade,
        details: `${vec.category} payload injected and detected in ${detectionMs}ms. Containment in ${containmentMs}ms.`,
        timestamp: new Date().toISOString(),
      };

      run.results.push(result);
      setCurrentRun({ ...run });
      onLogMessage(`CHAOS RUNNER: [${i + 1}/${vectors.length}] ${vec.name} — Grade: ${grade} (${detectionMs}ms detection)`);
    }

    if (run.status !== 'aborted') run.status = 'complete';
    run.endTime = new Date().toISOString();

    const avgDet = run.results.reduce((s, r) => s + r.detectionTimeMs, 0) / (run.results.length || 1);
    const avgCont = run.results.reduce((s, r) => s + r.containmentTimeMs, 0) / (run.results.length || 1);
    run.avgDetectionMs = Math.round(avgDet);
    run.avgContainmentMs = Math.round(avgCont);

    const gradeOrder = ['A+', 'A', 'B', 'C', 'D', 'F'];
    const worstIdx = Math.max(...run.results.map(r => gradeOrder.indexOf(r.grade)));
    run.overallGrade = gradeOrder[worstIdx] || 'A';

    setCurrentRun({ ...run });
    setHistory(prev => [run, ...prev.slice(0, 9)]);
    setActiveVectorIdx(-1);
    onLogMessage(`CHAOS RUNNER: Simulation complete. Overall grade: ${run.overallGrade}. Avg detection: ${run.avgDetectionMs}ms`);
  }, [selectedVectors, onLogMessage]);

  const abortSimulation = () => {
    abortRef.current = true;
    onLogMessage('CHAOS RUNNER: Simulation aborted by operator.');
  };

  const isRunning = currentRun?.status === 'running';

  return (
    <div className="max-w-7xl w-full mx-auto px-4 mt-6 relative z-10 flex flex-col gap-5 text-slate-900 dark:text-slate-100">
      {/* Header */}
      <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-orange-100 dark:bg-orange-600/20 rounded-xl border border-orange-200 dark:border-orange-700/40">
              <Flame className="w-5 h-5 text-orange-600 dark:text-orange-400" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider font-mono">Chaos Security Runner</h2>
              <p className="text-xs text-slate-600 dark:text-slate-400 font-mono mt-0.5">Automated Threat Simulation & Detection Grading • [SYNTHETIC_DEFENSIVE_ASSET]</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isRunning ? (
              <button onClick={abortSimulation}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold font-mono rounded-xl transition-all cursor-pointer flex items-center gap-2 shadow-md">
                <Square className="w-3.5 h-3.5" /> Abort
              </button>
            ) : (
              <button onClick={runSimulation} disabled={selectedVectors.size === 0}
                className="px-4 py-2 bg-orange-600 hover:bg-orange-500 disabled:opacity-50 text-white text-xs font-bold font-mono rounded-xl transition-all cursor-pointer flex items-center gap-2 shadow-md active:scale-95">
                <Play className="w-3.5 h-3.5 fill-white" /> Launch Simulation ({selectedVectors.size} vectors)
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Left: Vector Selection */}
        <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl">
          <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200 mb-3 flex items-center gap-2 uppercase font-mono">
            <Zap className="w-3.5 h-3.5 text-orange-500" /> Attack Vectors Catalog
          </h3>
          <div className="space-y-2.5">
            {ATTACK_VECTORS.map((vec, idx) => {
              const isSelected = selectedVectors.has(vec.id);
              const isActive = isRunning && activeVectorIdx === idx;
              const result = currentRun?.results.find(r => r.vectorId === vec.id);

              return (
                <div key={vec.id} className={`px-3.5 py-3 rounded-xl border transition-all ${
                  isActive ? 'bg-orange-50 dark:bg-orange-950/30 border-orange-500 animate-pulse' :
                  result ? 'bg-slate-50 dark:bg-slate-950/60 border-slate-200 dark:border-slate-800' :
                  isSelected ? 'bg-indigo-50/50 dark:bg-slate-950/40 border-indigo-200 dark:border-slate-800' :
                  'bg-slate-50/40 dark:bg-slate-950/20 border-slate-200 dark:border-slate-900 opacity-60'
                }`}>
                  <div className="flex items-center gap-3">
                    <input type="checkbox" checked={isSelected} onChange={() => toggleVector(vec.id)}
                      disabled={isRunning}
                      className="w-4 h-4 rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-orange-600 cursor-pointer" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-900 dark:text-white font-mono">{vec.name}</span>
                        <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase border ${
                          vec.severity === 'critical' ? 'bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-800' :
                          vec.severity === 'high' ? 'bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800' :
                          'bg-sky-100 dark:bg-sky-950 text-sky-800 dark:text-sky-300 border-sky-300 dark:border-sky-800'
                        }`}>{vec.severity}</span>
                      </div>
                      <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">{vec.description}</p>
                    </div>
                    {result && (
                      <div className="flex items-center gap-2">
                        <span className={`text-base font-extrabold font-mono ${gradeColors[result.grade]}`}>{result.grade}</span>
                        <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 font-bold">{result.detectionTimeMs}ms</span>
                      </div>
                    )}
                    {isActive && (
                      <div className="w-4 h-4 border-2 border-orange-500/30 border-t-orange-500 rounded-full animate-spin" />
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Results */}
        <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl">
          <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200 mb-3 flex items-center gap-2 uppercase font-mono">
            <BarChart3 className="w-3.5 h-3.5 text-orange-500" /> Detection & SLA Metrics
          </h3>

          {!currentRun && (
            <div className="flex flex-col items-center justify-center h-48 text-slate-500">
              <Flame className="w-8 h-8 mb-2 opacity-30 text-orange-500" />
              <p className="text-xs font-mono">Select vectors and launch simulation above</p>
            </div>
          )}

          {currentRun && (
            <div className="space-y-4">
              {/* Overall metrics */}
              <div className={`p-4 rounded-xl border ${
                currentRun.status === 'running' ? 'bg-orange-50 dark:bg-orange-950/20 border-orange-200 dark:border-orange-800/30 text-orange-900 dark:text-orange-200' :
                currentRun.status === 'complete' ? 'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800/30 text-emerald-900 dark:text-emerald-200' :
                'bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-800/30 text-rose-900 dark:text-rose-200'
              }`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono font-bold uppercase">
                    {currentRun.status === 'running' ? 'RUNNING...' : currentRun.status === 'complete' ? 'SIMULATION COMPLETE' : 'ABORTED'}
                  </span>
                  {currentRun.overallGrade && (
                    <span className={`text-2xl font-black font-mono ${gradeColors[currentRun.overallGrade]}`}>
                      {currentRun.overallGrade}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-3 gap-3 mt-3">
                  <div className="text-center">
                    <p className="text-[10px] text-slate-600 dark:text-slate-400 font-mono font-bold uppercase">Vectors</p>
                    <p className="text-lg font-extrabold text-slate-900 dark:text-white">{currentRun.results.length}/{selectedVectors.size}</p>
                  </div>
                  <div className="text-center">
                    <p className="text-[10px] text-slate-600 dark:text-slate-400 font-mono font-bold uppercase">Avg Detection</p>
                    <p className="text-lg font-extrabold text-sky-600 dark:text-sky-400">{currentRun.avgDetectionMs}ms</p>
                  </div>
                  <div className="text-center">
                    <p className="text-[10px] text-slate-600 dark:text-slate-400 font-mono font-bold uppercase">Avg Containment</p>
                    <p className="text-lg font-extrabold text-emerald-600 dark:text-emerald-400">{currentRun.avgContainmentMs}ms</p>
                  </div>
                </div>
              </div>

              {/* Results list */}
              {currentRun.results.length > 0 && (
                <div className="space-y-2 max-h-[250px] overflow-y-auto">
                  {currentRun.results.map(r => (
                    <div key={r.vectorId} className="flex items-center gap-3 px-3 py-2 bg-slate-50 dark:bg-slate-950/60 rounded-xl border border-slate-200 dark:border-slate-800">
                      <CheckCircle className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <span className="text-xs font-bold text-slate-900 dark:text-white font-mono">{r.vectorName}</span>
                        <div className="flex gap-3 text-[10px] font-mono text-slate-600 dark:text-slate-400 mt-0.5">
                          <span>Detection: <strong className="text-slate-900 dark:text-slate-200">{r.detectionTimeMs}ms</strong></span>
                          <span>Containment: <strong className="text-slate-900 dark:text-slate-200">{r.containmentTimeMs}ms</strong></span>
                        </div>
                      </div>
                      <span className={`text-base font-black font-mono ${gradeColors[r.grade]}`}>{r.grade}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* History */}
          {history.length > 1 && (
            <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800">
              <h4 className="text-[10px] font-mono font-bold text-slate-700 dark:text-slate-300 uppercase mb-2">Previous Runs</h4>
              <div className="space-y-1">
                {history.slice(1, 4).map(run => (
                  <div key={run.id} className="flex items-center justify-between px-2 py-1 text-xs font-mono text-slate-600 dark:text-slate-300">
                    <span>{new Date(run.startTime).toLocaleTimeString()}</span>
                    <span>{run.results.length} vectors</span>
                    <span className={`font-bold ${gradeColors[run.overallGrade]}`}>{run.overallGrade}</span>
                    <span>{run.avgDetectionMs}ms avg</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ChaosSimulator;
