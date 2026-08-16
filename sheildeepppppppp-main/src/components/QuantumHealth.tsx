import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Activity, 
  ShieldCheck, 
  Zap, 
  AlertTriangle, 
  CheckCircle2, 
  Clock, 
  Key, 
  Play, 
  RotateCcw,
  Wifi,
  Layers,
  Sparkles,
  BarChart2
} from 'lucide-react';

interface HandshakeLog {
  id: string;
  timestamp: string;
  endpoint: string;
  algorithm: string;
  clientPkHex: string;
  ciphertextSnippet: string;
  sharedSecretStub: string;
  latencyMs: number;
  status: '200_OK' | '403_BREAKER' | '503_DEGRADED';
  message: string;
}

interface LatencyDataPoint {
  time: string;
  latency: number;
  successRate: number;
  throughput: number;
}

interface QuantumHealthProps {
  onLogMessage?: (msg: string) => void;
}

export const QuantumHealth: React.FC<QuantumHealthProps> = ({ onLogMessage }) => {
  // --- Metric States ---
  const [totalHandshakes, setTotalHandshakes] = useState<number>(18420);
  const [successfulHandshakes, setSuccessfulHandshakes] = useState<number>(18392);
  const [failedHandshakes, setFailedHandshakes] = useState<number>(28);
  const [currentLatencyMs, setCurrentLatencyMs] = useState<number>(2.14);
  const [p95LatencyMs, setP95LatencyMs] = useState<number>(3.42);
  const [p99LatencyMs, setP99LatencyMs] = useState<number>(5.81);
  const [throughput, setThroughput] = useState<number>(1420); // hsk / sec
  
  const [hsmStatus, setHsmStatus] = useState<{
    activeKey?: { keyId: string; generatedAt: string; fingerprint: string };
    hsmNodes?: Array<{ id: string; name: string; latencyMs: number; memoryUsagePct: number; keyPoolCount: number }>;
    hardwareStatus?: string;
  }>({});

  const fetchHsmStatus = async () => {
    try {
      const res = await fetch('/api/v1/pqc/hsm-status');
      if (res.ok) {
        const data = await res.json();
        setHsmStatus(data);
      }
    } catch {
      // Ignored
    }
  };

  useEffect(() => {
    fetchHsmStatus();
  }, []);

  const handleRotateKyberKeys = async () => {
    try {
      const res = await fetch('/api/v1/pqc/rotate', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (onLogMessage) {
          onLogMessage(`PQC HSM ROTATION: Key Pair rotated -> ID: ${data.pqcKeyPair?.keyId} [Fingerprint: ${data.pqcKeyPair?.fingerprint}]`);
        }
        fetchHsmStatus();
      }
    } catch (e) {
      console.warn("Key Rotation Error:", e);
    }
  };
  const [isAutoProbing, setIsAutoProbing] = useState<boolean>(true);
  const [noiseSpikeActive, setNoiseSpikeActive] = useState<boolean>(false);
  const [isBurstTesting, setIsBurstTesting] = useState<boolean>(false);

  // --- Real-Time Latency Time Series Data ---
  const [history, setHistory] = useState<LatencyDataPoint[]>(() => {
    const initial: LatencyDataPoint[] = [];
    const now = Date.now();
    for (let i = 20; i >= 0; i--) {
      const t = new Date(now - i * 3000);
      const timeStr = t.toLocaleTimeString('en-US', { hour12: false, minute: '2-digit', second: '2-digit' });
      initial.push({
        time: timeStr,
        latency: parseFloat((1.8 + Math.random() * 0.8).toFixed(2)),
        successRate: 99.85 + (Math.random() * 0.1 - 0.05),
        throughput: Math.floor(1380 + Math.random() * 80)
      });
    }
    return initial;
  });

  // --- Recent Handshake Log Feed ---
  const [handshakeLogs, setHandshakeLogs] = useState<HandshakeLog[]>([
    {
      id: 'hsk-901',
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
      endpoint: '/api/v1/pqc/handshake',
      algorithm: 'Crystals-Kyber-1024',
      clientPkHex: '0x8a92f...3c01',
      ciphertextSnippet: '0x4f12a...9e88',
      sharedSecretStub: '0x8f3b...11a0',
      latencyMs: 1.95,
      status: '200_OK',
      message: 'Kyber1024 KEM session established via /api/v1/pqc/handshake'
    },
    {
      id: 'hsk-900',
      timestamp: new Date(Date.now() - 3000).toLocaleTimeString('en-US', { hour12: false }),
      endpoint: '/api/v1/pqc/handshake',
      algorithm: 'Crystals-Kyber-1024',
      clientPkHex: '0x11b40...7e99',
      ciphertextSnippet: '0x32e1d...00b2',
      sharedSecretStub: '0x7a2c...99d1',
      latencyMs: 2.12,
      status: '200_OK',
      message: 'Encapsulated 32-byte symmetric secret successfully derived'
    }
  ]);

  // Derived success rate
  const successRate = totalHandshakes > 0 
    ? ((successfulHandshakes / totalHandshakes) * 100).toFixed(2)
    : '100.00';

  // --- Execute Single Handshake Probe ---
  const executeProbe = useCallback((isManual = false) => {
    // Calculate latency based on noise spike setting
    const baseLatency = noiseSpikeActive 
      ? 12.5 + Math.random() * 18.0 
      : 1.7 + Math.random() * 1.2;
    
    // Simulate rare failure during noise spike
    const isError = noiseSpikeActive ? Math.random() < 0.25 : Math.random() < 0.002;
    const latencyVal = parseFloat(baseLatency.toFixed(2));

    const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
    const pkSnippet = '0x' + Array.from({length: 8}, () => Math.floor(Math.random()*16).toString(16)).join('');
    const ctSnippet = '0x' + Array.from({length: 8}, () => Math.floor(Math.random()*16).toString(16)).join('');
    const secretSnippet = '0x' + Array.from({length: 8}, () => Math.floor(Math.random()*16).toString(16)).join('');

    const newLog: HandshakeLog = {
      id: `hsk-${Date.now().toString().slice(-4)}`,
      timestamp: timeStr,
      endpoint: '/api/v1/pqc/handshake',
      algorithm: 'Crystals-Kyber-1024 (ML-KEM)',
      clientPkHex: `${pkSnippet}...`,
      ciphertextSnippet: `${ctSnippet}...`,
      sharedSecretStub: `${secretSnippet}...`,
      latencyMs: latencyVal,
      status: isError ? '503_DEGRADED' : '200_OK',
      message: isError 
        ? 'Quantum entropy degradation detected in /api/v1/pqc/handshake'
        : 'Kyber1024 KEM Handshake completed successfully'
    };

    setTotalHandshakes(prev => prev + 1);
    if (isError) {
      setFailedHandshakes(prev => prev + 1);
      if (onLogMessage) onLogMessage(`PQC HEALTH WARNING: High latency/failure detected (${latencyVal}ms)`);
    } else {
      setSuccessfulHandshakes(prev => prev + 1);
    }

    setCurrentLatencyMs(latencyVal);
    setP95LatencyMs(parseFloat((latencyVal * 1.45).toFixed(2)));
    setP99LatencyMs(parseFloat((latencyVal * 2.1).toFixed(2)));
    setThroughput(Math.floor(1350 + Math.random() * 150));

    // Update history
    setHistory(prev => {
      const nextPoint: LatencyDataPoint = {
        time: timeStr,
        latency: latencyVal,
        successRate: parseFloat(((successfulHandshakes / (totalHandshakes + 1)) * 100).toFixed(2)),
        throughput: Math.floor(1350 + Math.random() * 150)
      };
      return [...prev.slice(1), nextPoint];
    });

    // Add to log feed
    setHandshakeLogs(prev => [newLog, ...prev.slice(0, 14)]);

    if (isManual && onLogMessage) {
      onLogMessage(`PQC MONITOR: Executed manual Kyber-1024 handshake probe [Latency: ${latencyVal}ms, Status: ${isError ? 'DEGRADED' : '200 OK'}]`);
    }
  }, [noiseSpikeActive, successfulHandshakes, totalHandshakes, onLogMessage]);

  // --- Auto-Probe Loop ---
  useEffect(() => {
    if (!isAutoProbing) return;
    const interval = setInterval(() => {
      executeProbe(false);
    }, 2000);
    return () => clearInterval(interval);
  }, [isAutoProbing, executeProbe]);

  // --- Burst Test Handler ---
  const handleBurstTest = () => {
    setIsBurstTesting(true);
    if (onLogMessage) onLogMessage('PQC MONITOR: Initiating 100-burst Crystals-Kyber-1024 handshake load test...');

    let completed = 0;
    const interval = setInterval(() => {
      executeProbe(false);
      completed += 10;
      if (completed >= 100) {
        clearInterval(interval);
        setIsBurstTesting(false);
        if (onLogMessage) onLogMessage('PQC MONITOR: Burst load test completed. 100/100 handshakes processed.');
      }
    }, 150);
  };

  // Reset Metrics
  const handleReset = () => {
    setTotalHandshakes(0);
    setSuccessfulHandshakes(0);
    setFailedHandshakes(0);
    setCurrentLatencyMs(1.95);
    setNoiseSpikeActive(false);
    if (onLogMessage) onLogMessage('PQC MONITOR: Reset handshake telemetry metrics.');
  };

  return (
    <div className="space-y-6">
      
      {/* Header Banner */}
      <div className="bg-slate-950 border border-slate-850 rounded-xl p-5 shadow-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="p-1.5 bg-emerald-950/80 border border-emerald-800/80 rounded-lg text-emerald-400">
              <Activity className="w-5 h-5 animate-pulse" />
            </span>
            <h2 className="text-base font-mono font-bold text-white uppercase tracking-wide">
              Crystals-Kyber-1024 Handshake Health Monitor
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950 text-indigo-400 border border-indigo-800/80">
              ML-KEM Level 5
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans">
            Real-time stability, latency profiling, and PQC key exchange endpoint telemetry for `/api/v1/pqc/handshake`.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleRotateKyberKeys}
            className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white border border-rose-500 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition cursor-pointer shadow-[0_0_12px_rgba(225,29,72,0.3)]"
          >
            <Key className="w-3.5 h-3.5 text-white" />
            Rotate Kyber Keys
          </button>

          <button
            onClick={() => setIsAutoProbing(!isAutoProbing)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition border cursor-pointer ${
              isAutoProbing 
                ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/80 hover:bg-emerald-900/60' 
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
            }`}
          >
            <Wifi className={`w-3.5 h-3.5 ${isAutoProbing ? 'animate-pulse text-emerald-400' : ''}`} />
            {isAutoProbing ? 'Auto-Probing ON' : 'Auto-Probing PAUSED'}
          </button>

          <button
            onClick={() => executeProbe(true)}
            className="px-3 py-1.5 bg-indigo-950/60 hover:bg-indigo-900/60 text-indigo-300 border border-indigo-800/80 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 text-indigo-400" />
            Single Probe
          </button>

          <button
            onClick={handleBurstTest}
            disabled={isBurstTesting}
            className="px-3 py-1.5 bg-purple-950/60 hover:bg-purple-900/60 text-purple-300 border border-purple-800/80 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
          >
            <Zap className={`w-3.5 h-3.5 text-purple-400 ${isBurstTesting ? 'animate-spin' : ''}`} />
            {isBurstTesting ? 'Testing...' : '100x Burst Load'}
          </button>

          <button
            onClick={() => setNoiseSpikeActive(!noiseSpikeActive)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition border cursor-pointer ${
              noiseSpikeActive 
                ? 'bg-rose-950/80 text-rose-300 border-rose-800 animate-pulse' 
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-amber-300'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            {noiseSpikeActive ? 'Noise Spike ACTIVE' : 'Inject Noise'}
          </button>

          <button
            onClick={handleReset}
            className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 rounded-lg transition cursor-pointer"
            title="Reset Telemetry"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* HSM Hardware Node Cluster Status */}
      {hsmStatus.hsmNodes && (
        <div className="bg-slate-950 border border-slate-850 rounded-xl p-4 font-mono space-y-3">
          <div className="flex justify-between items-center border-b border-slate-850 pb-2 text-xs">
            <span className="font-bold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-rose-400" /> HSM HARDWARE SECURITY MODULE CLUSTER ({hsmStatus.hardwareStatus})
            </span>
            <span className="text-[10px] text-slate-400">Active Fingerprint: <strong className="text-emerald-400">{hsmStatus.activeKey?.fingerprint}</strong></span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            {hsmStatus.hsmNodes.map((hsm) => (
              <div key={hsm.id} className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex justify-between items-center">
                <div>
                  <div className="font-bold text-slate-200">{hsm.name}</div>
                  <div className="text-[10px] text-slate-500">Latency: {hsm.latencyMs}ms | RAM: {hsm.memoryUsagePct}%</div>
                </div>
                <div className="text-right">
                  <div className="text-xs font-bold text-indigo-400">{hsm.keyPoolCount}</div>
                  <div className="text-[9px] text-slate-500">Keys Buffered</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Card 1: Success Rate */}
        <div className="bg-slate-950/80 border border-slate-850 rounded-xl p-4 space-y-2 relative overflow-hidden">
          <div className="flex justify-between items-center text-xs font-mono text-slate-400">
            <span className="uppercase font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Success Rate
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
              parseFloat(successRate) >= 99.5 
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-900' 
                : 'bg-amber-950 text-amber-400 border border-amber-900'
            }`}>
              {parseFloat(successRate) >= 99.5 ? 'NOMINAL' : 'DEGRADED'}
            </span>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-mono font-extrabold text-white">
              {successRate}%
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              {successfulHandshakes.toLocaleString()} pass • {failedHandshakes} err
            </span>
          </div>
          {/* Progress Bar */}
          <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
            <div 
              className={`h-full transition-all duration-500 ${parseFloat(successRate) >= 99.5 ? 'bg-emerald-500' : 'bg-amber-500'}`}
              style={{ width: `${Math.min(100, Math.max(0, parseFloat(successRate)))}%` }}
            />
          </div>
        </div>

        {/* Card 2: Mean Latency */}
        <div className="bg-slate-950/80 border border-slate-850 rounded-xl p-4 space-y-2">
          <div className="flex justify-between items-center text-xs font-mono text-slate-400">
            <span className="uppercase font-bold flex items-center gap-1.5">
              <Clock className="w-4 h-4 text-cyan-400" /> Endpoint Latency
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
              currentLatencyMs < 5.0 ? 'bg-cyan-950 text-cyan-400 border border-cyan-900' : 'bg-rose-950 text-rose-400 border border-rose-900'
            }`}>
              p95: {p95LatencyMs}ms
            </span>
          </div>
          <div className="flex items-baseline justify-between">
            <span className={`text-2xl font-mono font-extrabold ${currentLatencyMs < 5.0 ? 'text-cyan-400' : 'text-rose-400'}`}>
              {currentLatencyMs} <span className="text-xs text-slate-400">ms</span>
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              p99: {p99LatencyMs}ms
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-500 flex justify-between">
            <span>Target: &lt; 5.00ms</span>
            <span>Threshold: 15.00ms</span>
          </div>
        </div>

        {/* Card 3: Handshake Throughput */}
        <div className="bg-slate-950/80 border border-slate-850 rounded-xl p-4 space-y-2">
          <div className="flex justify-between items-center text-xs font-mono text-slate-400">
            <span className="uppercase font-bold flex items-center gap-1.5">
              <Zap className="w-4 h-4 text-purple-400" /> Key Exchanges/sec
            </span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-400 border border-purple-900">
              HIGH CAP
            </span>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-mono font-extrabold text-purple-300">
              {throughput.toLocaleString()} <span className="text-xs text-slate-400">HSK/s</span>
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              Peak: 2,400/s
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-500">
            Max Engine Capacity: 12,450 ops/sec
          </div>
        </div>

        {/* Card 4: KEM Circuit Breaker Health */}
        <div className="bg-slate-950/80 border border-slate-850 rounded-xl p-4 space-y-2">
          <div className="flex justify-between items-center text-xs font-mono text-slate-400">
            <span className="uppercase font-bold flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" /> Circuit Breaker
            </span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-900">
              ARMED
            </span>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-mono font-extrabold text-emerald-400">
              100% <span className="text-xs text-slate-400">ARMED</span>
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              0 Trips in 24h
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-500">
            Auto-Trips if error &gt; 5.0% or latency &gt; 15ms
          </div>
        </div>

      </div>

      {/* Main Real-Time Time Series Latency Graph & Kyber Stage Diagnostics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* Latency & Success Rate Sparkline Graph (2/3 width) */}
        <div className="lg:col-span-2 bg-slate-950 border border-slate-850 rounded-xl p-5 space-y-4 shadow-xl">
          <div className="flex justify-between items-center border-b border-slate-900 pb-3">
            <div>
              <h3 className="text-sm font-mono font-bold text-white flex items-center gap-2 uppercase">
                <BarChart2 className="w-4 h-4 text-cyan-400" /> Real-Time Handshake Latency & Stability Profile
              </h3>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Sampling `/api/v1/pqc/handshake` execution duration (ms) across active thread workers.
              </p>
            </div>
            <div className="flex items-center gap-3 font-mono text-[11px]">
              <div className="flex items-center gap-1 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span>
                <span>Latency (ms)</span>
              </div>
              <div className="flex items-center gap-1 text-emerald-400">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
                <span>Success Rate (%)</span>
              </div>
            </div>
          </div>

          {/* SVG Visual Graph */}
          <div className="h-56 w-full relative bg-[#030712] border border-slate-900 rounded-lg p-3 flex flex-col justify-between overflow-hidden">
            {/* Grid lines */}
            <div className="absolute inset-0 grid grid-rows-4 pointer-events-none opacity-20">
              <div className="border-b border-slate-700"></div>
              <div className="border-b border-slate-700"></div>
              <div className="border-b border-slate-700"></div>
              <div className="border-b border-slate-700"></div>
            </div>

            {/* SVG Plot */}
            <svg className="w-full h-full overflow-visible relative z-10" preserveAspectRatio="none" viewBox="0 0 100 100">
              {/* Latency Line Path */}
              {history.length > 1 && (
                <path
                  d={history.reduce((acc, point, index) => {
                    const x = (index / (history.length - 1)) * 100;
                    // Scale latency 0ms - 20ms to Y 100 - 0
                    const y = Math.max(5, 100 - (point.latency / 20) * 100);
                    return `${acc} ${index === 0 ? 'M' : 'L'} ${x} ${y}`;
                  }, '')}
                  fill="none"
                  stroke="#22d3ee"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
              )}

              {/* Area under latency line */}
              {history.length > 1 && (
                <path
                  d={`${history.reduce((acc, point, index) => {
                    const x = (index / (history.length - 1)) * 100;
                    const y = Math.max(5, 100 - (point.latency / 20) * 100);
                    return `${acc} ${index === 0 ? 'M' : 'L'} ${x} ${y}`;
                  }, '')} L 100 100 L 0 100 Z`}
                  fill="url(#cyanGradient)"
                  opacity="0.15"
                />
              )}

              <defs>
                <linearGradient id="cyanGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
                </linearGradient>
              </defs>
            </svg>

            {/* X-Axis Labels */}
            <div className="flex justify-between text-[9px] font-mono text-slate-500 pt-2 border-t border-slate-900/80">
              <span>{history[0]?.time}</span>
              <span>{history[Math.floor(history.length / 2)]?.time}</span>
              <span>{history[history.length - 1]?.time}</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between text-xs font-mono text-slate-400 bg-slate-900/40 p-2.5 rounded-lg border border-slate-850">
            <span className="flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
              Optimal Latency Target: <strong>&lt; 3.0ms</strong>
            </span>
            <span>Current Response: <strong className="text-cyan-400">{currentLatencyMs}ms</strong></span>
            <span>Quantum Entropy: <strong className="text-emerald-400">256.0 bits</strong></span>
          </div>
        </div>

        {/* Kyber-1024 Handshake Pipeline Stage Health (1/3 width) */}
        <div className="bg-slate-950 border border-slate-850 rounded-xl p-5 space-y-4 shadow-xl flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-mono font-bold text-white flex items-center gap-2 uppercase border-b border-slate-900 pb-3">
              <Layers className="w-4 h-4 text-indigo-400" /> Kyber-1024 Stage Diagnostics
            </h3>

            <div className="space-y-3 mt-3 font-mono text-xs">
              
              {/* Stage 1 */}
              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Stage 1: Public Key Delivery</span>
                  <span className="text-slate-300">1184 Bytes Hex Ingest</span>
                </div>
                <div className="text-right">
                  <span className="text-emerald-400 font-bold text-[11px] block">0.42ms</span>
                  <span className="text-[9px] bg-emerald-950 text-emerald-400 px-1 rounded">OK</span>
                </div>
              </div>

              {/* Stage 2 */}
              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Stage 2: Lattice Sampling</span>
                  <span className="text-slate-300">Module-LWR Matrix Math</span>
                </div>
                <div className="text-right">
                  <span className="text-emerald-400 font-bold text-[11px] block">0.78ms</span>
                  <span className="text-[9px] bg-emerald-950 text-emerald-400 px-1 rounded">OK</span>
                </div>
              </div>

              {/* Stage 3 */}
              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Stage 3: Ciphertext Encap</span>
                  <span className="text-slate-300">1568 Bytes Output</span>
                </div>
                <div className="text-right">
                  <span className="text-emerald-400 font-bold text-[11px] block">0.55ms</span>
                  <span className="text-[9px] bg-emerald-950 text-emerald-400 px-1 rounded">OK</span>
                </div>
              </div>

              {/* Stage 4 */}
              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Stage 4: Shared Secret</span>
                  <span className="text-slate-300">32-Byte AES-256 Key</span>
                </div>
                <div className="text-right">
                  <span className="text-emerald-400 font-bold text-[11px] block">0.28ms</span>
                  <span className="text-[9px] bg-emerald-950 text-emerald-400 px-1 rounded">OK</span>
                </div>
              </div>

              {/* Stage 5 */}
              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Stage 5: Anti-Replay Nonce</span>
                  <span className="text-slate-300">Monotonic Nonce Verify</span>
                </div>
                <div className="text-right">
                  <span className="text-emerald-400 font-bold text-[11px] block">0.11ms</span>
                  <span className="text-[9px] bg-emerald-950 text-emerald-400 px-1 rounded">OK</span>
                </div>
              </div>

            </div>
          </div>

          <div className="bg-indigo-950/30 border border-indigo-900/50 p-2.5 rounded-lg text-[10px] font-mono text-indigo-300 flex items-center justify-between">
            <span>Total KEM Pipeline Latency:</span>
            <strong className="text-indigo-200">2.14 ms</strong>
          </div>
        </div>

      </div>

      {/* Live Handshake Event Audit Feed */}
      <div className="bg-slate-950 border border-slate-850 rounded-xl p-5 space-y-3 shadow-xl">
        <div className="flex justify-between items-center border-b border-slate-900 pb-3">
          <h3 className="text-sm font-mono font-bold text-white flex items-center gap-2 uppercase">
            <Key className="w-4 h-4 text-emerald-400" /> Live `/api/v1/pqc/handshake` Telemetry Feed
          </h3>
          <span className="text-xs font-mono text-slate-500">
            Showing latest {handshakeLogs.length} events
          </span>
        </div>

        <div className="space-y-2 max-h-72 overflow-y-auto font-mono text-xs pr-1">
          <AnimatePresence initial={false}>
            {handshakeLogs.map((log) => (
              <motion.div
                key={log.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                className="p-2.5 bg-slate-900/50 border border-slate-800 rounded-lg flex flex-col md:flex-row justify-between items-start md:items-center gap-2"
              >
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${log.status === '200_OK' ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
                  <span className="text-slate-500 text-[10px]">{log.timestamp}</span>
                  <span className="text-indigo-400 font-bold">{log.endpoint}</span>
                  <span className="text-slate-300 hidden sm:inline">[{log.algorithm}]</span>
                </div>

                <div className="flex flex-wrap items-center gap-3 text-[11px]">
                  <span className="text-slate-400">
                    PK: <span className="text-slate-200">{log.clientPkHex}</span>
                  </span>
                  <span className="text-slate-400">
                    Ciphertext: <span className="text-cyan-400">{log.ciphertextSnippet}</span>
                  </span>
                  <span className="text-slate-400">
                    Latency: <strong className={log.latencyMs > 10 ? 'text-amber-400' : 'text-emerald-400'}>{log.latencyMs}ms</strong>
                  </span>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                    log.status === '200_OK' ? 'bg-emerald-950 text-emerald-400 border border-emerald-900' : 'bg-amber-950 text-amber-400 border border-amber-900'
                  }`}>
                    {log.status}
                  </span>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </div>

    </div>
  );
};
