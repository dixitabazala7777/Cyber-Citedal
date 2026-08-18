import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { 
  Activity, 
  RefreshCw, 
  Terminal, 
  Radio 
} from 'lucide-react';

const tabItemVariants = {
  hidden: { 
    opacity: 0, 
    y: 15, 
    filter: 'blur(4px)' 
  },
  visible: { 
    opacity: 1, 
    y: 0, 
    filter: 'blur(0px)',
    transition: { 
      type: "spring" as const,
      stiffness: 120,
      damping: 18
    } 
  },
  exit: { 
    opacity: 0, 
    y: -15, 
    filter: 'blur(4px)',
    transition: { 
      duration: 0.2, 
      ease: "easeInOut" as const
    } 
  }
};



interface QuantumTunnelsProps {
  onLogMessage: (msg: string) => void;
}

interface Tunnel {
  id: string;
  source: string;
  target: string;
  cipher: string;
  throughput: number; // in MB/s
  status: 'active' | 'rekeying' | 'degraded';
  keyRotationCountdown: number; // in seconds
  keysRotatedToday: number;
  latency: number; // in ms
}

export const QuantumTunnels: React.FC<QuantumTunnelsProps> = ({ onLogMessage }) => {
  // Mock Tunnel list
  const [tunnels, setTunnels] = useState<Tunnel[]>([
    {
      id: 'Q-TUNNEL-US-EU',
      source: 'US-EAST-01 (Primary Gateway)',
      target: 'EU-WEST-02 (Core Compute)',
      cipher: 'Kyber-1024 + AES-256-GCM (NIST Cat 5)',
      throughput: 84.5,
      status: 'active',
      keyRotationCountdown: 14,
      keysRotatedToday: 148,
      latency: 72
    },
    {
      id: 'Q-TUNNEL-AP-EU',
      source: 'AP-SOUTH-01 (Edge Proxy)',
      target: 'EU-WEST-02 (Core Compute)',
      cipher: 'Saber-KEM + ChaCha20-Poly1305',
      throughput: 42.1,
      status: 'active',
      keyRotationCountdown: 28,
      keysRotatedToday: 95,
      latency: 148
    },
    {
      id: 'Q-TUNNEL-US-VAULT',
      source: 'US-EAST-01 (Primary Gateway)',
      target: 'US-WEST-02 (Secure Vault)',
      cipher: 'FrodoKEM-1344 + AES-256-GCM',
      throughput: 12.8,
      status: 'active',
      keyRotationCountdown: 45,
      keysRotatedToday: 42,
      latency: 24
    },
    {
      id: 'Q-TUNNEL-SA-DB',
      source: 'SA-EAST-01 (Database Mirror)',
      target: 'US-WEST-02 (Secure Vault)',
      cipher: 'Classic McEliece-8192 (Ultra-Secure)',
      throughput: 110.2,
      status: 'degraded',
      keyRotationCountdown: 8,
      keysRotatedToday: 210,
      latency: 214
    }
  ]);

  // Terminal diagnostics log states
  const [activeTunnelDiag, setActiveTunnelDiag] = useState<string | null>(null);
  const [diagLogs, setDiagLogs] = useState<string[]>([]);
  const [isDiagRunning, setIsDiagRunning] = useState(false);

  // Key rotation timer tick
  useEffect(() => {
    const timer = setInterval(() => {
      setTunnels((prevTunnels) => 
        prevTunnels.map((t) => {
          if (t.status === 'rekeying') return t;

          const nextCountdown = t.keyRotationCountdown - 1;
          if (nextCountdown <= 0) {
            // Trigger automatic re-keying log
            onLogMessage(`HYBRID KEM AUTOMATION: Initiating regular key refresh on secure tunnel ${t.id}.`);
            return {
              ...t,
              status: 'rekeying',
              keyRotationCountdown: 60 // reset to 60s
            };
          }
          return {
            ...t,
            keyRotationCountdown: nextCountdown
          };
        })
      );
    }, 1000);

    return () => clearInterval(timer);
  }, [onLogMessage]);

  // Fluctuate latency and throughput slightly to simulate real network dynamics
  useEffect(() => {
    const timer = setInterval(() => {
      setTunnels((prevTunnels) => 
        prevTunnels.map((t) => {
          if (t.status === 'rekeying') return t;
          const latencyShift = Math.floor((Math.random() - 0.5) * 6); // +-3 ms
          const throughputShift = (Math.random() - 0.5) * 4; // +-2 MB/s
          return {
            ...t,
            latency: Math.max(10, t.latency + latencyShift),
            throughput: Math.max(5, t.throughput + throughputShift)
          };
        })
      );
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  // Resolve rekeying status back to active after a delay
  useEffect(() => {
    const rekeyingTunnels = tunnels.filter((t) => t.status === 'rekeying');
    if (rekeyingTunnels.length > 0) {
      rekeyingTunnels.forEach((t) => {
        setTimeout(() => {
          setTunnels((prev) => 
            prev.map((tunnel) => {
              if (tunnel.id === t.id) {
                onLogMessage(`HYBRID KEM SYNCHRONIZED: ${tunnel.cipher} key negotiation completed. Key ID hash: SHA3-${Math.random().toString(36).substring(2, 10).toUpperCase()}`);
                return {
                  ...tunnel,
                  status: 'active',
                  keyRotationCountdown: 60,
                  keysRotatedToday: tunnel.keysRotatedToday + 1
                };
              }
              return tunnel;
            })
          );
        }, 3000);
      });
    }
  }, [tunnels, onLogMessage]);

  // Handle manual force rekeying
  const handleForceRekey = (id: string) => {
    onLogMessage(`COMMAND ISSUED: Forcing instant Post-Quantum key rotation on Tunnel ${id}`);
    setTunnels((prev) => 
      prev.map((t) => {
        if (t.id === id) {
          return {
            ...t,
            status: 'rekeying',
            keyRotationCountdown: 60
          };
        }
        return t;
      })
    );
  };

  // Run diagnostics simulation
  const handleRunDiagnostics = (tunnel: Tunnel) => {
    setActiveTunnelDiag(tunnel.id);
    setIsDiagRunning(true);
    setDiagLogs([
      `[DIAGNOSTICS] Launching post-quantum tunnel audit for ${tunnel.id}`,
      `[CIPHER] Active Negotiant: ${tunnel.cipher}`,
      `[LATENCY] Direct link check: current RTT is ${tunnel.latency}ms`
    ]);

    setTimeout(() => {
      setDiagLogs((prev) => [...prev, `[KEM] Running Kyber encapsulation speed test on CPU...`]);
      setTimeout(() => {
        setDiagLogs((prev) => [
          ...prev, 
          `[KEM] Kyber encapsulation: 0.12ms | decapsulation: 0.18ms`,
          `[DIGITAL SIGNATURE] Verifying Dilithium-5 identity signature on handshakes...`
        ]);
        setTimeout(() => {
          setDiagLogs((prev) => [
            ...prev,
            `[DIGITAL SIGNATURE] Verification PASSED (FIPS 204 verified)`,
            `[SYMMETRIC] AES-GCM 256 frame authenticity: 100.00% integrity score`,
            `[STATUS] TUNNEL AUDIT COMPLETED. Link is healthy and quantum-safe.`
          ]);
          setIsDiagRunning(false);
          onLogMessage(`AUDIT: Secure Tunnel ${tunnel.id} verified. No quantum vulnerabilities detected.`);
        }, 1200);
      }, 1200);
    }, 1200);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 max-w-7xl w-full mx-auto p-4">
      {/* Left Column (2/3 width): Quantum Tunnels Grid */}
      <motion.div className="lg:col-span-2 space-y-5" variants={tabItemVariants}>
        <div className="bg-[#090c10]/60 backdrop-blur-xl border border-slate-800/80 rounded-xl p-5 shadow-lg space-y-4 hover:border-slate-700/60 transition duration-300 relative group overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/10 to-transparent group-hover:via-cyan-500/30 transition-all duration-1000" />
          
          <div className="flex justify-between items-center border-b border-slate-900 pb-3">
            <div>
              <span className="text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2.5 py-0.5 rounded-full font-mono font-bold tracking-wider">
                HYBRID VPN RELAYS
              </span>
              <h2 className="text-base font-bold text-slate-100 font-sans tracking-tight mt-1">
                Post-Quantum Cryptographic VPN Tunnels
              </h2>
            </div>
            
            <div className="text-[10px] text-slate-500 font-mono text-right hidden sm:block">
              Total Secure Links: <span className="text-emerald-400 font-bold">{tunnels.length}</span>
            </div>
          </div>

          <p className="text-xs text-slate-400">
            Secure logical pipes connecting distributed edge compute units. Handshakes perform dual classic-quantum ciphers to resist immediate 'Store Now, Decrypt Later' (SNDL) attacks.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {tunnels.map((tunnel) => (
              <div 
                key={tunnel.id} 
                className={`bg-slate-950/40 border rounded-xl p-4 space-y-3.5 transition hover:border-cyan-500/40 flex flex-col justify-between ${
                  tunnel.status === 'rekeying' 
                    ? 'border-cyan-500/40 shadow-sm shadow-cyan-500/10' 
                    : tunnel.status === 'degraded'
                    ? 'border-amber-900/40 bg-amber-950/5'
                    : 'border-slate-850'
                }`}
              >
                <div>
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="font-mono text-[11px] font-bold text-slate-300">
                        {tunnel.id}
                      </h3>
                      <p className="text-[9px] text-slate-500 font-mono mt-0.5">{tunnel.cipher}</p>
                    </div>
                    
                    <span className={`text-[9px] px-2 py-0.5 rounded font-mono font-bold tracking-wider uppercase ${
                      tunnel.status === 'active' 
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                        : tunnel.status === 'rekeying'
                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse'
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}>
                      {tunnel.status}
                    </span>
                  </div>

                  {/* Visual Node-to-Node route with Node Laser Stream */}
                  <div className="flex items-center gap-2 bg-slate-950/80 rounded-lg p-2.5 mt-3 border border-slate-900 text-[10px] font-mono">
                    <span className="text-cyan-400 truncate w-[110px]" title={tunnel.source}>{tunnel.source.split(' ')[0]}</span>
                    
                    <div className="flex-1 h-3 relative mx-1 overflow-hidden flex items-center">
                      <style>{`
                        @keyframes laserStream-${tunnel.id} {
                          0% { left: -30%; opacity: 0; }
                          30% { opacity: 1; }
                          70% { opacity: 1; }
                          100% { left: 110%; opacity: 0; }
                        }
                      `}</style>
                      {/* The static background tunnel conduit */}
                      <div className="absolute inset-x-0 h-[1.5px] bg-slate-900" />
                      {/* Animated high-frequency laser pulse */}
                      <div 
                        className="absolute h-[2px] w-6 bg-gradient-to-r from-transparent via-cyan-400 to-emerald-400 rounded-full"
                        style={{
                          animation: `laserStream-${tunnel.id} 1.6s linear infinite`,
                          boxShadow: '0 0 6px rgba(34,211,238,0.6)'
                        }}
                      />
                    </div>

                    <span className="text-emerald-400 truncate w-[110px]" title={tunnel.target}>{tunnel.target.split(' ')[0]}</span>
                  </div>

                  {/* Performance stats */}
                  <div className="grid grid-cols-3 gap-2 mt-3.5 text-[10px] font-mono text-slate-400 text-center">
                    <div className="bg-slate-900/40 p-1.5 rounded border border-slate-900">
                      <p className="text-slate-500 text-[9px] uppercase font-semibold">Throughput</p>
                      <p className="font-bold text-slate-300 mt-0.5">{tunnel.throughput.toFixed(1)} MB/s</p>
                    </div>
                    <div className="bg-slate-900/40 p-1.5 rounded border border-slate-900">
                      <p className="text-slate-500 text-[9px] uppercase font-semibold">RTT Latency</p>
                      <p className="font-bold text-slate-300 mt-0.5">{tunnel.latency} ms</p>
                    </div>
                    <div className="bg-slate-900/40 p-1.5 rounded border border-slate-900">
                      <p className="text-slate-500 text-[9px] uppercase font-semibold">Keys Today</p>
                      <p className="font-bold text-slate-300 mt-0.5">{tunnel.keysRotatedToday}</p>
                    </div>
                  </div>
                </div>

                {/* Footer Controls with circular countdown rings */}
                <div className="border-t border-slate-900 pt-3 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-[10px] font-mono">
                    <div className="relative flex items-center justify-center w-7 h-7">
                      <svg className="w-7 h-7 transform -rotate-90">
                        <circle
                          cx="14"
                          cy="14"
                          r="11"
                          stroke="rgba(30, 41, 59, 0.5)"
                          strokeWidth="2"
                          fill="transparent"
                        />
                        <circle
                          cx="14"
                          cy="14"
                          r="11"
                          stroke={tunnel.status === 'rekeying' ? '#34d399' : '#10b981'}
                          strokeWidth="2"
                          fill="transparent"
                          strokeDasharray={2 * Math.PI * 11}
                          strokeDashoffset={2 * Math.PI * 11 * (1 - (tunnel.status === 'rekeying' ? 60 : tunnel.keyRotationCountdown) / 60)}
                          className="transition-all duration-1000 ease-linear"
                        />
                      </svg>
                      <span className={`absolute text-[8px] font-mono font-bold ${tunnel.status === 'rekeying' ? 'text-cyan-400 animate-spin' : 'text-emerald-400'}`}>
                        {tunnel.status === 'rekeying' ? '↻' : tunnel.keyRotationCountdown}
                      </span>
                    </div>
                    <span className="text-slate-500 font-semibold uppercase text-[9px] tracking-wide">QKD Rotation</span>
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => handleRunDiagnostics(tunnel)}
                      disabled={isDiagRunning}
                      className="px-2.5 py-1 bg-slate-900 hover:bg-slate-850 border border-slate-800 disabled:opacity-40 rounded text-[9px] font-mono font-bold uppercase transition text-slate-300"
                    >
                      Audit
                    </button>
                    <button
                      onClick={() => handleForceRekey(tunnel.id)}
                      disabled={tunnel.status === 'rekeying'}
                      className="px-2.5 py-1 bg-cyan-600/80 hover:bg-cyan-600 disabled:bg-slate-800 disabled:text-slate-500 rounded text-[9px] font-mono font-bold uppercase transition flex items-center gap-1 text-slate-900"
                    >
                      <RefreshCw className={`w-2.5 h-2.5 ${tunnel.status === 'rekeying' ? 'animate-spin' : ''}`} />
                      Rekey
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Right Column (1/3 width): Interactive Diagnostics Console */}
      <motion.div className="space-y-5" variants={tabItemVariants}>
        <div className="bg-[#090c10]/60 backdrop-blur-xl border border-slate-800/80 rounded-xl p-5 shadow-lg flex flex-col justify-between min-h-[360px] hover:border-slate-700/60 transition duration-300 relative group overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/10 to-transparent group-hover:via-cyan-500/30 transition-all duration-1000" />
          
          <div>
            <div className="flex items-center gap-1.5 text-cyan-400 font-bold border-b border-slate-900 pb-2 mb-2">
              <Terminal className="w-4 h-4" />
              <h3 className="text-xs uppercase tracking-wider">Tunnel Diagnostic Auditer</h3>
            </div>

            <p className="text-[11px] text-slate-400 leading-relaxed mb-4">
              Inspect negotiation layers, mathematical lattice correctness, signature integrity, and round-trip delays.
            </p>

            {activeTunnelDiag ? (
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-900 font-mono text-[10px] text-slate-400 space-y-2 min-h-[220px] max-h-[300px] overflow-y-auto">
                {diagLogs.map((log, idx) => (
                  <p 
                    key={idx} 
                    className={`${
                      log.includes('PASSED') || log.includes('COMPLETED') ? 'text-emerald-400 font-bold' : 
                      log.includes('DIAGNOSTICS') ? 'text-cyan-400' :
                      log.includes('Kyber') ? 'text-cyan-300' : 'text-slate-400'
                    }`}
                  >
                    {log}
                  </p>
                ))}
                {isDiagRunning && (
                  <div className="flex items-center gap-1 text-[9px] text-cyan-400 font-bold animate-pulse mt-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-ping"></span>
                    CALCULATING MATRICES...
                  </div>
                )}
              </div>
            ) : (
              <div className="border border-dashed border-slate-800/80 rounded-xl p-10 text-center font-mono text-xs text-slate-600 min-h-[220px] flex flex-col justify-center">
                <Radio className="w-8 h-8 text-slate-700 mx-auto mb-2 opacity-50" />
                Select 'Audit' on any secure tunnel to launch real-time link diagnostics.
              </div>
            )}
          </div>
        </div>

        {/* Global Tunnel Metrics */}
        <div className="bg-[#090c10]/60 backdrop-blur-xl border border-slate-800/80 rounded-xl p-5 shadow-lg space-y-4 hover:border-slate-700/60 transition duration-300 relative group overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/10 to-transparent group-hover:via-cyan-500/30 transition-all duration-1000" />
          
          <div className="flex items-center gap-1.5 text-cyan-400 font-bold border-b border-slate-900 pb-2">
            <Activity className="w-4 h-4" />
            <h3 className="text-xs uppercase tracking-wider">Quantum Intercept Intel</h3>
          </div>

          <div className="space-y-3.5 text-xs font-mono">
            <div className="flex justify-between items-center bg-slate-950/40 p-2.5 rounded border border-slate-900">
              <span className="text-slate-500">Decryption Index:</span>
              <span className="text-rose-400 font-bold">128-bit Symmetrical Grover Resist</span>
            </div>

            <div className="flex justify-between items-center bg-slate-950/40 p-2.5 rounded border border-slate-900">
              <span className="text-slate-500">Active Entropy Feed:</span>
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-ping"></span>
                Quantum RNG Live
              </span>
            </div>

            <div className="flex justify-between items-center bg-slate-950/40 p-2.5 rounded border border-slate-900">
              <span className="text-slate-500">SNDL Buffer:</span>
              <span className="text-cyan-400 font-bold">0% Vulnerable Storage</span>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};
