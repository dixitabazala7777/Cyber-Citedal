import React, { useState } from 'react';
import { 
  Braces, ShieldAlert, ShieldCheck, Terminal, 
  Lock, Unlock, Shield, Code, RefreshCw, Zap
} from 'lucide-react';

interface ApiEndpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  isEncrypted: boolean;
  hasRateLimit: boolean;
  exposedTokens: boolean;
  riskLevel: 'Critical' | 'High' | 'Safe';
  origin: 'Sanctioned App' | 'Shadow IT Rogue';
}

interface ApiSecurityProps {
  onLogMessage: (msg: string) => void;
}

export const ApiSecurity: React.FC<ApiSecurityProps> = ({ onLogMessage }) => {
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([
    {
      method: 'GET',
      path: '/api/v1/user/profile',
      isEncrypted: true,
      hasRateLimit: true,
      exposedTokens: false,
      riskLevel: 'Safe',
      origin: 'Sanctioned App'
    },
    {
      method: 'POST',
      path: '/api/v1/auth/token',
      isEncrypted: true,
      hasRateLimit: true,
      exposedTokens: false,
      riskLevel: 'Safe',
      origin: 'Sanctioned App'
    },
    {
      method: 'GET',
      path: '/api/unstable/debug/config-dump',
      isEncrypted: false,
      hasRateLimit: false,
      exposedTokens: true,
      riskLevel: 'Critical',
      origin: 'Shadow IT Rogue'
    },
    {
      method: 'POST',
      path: '/api/v3/experimental/data-sync',
      isEncrypted: true,
      hasRateLimit: false,
      exposedTokens: false,
      riskLevel: 'High',
      origin: 'Shadow IT Rogue'
    },
    {
      method: 'PUT',
      path: '/api/v1/payment/checkout',
      isEncrypted: true,
      hasRateLimit: true,
      exposedTokens: false,
      riskLevel: 'Safe',
      origin: 'Sanctioned App'
    },
    {
      method: 'DELETE',
      path: '/api/v1/nodes/deregister',
      isEncrypted: true,
      hasRateLimit: true,
      exposedTokens: false,
      riskLevel: 'Safe',
      origin: 'Sanctioned App'
    }
  ]);

  const [selectedPath, setSelectedPath] = useState<string>('/api/unstable/debug/config-dump');
  const [isProbing, setIsProbing] = useState<boolean>(false);
  const [probeLogs, setProbeLogs] = useState<string[]>([]);

  const handleFixEndpoint = (path: string) => {
    setEndpoints(prev => prev.map(ep => {
      if (ep.path === path) {
        onLogMessage(`API SHIELD: Patched security vulnerabilities on endpoint: ${path}`);
        playSynthConfirm();
        return {
          ...ep,
          isEncrypted: true,
          hasRateLimit: true,
          exposedTokens: false,
          riskLevel: 'Safe'
        };
      }
      return ep;
    }));
  };

  const playSynthConfirm = () => {
    const AudioContextClass = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AudioContextClass) return;
    try {
      const ctx = new AudioContextClass();
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(600, now);
      osc.frequency.exponentialRampToValueAtTime(1200, now + 0.15);
      gain.gain.setValueAtTime(0.02, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.4);
    } catch (e) {
      console.warn("Audio Context init failed", e);
    }
  };

  const simulateRateLimitProbe = () => {
    if (isProbing) return;
    setIsProbing(true);
    setProbeLogs(['[INIT] Initiating Rate Limit Security Sweep...', `[TARGET] Hooked to endpoint ${selectedPath}`]);
    
    const ep = endpoints.find(e => e.path === selectedPath) || endpoints[0];
    const delay = (ms: number) => new Promise(res => setTimeout(res, ms));

    const executeProbe = async () => {
      try {
        await delay(400);
        setProbeLogs(prev => [...prev, '⚡ Spawning 12 synthetic request threads...']);
        
        await delay(500);
        setProbeLogs(prev => [...prev, '⏱️ Latency Benchmarks (Hit 1 - 5):', '   -> req 1: 18ms (HTTP 200 OK)', '   -> req 2: 22ms (HTTP 200 OK)', '   -> req 3: 15ms (HTTP 200 OK)', '   -> req 4: 19ms (HTTP 200 OK)', '   -> req 5: 25ms (HTTP 200 OK)']);
        
        await delay(600);
        setProbeLogs(prev => [...prev, '⏱️ Latency Benchmarks (Hit 6 - 12):']);

        await delay(400);
        if (ep.hasRateLimit) {
          setProbeLogs(prev => [
            ...prev,
            '   -> req 6: 14ms (HTTP 429 Too Many Requests)',
            '   -> req 7: 11ms (HTTP 429 Too Many Requests)',
            '❌ Rate limiter successfully ENFORCED.',
            'ℹ️ Server Response Headers Dumped:',
            '   HTTP/1.1 429 Too Many Requests',
            '   Date: Tue, 21 Jul 2026 08:35:00 GMT',
            '   Content-Type: application/json',
            '   Retry-After: 60',
            '   X-RateLimit-Limit: 5',
            '   X-RateLimit-Remaining: 0'
          ]);
          onLogMessage(`API AUDIT: Rate limit validation succeeded on ${ep.path}`);
        } else {
          setProbeLogs(prev => [
            ...prev,
            '   -> req 6: 21ms (HTTP 200 OK)',
            '   -> req 7: 24ms (HTTP 200 OK)',
            '   -> req 8: 18ms (HTTP 200 OK)',
            '   -> req 9: 19ms (HTTP 200 OK)',
            '   -> req 10: 22ms (HTTP 200 OK)',
            '⚠️ WARNING: Endpoint completely vulnerability exposed!',
            'ℹ️ Response headers lack RateLimiting definitions.',
            'ℹ️ Server Response Headers Dumped:',
            '   HTTP/1.1 200 OK',
            '   Date: Tue, 21 Jul 2026 08:35:00 GMT',
            '   Content-Type: application/json; charset=utf-8',
            ep.exposedTokens ? '   X-Debug-Session-Token: raw_adm_bypass_jwt_827361' : '   X-Powered-By: Express',
            '   Access-Control-Allow-Origin: *'
          ]);
          onLogMessage(`API AUDIT ALERT: Rate limiting missing on endpoint ${ep.path}. Critical threat risk!`);
        }

        setIsProbing(false);
      } catch (err) {
        setProbeLogs(prev => [...prev, `[FATAL] Local scanner exception: ${err}`]);
        setIsProbing(false);
      }
    };

    executeProbe();
  };

  const selectedEp = endpoints.find(e => e.path === selectedPath) || endpoints[0];

  return (
    <div id="api-security-module" className="p-6 bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs dark:shadow-xl relative overflow-hidden min-h-[500px] text-slate-900 dark:text-slate-100">
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />
      
      {/* Header Panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-200 dark:border-slate-800 pb-4 mb-6 gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Braces className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold tracking-widest uppercase">SHADOW IT DETECTOR</span>
          </div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white font-sans tracking-wide">API Attack Surface & Shadow IT</h2>
          <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 max-w-xl">
            Audit API gateways to flag rogue external endpoints (Shadow IT), unencrypted endpoints, and endpoints missing rate limiting. Probes latency and scans authorization headers.
          </p>
        </div>
      </div>

      {/* Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Endpoint Directory List (Left 7 Cols) */}
        <div className="lg:col-span-7 space-y-3">
          <div className="text-[10px] font-bold text-slate-700 dark:text-slate-300 font-mono tracking-wider border-b border-slate-200 dark:border-slate-800 pb-2 mb-1 uppercase">
            API ENDPOINT REGISTRY CATALOG
          </div>

          <div className="overflow-x-auto bg-slate-50/50 dark:bg-slate-950/60 rounded-xl border border-slate-200 dark:border-slate-800 p-2">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 text-[10px]">
                  <th className="py-2.5 px-2 font-bold uppercase">METHOD</th>
                  <th className="py-2.5 px-2 font-bold uppercase">ENDPOINT PATH</th>
                  <th className="py-2.5 px-2 font-bold text-center uppercase">CRYPTO</th>
                  <th className="py-2.5 px-2 font-bold text-center uppercase">LIMITS</th>
                  <th className="py-2.5 px-2 font-bold text-center uppercase">TOKENS</th>
                  <th className="py-2.5 px-2 font-bold text-right uppercase">RISK</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/80 dark:divide-slate-800/60">
                {endpoints.map((ep) => (
                  <tr 
                    key={ep.path}
                    onClick={() => setSelectedPath(ep.path)}
                    className={`transition cursor-pointer ${
                      ep.path === selectedPath 
                        ? 'bg-indigo-50 dark:bg-indigo-950/40 text-slate-900 dark:text-white font-bold' 
                        : 'hover:bg-slate-100/70 dark:hover:bg-slate-900/50 text-slate-800 dark:text-slate-200'
                    }`}
                  >
                    <td className="py-2.5 px-2">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-extrabold uppercase border ${
                        ep.method === 'GET' ? 'bg-cyan-100 dark:bg-cyan-950 text-cyan-800 dark:text-cyan-300 border-cyan-300 dark:border-cyan-800' :
                        ep.method === 'POST' ? 'bg-indigo-100 dark:bg-indigo-950 text-indigo-800 dark:text-indigo-300 border-indigo-300 dark:border-indigo-800' :
                        ep.method === 'PUT' ? 'bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800' : 'bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-800'
                      }`}>
                        {ep.method}
                      </span>
                    </td>
                    <td className="py-2.5 px-2 truncate max-w-[160px] sm:max-w-[220px]" title={ep.path}>
                      <span className={`font-semibold ${ep.origin.includes('Shadow') ? 'text-amber-700 dark:text-amber-300' : 'text-slate-900 dark:text-slate-100'}`}>
                        {ep.path}
                      </span>
                    </td>
                    <td className="py-2.5 px-2 text-center">
                      {ep.isEncrypted ? (
                        <Lock className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 mx-auto" />
                      ) : (
                        <Unlock className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400 mx-auto animate-pulse" />
                      )}
                    </td>
                    <td className="py-2.5 px-2 text-center">
                      {ep.hasRateLimit ? (
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 mx-auto" />
                      ) : (
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400 mx-auto animate-pulse" />
                      )}
                    </td>
                    <td className="py-2.5 px-2 text-center">
                      {ep.exposedTokens ? (
                        <span className="text-[9px] font-black text-rose-700 dark:text-rose-300 bg-rose-100 dark:bg-rose-950/80 border border-rose-300 dark:border-rose-800 px-1 py-0.5 rounded animate-pulse">EXPOSED</span>
                      ) : (
                        <span className="text-slate-400 text-[10px]">NONE</span>
                      )}
                    </td>
                    <td className="py-2.5 px-2 text-right font-extrabold">
                      <span className={`${
                        ep.riskLevel === 'Critical' ? 'text-rose-600 dark:text-rose-400' :
                        ep.riskLevel === 'High' ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
                      }`}>
                        {ep.riskLevel}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Probe controls & Console Logs (Right 5 Cols) */}
        <div className="lg:col-span-5 space-y-4 flex flex-col justify-between">
          
          {/* Audit Control Box */}
          <div className="bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-4 text-xs font-mono shadow-xs">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-2 text-[10px] text-slate-700 dark:text-slate-300 font-bold tracking-wider uppercase flex items-center gap-1.5">
              <Code className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>ACTIVE ENDPOINT DOSSIER</span>
            </div>

            <div>
              <span className="text-[10px] text-slate-500 dark:text-slate-400 block font-bold uppercase">SELECTED ENDPOINT PATH</span>
              <span className="text-slate-900 dark:text-white font-bold block truncate text-sm mt-0.5" title={selectedEp.path}>{selectedEp.path}</span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="bg-white dark:bg-slate-900 p-2.5 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xs">
                <span className="text-[9px] text-slate-500 dark:text-slate-400 block uppercase font-bold">ORIGIN ROUTING</span>
                <span className={`font-bold block mt-0.5 ${selectedEp.origin.includes('Shadow') ? 'text-amber-600 dark:text-amber-300' : 'text-slate-900 dark:text-slate-200'}`}>
                  {selectedEp.origin.toUpperCase()}
                </span>
              </div>
              <div className="bg-white dark:bg-slate-900 p-2.5 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xs">
                <span className="text-[9px] text-slate-500 dark:text-slate-400 block uppercase font-bold">ENCRYPTION STATUS</span>
                <span className={`font-bold block mt-0.5 ${selectedEp.isEncrypted ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}>
                  {selectedEp.isEncrypted ? 'TLS 1.3 PASS' : 'PLAINTEXT INSECURE'}
                </span>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="flex gap-2 pt-2">
              <button
                onClick={simulateRateLimitProbe}
                disabled={isProbing}
                className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg font-bold font-mono text-xs transition cursor-pointer flex items-center justify-center gap-1.5 shadow-sm active:scale-95"
              >
                <Zap className="w-3.5 h-3.5" />
                PROBE RATE LIMITS
              </button>

              {selectedEp.riskLevel !== 'Safe' && (
                <button
                  onClick={() => handleFixEndpoint(selectedEp.path)}
                  className="flex-1 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold font-mono text-xs transition cursor-pointer flex items-center justify-center gap-1.5 shadow-sm active:scale-95"
                >
                  <Shield className="w-3.5 h-3.5" />
                  PATCH EXPLOIT
                </button>
              )}
            </div>
          </div>

          {/* Raw Rate Limit Probe Console Log (Always Pure Terminal Dark) */}
          <div className="bg-black text-emerald-400 border border-slate-800 rounded-xl overflow-hidden flex flex-col h-[200px] shadow-lg">
            <div className="px-3 py-2 bg-slate-950 border-b border-slate-800 flex justify-between items-center text-[10px] font-mono">
              <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 animate-pulse" />
                API PROBE OUTPUT STACK
              </span>
              {isProbing && (
                <RefreshCw className="w-3.5 h-3.5 text-amber-400 animate-spin" />
              )}
            </div>

            <div className="p-3 overflow-y-auto flex-1 font-mono text-[10px] leading-relaxed text-emerald-400 space-y-1.5 select-text">
              {probeLogs.length === 0 ? (
                <div className="text-zinc-500 italic py-8 text-center select-none font-mono text-[11px]">
                  Select endpoint and click Probe Rate Limits above to trigger automated flood scan...
                </div>
              ) : (
                probeLogs.map((log, lIdx) => (
                  <div key={`probe-log-${lIdx}`} className={`break-all ${
                    log.includes('⚠️ WARNING') || log.includes('unstable') ? 'text-amber-300 font-bold' :
                    log.includes('❌') || log.includes('exposed') ? 'text-rose-400 font-bold' :
                    log.includes('✔️') || log.includes('Limiter') || log.includes('X-RateLimit') ? 'text-emerald-300 font-semibold' : 'text-emerald-400'
                  }`}>
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};

export default ApiSecurity;
