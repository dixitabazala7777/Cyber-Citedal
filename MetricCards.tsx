import React, { useState, useEffect } from 'react';
import { Activity, ShieldCheck, ArrowUpRight, Layers, WifiOff } from 'lucide-react';

interface MetricCardsProps {
  networkThroughput: number;
  activeTunnels: number;
  infrastructureIntegrity?: number;
  totalBlocked?: number;
  isSupabaseSynced?: boolean;
  dbLinkStatus?: string;
}

const RollingNumber: React.FC<{ value: number; decimals?: number }> = ({ value, decimals = 0 }) => {
  const [displayValue, setDisplayValue] = useState(value);

  useEffect(() => {
    const start = displayValue;
    const end = value;
    if (start === end) return;

    const duration = 800;
    const startTime = performance.now();

    const animate = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const ease = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      const current = start + (end - start) * ease;
      setDisplayValue(current);

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }, [value, displayValue]);

  return (
    <>
      {decimals > 0
        ? displayValue.toFixed(decimals)
        : Math.floor(displayValue).toLocaleString()}
    </>
  );
};

export const MetricCards: React.FC<MetricCardsProps> = ({
  networkThroughput,
  activeTunnels,
  infrastructureIntegrity = 99.4
}) => {
  const isZeroTraffic = networkThroughput === 0;

  return (
    <section id="metric-cards" className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-7xl mx-auto relative z-10">
      {/* 1. Network Throughput Rate */}
      <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-lg hover:border-slate-300 dark:hover:border-slate-700 transition-all group relative overflow-hidden">
        <div className="flex justify-between items-start">
          <div className="flex items-center space-x-2.5">
            <div className={`p-2 rounded-xl border ${
              isZeroTraffic
                ? 'bg-rose-500/10 border-rose-500/25 dark:border-rose-500/30 text-rose-600 dark:text-rose-400'
                : 'bg-sky-500/10 border-sky-500/25 dark:border-sky-500/30 text-sky-600 dark:text-sky-400'
            }`}>
              {isZeroTraffic ? <WifiOff className="w-4 h-4" /> : <Activity className="w-4 h-4" />}
            </div>
            <div>
              <p className="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider">Throughput Rate</p>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                {isZeroTraffic ? 'Ingress Ports Severed' : 'Live Ingress Traffic'}
              </p>
            </div>
          </div>
          <span className={`px-2.5 py-0.5 text-[11px] font-bold rounded-lg flex items-center gap-1.5 font-mono border ${
            isZeroTraffic
              ? 'bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/25 dark:border-rose-500/30'
              : 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/25 dark:border-emerald-500/30'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${isZeroTraffic ? 'bg-rose-500' : 'bg-emerald-500 animate-pulse'}`}></span>
            {isZeroTraffic ? 'Severed / Blocked' : 'Streaming'}
          </span>
        </div>

        <div className="mt-4 flex items-baseline justify-between">
          <div>
            <h3 className="text-3xl font-black font-mono text-slate-900 dark:text-slate-100 tabular-nums">
              <RollingNumber value={networkThroughput} />
              <span className="text-xs font-medium text-slate-500 dark:text-slate-400 ml-1.5 font-sans">B / s</span>
            </h3>
          </div>
          {isZeroTraffic ? (
            <span className="text-xs text-rose-600 dark:text-rose-400 font-bold font-mono">SEVERED</span>
          ) : (
            <span className="text-xs text-emerald-600 dark:text-emerald-400 font-bold flex items-center gap-0.5 font-mono">
              <ArrowUpRight className="w-3.5 h-3.5" /> +12.4%
            </span>
          )}
        </div>

        <div className="w-full bg-slate-100 dark:bg-slate-950 rounded-full h-1 mt-4 overflow-hidden border border-slate-200 dark:border-slate-800">
          <div className={`h-1 rounded-full transition-all duration-500 ${
            isZeroTraffic ? 'bg-rose-500 w-[0%]' : 'bg-sky-500 w-[65%]'
          }`} />
        </div>
      </div>

      {/* 2. Secured Edge Tunnels */}
      <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-lg hover:border-slate-300 dark:hover:border-slate-700 transition-all group relative overflow-hidden">
        <div className="flex justify-between items-start">
          <div className="flex items-center space-x-2.5">
            <div className={`p-2 rounded-xl border ${
              activeTunnels === 0
                ? 'bg-rose-500/10 border-rose-500/25 dark:border-rose-500/30 text-rose-600 dark:text-rose-400'
                : 'bg-sky-500/10 border-sky-500/25 dark:border-sky-500/30 text-sky-600 dark:text-sky-400'
            }`}>
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <p className="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider">Active Gateways</p>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                {activeTunnels === 0 ? 'All Relays Quarantined' : 'Encapsulated Nodes'}
              </p>
            </div>
          </div>
          <span className={`px-2.5 py-0.5 text-[11px] font-bold rounded-lg font-mono border ${
            activeTunnels === 0
              ? 'bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/25 dark:border-rose-500/30'
              : 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/25 dark:border-sky-500/30'
          }`}>
            {activeTunnels === 0 ? 'ISOLATED' : 'Operational'}
          </span>
        </div>

        <div className="mt-4 flex items-baseline justify-between">
          <div>
            <h3 className="text-3xl font-black font-mono text-slate-900 dark:text-slate-100 tabular-nums">
              <RollingNumber value={activeTunnels} />
              <span className="text-xs font-medium text-slate-500 dark:text-slate-400 ml-1.5 font-sans">Nodes Active</span>
            </h3>
          </div>
          <span className={`text-xs font-mono font-medium ${
            activeTunnels === 0 ? 'text-rose-600 dark:text-rose-400 font-bold' : 'text-slate-500 dark:text-slate-400'
          }`}>
            {activeTunnels}/3 Online
          </span>
        </div>

        <div className="w-full bg-slate-100 dark:bg-slate-950 rounded-full h-1 mt-4 overflow-hidden border border-slate-200 dark:border-slate-800">
          <div className={`h-1 rounded-full transition-all duration-500 ${
            activeTunnels === 0 ? 'bg-rose-500 w-[0%]' : 'bg-sky-400 w-[100%]'
          }`} />
        </div>
      </div>

      {/* 3. Infrastructure Integrity SLA */}
      <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-lg hover:border-slate-300 dark:hover:border-slate-700 transition-all group relative overflow-hidden">
        <div className="flex justify-between items-start">
          <div className="flex items-center space-x-2.5">
            <div className={`p-2 rounded-xl border ${
              isZeroTraffic
                ? 'bg-amber-500/10 border-amber-500/25 dark:border-amber-500/30 text-amber-600 dark:text-amber-400'
                : 'bg-emerald-500/10 border-emerald-500/25 dark:border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
            }`}>
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <p className="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider">System Integrity</p>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                {isZeroTraffic ? 'Fail-Safe Defensive Posture' : 'SLA Performance'}
              </p>
            </div>
          </div>
          <span className={`px-2.5 py-0.5 text-[11px] font-bold rounded-lg font-mono border ${
            isZeroTraffic
              ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/25 dark:border-amber-500/30'
              : 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/25 dark:border-emerald-500/30'
          }`}>
            {isZeroTraffic ? 'Quarantine Mode' : '99.9% Target'}
          </span>
        </div>

        <div className="mt-4 flex items-baseline justify-between">
          <div>
            <h3 className="text-3xl font-black font-mono text-slate-900 dark:text-slate-100 tabular-nums">
              <RollingNumber value={isZeroTraffic ? 100 : infrastructureIntegrity} decimals={1} />
              <span className="text-xs font-medium text-slate-500 dark:text-slate-400 ml-1 font-sans">%</span>
            </h3>
          </div>
          <span className={`text-xs font-bold font-mono ${
            isZeroTraffic ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
          }`}>
            {isZeroTraffic ? 'Quarantined' : 'Pristine'}
          </span>
        </div>

        <div className="w-full bg-slate-100 dark:bg-slate-950 rounded-full h-1 mt-4 overflow-hidden border border-slate-200 dark:border-slate-800">
          <div className={`h-1 rounded-full transition-all duration-500 ${
            isZeroTraffic ? 'bg-amber-500 dark:bg-amber-400 w-[100%]' : 'bg-emerald-500 dark:bg-emerald-400 w-[99%]'
          }`} />
        </div>
      </div>
    </section>
  );
};
