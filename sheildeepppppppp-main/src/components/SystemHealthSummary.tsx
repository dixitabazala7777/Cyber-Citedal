import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Cpu, HardDrive, Wifi, Activity, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface SystemHealthSummaryProps {
  isSimulating: boolean;
  activeIncidentsCount: number;
}

export const SystemHealthSummary: React.FC<SystemHealthSummaryProps> = ({
  isSimulating,
  activeIncidentsCount,
}) => {
  const [cpu, setCpu] = useState(48);
  const [memory, setMemory] = useState(64);
  const [bandwidth, setBandwidth] = useState(88);
  const [integrity, setIntegrity] = useState(96);

  useEffect(() => {
    const updateMetrics = () => {
      setCpu(() => {
        const base = isSimulating ? 62 : 45;
        const noise = Math.sin(Date.now() / 5000) * 12 + (Math.random() - 0.5) * 6;
        return Math.max(10, Math.min(99, Math.round(base + noise)));
      });

      setMemory(() => {
        const base = isSimulating ? 72 : 58;
        const noise = Math.cos(Date.now() / 8000) * 4 + (Math.random() - 0.5) * 2;
        return Math.max(20, Math.min(99, Math.round(base + noise)));
      });

      setBandwidth(() => {
        const base = isSimulating ? 91 : 84;
        const noise = Math.sin(Date.now() / 3000) * 6 + (Math.random() - 0.5) * 4;
        return Math.max(30, Math.min(100, Math.round(base + noise)));
      });
    };

    updateMetrics();
    const interval = setInterval(updateMetrics, 2000);
    return () => clearInterval(interval);
  }, [isSimulating]);

  useEffect(() => {
    const penalty = activeIncidentsCount * 12;
    const cpuOverhead = cpu > 80 ? (cpu - 80) * 0.4 : 0;
    const memOverhead = memory > 85 ? (memory - 85) * 0.5 : 0;
    const baseIntegrity = 100 - penalty - cpuOverhead - memOverhead;
    setIntegrity(Math.max(12, Math.min(100, Math.round(baseIntegrity))));
  }, [cpu, memory, activeIncidentsCount]);

  const radius = 64;
  const stroke = 7;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const strokeDashoffset = circumference - (integrity / 100) * circumference;

  return (
    <div
      id="system-health-summary-card"
      className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs dark:shadow-xl flex flex-col md:flex-row items-center gap-6 relative overflow-hidden transition-all duration-200"
    >
      {/* Radial Gauge Chart */}
      <div className="relative flex flex-col items-center justify-center p-2 shrink-0">
        <div className="relative flex items-center justify-center w-36 h-36">
          <svg className="w-full h-full transform -rotate-90">
            <defs>
              <linearGradient id="integrityGradientDark" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#10B981" />
                <stop offset="50%" stopColor="#0284C7" />
                <stop offset="100%" stopColor="#38BDF8" />
              </linearGradient>
            </defs>
            <circle
              className="text-slate-100 dark:text-slate-950 stroke-slate-200 dark:stroke-slate-800"
              strokeWidth={stroke}
              fill="transparent"
              r={normalizedRadius}
              cx={radius + stroke}
              cy={radius + stroke}
            />
            <motion.circle
              stroke="url(#integrityGradientDark)"
              strokeWidth={stroke}
              strokeDasharray={circumference + ' ' + circumference}
              style={{ strokeDashoffset }}
              strokeLinecap="round"
              fill="transparent"
              r={normalizedRadius}
              cx={radius + stroke}
              cy={radius + stroke}
              animate={{ strokeDashoffset }}
              transition={{ type: 'spring', stiffness: 60, damping: 15 }}
            />
          </svg>

          <div className="absolute flex flex-col items-center text-center">
            <span className="text-[10px] font-bold tracking-wider text-slate-500 dark:text-slate-400 uppercase font-sans">Integrity</span>
            <span className="text-2xl font-black font-mono tracking-tight text-slate-900 dark:text-slate-100 mt-0.5 tabular-nums">
              {integrity}%
            </span>
            <span className={`text-[9px] font-bold font-mono uppercase mt-0.5 px-2 py-0.5 rounded-full border ${
              integrity > 85
                ? 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 dark:bg-emerald-500/20 border-emerald-500/30'
                : integrity > 60
                  ? 'text-amber-600 dark:text-amber-400 bg-amber-500/10 dark:bg-amber-500/20 border-amber-500/30'
                  : 'text-rose-600 dark:text-rose-400 bg-rose-500/10 dark:bg-rose-500/20 border-rose-500/30 animate-pulse'
            }`}>
              {integrity > 85 ? 'PRISTINE' : integrity > 60 ? 'DEGRADED' : 'CRITICAL'}
            </span>
          </div>
        </div>
      </div>

      {/* Metrics, Indicators, and Live Stats */}
      <div className="flex-1 w-full space-y-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 bg-sky-500/10 border border-sky-500/25 dark:border-sky-500/30 rounded-xl text-sky-600 dark:text-sky-400">
              <Activity className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wide font-sans">System Infrastructure Integrity</h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-sans">Real-time status analysis of operational node capacity and thread safety</p>
        </div>

        {/* Sub-metric tracks */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {/* CPU Allocation */}
          <div id="gauge-cpu" className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="flex items-center gap-1.5 text-slate-600 dark:text-slate-400 font-semibold font-sans">
                <Cpu className="w-3.5 h-3.5 text-sky-500 dark:text-sky-400" />
                CPU Load
              </span>
              <span className="text-slate-900 dark:text-slate-100 font-bold">{cpu}%</span>
            </div>
            <div className="h-1.5 bg-slate-200 dark:bg-slate-900 rounded-full mt-2 overflow-hidden border border-slate-300 dark:border-slate-800">
              <motion.div
                className="h-full bg-sky-500 dark:bg-sky-400 rounded-full"
                animate={{ width: `${cpu}%` }}
                transition={{ type: 'spring', stiffness: 80, damping: 15 }}
              />
            </div>
          </div>

          {/* Memory Overhead */}
          <div id="gauge-mem" className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="flex items-center gap-1.5 text-slate-600 dark:text-slate-400 font-semibold font-sans">
                <HardDrive className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
                Memory
              </span>
              <span className="text-slate-900 dark:text-slate-100 font-bold">{memory}%</span>
            </div>
            <div className="h-1.5 bg-slate-200 dark:bg-slate-900 rounded-full mt-2 overflow-hidden border border-slate-300 dark:border-slate-800">
              <motion.div
                className="h-full bg-slate-500 dark:bg-slate-400 rounded-full"
                animate={{ width: `${memory}%` }}
                transition={{ type: 'spring', stiffness: 80, damping: 15 }}
              />
            </div>
          </div>

          {/* Bandwidth Efficiency */}
          <div id="gauge-bandwidth" className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="flex items-center gap-1.5 text-slate-600 dark:text-slate-400 font-semibold font-sans">
                <Wifi className="w-3.5 h-3.5 text-emerald-500 dark:text-emerald-400" />
                Bandwidth
              </span>
              <span className="text-slate-900 dark:text-slate-100 font-bold">{bandwidth}%</span>
            </div>
            <div className="h-1.5 bg-slate-200 dark:bg-slate-900 rounded-full mt-2 overflow-hidden border border-slate-300 dark:border-slate-800">
              <motion.div
                className="h-full bg-emerald-500 dark:bg-emerald-400 rounded-full"
                animate={{ width: `${bandwidth}%` }}
                transition={{ type: 'spring', stiffness: 80, damping: 15 }}
              />
            </div>
          </div>
        </div>

        {/* Summary status tag */}
        <div className={`p-3 rounded-xl border text-xs font-medium font-sans flex items-center gap-2.5 ${
          integrity > 85 
            ? 'bg-emerald-500/10 border-emerald-500/25 dark:border-emerald-500/30 text-emerald-800 dark:text-emerald-300' 
            : integrity > 60 
              ? 'bg-amber-500/10 border-amber-500/25 dark:border-amber-500/30 text-amber-800 dark:text-amber-300' 
              : 'bg-rose-500/10 border-rose-500/25 dark:border-rose-500/30 text-rose-800 dark:text-rose-300 animate-pulse'
        }`}>
          {integrity > 85 ? (
            <>
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span>All core threads nominal. Zero packet dropping detected across active boundary relays.</span>
            </>
          ) : integrity > 60 ? (
            <>
              <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
              <span>Core load fluctuating. Active node connections degraded. Monitor alert log queues.</span>
            </>
          ) : (
            <>
              <ShieldAlert className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
              <span>CRITICAL: High risk parameters detected. Deploy additional defensive policies.</span>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
