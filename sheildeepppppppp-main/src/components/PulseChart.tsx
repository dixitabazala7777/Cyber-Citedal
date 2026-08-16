import React, { useState } from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import { ChartDataPoint } from '../types';
import { Radio, RefreshCw } from 'lucide-react';
import { motion } from 'motion/react';

interface PulseChartProps {
  data: ChartDataPoint[];
  isSimulating: boolean;
  onRefresh: () => void;
}

interface TooltipProps {
  active?: boolean;
  payload?: Array<{
    name: string;
    value: number;
    stroke: string;
  }>;
  label?: string;
}

const CustomTooltip = ({ active, payload, label }: TooltipProps) => {
  if (active && payload && payload.length) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ type: 'spring', stiffness: 350, damping: 20 }}
        className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 p-4 rounded-xl shadow-xl dark:shadow-2xl backdrop-blur-md font-mono text-xs text-slate-800 dark:text-slate-200 space-y-2 max-w-[240px]"
      >
        <p className="text-slate-400 dark:text-slate-500 text-[10px] uppercase font-bold tracking-wider border-b border-slate-100 dark:border-slate-800 pb-1.5 mb-1.5">{label}</p>
        {payload.map((p) => (
          <div key={p.name} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: p.stroke }} />
              <span className="text-slate-600 dark:text-slate-400 font-sans font-medium">{p.name}:</span>
            </span>
            <span className="font-bold text-slate-900 dark:text-white text-right">{p.value.toLocaleString()}</span>
          </div>
        ))}
      </motion.div>
    );
  }
  return null;
};

const CustomActiveDot = (props: { cx?: number; cy?: number; stroke?: string }) => {
  const { cx, cy, stroke } = props;
  if (!cx || !cy) return null;
  return (
    <g>
      <circle 
        cx={cx} 
        cy={cy} 
        r={10} 
        fill="none" 
        stroke={stroke} 
        strokeWidth={1.5} 
        className="animate-ping" 
        style={{ transformOrigin: `${cx}px ${cy}px` }} 
      />
      <circle 
        cx={cx} 
        cy={cy} 
        r={4} 
        fill={stroke} 
        stroke="#ffffff" 
        strokeWidth={1.5} 
      />
    </g>
  );
};

export const PulseChart: React.FC<PulseChartProps> = ({ data, isSimulating, onRefresh }) => {
  const [showTraffic, setShowTraffic] = useState(true);
  const [showThreats, setShowThreats] = useState(true);
  const [showBlocked, setShowBlocked] = useState(true);
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d'>('24h');

  const getFilteredData = () => {
    if (timeRange === '1h') {
      return data.slice(-5);
    }
    if (timeRange === '7d') {
      return data.map((d, i) => ({
        ...d,
        time: `Day ${Math.floor(i / 3) + 1}`,
      }));
    }
    return data;
  };

  return (
    <div id="pulse-chart-card" className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs dark:shadow-xl flex flex-col h-[400px] transition-all duration-200 relative group overflow-hidden">
      {/* Chart Header Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4 z-10">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 bg-sky-500/10 border border-sky-500/25 dark:border-sky-500/30 rounded-xl text-sky-600 dark:text-sky-400">
              <Radio className="w-4 h-4 animate-pulse" />
            </div>
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wide font-sans">Security Pulse Analytics</h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-sans">Live correlation of active traffic vs security incidents</p>
        </div>

        {/* Filters and Actions */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Time range toggles */}
          <div className="flex bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-0.5 text-xs font-mono text-slate-600 dark:text-slate-400">
            {(['1h', '24h', '7d'] as const).map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-3 py-1 rounded-lg transition cursor-pointer font-bold ${
                  timeRange === r ? 'bg-sky-600 text-white dark:text-slate-950 shadow-md font-bold' : 'hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          <button
            onClick={onRefresh}
            className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition cursor-pointer"
            title="Refresh stream"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin text-sky-500 dark:text-sky-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Toggles Legend layer */}
      <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-600 dark:text-slate-400 mb-3 z-10 border-b border-slate-100 dark:border-slate-800/80 pb-2">
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showTraffic}
            onChange={() => setShowTraffic(!showTraffic)}
            className="rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-sky-500 dark:text-sky-400 focus:ring-0 cursor-pointer"
          />
          <span className="text-sky-600 dark:text-sky-400 font-bold font-sans">Network Traffic</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showThreats}
            onChange={() => setShowThreats(!showThreats)}
            className="rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-amber-500 dark:text-amber-400 focus:ring-0 cursor-pointer"
          />
          <span className="text-amber-600 dark:text-amber-400 font-bold font-sans">Threat Events</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showBlocked}
            onChange={() => setShowBlocked(!showBlocked)}
            className="rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-rose-500 dark:text-rose-400 focus:ring-0 cursor-pointer"
          />
          <span className="text-rose-600 dark:text-rose-400 font-bold font-sans">Intrusions Blocked</span>
        </label>
      </div>

      {/* Chart Canvas Area */}
      <div className="flex-1 w-full min-h-[210px] z-10">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={getFilteredData()} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorTrafficDark" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#0284c7" stopOpacity={0.35}/>
                <stop offset="95%" stopColor="#0284c7" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorThreatsDark" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.35}/>
                <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorBlockedDark" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.35}/>
                <stop offset="95%" stopColor="#f43f5e" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#94a3b8" strokeOpacity={0.15} />
            <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
            <YAxis stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
            <Tooltip content={<CustomTooltip />} cursor={{ stroke: '#64748b', strokeWidth: 1, strokeDasharray: '4 4' }} />
            {showTraffic && (
              <Area
                type="monotone"
                dataKey="traffic"
                stroke="#0284c7"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#colorTrafficDark)"
                name="Traffic Rate"
                activeDot={<CustomActiveDot stroke="#0284c7" />}
                isAnimationActive={true}
                animationDuration={750}
              />
            )}
            {showThreats && (
              <Area
                type="monotone"
                dataKey="threats"
                stroke="#f59e0b"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#colorThreatsDark)"
                name="Threats Found"
                activeDot={<CustomActiveDot stroke="#f59e0b" />}
                isAnimationActive={true}
                animationDuration={750}
              />
            )}
            {showBlocked && (
              <Area
                type="monotone"
                dataKey="blocked"
                stroke="#f43f5e"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#colorBlockedDark)"
                name="Threats Blocked"
                activeDot={<CustomActiveDot stroke="#f43f5e" />}
                isAnimationActive={true}
                animationDuration={750}
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
