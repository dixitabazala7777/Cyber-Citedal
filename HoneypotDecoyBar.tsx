import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Radio,
  ShieldAlert,
  ShieldCheck,
  Flame,
  Zap,
  Sliders,
  RotateCcw,
  WifiOff,
  Cpu,
  AlertTriangle,
  Server,
  Activity
} from 'lucide-react';

/**
 * Threat engagement status enumeration
 */
export type HoneypotThreatStatus = 'ARMED' | 'ENGAGED' | 'CRITICAL';

/**
 * Component Props for HoneypotDecoyBar
 */
export interface HoneypotDecoyBarProps {
  /**
   * The current decoy engagement / load level percentage (0 - 100).
   * Safely handles null, undefined, NaN, strings, or out-of-bounds numbers.
   */
  loadLevel?: number | null;
  /** Initial fallback load percentage if uncontrolled (defaults to 22) */
  defaultLoadLevel?: number;
  /** Number of active decoy traps / sensors (defaults to 4) */
  activeDecoysCount?: number;
  /** Total maximum decoy sensor capacity (defaults to 4) */
  totalDecoysCount?: number;
  /** Live threat interactions / probes per minute (defaults to 34) */
  interactionsPerMin?: number;
  /** Component header label (defaults to "HONEYPOT DECOY ENGAGEMENT") */
  label?: string;
  /** Subtitle / subsystem descriptor */
  subLabel?: string;
  /** Flag indicating telemetry network disconnection or offline status */
  isOffline?: boolean;
  /** Flag indicating initial telemetry synchronization */
  isLoading?: boolean;
  /** Whether to render interactive test & simulation controls */
  showControls?: boolean;
  /** Whether to show secondary telemetry metrics (active decoys, rate, threat status) */
  showMetrics?: boolean;
  /** Display variant: 'card' (standard HUD card), 'compact' (streamlined bar), 'minimal' (inline) */
  variant?: 'card' | 'compact' | 'minimal';
  /** Callback triggered when load level or threat status changes */
  onLoadChange?: (load: number, status: HoneypotThreatStatus) => void;
  /** Optional callback to push logs to parent dashboard */
  onLogMessage?: (msg: string, type?: 'info' | 'warn' | 'error' | 'success') => void;
  /** Additional CSS classes for root container */
  className?: string;
}

/**
 * Safely parse, clean, and clamp any raw decoy activity/load input.
 * Guarantees a valid numeric result in the range [0, 100].
 *
 * @param val - The raw input value (number, null, undefined, string, NaN)
 * @param fallback - Default fallback if value is null, undefined, or NaN (defaults to 0)
 * @returns A safe, clamped number between 0 and 100
 */
export function sanitizeDecoyLoad(val: unknown, fallback: number = 0): number {
  const safeFallback = (typeof fallback === 'number' && Number.isFinite(fallback))
    ? Math.min(100, Math.max(0, fallback))
    : 0;

  if (val === null || val === undefined) {
    return safeFallback;
  }

  let numeric: number;
  if (typeof val === 'number') {
    numeric = val;
  } else if (typeof val === 'string') {
    const cleanStr = val.replace(/%/g, '').trim();
    if (cleanStr === '') {
      return safeFallback;
    }
    numeric = Number(cleanStr);
  } else {
    return safeFallback;
  }

  if (Number.isNaN(numeric) || !Number.isFinite(numeric)) {
    return safeFallback;
  }

  return Math.min(100, Math.max(0, numeric));
}

/**
 * Returns state-driven styling tokens based on decoy activity / load percentage.
 *
 * Requirements:
 * - Idle / Low Activity (< 30%): Subdued Cyber Blue (#10b981) -> "ARMED"
 * - Moderate Engagement (30% - 70%): Warning Amber (#D29922) -> "ENGAGED"
 * - Heavy Attack / Breach Attempt (> 70%): Alert Crimson with subtle pulsing animation (#DA3633) -> "CRITICAL"
 */
export function getHoneypotDecoyState(load: number) {
  // Heavy Attack / Breach Attempt (> 70%)
  if (load > 70) {
    return {
      status: 'CRITICAL' as HoneypotThreatStatus,
      statusLabel: 'CRITICAL',
      colorHex: '#DA3633',
      colorName: 'crimson',
      textColor: 'text-rose-400',
      textGlow: 'drop-shadow-[0_0_10px_rgba(239,68,68,0.9)]',
      borderClass: 'border-rose-500/60 hover:border-rose-500/90',
      cardGlow: 'shadow-[0_0_30px_rgba(239,68,68,0.25)] animate-pulse',
      barGradient: 'from-rose-700 via-red-500 to-rose-400',
      barGlow: 'shadow-[0_0_22px_rgba(239,68,68,0.85)]',
      badgeClass: 'bg-rose-950/90 text-rose-300 border-rose-700 shadow-[0_0_14px_rgba(239,68,68,0.4)] animate-pulse',
      iconContainer: 'bg-rose-950/80 border-rose-600/90 text-rose-400 animate-pulse',
      statusIcon: ShieldAlert,
      pulseGlow: true,
      description: 'Heavy Attack / Sandbox Traps Under Siege',
    };
  }

  // Moderate Engagement (30% - 70%)
  if (load >= 30) {
    return {
      status: 'ENGAGED' as HoneypotThreatStatus,
      statusLabel: 'ENGAGED',
      colorHex: '#D29922',
      colorName: 'amber',
      textColor: 'text-amber-400',
      textGlow: 'drop-shadow-[0_0_8px_rgba(245,158,11,0.7)]',
      borderClass: 'border-amber-500/40 hover:border-amber-500/70',
      cardGlow: 'shadow-[0_0_25px_rgba(245,158,11,0.12)]',
      barGradient: 'from-amber-600 via-amber-500 to-yellow-300',
      barGlow: 'shadow-[0_0_16px_rgba(245,158,11,0.65)]',
      badgeClass: 'bg-amber-950/80 text-amber-300 border-amber-800/80 shadow-[0_0_10px_rgba(245,158,11,0.2)]',
      iconContainer: 'bg-amber-950/70 border-amber-700/80 text-amber-400',
      statusIcon: AlertTriangle,
      pulseGlow: false,
      description: 'Active Exploitation / Deception Traps Intercepting Probes',
    };
  }

  // Idle / Low Activity (< 30%)
  return {
    status: 'ARMED' as HoneypotThreatStatus,
    statusLabel: 'ARMED',
    colorHex: '#10b981',
    colorName: 'cyber-blue',
    textColor: 'text-sky-400',
    textGlow: 'drop-shadow-[0_0_8px_rgba(14,165,233,0.7)]',
    borderClass: 'border-sky-500/40 hover:border-sky-500/70',
    cardGlow: 'shadow-[0_0_25px_rgba(14,165,233,0.12)]',
    barGradient: 'from-sky-600 via-sky-400 to-cyan-300',
    barGlow: 'shadow-[0_0_16px_rgba(14,165,233,0.65)]',
    badgeClass: 'bg-sky-950/80 text-sky-300 border-sky-800/80 shadow-[0_0_10px_rgba(14,165,233,0.2)]',
    iconContainer: 'bg-sky-950/70 border-sky-700/80 text-sky-400',
    statusIcon: ShieldCheck,
    pulseGlow: false,
    description: 'Decoy Nodes Armed / Nominal Baseline Activity',
  };
}

/**
 * Production-ready Honeypot Decoy Bar Component for DEEPSHIELD Enterprise
 */
export const HoneypotDecoyBar: React.FC<HoneypotDecoyBarProps> = ({
  loadLevel,
  defaultLoadLevel = 22,
  activeDecoysCount = 4,
  totalDecoysCount = 4,
  interactionsPerMin = 34,
  label = 'HONEYPOT DECOY ENGAGEMENT',
  subLabel = 'Dynamic AI Deception & Multi-Vector Threat Replicators',
  isOffline = false,
  isLoading = false,
  showControls = true,
  showMetrics = true,
  variant = 'card',
  onLoadChange,
  onLogMessage,
  className = '',
}) => {
  const isControlled = loadLevel !== undefined && loadLevel !== null;

  // Internal state for interactive testing and simulation
  const [internalLoad, setInternalLoad] = useState<number>(() =>
    sanitizeDecoyLoad(isControlled ? loadLevel : defaultLoadLevel, 22)
  );

  const [internalInteractions, setInternalInteractions] = useState<number>(interactionsPerMin);
  const [isLiveOscillating, setIsLiveOscillating] = useState<boolean>(false);
  const [showControlsDrawer, setShowControlsDrawer] = useState<boolean>(false);

  // Derive active sanitized load level
  const activeLoad = useMemo(() => {
    const raw = isControlled ? loadLevel : internalLoad;
    return sanitizeDecoyLoad(raw, 0);
  }, [isControlled, loadLevel, internalLoad]);

  // Derive styling theme based on current load
  const stateTheme = useMemo(() => getHoneypotDecoyState(activeLoad), [activeLoad]);
  const StatusIcon = isOffline ? WifiOff : stateTheme.statusIcon;

  // Sync callbacks when load or status changes
  useEffect(() => {
    if (onLoadChange) {
      onLoadChange(activeLoad, stateTheme.status);
    }
  }, [activeLoad, stateTheme.status, onLoadChange]);

  // Safe setter with logging
  const setLoadSafe = useCallback((newVal: number, logDesc?: string) => {
    const sanitized = sanitizeDecoyLoad(newVal);
    setInternalLoad(sanitized);

    // Dynamically scale simulated interactions/min proportionally to load
    const dynamicRate = Math.max(2, Math.round(sanitized * 4.2 + (Math.random() - 0.5) * 10));
    setInternalInteractions(dynamicRate);

    if (onLogMessage && logDesc) {
      const nextState = getHoneypotDecoyState(sanitized);
      const logType = sanitized > 70 ? 'error' : sanitized >= 30 ? 'warn' : 'info';
      onLogMessage(`HONEYPOT TELEMETRY: ${logDesc} -> ${sanitized.toFixed(1)}% [${nextState.status}]`, logType);
    }
  }, [onLogMessage]);

  // Auto-oscillation attack simulation loop
  useEffect(() => {
    if (!isLiveOscillating) return;

    const interval = setInterval(() => {
      setInternalLoad(() => {
        // Natural attack burst oscillation
        const time = Date.now() / 3500;
        const base = 48 + Math.sin(time) * 32;
        const noise = (Math.random() - 0.5) * 12;
        const nextVal = Math.max(5, Math.min(98, Math.round(base + noise)));
        setInternalInteractions(Math.round(nextVal * 3.8 + Math.random() * 15));
        return nextVal;
      });
    }, 2000);

    return () => clearInterval(interval);
  }, [isLiveOscillating]);

  // Simulation Trigger Handlers
  const handleTriggerSpike = () => {
    setLoadSafe(88.5, 'SURGE: Massive distributed credential stuffing & SCADA injection attack');
  };

  const handleTriggerWarning = () => {
    setLoadSafe(52.0, 'ELEVATED: Automated vulnerability probe cluster detected');
  };

  const handleTriggerIdle = () => {
    setLoadSafe(14.0, 'COOLDOWN: Decoy traffic returned to baseline scan levels');
  };

  // -------------------------------------------------------------
  // VARIANT: Minimal (Compact inline progress bar + tag)
  // -------------------------------------------------------------
  if (variant === 'minimal') {
    return (
      <div className={`space-y-1 font-mono ${className}`}>
        <div className="flex items-center justify-between text-xs">
          <span className="font-bold text-slate-300 uppercase flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full ${isOffline
                ? 'bg-slate-500'
                : stateTheme.colorName === 'cyber-blue'
                  ? 'bg-sky-400'
                  : stateTheme.colorName === 'amber'
                    ? 'bg-amber-400'
                    : 'bg-rose-400 animate-ping'
                }`}
            />
            {label}
          </span>
          <div className="flex items-center gap-2">
            <span className={`font-extrabold ${isOffline ? 'text-slate-500' : stateTheme.textColor} ${isOffline ? '' : stateTheme.textGlow}`}>
              {isOffline ? 'OFFLINE' : isLoading ? 'SYNC...' : `${activeLoad.toFixed(1)}%`}
            </span>
            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold border ${isOffline ? 'bg-slate-900 text-slate-500 border-slate-800' : stateTheme.badgeClass}`}>
              {isOffline ? 'DISCONNECTED' : stateTheme.statusLabel}
            </span>
          </div>
        </div>

        {/* The Decoy Load Track */}
        <div className="w-full bg-slate-900/90 border border-slate-800/80 h-2 rounded-full overflow-hidden relative shadow-inner">
          <div
            role="progressbar"
            aria-label={label}
            aria-valuenow={isOffline ? 0 : activeLoad}
            aria-valuemin={0}
            aria-valuemax={100}
            className={`h-full bg-gradient-to-r ${isOffline ? 'from-slate-700 to-slate-800' : stateTheme.barGradient} ${isOffline ? '' : stateTheme.barGlow} transition-all duration-700 ease-out`}
            style={{ width: `${isOffline ? 0 : activeLoad}%` }}
          />
        </div>
      </div>
    );
  }

  // -------------------------------------------------------------
  // VARIANT: Compact (Streamlined topbar/card HUD bar)
  // -------------------------------------------------------------
  if (variant === 'compact') {
    return (
      <div
        className={`bg-[#090c10]/80 backdrop-blur-md border ${isOffline ? 'border-slate-800' : stateTheme.borderClass} ${isOffline ? '' : stateTheme.cardGlow} rounded-xl p-3 font-mono transition-all duration-300 ${className}`}
      >
        <div className="flex items-center justify-between gap-3 mb-2">
          <div className="flex items-center gap-2">
            <div className={`p-1.5 rounded-lg border ${isOffline ? 'bg-slate-900 border-slate-800 text-slate-500' : stateTheme.iconContainer}`}>
              <StatusIcon className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-white uppercase tracking-wider">{label}</div>
              <div className="text-[10px] text-slate-500 font-sans">{subLabel}</div>
            </div>
          </div>

          <div className="flex items-center gap-2 text-right">
            <div className={`text-lg font-black tracking-tight ${isOffline ? 'text-slate-500' : stateTheme.textColor} ${isOffline ? '' : stateTheme.textGlow}`}>
              {isOffline ? 'OFFLINE' : isLoading ? 'SYNC...' : `${activeLoad.toFixed(1)}%`}
            </div>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${isOffline ? 'bg-slate-900 text-slate-500 border-slate-800' : stateTheme.badgeClass}`}>
              {isOffline ? 'DISCONNECTED' : stateTheme.statusLabel}
            </span>
          </div>
        </div>

        <div className="w-full bg-slate-950 border border-slate-850 h-2.5 rounded-full overflow-hidden relative p-0.5 shadow-inner">
          <div
            role="progressbar"
            aria-label={label}
            aria-valuenow={isOffline ? 0 : activeLoad}
            aria-valuemin={0}
            aria-valuemax={100}
            className={`h-full rounded-full bg-gradient-to-r ${isOffline ? 'from-slate-700 to-slate-800' : stateTheme.barGradient} ${isOffline ? '' : stateTheme.barGlow} transition-all duration-700 ease-out`}
            style={{ width: `${isOffline ? 0 : activeLoad}%` }}
          />
        </div>
      </div>
    );
  }

  // -------------------------------------------------------------
  // VARIANT: Card (Full Cyberpunk Security Dashboard HUD Component)
  // -------------------------------------------------------------
  return (
    <div
      id="honeypot-decoy-bar-component"
      className={`bg-[#090c10]/80 backdrop-blur-md border ${isOffline ? 'border-white/10' : stateTheme.borderClass} ${isOffline ? '' : stateTheme.cardGlow} ring-1 ring-white/5 rounded-2xl p-5 md:p-6 transition-all duration-500 font-mono relative overflow-hidden group hover:border-white/20 ${className}`}
    >
      {/* Top Accent Light Bar */}
      <div
        className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-indigo-500/20 to-transparent pointer-events-none"
      />

      {/* Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/5 relative z-10">

        {/* Left: Icon & Titles */}
        <div className="flex items-center gap-3">
          <div
            className={`p-2.5 rounded-xl border transition-colors duration-300 ${isOffline ? 'bg-slate-900 border-slate-800 text-slate-500' : stateTheme.iconContainer
              }`}
          >
            <StatusIcon className={`w-6 h-6 ${stateTheme.pulseGlow && !isOffline ? 'animate-bounce' : ''}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm md:text-base font-bold text-white uppercase tracking-wider">
                {label}
              </h2>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${isOffline
                ? 'bg-slate-900 text-slate-500 border-slate-800'
                : 'bg-indigo-950 text-indigo-300 border-indigo-800/80'
                }`}>
                {isOffline ? 'OFFLINE' : 'DECEPTION CORE'}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              {subLabel}
            </p>
          </div>
        </div>

        {/* Right: Percentage Counter & Status Tag */}
        <div className="flex items-center gap-3 self-end sm:self-auto">
          <div className="text-right">
            <div className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">
              Decoy Engagement Load
            </div>
            <div className={`text-2xl md:text-3xl font-black tracking-tight ${isOffline ? 'text-slate-500' : stateTheme.textColor} ${isOffline ? '' : stateTheme.textGlow}`}>
              {isOffline ? (
                <span className="text-slate-500 text-xl flex items-center gap-1.5 justify-end">
                  <WifiOff className="w-4 h-4" /> OFFLINE
                </span>
              ) : isLoading ? (
                <span className="text-slate-400 animate-pulse text-xl">RECONNECTING TELEMETRY...</span>
              ) : (
                `${activeLoad.toFixed(1)}%`
              )}
            </div>
          </div>

          <div className="flex flex-col items-end gap-1">
            <span className={`px-2.5 py-1 rounded-md text-xs font-extrabold tracking-wider border uppercase ${isOffline ? 'bg-slate-900 text-slate-500 border-slate-800' : stateTheme.badgeClass
              }`}>
              {isOffline ? 'DISCONNECTED' : stateTheme.statusLabel}
            </span>
            <span className="text-[9px] text-slate-500 font-sans">
              {isOffline ? 'TELEMETRY OFFLINE' : stateTheme.status === 'ARMED' ? 'NOMINAL SCAN' : stateTheme.status === 'ENGAGED' ? 'ELEVATED ATTACK' : 'MAX CONTINGENCY'}
            </span>
          </div>
        </div>
      </div>

      {/* Main Telemetry & Decoy Activity Bar Section */}
      <div className="my-6 space-y-2.5 relative z-10">

        {/* Track Label and Scale Details */}
        <div className="flex justify-between items-center text-[11px] text-slate-400 font-medium">
          <span className="flex items-center gap-1.5">
            <Activity className={`w-3.5 h-3.5 ${isOffline ? 'text-slate-500' : stateTheme.textColor}`} />
            <span>{isOffline ? 'Telemetry Ingestion Suspended' : stateTheme.description}</span>
          </span>
          <span className="text-slate-500 text-[10px]">
            {isOffline ? 'Reconnecting Socket...' : activeLoad > 70 ? 'Alert: Breach Attempt in Progress' : activeLoad >= 30 ? 'Moderate Trap Interception' : 'Sensors Armed & Listening'}
          </span>
        </div>

        {/* Multi-layered Cyber Progress Bar */}
        <div className="relative w-full bg-slate-950/90 border border-slate-800 rounded-xl p-1.5 shadow-inner">
          <div className="w-full bg-[#090c10] h-6 md:h-7 rounded-lg overflow-hidden relative flex items-center">

            {/* Background Tick Marks at 30% (Warning) and 70% (Critical) */}
            <div className="absolute left-[30%] h-full w-[1px] bg-slate-800/90 pointer-events-none z-20" />
            <div className="absolute left-[70%] h-full w-[1px] bg-slate-800/90 pointer-events-none z-20" />

            {/* Filled Animated Gradient Bar */}
            <div
              role="progressbar"
              aria-label={label}
              aria-valuenow={isOffline ? 0 : activeLoad}
              aria-valuemin={0}
              aria-valuemax={100}
              className={`h-full rounded-md bg-gradient-to-r ${isOffline ? 'from-slate-700 to-slate-800' : stateTheme.barGradient
                } ${isOffline ? '' : stateTheme.barGlow} transition-all duration-700 ease-out relative flex items-center justify-end pr-2 overflow-hidden`}
              style={{ width: `${isOffline ? 0 : activeLoad}%` }}
            >
              {/* Dynamic Laser Scan Highlight Effect */}
              {!isOffline && (
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent opacity-60 animate-pulse pointer-events-none" />
              )}

              {/* Leading Tip Indicator Glow */}
              {!isOffline && activeLoad > 8 && (
                <span className="relative z-10 w-1.5 h-3.5 bg-white rounded-full shadow-[0_0_8px_#ffffff] opacity-90" />
              )}
            </div>

            {/* Offline Scan Overlay */}
            {isOffline && (
              <div className="absolute inset-0 flex items-center justify-center text-[10px] text-slate-500 font-mono font-bold tracking-widest uppercase">
                RECONNECTING TELEMETRY...
              </div>
            )}
          </div>
        </div>

        {/* Scale Range Ticks */}
        <div className="flex justify-between text-[10px] text-slate-500 px-1 pt-0.5">
          <span className="hover:text-sky-400 transition-colors">0% (IDLE)</span>
          <span className="hover:text-sky-400 transition-colors">30% (ARMED / LOW)</span>
          <span className="hover:text-amber-400 transition-colors">70% (ENGAGED)</span>
          <span className="hover:text-rose-400 transition-colors">100% (CRITICAL)</span>
        </div>
      </div>

      {/* Secondary Metrics Strip */}
      {showMetrics && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 pb-2 border-t border-slate-850/80 text-xs relative z-10">

          {/* Metric 1: Decoys Active */}
          <div className="p-2.5 bg-slate-900/60 border border-slate-850 rounded-lg">
            <span className="text-[10px] text-slate-500 uppercase font-medium flex items-center gap-1">
              <Server className="w-3 h-3 text-sky-400" /> Decoys Active
            </span>
            <span className="font-bold text-slate-100 text-sm">
              {isOffline ? '0 / 4' : `${activeDecoysCount} / ${totalDecoysCount} Traps`}
            </span>
          </div>

          {/* Metric 2: Interactions / Min */}
          <div className="p-2.5 bg-slate-900/60 border border-slate-850 rounded-lg">
            <span className="text-[10px] text-slate-500 uppercase font-medium flex items-center gap-1">
              <Flame className={`w-3 h-3 ${isOffline ? 'text-slate-500' : 'text-amber-400 animate-bounce'}`} /> Interactions/min
            </span>
            <span className={`font-bold text-sm ${isOffline ? 'text-slate-500' : activeLoad > 70 ? 'text-rose-400 font-black' : activeLoad >= 30 ? 'text-amber-400' : 'text-sky-400'}`}>
              {isOffline ? '0' : `${internalInteractions} evt/min`}
            </span>
          </div>

          {/* Metric 3: Threat Level Status */}
          <div className="p-2.5 bg-slate-900/60 border border-slate-850 rounded-lg">
            <span className="text-[10px] text-slate-500 uppercase font-medium flex items-center gap-1">
              <Radio className="w-3 h-3 text-indigo-400" /> Threat Status
            </span>
            <span className={`font-bold text-sm uppercase ${isOffline ? 'text-slate-500' : stateTheme.textColor}`}>
              {isOffline ? 'OFFLINE' : stateTheme.status}
            </span>
          </div>

          {/* Metric 4: Containment Index */}
          <div className="p-2.5 bg-slate-900/60 border border-slate-850 rounded-lg">
            <span className="text-[10px] text-slate-500 uppercase font-medium flex items-center gap-1">
              <Zap className="w-3 h-3 text-emerald-400" /> Isolation Sandbox
            </span>
            <span className="font-bold text-sm text-emerald-400">
              {isOffline ? 'STANDBY' : '100% SEALED'}
            </span>
          </div>

        </div>
      )}

      {/* Interactive Testing & Simulation Controls */}
      {showControls && (
        <div className="mt-4 pt-4 border-t border-slate-850/80 relative z-10">

          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowControlsDrawer(!showControlsDrawer)}
                className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition cursor-pointer"
              >
                <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                {showControlsDrawer ? 'Hide Simulation Tools' : 'Simulate Attack Telemetry'}
              </button>

              <button
                type="button"
                onClick={() => setIsLiveOscillating(!isLiveOscillating)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition border cursor-pointer ${isLiveOscillating
                  ? 'bg-amber-950/80 text-amber-300 border-amber-700 animate-pulse'
                  : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
                  }`}
              >
                <Radio className={`w-3.5 h-3.5 ${isLiveOscillating ? 'text-amber-400 animate-pulse' : ''}`} />
                {isLiveOscillating ? 'Attack Stream: ACTIVE' : 'Attack Stream: PAUSED'}
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleTriggerSpike}
                className="px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 border border-rose-800/80 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition cursor-pointer"
                title="Simulate heavy attack surge (>70%)"
              >
                <Zap className="w-3.5 h-3.5 text-rose-400" />
                Payload Spike
              </button>

              <button
                type="button"
                onClick={handleTriggerIdle}
                className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-sky-400 border border-slate-800 rounded-lg transition cursor-pointer"
                title="Reset to Idle Baseline (<30%)"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Expandable Simulation Drawer */}
          {showControlsDrawer && (
            <div className="mt-3 p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-[11px] text-slate-400 font-bold flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-indigo-400" />
                  Manual Attack Ingestion Override Slider:
                </span>
                <span className={`text-xs font-extrabold ${stateTheme.textColor}`}>
                  {activeLoad.toFixed(1)}% [{stateTheme.status}]
                </span>
              </div>

              <input
                type="range"
                min="0"
                max="100"
                step="0.5"
                value={activeLoad}
                onChange={(e) => setLoadSafe(parseFloat(e.target.value), 'Manual slider adjusted')}
                className="w-full h-2 bg-slate-950 rounded-lg appearance-none cursor-pointer accent-indigo-500"
              />

              {/* State Presets */}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Threat Presets:</span>

                <button
                  type="button"
                  onClick={handleTriggerIdle}
                  className="px-2.5 py-1 bg-sky-950/70 hover:bg-sky-900 text-sky-300 border border-sky-800/80 rounded text-[11px] font-bold transition cursor-pointer"
                >
                  Idle / Low (14%) - ARMED
                </button>

                <button
                  type="button"
                  onClick={handleTriggerWarning}
                  className="px-2.5 py-1 bg-amber-950/70 hover:bg-amber-900 text-amber-300 border border-amber-800/80 rounded text-[11px] font-bold transition cursor-pointer"
                >
                  Moderate (52%) - ENGAGED
                </button>

                <button
                  type="button"
                  onClick={handleTriggerSpike}
                  className="px-2.5 py-1 bg-rose-950/70 hover:bg-rose-900 text-rose-300 border border-rose-800/80 rounded text-[11px] font-bold transition cursor-pointer"
                >
                  Critical Spike (88%) - CRITICAL
                </button>
              </div>

            </div>
          )}

        </div>
      )}

    </div>
  );
};

export default HoneypotDecoyBar;
