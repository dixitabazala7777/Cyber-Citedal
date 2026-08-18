import React, { useState, useEffect } from 'react';
import { Shield, Bell, AlertTriangle, RotateCcw, Lock, Clock, Search, User, Sun, Moon } from 'lucide-react';

export interface StatusBannerProps {
  activeIncidentsCount: number;
  threatLevel: 'STABLE' | 'ELEVATED' | 'CRITICAL';
  systemState: string;
  isLockdownActive?: boolean;
  onToggleLockdown?: () => void;
  onRestoreSystem?: () => void;
  onOpenDrawer: () => void;
  historicalAlertsCount: number;
  pinnedCount: number;
  onSimulateCriticalAttack?: () => void;
  theme?: 'light' | 'dark';
  onToggleTheme?: () => void;
}

export const StatusBanner: React.FC<StatusBannerProps> = ({
  activeIncidentsCount,
  threatLevel,
  systemState,
  isLockdownActive = false,
  onToggleLockdown,
  onRestoreSystem,
  onOpenDrawer,
  historicalAlertsCount,
  pinnedCount,
  onSimulateCriticalAttack,
  theme = 'dark',
  onToggleTheme
}) => {
  const [utcTime, setUtcTime] = useState<string>('');
  const [localTime, setLocalTime] = useState<string>('');

  useEffect(() => {
    const updateClocks = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
      setLocalTime(now.toLocaleTimeString('en-US', { hour12: false }));
    };

    updateClocks();
    const timer = setInterval(updateClocks, 1000);
    return () => clearInterval(timer);
  }, []);

  const getStatusBadge = () => {
    if (isLockdownActive) {
      return (
        <span className="px-3 py-1 text-xs font-bold bg-rose-500/15 dark:bg-rose-500/20 text-rose-600 dark:text-rose-300 border border-rose-500/30 dark:border-rose-500/40 rounded-lg flex items-center gap-1.5 font-mono">
          <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
          DEFCON 1 • SYSTEM EMERGENCY LOCKDOWN
        </span>
      );
    }

    switch (threatLevel) {
      case 'CRITICAL':
        return (
          <span className="px-3 py-1 text-xs font-bold bg-rose-500/15 dark:bg-rose-500/20 text-rose-600 dark:text-rose-400 border border-rose-500/30 dark:border-rose-500/40 rounded-lg flex items-center gap-1.5 font-mono">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            Elevated Threat • Defcon 2
          </span>
        );
      case 'ELEVATED':
        return (
          <span className="px-3 py-1 text-xs font-bold bg-amber-500/15 dark:bg-amber-500/20 text-amber-600 dark:text-amber-300 border border-amber-500/30 dark:border-amber-500/40 rounded-lg flex items-center gap-1.5 font-mono">
            <span className="w-2 h-2 rounded-full bg-amber-500"></span>
            Notice • Defcon 4
          </span>
        );
      default:
        return (
          <span className="px-3 py-1 text-xs font-bold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 rounded-lg flex items-center gap-1.5 font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            Operational • Defcon 5
          </span>
        );
    }
  };

  return (
    <header className="bg-white/95 dark:bg-slate-950/95 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 px-6 py-4 sticky top-0 z-40 shadow-xs dark:shadow-xl transition-colors duration-150">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Brand & Environment */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-sky-500/10 border border-sky-500/25 dark:border-sky-500/30 rounded-xl text-sky-600 dark:text-sky-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-lg font-black tracking-wider uppercase text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  DEEPSHEILD
                  <span className="text-[10px] font-semibold px-2 py-0.5 bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/25 dark:border-sky-500/30 rounded font-mono">
                    ENTERPRISE
                  </span>
                </h1>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">
                Prod-US-East-1 • Real-Time Threat Intelligence & Edge Defense
              </p>
            </div>
          </div>

          <div className="hidden sm:block h-6 w-px bg-slate-200 dark:bg-slate-800" />

          {/* Operational Status Badge */}
          <div className="hidden md:flex items-center">
            {getStatusBadge()}
          </div>
        </div>

        {/* Center: Command Bar Trigger */}
        <div className="hidden lg:flex items-center">
          <button
            onClick={onOpenDrawer}
            className="flex items-center space-x-2.5 px-4 py-2 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 rounded-xl text-xs transition cursor-pointer"
          >
            <Search className="w-4 h-4 text-sky-500 dark:text-sky-400" />
            <span className="font-medium">Search telemetry or incidents...</span>
            <kbd className="px-2 py-0.5 text-[10px] font-mono font-bold bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded text-slate-500 dark:text-slate-400 ml-2">
              ⌘K
            </kbd>
          </button>
        </div>

        {/* Right Actions */}
        <div className="flex items-center space-x-3">
          {/* UTC & Local Clock */}
          <div className="hidden md:flex items-center space-x-3 text-xs text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-900 px-3.5 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 font-mono">
            <Clock className="w-4 h-4 text-sky-500 dark:text-sky-400" />
            <span>UTC: <strong className="text-slate-800 dark:text-slate-200">{utcTime.slice(17, 25) || '10:00:00'}</strong></span>
            <span className="text-slate-300 dark:text-slate-700">|</span>
            <span>Local: <strong className="text-slate-800 dark:text-slate-200">{localTime || '10:00:00'}</strong></span>
          </div>

          {/* Theme Switcher Button */}
          {onToggleTheme && (
            <button
              onClick={onToggleTheme}
              className="p-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 text-amber-500 dark:text-amber-400 border border-slate-200 dark:border-slate-800 rounded-xl transition cursor-pointer"
              title={theme === 'dark' ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          )}

          {/* Test Alert Trigger */}
          {onSimulateCriticalAttack && (
            <button
              onClick={onSimulateCriticalAttack}
              className="text-xs bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800 px-3.5 py-1.5 rounded-xl flex items-center gap-1.5 transition cursor-pointer font-semibold"
              title="Inject test alert notification"
            >
              <AlertTriangle className="w-4 h-4 text-amber-500 dark:text-amber-400" />
              <span className="hidden sm:inline">Test Alert</span>
            </button>
          )}

          {/* Emergency Lockdown Toggle */}
          {isLockdownActive && onRestoreSystem ? (
            <button
              onClick={onRestoreSystem}
              className="text-xs bg-rose-600 hover:bg-rose-500 text-white border border-rose-400 px-3.5 py-1.5 rounded-xl flex items-center gap-1.5 font-bold transition cursor-pointer animate-pulse shadow-[0_0_15px_rgba(244,63,94,0.4)]"
              title="Disengage Emergency Lockdown"
            >
              <RotateCcw className="w-4 h-4 text-white" />
              <span className="font-mono">DISENGAGE LOCKDOWN</span>
            </button>
          ) : (
            onToggleLockdown && (
              <button
                onClick={onToggleLockdown}
                className="text-xs bg-rose-500/10 hover:bg-rose-500/20 dark:bg-rose-500/15 dark:hover:bg-rose-500/25 text-rose-600 dark:text-rose-300 border border-rose-500/30 dark:border-rose-500/40 px-3.5 py-1.5 rounded-xl flex items-center gap-1.5 font-bold transition cursor-pointer"
                title="Engage Emergency Lockdown"
              >
                <Lock className="w-4 h-4 text-rose-500 dark:text-rose-400" />
                <span className="font-mono">Lockdown</span>
              </button>
            )
          )}

          {/* Notifications Drawer Bell */}
          <button
            onClick={onOpenDrawer}
            className="relative p-2 text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 rounded-xl transition cursor-pointer"
            title="Notifications & Security Alerts"
          >
            <Bell className="w-4 h-4" />
            {(activeIncidentsCount > 0 || pinnedCount > 0) && (
              <span className="absolute -top-1 -right-1 px-1.5 py-0.5 text-[10px] font-bold bg-rose-500 text-white rounded-full leading-none">
                {activeIncidentsCount + pinnedCount}
              </span>
            )}
          </button>

          {/* Admin Avatar */}
          <div className="flex items-center space-x-2 pl-1 border-l border-slate-200 dark:border-slate-800">
            <div className="w-8 h-8 rounded-xl bg-sky-500/15 dark:bg-sky-500/20 border border-sky-500/30 dark:border-sky-500/40 text-sky-600 dark:text-sky-300 flex items-center justify-center text-xs font-bold font-mono">
              <User className="w-4 h-4" />
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
