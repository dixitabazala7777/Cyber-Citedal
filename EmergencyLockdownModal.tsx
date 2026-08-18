import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldAlert, 
  RotateCcw, 
  WifiOff, 
  Server, 
  Activity, 
  Lock, 
  AlertOctagon,
  Eye,
  CheckCircle2,
  X
} from 'lucide-react';

interface EmergencyLockdownModalProps {
  isOpen: boolean;
  isLockdownActive: boolean;
  mode: 'confirm_engage' | 'active_overlay' | 'confirm_disengage';
  onConfirmEngage: () => void;
  onConfirmDisengage: () => void;
  onClose: () => void;
  isolatedNodesCount: number;
  totalNodesCount: number;
}

export const EmergencyLockdownModal: React.FC<EmergencyLockdownModalProps> = ({
  isOpen,
  isLockdownActive,
  mode,
  onConfirmEngage,
  onConfirmDisengage,
  onClose,
  isolatedNodesCount,
  totalNodesCount
}) => {
  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
        {/* Darkened Crimson Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-slate-950/85 backdrop-blur-md"
          onClick={onClose}
        />

        {/* Modal Window */}
        <motion.div
          initial={{ scale: 0.92, opacity: 0, y: 15 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.92, opacity: 0, y: 15 }}
          transition={{ type: 'spring', stiffness: 320, damping: 25 }}
          className={`relative z-10 w-full max-w-xl bg-slate-950 border-2 ${
            mode === 'confirm_disengage'
              ? 'border-emerald-500 shadow-[0_0_50px_rgba(16,185,129,0.3)]'
              : 'border-rose-600 shadow-[0_0_60px_rgba(225,29,72,0.4)]'
          } rounded-2xl overflow-hidden font-mono text-slate-100`}
        >
          {/* 1. CONFIRM ENGAGE LOCKDOWN MODE */}
          {mode === 'confirm_engage' && (
            <div>
              {/* Header */}
              <div className="bg-rose-950/90 border-b border-rose-600/60 px-6 py-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-rose-600/20 border border-rose-500/40 text-rose-400">
                    <Lock className="w-5 h-5 text-rose-500" />
                  </div>
                  <div>
                    <h3 className="text-sm font-black tracking-widest text-rose-100 uppercase">
                      ENGAGE EMERGENCY PROTOCOL?
                    </h3>
                    <p className="text-[11px] text-rose-300 font-medium">
                      Zero-Trust Fail-Safe Quarantine Confirmation
                    </p>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  className="p-1 rounded hover:bg-rose-900/50 text-rose-400 hover:text-rose-200 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Body */}
              <div className="p-6 space-y-4 text-xs">
                <div className="p-4 bg-rose-950/30 border border-rose-900/50 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-rose-300 font-bold text-sm">
                    <ShieldAlert className="w-4 h-4 text-rose-500" />
                    <span>ISOLATE ALL INGRESS & EDGE TRAFFIC?</span>
                  </div>
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    Activating the global kill-switch will immediately execute the following security containment measures:
                  </p>
                  <ul className="space-y-1.5 text-[11px] text-slate-400 list-disc pl-4 mt-2">
                    <li><strong className="text-rose-300">Throughput Severed:</strong> Ingress traffic rate drops immediately to 0 B/s.</li>
                    <li><strong className="text-rose-300">Gateways Isolated:</strong> US-EAST-01, EU-WEST-02, and AP-SOUTH-01 severed from boundary relays.</li>
                    <li><strong className="text-rose-300">Active Threats Contained:</strong> All active ingress packets and telemetry streams dropped.</li>
                    <li><strong className="text-rose-300">DEFCON 1 Status:</strong> System state escalates to emergency lockdown posture.</li>
                  </ul>
                </div>

                {/* Actions */}
                <div className="pt-2 flex flex-col sm:flex-row gap-3">
                  <button
                    onClick={onConfirmEngage}
                    className="flex-1 py-3 px-4 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(244,63,94,0.4)] flex items-center justify-center gap-2 transition cursor-pointer text-xs uppercase tracking-wider"
                  >
                    <Lock className="w-4 h-4" />
                    <span>CONFIRM EMERGENCY LOCKDOWN</span>
                  </button>
                  <button
                    onClick={onClose}
                    className="py-3 px-5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white font-bold rounded-xl border border-slate-800 transition cursor-pointer text-xs"
                  >
                    CANCEL
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* 2. CONFIRM DISENGAGE LOCKDOWN MODE */}
          {mode === 'confirm_disengage' && (
            <div>
              {/* Header */}
              <div className="bg-emerald-950/90 border-b border-emerald-600/60 px-6 py-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-emerald-600/20 border border-emerald-500/40 text-emerald-400">
                    <RotateCcw className="w-5 h-5 text-emerald-400" />
                  </div>
                  <div>
                    <h3 className="text-sm font-black tracking-widest text-emerald-100 uppercase">
                      DISENGAGE EMERGENCY LOCKDOWN?
                    </h3>
                    <p className="text-[11px] text-emerald-300 font-medium">
                      Re-Arm Edge Gateways & Restore Ingress Traffic
                    </p>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  className="p-1 rounded hover:bg-emerald-900/50 text-emerald-400 hover:text-emerald-200 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Body */}
              <div className="p-6 space-y-4 text-xs">
                <div className="p-4 bg-emerald-950/30 border border-emerald-900/50 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-emerald-300 font-bold text-sm">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>RESTORE OPERATIONAL SYSTEM STATE</span>
                  </div>
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    Disengaging lockdown will safely re-arm edge gateway nodes, restore ingress packet routing, and resume real-time security monitoring.
                  </p>
                </div>

                {/* Actions */}
                <div className="pt-2 flex flex-col sm:flex-row gap-3">
                  <button
                    onClick={onConfirmDisengage}
                    className="flex-1 py-3 px-4 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(16,185,129,0.4)] flex items-center justify-center gap-2 transition cursor-pointer text-xs uppercase tracking-wider"
                  >
                    <RotateCcw className="w-4 h-4" />
                    <span>CONFIRM DISENGAGE LOCKDOWN</span>
                  </button>
                  <button
                    onClick={onClose}
                    className="py-3 px-5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white font-bold rounded-xl border border-slate-800 transition cursor-pointer text-xs"
                  >
                    CANCEL
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* 3. ACTIVE LOCKDOWN OVERLAY INSPECTION MODE */}
          {mode === 'active_overlay' && (
            <div>
              {/* Top Warning Strip */}
              <div className="bg-rose-950/90 border-b border-rose-600/60 px-6 py-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-rose-600/30 border border-rose-500 text-rose-400 animate-pulse">
                    <AlertOctagon className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="text-base font-black tracking-widest text-rose-100 uppercase">
                      DEFCON 1 • SYSTEM EMERGENCY LOCKDOWN
                    </h3>
                    <p className="text-[11px] text-rose-400 font-medium">
                      Zero-Trust Fail-Safe Quarantine Engaged
                    </p>
                  </div>
                </div>
                <span className="px-2.5 py-1 text-[10px] bg-rose-600 text-white rounded font-extrabold uppercase animate-pulse">
                  SEVERED
                </span>
              </div>

              {/* Body Content */}
              <div className="p-6 space-y-5 text-xs">
                <div className="p-4 bg-rose-950/30 border border-rose-900/50 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-rose-300 font-bold text-sm">
                    <ShieldAlert className="w-4 h-4 text-rose-500" />
                    <span>All Network & Ingress Packet Streams Dropped</span>
                  </div>
                  <p className="text-slate-400 leading-relaxed text-[11px]">
                    The global <strong>[KILL-SWITCH]</strong> is active. All distributed edge proxies and ingress channels have been severed to prevent lateral movement.
                  </p>
                </div>

                {/* Quarantine Status Grid */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                    <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase">
                      <Server className="w-3.5 h-3.5 text-rose-400" />
                      <span>Gateway Nodes</span>
                    </div>
                    <div className="text-sm font-bold text-rose-400">
                      {isolatedNodesCount} / {totalNodesCount} ISOLATED
                    </div>
                    <span className="text-[10px] text-slate-500 block">0% Load • Severed</span>
                  </div>

                  <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                    <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase">
                      <WifiOff className="w-3.5 h-3.5 text-rose-400" />
                      <span>Network Throughput</span>
                    </div>
                    <div className="text-sm font-bold text-rose-400">
                      0 B/s (SEVERED)
                    </div>
                    <span className="text-[10px] text-slate-500 block">Packet filter: DROP ALL</span>
                  </div>

                  <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                    <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase">
                      <Activity className="w-3.5 h-3.5 text-rose-400" />
                      <span>Telemetry Streams</span>
                    </div>
                    <div className="text-sm font-bold text-amber-400">
                      FROZEN / OFF
                    </div>
                    <span className="text-[10px] text-slate-500 block">Ingress Paused</span>
                  </div>

                  <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                    <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase">
                      <Lock className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Security Perimeter</span>
                    </div>
                    <div className="text-sm font-bold text-emerald-400">
                      100% SEALED
                    </div>
                    <span className="text-[10px] text-slate-500 block">Admin Whitelist Only</span>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="pt-2 flex flex-col sm:flex-row gap-3">
                  <button
                    onClick={onConfirmDisengage}
                    className="flex-1 py-3 px-4 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(16,185,129,0.4)] flex items-center justify-center gap-2 transition transform active:scale-95 cursor-pointer text-xs uppercase tracking-wider border border-emerald-400/50"
                  >
                    <RotateCcw className="w-4 h-4" />
                    <span>DISENGAGE LOCKDOWN</span>
                  </button>

                  <button
                    onClick={onClose}
                    className="py-3 px-4 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white font-bold rounded-xl border border-slate-700 flex items-center justify-center gap-2 transition cursor-pointer text-xs"
                    title="Keep lockdown active and inspect dashboard components"
                  >
                    <Eye className="w-4 h-4 text-slate-400" />
                    <span>Inspect Dashboard</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Footer note */}
          <div className="bg-slate-950/90 border-t border-slate-800/80 px-6 py-2.5 text-[10px] text-slate-500 flex items-center justify-between">
            <span>DEEPSHEILD Zero-Trust Kernel</span>
            <span className={isLockdownActive ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
              {isLockdownActive ? "STATUS: GLOBAL QUARANTINE" : "STATUS: NOMINAL"}
            </span>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
