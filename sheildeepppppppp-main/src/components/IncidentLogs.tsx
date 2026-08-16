import React, { useState, useEffect, useRef } from 'react';
import { Incident } from '../types';
import { Search, ShieldAlert, Eye, CheckCircle2, ShieldOff, Clock, ArrowUpDown, Play, FileCode, Copy, Check } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { ExploitReplayModal } from './ExploitReplayModal';

interface IncidentLogsProps {
  incidents: Incident[];
  onBlockIp: (ip: string, category: string) => void;
  onResolveIncident: (id: string) => void;
}

const TypewriterCode: React.FC<{ text: string }> = ({ text }) => {
  const [displayText, setDisplayText] = useState('');
  
  useEffect(() => {
    let index = 0;
    setDisplayText('');
    
    const interval = setInterval(() => {
      setDisplayText((prev) => prev + text.charAt(index));
      index++;
      if (index >= text.length) {
        clearInterval(interval);
      }
    }, 12);
    
    return () => clearInterval(interval);
  }, [text]);

  return (
    <span className="relative">
      {displayText}
      <span className="inline-block w-1.5 h-3.5 bg-sky-400 ml-1 animate-pulse" />
    </span>
  );
};

export const IncidentLogs: React.FC<IncidentLogsProps> = ({
  incidents,
  onBlockIp,
  onResolveIncident
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [replayIncident, setReplayIncident] = useState<Incident | null>(null);
  const [wafIncident, setWafIncident] = useState<Incident | null>(null);
  const [copiedWaf, setCopiedWaf] = useState<string | null>(null);
  
  const [autoScroll, setAutoScroll] = useState(true);
  const [shouldShake, setShouldShake] = useState(false);
  const [lastIncidentId, setLastIncidentId] = useState('');
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (incidents.length > 0) {
      const latest = incidents[0];
      if (latest.id !== lastIncidentId) {
        setLastIncidentId(latest.id);
        if (latest.severity === 'critical') {
          setShouldShake(true);
          const timer = setTimeout(() => setShouldShake(false), 500);
          return () => clearTimeout(timer);
        }
      }
    }
  }, [incidents, lastIncidentId]);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    }
  }, [incidents, autoScroll]);

  const getSeverityBadge = (severity: Incident['severity']) => {
    switch (severity) {
      case 'critical':
        return 'bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/30';
      case 'high':
        return 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30';
      case 'medium':
        return 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-300 border-yellow-500/30';
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700';
    }
  };

  const getStatusLabel = (status: Incident['status']) => {
    switch (status) {
      case 'blocked':
        return 'CONTAINED / DROPPED';
      case 'resolved':
        return 'RESOLVED';
      case 'active':
        return 'ACTIVE INTRUSION';
      default:
        return status ? status.toUpperCase() : 'UNKNOWN';
    }
  };

  const getStatusBadge = (status: Incident['status']) => {
    switch (status) {
      case 'blocked':
        return 'bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/30';
      case 'resolved':
        return 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700';
      case 'active':
        return 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30';
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700';
    }
  };

  const filteredIncidents = incidents.filter((inc) => {
    const q = searchTerm.toLowerCase();
    const matchesSearch =
      inc.sourceIp.toLowerCase().includes(q) ||
      inc.targetService.toLowerCase().includes(q) ||
      inc.id.toLowerCase().includes(q) ||
      inc.category.toLowerCase().includes(q) ||
      (inc.payload && inc.payload.toLowerCase().includes(q));

    const matchesSeverity = selectedSeverity === 'all' || inc.severity === selectedSeverity;

    return matchesSearch && matchesSeverity;
  });

  return (
    <motion.div
      id="incident-logs-card"
      animate={shouldShake ? { x: [-8, 8, -6, 6, -4, 4, -2, 2, 0], borderColor: '#f43f5e' } : {}}
      transition={{ duration: 0.5 }}
      className={`bg-white dark:bg-slate-900/60 border ${
        shouldShake ? 'border-rose-500 shadow-[0_0_25px_rgba(244,63,94,0.25)]' : 'border-slate-200 dark:border-slate-800'
      } rounded-2xl p-6 shadow-xs dark:shadow-xl flex flex-col h-full min-h-[480px] relative z-10 transition-colors duration-300`}
    >
      {/* Panel Header with Glowing Threat Pulse */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 bg-sky-500/10 border border-sky-500/25 dark:border-sky-500/30 rounded-xl text-sky-600 dark:text-sky-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wide font-sans">Active Incidents Ledger</h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-sans">
            Real-time perimeter firewall audit trail and decrypted intrusion telemetry
          </p>
        </div>

        {/* Severity Filter Badges & Auto-scroll Toggle */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-2.5 py-1 text-xs font-mono rounded-lg transition border cursor-pointer ${
              autoScroll
                ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30 font-bold'
                : 'bg-slate-100 dark:bg-slate-950 text-slate-500 border-slate-200 dark:border-slate-800'
            }`}
            title="Auto-scroll to latest incident"
          >
            {autoScroll ? '● AUTO-SCROLL ON' : '○ AUTO-SCROLL OFF'}
          </button>

          <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 p-1 rounded-xl">
            {/* ALL */}
            <button
              onClick={() => setSelectedSeverity('all')}
              className={`px-2.5 py-1 text-xs font-mono rounded-lg transition uppercase cursor-pointer font-bold ${
                selectedSeverity === 'all'
                  ? 'bg-sky-600 text-white dark:text-slate-950 shadow-xs font-bold'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              ALL
            </button>

            {/* CRITICAL */}
            <button
              onClick={() => setSelectedSeverity('critical')}
              className={`px-2.5 py-1 text-xs font-mono rounded-lg transition uppercase cursor-pointer font-bold flex items-center gap-1.5 border ${
                selectedSeverity === 'critical'
                  ? 'bg-rose-500 text-white border-rose-400 shadow-xs'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-300 hover:bg-rose-500/20'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
              CRITICAL
            </button>

            {/* HIGH */}
            <button
              onClick={() => setSelectedSeverity('high')}
              className={`px-2.5 py-1 text-xs font-mono rounded-lg transition uppercase cursor-pointer font-bold flex items-center gap-1.5 border ${
                selectedSeverity === 'high'
                  ? 'bg-amber-500 text-white dark:text-slate-950 border-amber-400 shadow-xs'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-700 dark:text-amber-300 hover:bg-amber-500/20'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              HIGH
            </button>

            {/* MEDIUM */}
            <button
              onClick={() => setSelectedSeverity('medium')}
              className={`px-2.5 py-1 text-xs font-mono rounded-lg transition uppercase cursor-pointer font-bold flex items-center gap-1.5 border ${
                selectedSeverity === 'medium'
                  ? 'bg-yellow-400 text-slate-950 border-yellow-300 shadow-xs'
                  : 'bg-yellow-500/10 border-yellow-500/30 text-yellow-700 dark:text-yellow-300 hover:bg-yellow-500/20'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-yellow-400" />
              MEDIUM
            </button>
          </div>
        </div>
      </div>

      {/* Search Input Bar */}
      <div className="relative mb-4">
        <Search className="absolute left-3.5 top-3 w-4 h-4 text-slate-400 dark:text-slate-500" />
        <input
          id="search-incidents"
          type="text"
          placeholder="Filter events by IP, Target Service, Incident ID, Vector Category, or Payload..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full bg-slate-50 dark:bg-slate-950 text-xs pl-10 pr-4 py-2.5 border border-slate-200 dark:border-slate-800 rounded-xl focus:outline-none focus:border-sky-500/60 focus:ring-1 focus:ring-sky-500/30 text-slate-900 dark:text-slate-100 font-mono placeholder:text-slate-400 dark:placeholder:text-slate-500 transition"
        />
      </div>

      {/* Incidents Table / List */}
      <div 
        ref={containerRef}
        className="flex-1 overflow-y-auto max-h-[360px] border border-slate-200 dark:border-slate-800 rounded-xl bg-slate-50/50 dark:bg-slate-950"
      >
        {filteredIncidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full py-16 text-slate-400 dark:text-slate-500">
            <CheckCircle2 className="w-10 h-10 text-emerald-500 dark:text-emerald-400 mb-2" />
            <p className="text-sm font-mono font-bold text-slate-700 dark:text-slate-300">Perimeter Nominal</p>
            <p className="text-xs font-mono text-slate-500 mt-0.5">No active threat vectors matching current filter parameters</p>
          </div>
        ) : (
          <div className="min-w-full divide-y divide-slate-200 dark:divide-slate-800/80 hidden md:block">
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr className="bg-slate-100/90 dark:bg-slate-900/90 text-[10px] uppercase tracking-wider text-slate-600 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 font-bold sticky top-0 z-10 backdrop-blur-md">
                  <th className="px-4 py-3">Timestamp / ID</th>
                  <th className="px-4 py-3">Source IP</th>
                  <th className="px-4 py-3">Attack Category</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Target Service</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800/80 text-xs font-mono">
                <AnimatePresence initial={false}>
                  {filteredIncidents.map((inc) => {
                    const isNew = Date.now() - new Date(inc.timestamp).getTime() < 8000;
                    return (
                      <motion.tr
                        key={inc.id}
                        initial={{ opacity: 0, y: -12, backgroundColor: isNew ? 'rgba(244, 63, 94, 0.15)' : 'rgba(0, 0, 0, 0)' }}
                        animate={{ opacity: 1, y: 0, backgroundColor: 'rgba(0, 0, 0, 0)' }}
                        exit={{ opacity: 0, scale: 0.95 }}
                        transition={{ type: 'spring', stiffness: 350, damping: 25 }}
                        className={`hover:bg-slate-100/80 dark:hover:bg-slate-900/70 transition-colors group relative ${
                          isNew ? 'border-l-4 border-l-rose-500 bg-rose-500/5' : ''
                        }`}
                      >
                        <td className="px-4 py-3.5">
                          <div className="text-slate-800 dark:text-slate-200 font-semibold flex items-center gap-1.5">
                            <Clock className={`w-3.5 h-3.5 ${isNew ? 'text-rose-500 animate-pulse' : 'text-slate-400 dark:text-slate-500'}`} />
                            {new Date(inc.timestamp).toLocaleTimeString()}
                          </div>
                          <span className="text-[10px] text-slate-400 dark:text-slate-500 block mt-0.5">{inc.id}</span>
                        </td>
                        <td className="px-4 py-3.5 text-slate-900 dark:text-slate-100 font-bold">
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-600 dark:text-slate-400 text-[10px] bg-slate-100 dark:bg-slate-900 px-1.5 py-0.5 rounded uppercase border border-slate-200 dark:border-slate-800">
                              {inc.countryCode}
                            </span>
                            <span className="text-sky-600 dark:text-sky-300 font-bold">{inc.sourceIp}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3.5 text-slate-700 dark:text-slate-300 font-medium">
                          {inc.category}
                        </td>
                        <td className="px-4 py-3.5">
                          <span className={`px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase ${getSeverityBadge(inc.severity)}`}>
                            {inc.severity}
                          </span>
                        </td>
                        <td className="px-4 py-3.5 text-slate-600 dark:text-slate-400 truncate max-w-[140px]" title={inc.targetService}>
                          {inc.targetService}
                        </td>
                        <td className="px-4 py-3.5">
                          <span className={`px-2 py-0.5 rounded-md border text-[10px] font-semibold uppercase ${getStatusBadge(inc.status)}`}>
                            {getStatusLabel(inc.status)}
                          </span>
                        </td>
                        <td className="px-4 py-3.5 text-right">
                          <div className="flex items-center justify-end gap-1.5 opacity-80 group-hover:opacity-100 transition">
                            <button
                              onClick={() => setSelectedIncident(inc)}
                              className="p-1.5 bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 rounded-lg text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white cursor-pointer transition"
                              title="Inspect payload"
                            >
                              <Eye className="w-3.5 h-3.5 text-sky-500 dark:text-sky-400" />
                            </button>
                            {inc.status === 'active' && (
                              <>
                                <button
                                  onClick={() => onResolveIncident(inc.id)}
                                  className="p-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 rounded-lg text-emerald-600 dark:text-emerald-400 cursor-pointer transition"
                                  title="Resolve alert"
                                >
                                  <CheckCircle2 className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  onClick={() => onBlockIp(inc.sourceIp, inc.category)}
                                  className="p-1.5 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 rounded-lg text-rose-600 dark:text-rose-400 cursor-pointer transition"
                                  title="Block Source IP"
                                >
                                  <ShieldOff className="w-3.5 h-3.5" />
                                </button>
                              </>
                            )}
                            {/* WAF Patch Generator button */}
                            <button
                              onClick={() => setWafIncident(inc)}
                              className="p-1.5 bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 rounded-lg text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white cursor-pointer transition"
                              title="Generate WAF Patch"
                            >
                              <FileCode className="w-3.5 h-3.5 text-sky-500 dark:text-sky-400" />
                            </button>
                          </div>
                        </td>
                      </motion.tr>
                    );
                  })}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        )}

        {/* Mobile View */}
        <div className="md:hidden divide-y divide-slate-200 dark:divide-slate-800/80">
          <AnimatePresence initial={false}>
            {filteredIncidents.map((inc) => (
              <motion.div
                key={inc.id}
                initial={{ opacity: 0, x: -15 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, scale: 0.9 }}
                className="p-4 flex flex-col gap-3 hover:bg-slate-100/80 dark:hover:bg-slate-900/60"
              >
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">{inc.id}</span>
                    <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-100 font-mono mt-0.5">{inc.sourceIp} ({inc.countryCode})</h4>
                  </div>
                  <span className={`px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase ${getSeverityBadge(inc.severity)}`}>
                    {inc.severity}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs font-mono text-slate-600 dark:text-slate-400">
                  <div>
                    <span className="text-[10px] text-slate-400 dark:text-slate-500 block">Category</span>
                    <span className="text-slate-800 dark:text-slate-200">
                      {inc.category}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 dark:text-slate-500 block">Status</span>
                    <span className={`inline-block mt-0.5 px-2 py-0.5 rounded-md border text-[9px] uppercase ${getStatusBadge(inc.status)}`}>
                      {getStatusLabel(inc.status)}
                    </span>
                  </div>
                </div>

                <div className="flex gap-2 justify-end pt-2 border-t border-slate-200 dark:border-slate-800">
                  <button
                    onClick={() => setSelectedIncident(inc)}
                    className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 cursor-pointer"
                  >
                    <Eye className="w-3 h-3 text-sky-500 dark:text-sky-400" />
                    Inspect
                  </button>
                  {inc.status === 'active' && (
                    <>
                      <button
                        onClick={() => onResolveIncident(inc.id)}
                        className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono bg-emerald-500/10 hover:bg-emerald-500/20 rounded-lg border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 cursor-pointer"
                      >
                        <CheckCircle2 className="w-3 h-3" />
                        Resolve
                      </button>
                      <button
                        onClick={() => onBlockIp(inc.sourceIp, inc.category)}
                        className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono bg-rose-500/10 hover:bg-rose-500/20 rounded-lg border border-rose-500/30 text-rose-600 dark:text-rose-400 cursor-pointer"
                      >
                        <ShieldOff className="w-3 h-3" />
                        Block
                      </button>
                    </>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </div>

      {/* Inspector Modal */}
      <AnimatePresence>
        {selectedIncident && (
          <div className="fixed inset-0 bg-slate-950/70 backdrop-blur-md flex items-center justify-center z-50 p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              transition={{ type: 'spring', stiffness: 380, damping: 25 }}
              className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-2xl max-w-lg w-full overflow-hidden shadow-2xl relative font-mono"
            >
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-slate-900/80">
                <div className="flex items-center gap-2.5">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block"></span>
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block"></span>
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"></span>
                  </div>
                  <h3 className="font-bold text-slate-900 dark:text-slate-100 text-xs ml-2 uppercase">RAW PAYLOAD INSPECTOR</h3>
                </div>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white text-xs border border-slate-200 dark:border-slate-800 px-2 py-1 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer"
                >
                  ESC
                </button>
              </div>
              
              <div className="p-5 space-y-4 text-xs">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Incident ID</span>
                    <span className="text-slate-800 dark:text-slate-200 font-semibold">{selectedIncident.id}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Timestamp</span>
                    <span className="text-slate-800 dark:text-slate-200">{new Date(selectedIncident.timestamp).toLocaleString()}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Source IP</span>
                    <span className="text-sky-600 dark:text-sky-300 font-bold">{selectedIncident.sourceIp} ({selectedIncident.countryCode})</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Target Service</span>
                    <span className="text-slate-800 dark:text-slate-200">{selectedIncident.targetService}</span>
                  </div>
                </div>

                <div className="p-4 bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-xl min-h-[100px] flex flex-col justify-between">
                  <div>
                    <span className="text-slate-500 text-[10px] block uppercase mb-1.5 border-b border-slate-200 dark:border-slate-800 pb-1 font-bold">Decrypted Payload Trace</span>
                    <code className="text-rose-600 dark:text-rose-400 text-xs break-all whitespace-pre-wrap leading-relaxed block">
                      <TypewriterCode text={selectedIncident.payload || 'No payload header provided.'} />
                    </code>
                  </div>
                </div>

                <div className="flex gap-2 justify-end">
                  <button
                    onClick={() => {
                      setReplayIncident(selectedIncident);
                      setSelectedIncident(null);
                    }}
                    className="px-4 py-2 bg-sky-600 hover:bg-sky-500 border border-sky-500 text-white dark:text-slate-950 text-xs font-bold rounded-xl cursor-pointer transition flex items-center gap-1.5 shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    REPLAY 5-GATE VECTOR
                  </button>
                  {selectedIncident.status === 'active' && (
                    <button
                      onClick={() => {
                        onBlockIp(selectedIncident.sourceIp, selectedIncident.category);
                        setSelectedIncident(null);
                      }}
                      className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold rounded-xl cursor-pointer transition"
                    >
                      Block Connection
                    </button>
                  )}
                  <button
                    onClick={() => setSelectedIncident(null)}
                    className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 text-xs rounded-xl cursor-pointer transition"
                  >
                    Close
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Exploit Vector Replay Modal */}
      {replayIncident && (
        <ExploitReplayModal
          incident={replayIncident}
          onClose={() => setReplayIncident(null)}
        />
      )}

      {/* WAF Patch Generator Modal */}
      <AnimatePresence>
        {wafIncident && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-sm p-4"
            onClick={() => { setWafIncident(null); setCopiedWaf(null); }}>
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              onClick={e => e.stopPropagation()}
              className="w-full max-w-2xl bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-2xl max-h-[80vh] overflow-y-auto font-mono"
            >
              <div className="flex items-center justify-between mb-4 pb-2 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-sky-500 dark:text-sky-400" />
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">1-Click WAF Patch Generator</h3>
                </div>
                <button onClick={() => { setWafIncident(null); setCopiedWaf(null); }}
                  className="text-slate-400 hover:text-slate-900 dark:hover:text-white cursor-pointer text-lg">×</button>
              </div>
              <p className="text-[10px] text-slate-500 mb-4">
                Incident: {wafIncident.id} • {wafIncident.sourceIp} • {wafIncident.category}
              </p>

              {(() => {
                const ip = wafIncident.sourceIp;
                const cat = wafIncident.category;
                const cloudflareRule = `(ip.src eq ${ip}) or (http.request.uri.query contains "${cat.toLowerCase().replace(/\s/g, '_')}_sig")`;
                const awsWafRule = JSON.stringify({
                  Name: `DEEPSHIELD-Block-${wafIncident.id}`,
                  Priority: 1,
                  Action: { Block: {} },
                  Statement: {
                    OrStatement: {
                      Statements: [
                        { IPSetReferenceStatement: { ARN: `arn:aws:wafv2:*:*:ipset/blocked-${ip.replace(/\./g, '-')}` } },
                        { ByteMatchStatement: { FieldToMatch: { UriPath: {} }, TextTransformations: [{ Priority: 0, Type: "NONE" }], PositionalConstraint: "CONTAINS", SearchString: cat.toLowerCase() } }
                      ]
                    }
                  },
                  VisibilityConfig: { SampledRequestsEnabled: true, CloudWatchMetricsEnabled: true, MetricName: `DeepShield-${wafIncident.id}` }
                }, null, 2);
                const nginxRule = `# DEEPSHIELD Auto-Generated Block Rule — ${wafIncident.id}\n# Category: ${cat} | Source: ${ip}\n# Generated: ${new Date().toISOString()}\ndeny ${ip};\n\n# Optional: block by pattern\nlocation ~* "(${cat.toLowerCase().replace(/\s/g, '|')})" {\n  return 403;\n}`;

                const rules = [
                  { id: 'cloudflare', label: 'Cloudflare WAF Expression', code: cloudflareRule },
                  { id: 'aws', label: 'AWS WAF JSON Rule', code: awsWafRule },
                  { id: 'nginx', label: 'Nginx Deny Block', code: nginxRule },
                ];

                const copyToClipboard = (id: string, text: string) => {
                  navigator.clipboard.writeText(text);
                  setCopiedWaf(id);
                  setTimeout(() => setCopiedWaf(null), 2000);
                };

                return (
                  <div className="space-y-4">
                    {rules.map(rule => (
                      <div key={rule.id} className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                        <div className="flex items-center justify-between px-4 py-2 border-b border-slate-200 dark:border-slate-800/80 bg-slate-100/80 dark:bg-slate-950/60">
                          <span className="text-[11px] font-semibold text-slate-800 dark:text-slate-300">{rule.label}</span>
                          <button onClick={() => copyToClipboard(rule.id, rule.code)}
                            className="flex items-center gap-1 px-2.5 py-1 text-[10px] font-mono bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/30 rounded-lg hover:bg-sky-500/20 cursor-pointer transition">
                            {copiedWaf === rule.id ? <><Check className="w-3 h-3 text-emerald-500" /> Copied</> : <><Copy className="w-3 h-3" /> Copy</>}
                          </button>
                        </div>
                        <pre className="px-4 py-3 text-[11px] font-mono text-slate-700 dark:text-slate-400 overflow-x-auto whitespace-pre-wrap">{rule.code}</pre>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};
