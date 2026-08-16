import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Incident } from '../types';
import { 
  X, 
  Pin, 
  Trash2, 
  Bell, 
  Search, 
  Sparkles,
  ChevronDown,
  ChevronUp,
  Inbox
} from 'lucide-react';

interface NotificationDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  incidents: Incident[];
  pinnedAlertIds: string[];
  onTogglePin: (id: string) => void;
  onClearAllHistorical: () => void;
}

export const NotificationDrawer: React.FC<NotificationDrawerProps> = ({
  isOpen,
  onClose,
  incidents,
  pinnedAlertIds,
  onTogglePin,
  onClearAllHistorical,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'critical' | 'pinned'>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Esc key closes drawer
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Handle body scroll locking when drawer is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  // Aggregate historical critical and high severity incidents
  const historicalAlerts = incidents.filter(
    (inc) => inc.severity === 'critical' || inc.severity === 'high'
  );

  // Filter alerts based on selection and search
  const filteredAlerts = historicalAlerts.filter((alert) => {
    const matchesSearch =
      alert.sourceIp.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.category.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.targetService.toLowerCase().includes(searchTerm.toLowerCase());

    if (!matchesSearch) return false;

    if (filterType === 'critical') {
      return alert.severity === 'critical';
    }
    if (filterType === 'pinned') {
      return pinnedAlertIds.includes(alert.id);
    }
    return true;
  });

  const handlePinClick = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    onTogglePin(id);
  };

  const getSeverityColor = (sev: string) => {
    if (sev === 'critical') return 'text-red-400 border-red-500/30 bg-red-950/40';
    return 'text-amber-400 border-amber-500/30 bg-amber-950/40';
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'blocked':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
      case 'resolved':
        return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
      default:
        return 'text-slate-400 bg-slate-500/10 border-slate-800';
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop Blur Overlay */}
          <motion.div
            id="notification-drawer-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-slate-950/70 backdrop-blur-md z-50 transition-opacity"
          />

          {/* Sliding Drawer Container */}
          <motion.div
            id="notification-drawer-sidebar"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 26, stiffness: 220 }}
            className="fixed top-0 right-0 h-full w-full max-w-md bg-white/98 dark:bg-[#040812]/95 border-l border-slate-200 dark:border-slate-800/80 shadow-2xl dark:shadow-[0_0_50px_rgba(0,0,0,0.8)] z-50 flex flex-col font-sans"
          >
            {/* Glowing neon top accents */}
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-sky-500 via-indigo-500 to-rose-500" />

            {/* Drawer Header */}
            <div className="p-5 border-b border-slate-200 dark:border-slate-900 flex justify-between items-center bg-slate-50 dark:bg-[#050b18]/80 mt-[2px]">
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Bell className="w-5 h-5 text-sky-600 dark:text-cyan-400 animate-pulse" />
                  {pinnedAlertIds.length > 0 && (
                    <span className="absolute -top-1.5 -right-1.5 bg-sky-500 dark:bg-cyan-500 text-white dark:text-slate-950 text-[9px] font-extrabold w-4 h-4 rounded-full flex items-center justify-center border border-white dark:border-[#040812]">
                      {pinnedAlertIds.length}
                    </span>
                  )}
                </div>
                <div>
                  <h3 className="font-bold text-slate-900 dark:text-white font-mono text-sm tracking-wide">INCIDENT COMMUNICATOR</h3>
                  <p className="text-[9px] text-slate-500 font-mono uppercase tracking-widest mt-0.5">Historical Alert Ledger</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3">
                {historicalAlerts.length > 0 && (
                  <button
                    onClick={onClearAllHistorical}
                    title="Clear database logs"
                    className="p-1.5 hover:bg-rose-500/10 border border-transparent hover:border-rose-500/20 text-slate-400 hover:text-rose-500 rounded-lg transition duration-200 cursor-pointer"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
                <button
                  onClick={onClose}
                  className="p-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white rounded-lg transition duration-200 font-mono text-xs flex items-center gap-1 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                  <span>ESC</span>
                </button>
              </div>
            </div>

            {/* Quick Stats Banner */}
            <div className="px-5 py-3.5 bg-slate-100/60 dark:bg-slate-950/60 border-b border-slate-200 dark:border-slate-900 grid grid-cols-3 gap-2 text-center text-xs font-mono">
              <div className="border-r border-slate-200 dark:border-slate-900/60 pr-2">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Historical</span>
                <span className="text-slate-900 dark:text-white font-extrabold text-sm mt-0.5 block">{historicalAlerts.length}</span>
              </div>
              <div className="border-r border-slate-200 dark:border-slate-900/60 px-2">
                <span className="text-[10px] text-rose-600 dark:text-rose-500 uppercase tracking-wider block">Critical</span>
                <span className="text-rose-600 dark:text-rose-400 font-extrabold text-sm mt-0.5 block">
                  {historicalAlerts.filter(a => a.severity === 'critical').length}
                </span>
              </div>
              <div className="pl-2">
                <span className="text-[10px] text-sky-600 dark:text-cyan-400 uppercase tracking-wider block">Pinned</span>
                <span className="text-sky-700 dark:text-cyan-300 font-extrabold text-sm mt-0.5 block">{pinnedAlertIds.length}</span>
              </div>
            </div>

            {/* Filters and Search Bar */}
            <div className="p-4 bg-slate-50 dark:bg-[#050b18]/40 border-b border-slate-200 dark:border-slate-900 space-y-3">
              {/* Search */}
              <div className="relative">
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-400 dark:text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter by IP, type, target..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-white dark:bg-slate-950/80 text-xs pl-9 pr-3 py-2 border border-slate-200 dark:border-slate-850 rounded-lg focus:outline-none focus:border-sky-500/80 text-slate-900 dark:text-white font-mono placeholder-slate-400 dark:placeholder-slate-500 transition"
                />
              </div>

              {/* Filter Tabs */}
              <div className="flex bg-slate-100 dark:bg-slate-950/80 p-0.5 border border-slate-200 dark:border-slate-900 rounded-lg text-[10px] font-mono font-bold uppercase">
                <button
                  onClick={() => setFilterType('all')}
                  className={`flex-1 py-1.5 rounded-md text-center transition cursor-pointer ${
                    filterType === 'all'
                      ? 'bg-sky-500/10 text-sky-700 dark:text-cyan-400 border border-sky-500/20'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  All ({historicalAlerts.length})
                </button>
                <button
                  onClick={() => setFilterType('critical')}
                  className={`flex-1 py-1.5 rounded-md text-center transition cursor-pointer ${
                    filterType === 'critical'
                      ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Critical ({historicalAlerts.filter((a) => a.severity === 'critical').length})
                </button>
                <button
                  onClick={() => setFilterType('pinned')}
                  className={`flex-1 py-1.5 rounded-md text-center transition cursor-pointer flex items-center justify-center gap-1 ${
                    filterType === 'pinned'
                      ? 'bg-sky-500/10 text-sky-700 dark:text-cyan-400 border border-sky-500/20'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <Pin className="w-2.5 h-2.5" />
                  Pinned ({pinnedAlertIds.length})
                </button>
              </div>
            </div>

            {/* List of aggregated historical alerts */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
              {filteredAlerts.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-center py-12 text-slate-500 space-y-3">
                  <div className="p-3 bg-slate-950 rounded-full border border-slate-900">
                    <Inbox className="w-6 h-6 text-slate-600" />
                  </div>
                  <div>
                    <p className="font-mono text-xs font-bold text-slate-400">Ledger Buffer Clean</p>
                    <p className="text-[10px] text-slate-500 font-mono mt-1 max-w-[200px]">
                      No alerts match the current filter or search criteria.
                    </p>
                  </div>
                </div>
              ) : (
                <AnimatePresence initial={false}>
                  {filteredAlerts.map((alert) => {
                    const isPinned = pinnedAlertIds.includes(alert.id);
                    const isExpanded = expandedId === alert.id;
                    const timeString = new Date(alert.timestamp).toLocaleTimeString('en-US', {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                      hour12: false,
                    });

                    return (
                      <motion.div
                        key={alert.id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95 }}
                        transition={{ duration: 0.2 }}
                        className={`bg-slate-50 dark:bg-[#050b18]/60 hover:bg-slate-100 dark:hover:bg-[#070e22]/80 border ${
                          isPinned 
                            ? 'border-sky-500/40 dark:border-cyan-500/30 bg-sky-50/50 dark:bg-cyan-950/5 shadow-xs' 
                            : 'border-slate-200 dark:border-slate-900 hover:border-slate-300 dark:hover:border-slate-800'
                        } rounded-xl p-3.5 transition-all duration-300 relative group overflow-hidden cursor-pointer flex flex-col justify-between`}
                        onClick={() => setExpandedId(isExpanded ? null : alert.id)}
                      >
                        {/* Pinned left border */}
                        {isPinned && (
                          <div className="absolute top-0 bottom-0 left-0 w-1 bg-sky-500 dark:bg-cyan-400" />
                        )}

                        <div className="flex justify-between items-start gap-2">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded border text-[9px] font-bold uppercase tracking-wider ${getSeverityColor(alert.severity)}`}>
                              {alert.severity}
                            </span>
                            <span className="text-slate-500 font-mono text-[10px]">{timeString}</span>
                          </div>

                          <div className="flex items-center gap-1.5">
                            <button
                              onClick={(e) => handlePinClick(alert.id, e)}
                              className={`p-1.5 rounded-md border transition cursor-pointer ${
                                isPinned
                                  ? 'bg-sky-500/15 border-sky-500/30 text-sky-700 dark:text-cyan-400 hover:bg-sky-500/25'
                                  : 'bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-900 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 hover:border-slate-300 dark:hover:border-slate-800'
                              }`}
                              title={isPinned ? 'Unpin Event' : 'Pin Event'}
                            >
                              <Pin className={`w-3 h-3 ${isPinned ? 'fill-current' : ''}`} />
                            </button>
                            {isExpanded ? (
                              <ChevronUp className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
                            ) : (
                              <ChevronDown className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
                            )}
                          </div>
                        </div>

                        {/* Event Category & IP */}
                        <div className="mt-2 flex items-center justify-between font-mono">
                          <div className="text-xs text-slate-900 dark:text-white font-bold tracking-tight">
                            {alert.category}
                          </div>
                          <div className="text-[10px] text-slate-700 dark:text-slate-300 font-bold bg-slate-100 dark:bg-slate-950/80 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-900">
                            {alert.sourceIp}
                          </div>
                        </div>

                        {/* Collapsible details section */}
                        <AnimatePresence>
                          {isExpanded && (
                            <motion.div
                              initial={{ height: 0, opacity: 0, marginTop: 0 }}
                              animate={{ height: 'auto', opacity: 1, marginTop: 12 }}
                              exit={{ height: 0, opacity: 0, marginTop: 0 }}
                              transition={{ duration: 0.2 }}
                              className="overflow-hidden border-t border-slate-200 dark:border-slate-900/60 pt-3 space-y-2.5"
                            >
                              <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                                <div>
                                  <span className="text-slate-500 block uppercase text-[8px] tracking-wider">Alert ID</span>
                                  <span className="text-slate-700 dark:text-slate-300">{alert.id}</span>
                                </div>
                                <div>
                                  <span className="text-slate-500 block uppercase text-[8px] tracking-wider">Status</span>
                                  <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase inline-block border ${getStatusColor(alert.status)}`}>
                                    {alert.status}
                                  </span>
                                </div>
                              </div>

                              <div className="text-[10px] font-mono">
                                <span className="text-slate-500 block uppercase text-[8px] tracking-wider">Target Resource</span>
                                <span className="text-sky-600 dark:text-cyan-400 break-all">{alert.targetService}</span>
                              </div>

                              {alert.payload && (
                                <div className="p-2.5 bg-slate-950 border border-slate-900 rounded-lg text-[9px] font-mono">
                                  <span className="text-rose-400 block uppercase text-[8px] font-bold tracking-wider mb-1">Decrypted Payload</span>
                                  <code className="text-slate-300 break-all leading-normal block whitespace-pre-wrap">
                                    {alert.payload}
                                  </code>
                                </div>
                              )}
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    );
                  })}
                </AnimatePresence>
              )}
            </div>

            {/* Clear and Info footer */}
            <div className="p-4 border-t border-slate-200 dark:border-slate-900 bg-slate-50 dark:bg-slate-950/60 text-[10px] text-slate-500 font-mono flex justify-between items-center">
              <span>Historical record cap: 40 entries</span>
              <span className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
                <Sparkles className="w-3.5 h-3.5 text-sky-500 dark:text-cyan-400" />
                Crypto Secure Audit Log
              </span>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};
