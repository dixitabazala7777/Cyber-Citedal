import React, { useEffect, useRef, useState, useCallback } from 'react';
import { HoneypotEvent } from '../types/honeypot';
import {
  Terminal,
  ShieldX,
  Clipboard,
  Search,
  ArrowDown,
  Trash2,
  Clock,
  Filter,
  Check,
  Pause,
  Play
} from 'lucide-react';

interface LiveTerminalFeedProps {
  events: HoneypotEvent[];
  onClear: () => void;
  onBlockIp: (ip: string, reason: string) => void;
  className?: string;
}

export const LiveTerminalFeed: React.FC<LiveTerminalFeedProps> = ({
  events,
  onClear,
  onBlockIp,
  className = ''
}) => {
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO'>('ALL');
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [showTimestamps, setShowTimestamps] = useState<boolean>(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isHovered, setIsHovered] = useState<boolean>(false);
  const [isScrolledUp, setIsScrolledUp] = useState<boolean>(false);

  const feedContainerRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = useCallback((smooth = false) => {
    if (feedContainerRef.current) {
      if (smooth) {
        feedContainerRef.current.scrollTo({
          top: feedContainerRef.current.scrollHeight,
          behavior: 'smooth'
        });
      } else {
        feedContainerRef.current.scrollTop = feedContainerRef.current.scrollHeight;
      }
      setIsScrolledUp(false);
    }
  }, []);

  useEffect(() => {
    if (autoScroll && !isHovered && !isScrolledUp && feedContainerRef.current) {
      feedContainerRef.current.scrollTop = feedContainerRef.current.scrollHeight;
    }
  }, [events, autoScroll, isHovered, isScrolledUp]);

  const handleScroll = () => {
    if (!feedContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = feedContainerRef.current;
    const distanceToBottom = scrollHeight - scrollTop - clientHeight;
    setIsScrolledUp(distanceToBottom > 40);
  };

  const handleCopyJson = (evt: HoneypotEvent) => {
    navigator.clipboard.writeText(JSON.stringify(evt, null, 2));
    setCopiedId(evt.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredEvents = events.filter(e => {
    if (severityFilter !== 'ALL' && e.severity !== severityFilter) {
      return false;
    }
    const searchStr = `${e.attackerIp} ${e.service} ${e.message} ${e.severity} ${e.targetPort}`.toLowerCase();
    return searchStr.includes(filter.toLowerCase());
  });

  // Black & White / High-Contrast Professional Monochrome Severity Typography
  const getSeverityStyle = (severity: HoneypotEvent['severity']) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-white text-black font-black border border-white px-2 py-0.5 rounded uppercase tracking-widest text-[9px] select-none shadow-xs';
      case 'HIGH':
        return 'bg-zinc-200 text-zinc-950 font-extrabold border border-zinc-300 px-2 py-0.5 rounded uppercase tracking-wider text-[9px] select-none';
      case 'MEDIUM':
        return 'bg-zinc-800 text-zinc-200 font-bold border border-zinc-600 px-2 py-0.5 rounded uppercase tracking-wider text-[9px] select-none';
      default:
        return 'bg-zinc-900 text-zinc-400 font-semibold border border-zinc-800 px-2 py-0.5 rounded uppercase tracking-wider text-[9px] select-none';
    }
  };

  // Black & White / Monochrome Service Badge
  const getServiceStyle = (_service: HoneypotEvent['service']) => {
    return 'text-zinc-200 border-zinc-700 bg-zinc-900/90 font-mono font-bold';
  };

  return (
    <div
      className={`bg-black/95 backdrop-blur-xl border border-zinc-800 ring-1 ring-white/10 rounded-2xl overflow-hidden flex flex-col h-[480px] md:h-[520px] max-h-[560px] shadow-2xl relative font-mono ${className}`}
    >
      {/* Monochrome Terminal Header Bar */}
      <div className="px-4 py-3 bg-zinc-950 border-b border-zinc-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-zinc-600 inline-block border border-zinc-500"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-zinc-700 inline-block border border-zinc-600"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-zinc-800 inline-block border border-zinc-700"></span>
          </div>
          <div className="flex items-center gap-2 ml-2">
            <Terminal className="w-4 h-4 text-white animate-pulse" />
            <span className="text-xs font-mono font-bold tracking-tight text-white uppercase">DECOY TELEMETRY LOGS // RAW STREAM</span>
            <span className="text-[10px] bg-zinc-900 text-zinc-300 border border-zinc-700 px-2 py-0.5 rounded font-mono font-bold">
              {filteredEvents.length} EVENTS
            </span>
          </div>
          {(isHovered || isScrolledUp) && autoScroll && (
            <span className="text-[9px] bg-white text-black border border-white px-2 py-0.5 rounded font-mono font-black flex items-center gap-1">
              <Pause className="w-2.5 h-2.5" /> PAUSED
            </span>
          )}
        </div>

        {/* Filter & Actions */}
        <div className="flex items-center gap-2 w-full sm:w-auto flex-wrap">
          <div className="relative flex-1 sm:w-44">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-400" />
            <input
              type="text"
              placeholder="Search threat metrics..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-2.5 py-1 pl-8 text-xs font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-white transition-all"
            />
          </div>

          {/* Severity Dropdown Filter */}
          <div className="flex items-center gap-1 bg-zinc-900 border border-zinc-700 rounded-lg px-2 py-1">
            <Filter className="w-3 h-3 text-zinc-400" />
            <select
              id="live-terminal-severity-filter"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO')}
              className="bg-transparent text-[10px] font-mono text-zinc-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-zinc-900 text-zinc-200">SEVERITY: ALL</option>
              <option value="CRITICAL" className="bg-zinc-900 text-white font-bold">CRITICAL</option>
              <option value="HIGH" className="bg-zinc-900 text-zinc-300">HIGH</option>
              <option value="MEDIUM" className="bg-zinc-900 text-zinc-400">MEDIUM</option>
              <option value="INFO" className="bg-zinc-900 text-zinc-500">INFO</option>
            </select>
          </div>

          <button
            type="button"
            onClick={() => setShowTimestamps(!showTimestamps)}
            title={showTimestamps ? "Hide Timestamps" : "Show Timestamps"}
            className={`px-2.5 py-1 rounded-lg border text-[10px] font-mono font-bold flex items-center gap-1 transition cursor-pointer ${showTimestamps
              ? 'bg-white text-black border-white'
              : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:text-white'
              }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{showTimestamps ? 'TS ON' : 'TS OFF'}</span>
          </button>

          <button
            type="button"
            onClick={() => {
              const next = !autoScroll;
              setAutoScroll(next);
              if (next) scrollToBottom(true);
            }}
            title={autoScroll ? "Disable Auto-scroll" : "Enable Auto-scroll"}
            className={`p-1.5 rounded-lg border text-[10px] font-mono font-bold flex items-center gap-1 transition cursor-pointer ${autoScroll
              ? 'bg-white text-black border-white'
              : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:text-white'
              }`}
          >
            {autoScroll ? <ArrowDown className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>

          <button
            type="button"
            onClick={onClear}
            title="Clear Stream"
            className="p-1.5 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-400 hover:text-white hover:border-zinc-500 transition cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Terminal Feed Scroll Body */}
      <div
        ref={feedContainerRef}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto font-mono text-xs p-3 space-y-1 select-text bg-black"
      >
        {filteredEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-zinc-500 space-y-2 select-none">
            <Terminal className="w-8 h-8 opacity-40 animate-pulse text-white" />
            <p className="text-xs text-zinc-400">Connecting to decoy telemetry feed socket...</p>
          </div>
        ) : (
          filteredEvents.map((evt) => {
            const isSelected = selectedEventId === evt.id;
            return (
              <div
                key={evt.id}
                className={`group rounded-lg border transition-all duration-150 ${isSelected
                  ? 'bg-zinc-900/90 border-zinc-600 shadow-lg'
                  : 'border-transparent hover:border-zinc-800 hover:bg-zinc-900/50'
                  }`}
              >
                <div
                  onClick={() => setSelectedEventId(isSelected ? null : evt.id)}
                  className="flex flex-wrap items-center gap-2 px-3 py-1.5 cursor-pointer leading-relaxed"
                >
                  {/* Timestamp */}
                  {showTimestamps && (
                    <span className="text-[10px] text-zinc-500 select-none">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </span>
                  )}

                  {/* Severity Badge */}
                  <span className={`text-[9px] ${getSeverityStyle(evt.severity)}`}>
                    {evt.severity}
                  </span>

                  {/* Service Badge */}
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${getServiceStyle(evt.service)}`}>
                    {evt.service}:{evt.targetPort}
                  </span>

                  {/* Attacker IP and Flag */}
                  <span className="text-white font-bold flex items-center gap-1">
                    <span className="text-zinc-500 text-[10px]">SRC:</span> {evt.attackerIp}
                    <span className="text-[9px] text-zinc-300 bg-zinc-900 px-1 py-0.2 rounded border border-zinc-700 uppercase">
                      {evt.attackerCountryCode}
                    </span>
                  </span>

                  {/* Attack Message */}
                  <div className="text-zinc-300 font-mono text-xs truncate max-w-lg md:max-w-md xl:max-w-xl">
                    {evt.message}
                  </div>
                </div>

                {/* Expanded Details Card */}
                {isSelected && (
                  <div className="px-4 pb-4 border-t border-zinc-800 pt-3 bg-zinc-950/80 space-y-3 font-mono text-xs select-text">
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                      <div>
                        <span className="text-[10px] text-zinc-500 block uppercase">ATTACK TIMESTAMP</span>
                        <span className="text-zinc-200 text-[11px]">{new Date(evt.timestamp).toLocaleString()}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-zinc-500 block uppercase">SENSOR SERVICE MODEL</span>
                        <span className="text-white font-bold">{evt.service} Decoy Framework</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-zinc-500 block uppercase">LOCATION SOURCE</span>
                        <span className="text-zinc-200 flex items-center gap-1.5">
                          <img
                            src={`https://flagcdn.com/16x12/${evt.attackerCountryCode.toLowerCase()}.png`}
                            alt={evt.attackerCountry}
                            className="w-4 h-3 rounded grayscale contrast-125"
                          />
                          {evt.attackerCountry} ({evt.attackerCountryCode})
                        </span>
                      </div>
                    </div>

                    {/* Service Specific Payloads in Pure High-Contrast Monospace */}
                    <div className="bg-black border border-zinc-800 rounded-xl p-3 text-[11px] text-zinc-200 relative">
                      <span className="text-[9px] text-zinc-500 block mb-2 border-b border-zinc-800 pb-1 uppercase font-bold">
                        EXPLOITED INTERFACE METADATA
                      </span>

                      {evt.service === 'Cowrie' && (
                        <div className="space-y-1">
                          <div><span className="text-zinc-500">Decoy Credentials:</span> <span className="text-white font-bold">{evt.details.username} / {evt.details.password}</span></div>
                          {evt.details.command && (
                            <div><span className="text-zinc-500">Attempted Commands:</span> <code className="bg-zinc-900 text-white px-1 py-0.5 rounded border border-zinc-700">{evt.details.command}</code></div>
                          )}
                        </div>
                      )}

                      {evt.service === 'Dionaea' && (
                        <div className="space-y-1">
                          <div><span className="text-zinc-500">Target Signature:</span> <span className="text-white font-bold">{evt.details.exploitMethod}</span></div>
                          <div><span className="text-zinc-500">Malware Payload Hash:</span> <code className="text-zinc-300 break-all">{evt.details.payloadHash}</code></div>
                        </div>
                      )}

                      {evt.service === 'ElasticPot' && (
                        <div className="space-y-1">
                          <div><span className="text-zinc-500">HTTP Protocol Request:</span> <span className="text-white font-bold">{evt.details.httpMethod} {evt.details.httpPath}</span></div>
                          <div><span className="text-zinc-500">Server Response Mimic:</span> Apache/2.4.41 with decoy tokens</div>
                        </div>
                      )}

                      {evt.service === 'Conpot' && (
                        <div className="space-y-1">
                          <div><span className="text-zinc-500">Modbus PLC Register:</span> <span className="text-white font-bold">{evt.details.scadaRegister}</span></div>
                          <div><span className="text-zinc-500">Operation Command:</span> <span className="text-zinc-300">{evt.details.scadaOperation}</span></div>
                        </div>
                      )}

                      <button
                        type="button"
                        onClick={() => handleCopyJson(evt)}
                        className="absolute right-3 top-3 p-1.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 hover:text-white rounded-lg border border-zinc-700 transition cursor-pointer flex items-center gap-1 text-[9px] font-bold"
                        title="Copy Event JSON"
                      >
                        {copiedId === evt.id ? (
                          <>
                            <Check className="w-3 h-3 text-white" />
                            <span className="text-white">COPIED</span>
                          </>
                        ) : (
                          <>
                            <Clipboard className="w-3 h-3 text-zinc-400" />
                            <span>COPY JSON</span>
                          </>
                        )}
                      </button>
                    </div>

                    {/* Action Call */}
                    <div className="flex justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => onBlockIp(evt.attackerIp, `Honeypot Trigger: ${evt.service} intrusion exploit`)}
                        className="px-3 py-1.5 bg-white hover:bg-zinc-200 text-black border border-white rounded-lg font-mono font-black text-[10px] tracking-wider transition flex items-center gap-1.5 cursor-pointer uppercase shadow-xs"
                      >
                        <ShieldX className="w-3.5 h-3.5 text-black" />
                        AUTO-BLOCK ATTACKER IP
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Floating "Scroll to Bottom" badge */}
      {isScrolledUp && (
        <button
          type="button"
          onClick={() => scrollToBottom(true)}
          className="absolute bottom-4 right-6 px-3.5 py-1.5 bg-white hover:bg-zinc-200 text-black rounded-full text-xs font-mono font-bold shadow-2xl flex items-center gap-1.5 cursor-pointer transition animate-bounce z-20 border border-white"
        >
          <ArrowDown className="w-3.5 h-3.5 text-black" />
          <span>New Logs Below</span>
        </button>
      )}
    </div>
  );
};

export default LiveTerminalFeed;
