import React, { useState } from 'react';
import { 
  Eye, UserX, AlertTriangle, CheckCircle, 
  TrendingUp, MapPin, Clock, Server
} from 'lucide-react';

interface UebaIdentity {
  username: string;
  role: string;
  riskScore: number;
  status: 'Safe' | 'Monitored' | 'Quarantined';
  lastActive: string;
  anomalies: string[];
  location: string;
  bandwidthUsage: string;
}

interface UebaDetectorProps {
  onLogMessage: (msg: string) => void;
}

export const UebaDetector: React.FC<UebaDetectorProps> = ({ onLogMessage }) => {
  const [identities, setIdentities] = useState<UebaIdentity[]>([
    {
      username: 'svc-kube-core-daemon',
      role: 'Automated System Service',
      riskScore: 94,
      status: 'Monitored',
      lastActive: 'Just now',
      anomalies: [
        'Brute-force credential attempts on local service endpoints',
        'Unauthorized sub-container spawn requests in namespace default'
      ],
      location: 'Internal Subnet (K8s Clusters)',
      bandwidthUsage: '14.2 GB/hr'
    },
    {
      username: 'dev-schmidt-admin',
      role: 'Senior Infrastructure Lead',
      riskScore: 84,
      status: 'Monitored',
      lastActive: '14 mins ago',
      anomalies: [
        'Impossible Travel Flagged: login US East-01, then Dublin EU-West-02 within 25 mins',
        'Accessing backup recovery vaults at anomalous off-hours (03:14 AM)'
      ],
      location: 'Amsterdam, NL (Tor Exit Node proxy route)',
      bandwidthUsage: '8.4 GB'
    },
    {
      username: 'ctr-lin-external',
      role: 'Contractor QA Agent',
      riskScore: 42,
      status: 'Monitored',
      lastActive: '1 hr ago',
      anomalies: [
        'SQL query length exceeded average thresholds by 400%',
        'Multiple read actions targeting secure user database metadata tables'
      ],
      location: 'San Jose, CA, USA',
      bandwidthUsage: '142 MB'
    },
    {
      username: 'ops-taylor-support',
      role: 'Support Desk Agent',
      riskScore: 12,
      status: 'Safe',
      lastActive: '4 mins ago',
      anomalies: [],
      location: 'Austin, TX, USA',
      bandwidthUsage: '22 MB'
    }
  ]);

  const [selectedUsername, setSelectedUsername] = useState<string>('svc-kube-core-daemon');

  const handleQuarantine = (username: string) => {
    setIdentities(prev => prev.map(id => {
      if (id.username === username) {
        onLogMessage(`UEBA ENGINE: Identity ${username} has been QUARANTINED. Active sessions invalidated.`);
        playSynthWarn();
        return { ...id, status: 'Quarantined', riskScore: 100 };
      }
      return id;
    }));
  };

  const playSynthWarn = () => {
    try {
      const AudioContextClass = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
      if (!AudioContextClass) return;
      const ctx = new AudioContextClass();
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(330, now);
      osc.frequency.setValueAtTime(180, now + 0.15);
      gain.gain.setValueAtTime(0.03, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.45);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.5);
    } catch (e) {
      console.warn("Audio Context init failed", e);
    }
  };

  // Generate mock weekly heatmap grid: Days of week (7) x Time periods (8 blocks of 3 hours)
  const heatmapData = [
    // 0 = Baseline (Safe), 1 = Slight Deviation, 2 = Critical Anomaly
    [0, 0, 0, 1, 0, 0, 0, 0], // Mon
    [0, 0, 2, 0, 0, 0, 0, 1], // Tue (Amsterdam impossible travel block)
    [0, 0, 0, 0, 1, 0, 0, 0], // Wed
    [2, 0, 0, 0, 0, 1, 0, 0], // Thu (K8s escalation attempt)
    [0, 0, 0, 2, 0, 0, 1, 0], // Fri (Database scan)
    [1, 1, 0, 0, 0, 0, 0, 0], // Sat
    [0, 0, 0, 0, 0, 0, 0, 0], // Sun
  ];

  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const times = ['00-03', '03-06', '06-09', '09-12', '12-15', '15-18', '18-21', '21-24'];

  const selectedIdentity = identities.find(id => id.username === selectedUsername) || identities[0];

  return (
    <div id="ueba-detector-module" className="p-6 bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs dark:shadow-xl relative overflow-hidden min-h-[500px] text-slate-900 dark:text-slate-100">
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />
      
      {/* Header Panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-200 dark:border-slate-800 pb-4 mb-6 gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Eye className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold tracking-widest uppercase">BEHAVIOR TELEMETRY CORE</span>
          </div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white font-sans tracking-wide">UEBA Insider Threat Anomaly Detector</h2>
          <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 max-w-xl">
            Monitors identity behavior profiles against historical baselines, flagging unauthorized sub-shell processes, impossible geographical logins, and volumetric data leaks.
          </p>
        </div>
      </div>

      {/* Grid Content */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Identity Profiles List (Left 5 Cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="text-[10px] font-bold text-slate-700 dark:text-slate-300 font-mono tracking-wider border-b border-slate-200 dark:border-slate-800 pb-2 uppercase">
            ACTIVE IDENTITY DIRECTORY
          </div>

          <div className="space-y-2">
            {identities.map((id) => {
              const isSelected = id.username === selectedUsername;
              return (
                <div
                  key={id.username}
                  onClick={() => setSelectedUsername(id.username)}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer transition-all ${
                    isSelected 
                      ? 'bg-indigo-50 dark:bg-indigo-950/40 border-indigo-500 dark:border-indigo-500 shadow-sm' 
                      : 'bg-white dark:bg-slate-950/60 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-900/30'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-slate-900 dark:text-white truncate max-w-[200px] font-mono">
                        {id.username}
                      </h4>
                      <span className="text-[9px] text-slate-600 dark:text-slate-400 font-mono mt-1 inline-block uppercase font-semibold">
                        {id.role}
                      </span>
                    </div>
                    
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                        id.status === 'Quarantined' ? 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-800' :
                        id.riskScore >= 80 ? 'bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800 animate-pulse' :
                        id.riskScore >= 40 ? 'bg-yellow-100 dark:bg-yellow-950 text-yellow-800 dark:text-yellow-300 border-yellow-300 dark:border-yellow-800' : 'bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                      }`}>
                        {id.status === 'Quarantined' ? 'QUARANTINED' : `${id.riskScore} RISK`}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Identity Details & Access Heatmap (Right 7 Cols) */}
        <div className="lg:col-span-7 space-y-5 flex flex-col justify-between">
          
          {/* Identity Dossier Card */}
          <div className="bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-4 shadow-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
              <div>
                <span className="text-[9px] text-slate-600 dark:text-slate-400 font-mono font-bold uppercase">INSIDER THREAT ASSESSMENT RECORD</span>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono mt-0.5">{selectedIdentity.username}</h3>
              </div>
              
              {selectedIdentity.status !== 'Quarantined' ? (
                <button
                  onClick={() => handleQuarantine(selectedIdentity.username)}
                  className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-500 text-white border border-rose-600 rounded-lg text-xs font-mono font-bold transition flex items-center justify-center gap-1.5 cursor-pointer shadow-xs active:scale-95"
                >
                  <UserX className="w-3.5 h-3.5" />
                  QUARANTINE IDENTITY
                </button>
              ) : (
                <span className="px-3 py-1 bg-rose-100 dark:bg-rose-950/80 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-800 rounded text-xs font-mono font-bold flex items-center gap-1.5">
                  <CheckCircle className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
                  FULLY QUARANTINED
                </span>
              )}
            </div>

            {/* Geo Metadata */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 flex flex-col gap-1 shadow-xs">
                <span className="text-[10px] text-slate-500 dark:text-slate-400 font-bold uppercase">LAST ACTIVE REGION</span>
                <span className="text-slate-900 dark:text-slate-100 font-bold flex items-center gap-1">
                  <MapPin className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
                  {selectedIdentity.location}
                </span>
              </div>
              <div className="p-3 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 flex flex-col gap-1 shadow-xs">
                <span className="text-[10px] text-slate-500 dark:text-slate-400 font-bold uppercase">BANDWIDTH TRANSFER</span>
                <span className="text-slate-900 dark:text-slate-100 font-bold flex items-center gap-1">
                  <Server className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
                  {selectedIdentity.bandwidthUsage}
                </span>
              </div>
              <div className="p-3 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 flex flex-col gap-1 shadow-xs">
                <span className="text-[10px] text-slate-500 dark:text-slate-400 font-bold uppercase">ACTIVE SESSION LIMIT</span>
                <span className="text-slate-900 dark:text-slate-100 font-bold flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                  {selectedIdentity.lastActive}
                </span>
              </div>
            </div>

            {/* Logged Anomalies List */}
            <div className="space-y-2">
              <div className="text-[10px] font-bold text-slate-700 dark:text-slate-300 font-mono tracking-wider uppercase">
                TRIGGERED ANOMALY LEDGERS
              </div>
              {selectedIdentity.anomalies.length === 0 ? (
                <div className="p-3 bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-lg text-slate-500 italic text-xs font-sans">
                  No behavioral anomalies matched. Baseline parameters fully clean.
                </div>
              ) : (
                <div className="space-y-1.5">
                  {selectedIdentity.anomalies.map((anom, idx) => (
                    <div key={idx} className="p-2.5 bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900/40 rounded-lg flex items-start gap-2 text-xs text-rose-900 dark:text-rose-200">
                      <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                      <span className="font-sans leading-relaxed font-medium">{anom}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Baseline vs Anomaly Activity Heatmap */}
          <div className="bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-3 shadow-xs">
            <div className="flex justify-between items-center border-b border-slate-200 dark:border-slate-800 pb-2">
              <div className="text-[10px] font-bold text-slate-700 dark:text-slate-300 font-mono tracking-wider flex items-center gap-1.5 uppercase">
                <TrendingUp className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                <span>WEEKLY SYSTEM PATTERN ANALYZER</span>
              </div>
              
              {/* Heatmap Legend */}
              <div className="flex items-center gap-2.5 text-[9px] font-mono text-slate-600 dark:text-slate-400 font-semibold">
                <div className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded bg-slate-200 dark:bg-slate-800 border border-slate-300 dark:border-slate-700" />
                  <span>IDLE</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded bg-indigo-200 dark:bg-indigo-900/60 border border-indigo-300 dark:border-indigo-700" />
                  <span>BASE</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded bg-amber-400/40 border border-amber-500" />
                  <span>DEV</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded bg-rose-500 border border-rose-600 animate-pulse" />
                  <span>ANOMALY</span>
                </div>
              </div>
            </div>

            {/* Grid Map Wrapper */}
            <div className="flex flex-col gap-2 font-mono text-[10px]">
              {/* Heatmap Column Headers */}
              <div className="grid grid-cols-9 text-center text-slate-600 dark:text-slate-400 font-bold">
                <div />
                {times.map((t, idx) => (
                  <div key={idx} className="truncate">{t}</div>
                ))}
              </div>

              {/* Heatmap Grid Rows */}
              <div className="space-y-1.5">
                {heatmapData.map((row, rIdx) => (
                  <div key={rIdx} className="grid grid-cols-9 items-center text-center">
                    {/* Day label */}
                    <div className="text-left text-slate-700 dark:text-slate-300 font-bold pr-1">{days[rIdx]}</div>
                    
                    {/* Heat Tiles */}
                    {row.map((val, cIdx) => (
                      <div key={cIdx} className="px-0.5">
                        <div className={`h-5 w-full rounded border transition-all ${
                          val === 0 
                            ? 'bg-slate-200/80 dark:bg-slate-900 border-slate-300 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700' 
                            : val === 1 
                              ? 'bg-amber-400/30 border-amber-500 hover:bg-amber-400/50' 
                              : 'bg-rose-500 border-rose-600 hover:bg-rose-600 shadow-[0_0_8px_rgba(239,68,68,0.3)] animate-pulse'
                        }`}
                        title={val === 2 ? `Anomaly flagged inside ${times[cIdx]} block` : `Baseline activity verified`}
                        />
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};

export default UebaDetector;
