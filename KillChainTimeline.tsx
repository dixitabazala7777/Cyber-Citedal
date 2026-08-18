import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Search, LogIn, ArrowRightLeft, Download,
  ChevronRight, ExternalLink, Shield, AlertTriangle
} from 'lucide-react';
import { Incident } from '../types';

interface KillChainTimelineProps {
  incidents: Incident[];
  onLogMessage: (msg: string) => void;
}

interface MitreStage {
  id: string;
  label: string;
  icon: React.FC<{ className?: string }>;
  color: string;
  bgColor: string;
  borderColor: string;
  techniques: MitreTechnique[];
}

interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  incidentCategories: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
}

const MITRE_STAGES: MitreStage[] = [
  {
    id: 'recon', label: 'Reconnaissance', icon: Search,
    color: 'text-sky-600 dark:text-sky-400', bgColor: 'bg-sky-50 dark:bg-sky-950/40', borderColor: 'border-sky-200 dark:border-sky-800/60',
    techniques: [
      { id: 'T1595', name: 'Active Scanning', description: 'Adversary probes target for open ports and services', incidentCategories: ['Port Scan'], severity: 'medium' },
      { id: 'T1589', name: 'Gather Victim Identity', description: 'Adversary collects credentials and identity information', incidentCategories: ['Phishing', 'Brute Force'], severity: 'medium' },
      { id: 'T1590', name: 'Gather Network Info', description: 'DNS, WHOIS, and IP range enumeration', incidentCategories: ['Port Scan'], severity: 'low' },
    ]
  },
  {
    id: 'initial-access', label: 'Initial Access', icon: LogIn,
    color: 'text-amber-600 dark:text-amber-400', bgColor: 'bg-amber-50 dark:bg-amber-950/40', borderColor: 'border-amber-200 dark:border-amber-800/60',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing App', description: 'SQL injection, XSS, or RCE against web services', incidentCategories: ['SQL Injection'], severity: 'critical' },
      { id: 'T1566', name: 'Phishing', description: 'Spearphishing with malicious attachments or links', incidentCategories: ['Phishing'], severity: 'high' },
      { id: 'T1110', name: 'Brute Force', description: 'Password spraying, credential stuffing, or dictionary attacks', incidentCategories: ['Brute Force'], severity: 'high' },
    ]
  },
  {
    id: 'lateral-movement', label: 'Lateral Movement', icon: ArrowRightLeft,
    color: 'text-rose-600 dark:text-rose-400', bgColor: 'bg-rose-50 dark:bg-rose-950/40', borderColor: 'border-rose-200 dark:border-rose-800/60',
    techniques: [
      { id: 'T1021', name: 'Remote Services', description: 'SSH, RDP, or SMB lateral movement using stolen creds', incidentCategories: ['Brute Force'], severity: 'critical' },
      { id: 'T1080', name: 'Taint Shared Content', description: 'Planting malware in shared folders or repos', incidentCategories: ['Malware'], severity: 'critical' },
      { id: 'T1570', name: 'Lateral Tool Transfer', description: 'Moving tools across the network for further exploitation', incidentCategories: ['Malware'], severity: 'high' },
    ]
  },
  {
    id: 'exfiltration', label: 'Exfiltration', icon: Download,
    color: 'text-purple-600 dark:text-purple-400', bgColor: 'bg-purple-50 dark:bg-purple-950/40', borderColor: 'border-purple-200 dark:border-purple-800/60',
    techniques: [
      { id: 'T1041', name: 'Exfil Over C2 Channel', description: 'Data exfiltration using existing command-and-control channel', incidentCategories: ['DDoS', 'Malware'], severity: 'critical' },
      { id: 'T1048', name: 'Exfil Over Alternative Protocol', description: 'DNS tunneling, ICMP, or custom protocols to exfiltrate data', incidentCategories: ['DDoS'], severity: 'high' },
      { id: 'T1567', name: 'Exfil Over Web Service', description: 'Using cloud storage (S3, GDrive) for data exfiltration', incidentCategories: ['Malware'], severity: 'high' },
    ]
  },
];

export const KillChainTimeline: React.FC<KillChainTimelineProps> = ({ incidents, onLogMessage }) => {
  const [expandedStage, setExpandedStage] = useState<string | null>(null);
  const [expandedTechnique, setExpandedTechnique] = useState<string | null>(null);

  const stageActivity = useMemo(() => {
    const activity: Record<string, { count: number; incidents: Incident[]; activeTechniques: string[] }> = {};
    for (const stage of MITRE_STAGES) {
      const matchedIncidents: Incident[] = [];
      const activeTechs: string[] = [];
      for (const tech of stage.techniques) {
        const matching = incidents.filter(inc =>
          tech.incidentCategories.some(cat =>
            inc.category.toLowerCase().includes(cat.toLowerCase())
          )
        );
        if (matching.length > 0) {
          matchedIncidents.push(...matching);
          activeTechs.push(tech.id);
        }
      }
      const uniqueIncidents = Array.from(new Map(matchedIncidents.map(i => [i.id, i])).values());
      activity[stage.id] = { count: uniqueIncidents.length, incidents: uniqueIncidents, activeTechniques: activeTechs };
    }
    return activity;
  }, [incidents]);

  const totalProgression = useMemo(() => {
    const activeStages = MITRE_STAGES.filter(s => stageActivity[s.id].count > 0).length;
    return Math.round((activeStages / MITRE_STAGES.length) * 100);
  }, [stageActivity]);

  return (
    <div className="bg-white dark:bg-[#161b22] border border-slate-200 dark:border-[#30363d] rounded-xl p-5 shadow-xs dark:shadow-sm">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        <div className="flex items-center gap-2.5">
          <div className="p-2 bg-purple-50 dark:bg-purple-500/10 border border-purple-200 dark:border-purple-500/20 rounded-lg text-purple-600 dark:text-purple-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-50">MITRE ATT&CK Kill-Chain Timeline</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">Interactive threat progression mapping</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {totalProgression > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-600 dark:text-slate-400 font-medium">Kill-Chain Progression</span>
              <div className="w-24 h-2 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${totalProgression}%` }}
                  className={`h-full rounded-full ${totalProgression >= 75 ? 'bg-rose-500' : totalProgression >= 50 ? 'bg-amber-500' : 'bg-blue-500'}`}
                />
              </div>
              <span className={`text-xs font-bold font-mono ${totalProgression >= 75 ? 'text-rose-600 dark:text-rose-400' : totalProgression >= 50 ? 'text-amber-600 dark:text-amber-400' : 'text-blue-600 dark:text-blue-400'}`}>
                {totalProgression}%
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Timeline */}
      <div className="flex flex-col gap-3">
        {MITRE_STAGES.map((stage, idx) => {
          const activity = stageActivity[stage.id];
          const isExpanded = expandedStage === stage.id;
          const isActive = activity.count > 0;
          const StageIcon = stage.icon;

          return (
            <div key={stage.id}>
              {/* Stage row with connector */}
              <div className="flex items-stretch gap-3">
                {/* Connector line */}
                <div className="flex flex-col items-center w-7">
                  <div className={`w-7 h-7 rounded-full flex items-center justify-center border-2 ${
                    isActive ? stage.borderColor + ' ' + stage.bgColor : 'border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800'
                  }`}>
                    <StageIcon className={`w-3.5 h-3.5 ${isActive ? stage.color : 'text-slate-500 dark:text-slate-400'}`} />
                  </div>
                  {idx < MITRE_STAGES.length - 1 && (
                    <div className={`w-0.5 flex-1 min-h-[16px] mt-1 ${isActive ? 'bg-slate-300 dark:bg-slate-600' : 'bg-slate-200 dark:bg-slate-800'}`} />
                  )}
                </div>

                {/* Stage card */}
                <button
                  onClick={() => setExpandedStage(isExpanded ? null : stage.id)}
                  className={`flex-1 px-4 py-3 rounded-lg border text-left transition-all cursor-pointer ${
                    isActive
                      ? `${stage.bgColor} ${stage.borderColor}`
                      : 'bg-slate-50 dark:bg-[#090c10] border-slate-200 dark:border-[#30363d] hover:border-slate-300 dark:hover:border-slate-600'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <span className={`text-xs font-bold ${isActive ? stage.color : 'text-slate-800 dark:text-slate-200'}`}>{stage.label}</span>
                      {isActive && (
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${stage.bgColor} ${stage.color} border ${stage.borderColor}`}>
                          {activity.count} incident{activity.count !== 1 ? 's' : ''}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {activity.activeTechniques.map(tid => (
                        <span key={tid} className="text-[10px] font-mono font-semibold text-slate-500 dark:text-slate-400">{tid}</span>
                      ))}
                      <ChevronRight className={`w-4 h-4 text-slate-500 dark:text-slate-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                    </div>
                  </div>
                </button>
              </div>

              {/* Expanded techniques */}
              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="ml-10 mt-2 mb-2 overflow-hidden"
                  >
                    <div className="space-y-2 pl-3 border-l-2 border-slate-200 dark:border-slate-700">
                      {stage.techniques.map(tech => {
                        const techIncidents = incidents.filter(inc =>
                          tech.incidentCategories.some(cat => inc.category.toLowerCase().includes(cat.toLowerCase()))
                        );
                        const isTechActive = techIncidents.length > 0;
                        const isTechExpanded = expandedTechnique === tech.id;

                        return (
                          <div key={tech.id}>
                            <button
                              onClick={() => {
                                setExpandedTechnique(isTechExpanded ? null : tech.id);
                                if (isTechActive) onLogMessage(`MITRE: Inspecting ${tech.id} — ${tech.name}`);
                              }}
                              className={`w-full text-left px-3.5 py-2.5 rounded-lg border transition-all cursor-pointer ${
                                isTechActive
                                  ? 'bg-white dark:bg-slate-900 border-slate-300 dark:border-slate-700 hover:border-slate-400'
                                  : 'bg-slate-50 dark:bg-slate-950/40 border-slate-200 dark:border-slate-800'
                              }`}
                            >
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2.5">
                                  <code className={`text-xs font-mono font-bold ${isTechActive ? stage.color : 'text-slate-600 dark:text-slate-400'}`}>{tech.id}</code>
                                  <span className={`text-xs font-semibold ${isTechActive ? 'text-slate-900 dark:text-slate-100' : 'text-slate-600 dark:text-slate-400'}`}>{tech.name}</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  {isTechActive && (
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                      tech.severity === 'critical' ? 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300 border border-rose-300' :
                                      tech.severity === 'high' ? 'bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300' :
                                      'bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300 border border-blue-300'
                                    }`}>
                                      {tech.severity.toUpperCase()} • {techIncidents.length}
                                    </span>
                                  )}
                                  <ExternalLink className="w-3.5 h-3.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200" />
                                </div>
                              </div>
                            </button>

                            {/* Expanded: show evidence incidents */}
                            <AnimatePresence>
                              {isTechExpanded && isTechActive && (
                                <motion.div
                                  initial={{ height: 0, opacity: 0 }}
                                  animate={{ height: 'auto', opacity: 1 }}
                                  exit={{ height: 0, opacity: 0 }}
                                  className="ml-4 mt-2 space-y-1.5 overflow-hidden"
                                >
                                  <p className="text-xs text-slate-600 dark:text-slate-400 font-mono mb-1">{tech.description}</p>
                                  {techIncidents.slice(0, 5).map(inc => (
                                    <div key={inc.id} className="flex items-center gap-2 px-3 py-1.5 bg-slate-100 dark:bg-slate-900 rounded border border-slate-200 dark:border-slate-800 text-xs font-mono">
                                      <AlertTriangle className={`w-3.5 h-3.5 ${
                                        inc.severity === 'critical' ? 'text-rose-600 dark:text-rose-400' :
                                        inc.severity === 'high' ? 'text-amber-600 dark:text-amber-400' : 'text-blue-600 dark:text-blue-400'
                                      }`} />
                                      <span className="text-slate-500 font-semibold">{inc.id}</span>
                                      <span className="text-slate-800 dark:text-slate-200 font-bold">{inc.sourceIp}</span>
                                      <span className="text-slate-500">→ {inc.targetService}</span>
                                      <span className={`ml-auto font-bold ${
                                        inc.status === 'blocked' ? 'text-emerald-600 dark:text-emerald-400' :
                                        inc.status === 'active' ? 'text-rose-600 dark:text-rose-400' : 'text-slate-500'
                                      }`}>{inc.status}</span>
                                    </div>
                                  ))}
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </div>
                        );
                      })}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </div>
  );
};
