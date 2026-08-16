import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Incident } from '../types';
import { 
  Shield, ShieldAlert, Terminal, X, Activity
} from 'lucide-react';

interface MitreMatrixProps {
  incidents: Incident[];
  onResolveIncident?: (id: string) => void;
  onBlockIp?: (ip: string, category: string) => void;
}

interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  categoryMapping: string[]; // maps to Incident.category
  mitigationSteps: string[];
}

interface MitreTactic {
  id: string;
  name: string;
  techniques: MitreTechnique[];
}

export const MitreMatrix: React.FC<MitreMatrixProps> = ({ 
  incidents, 
  onResolveIncident,
  onBlockIp 
}) => {
  const [selectedTechnique, setSelectedTechnique] = useState<{
    tacticName: string;
    technique: MitreTechnique;
    mappedIncidents: Incident[];
  } | null>(null);

  // Define standard MITRE Tactics and Techniques
  const tactics: MitreTactic[] = useMemo(() => [
    {
      id: 'TA0001',
      name: 'Initial Access',
      techniques: [
        {
          id: 'T1190',
          name: 'Exploit Public-Facing Application',
          description: 'Adversaries may attempt to exploit a weakness in an Internet-facing computer or program to gain initial access to a system.',
          categoryMapping: ['SQL Injection'],
          mitigationSteps: [
            'Deploy active SQL/WAF filtering rules immediately.',
            'Enable deep packet parameter validation.',
            'Isolate database subnet gateways.'
          ]
        },
        {
          id: 'T1595',
          name: 'Active Scanning',
          description: 'Adversaries may execute active scanning to gather information about networks and ports to identify targets for exploit development.',
          categoryMapping: ['Port Scan'],
          mitigationSteps: [
            'Deploy dynamic connection threshold limiters.',
            'Reject anomalous TCP handshakes automatically.',
            'Enable network perimeter blackout.'
          ]
        },
        {
          id: 'T1566',
          name: 'Phishing',
          description: 'Adversaries may send phishing messages to gain access to system resources or harvest credentials.',
          categoryMapping: ['Phishing'],
          mitigationSteps: [
            'Enforce system-wide multi-factor authentication reset.',
            'Quarantine inbound message routing channels.',
            'Deploy secure sandbox attachment screening.'
          ]
        }
      ]
    },
    {
      id: 'TA0002',
      name: 'Execution',
      techniques: [
        {
          id: 'T1059',
          name: 'Command & Scripting Interpreter',
          description: 'Adversaries may abuse local command or scripting interpreters to execute malicious code on production nodes.',
          categoryMapping: ['Malware'],
          mitigationSteps: [
            'Deploy secure application blocklists on host environments.',
            'Enforce read-only volumes for core operating parameters.',
            'Audit sub-shell invocation logs immediately.'
          ]
        },
        {
          id: 'T1203',
          name: 'Exploitation for Client Execution',
          description: 'Adversaries may exploit vulnerabilities in client applications to execute code outside of normal security perimeters.',
          categoryMapping: ['SQL Injection'],
          mitigationSteps: [
            'Upgrade API endpoints to strongly typed models.',
            'Enforce parameterized queries at the application level.',
            'Purge stale ingress data sessions.'
          ]
        }
      ]
    },
    {
      id: 'TA0003',
      name: 'Persistence',
      techniques: [
        {
          id: 'T1547',
          name: 'Boot or Logon Autostart',
          description: 'Adversaries may configure system files or registry entries to automatically run code during startup to maintain long-term node control.',
          categoryMapping: ['Malware'],
          mitigationSteps: [
            'Audit running background services on affected hosts.',
            'Enforce host file integrity verification.',
            'Initialize cryptographic container signature rebuild.'
          ]
        },
        {
          id: 'T1098',
          name: 'Account Manipulation',
          description: 'Adversaries may manipulate accounts or security permissions to maintain persistent, high-privilege access pathways.',
          categoryMapping: ['Brute Force'],
          mitigationSteps: [
            'Revoke active session tokens for the affected identities.',
            'Invalidate static administrative access keys.',
            'Re-evaluate IAM active boundary roles.'
          ]
        }
      ]
    },
    {
      id: 'TA0004',
      name: 'Privilege Escalation',
      techniques: [
        {
          id: 'T1548',
          name: 'Abuse Privilege Escalation',
          description: 'Adversaries may exploit OS configurations or bypass active security gates to run code under elevated permissions.',
          categoryMapping: ['Brute Force', 'SQL Injection'],
          mitigationSteps: [
            'Isolate and secure administrative API endpoints.',
            'Enforce physical key hardware MFA verification.',
            'Trigger automatic container container recycle.'
          ]
        },
        {
          id: 'T1068',
          name: 'Exploitation for Privilege Escalation',
          description: 'Adversaries may exploit local hardware or system kernel vulnerabilities to elevate execution access level.',
          categoryMapping: ['Malware'],
          mitigationSteps: [
            'Apply emergency OS kernels patches immediately.',
            'Limit localized execution to secure unprivileged sandboxes.',
            'Kill sub-process cascades on degraded hosts.'
          ]
        }
      ]
    },
    {
      id: 'TA0006',
      name: 'Credential Access',
      techniques: [
        {
          id: 'T1110',
          name: 'Brute Force Attempts',
          description: 'Adversaries may run automated scripts or dictionaries to guess usernames or passwords to bypass authentication controls.',
          categoryMapping: ['Brute Force'],
          mitigationSteps: [
            'Apply progressive connection lockouts on ingress ports.',
            'Block origin subnet addresses on perimeter gateways.',
            'Force absolute administrative pass-phrase cycles.'
          ]
        },
        {
          id: 'T1555',
          name: 'Credentials from Password Stores',
          description: 'Adversaries may search local system files, environment variables, or databases to find unencrypted credential pools.',
          categoryMapping: ['Phishing'],
          mitigationSteps: [
            'Re-key all system secrets and environment parameters.',
            'Rotate active cloud database access clusters.',
            'Audit memory-leak vectors on authentication microservices.'
          ]
        }
      ]
    },
    {
      id: 'TA0010',
      name: 'Exfiltration',
      techniques: [
        {
          id: 'T1048',
          name: 'Exfiltration Over Alternative Protocol',
          description: 'Adversaries may steal sensitive system information or databases and send them to an external node over a non-standard port or channel.',
          categoryMapping: ['DDoS'],
          mitigationSteps: [
            'Enforce outbound rate limiting on public-facing gateways.',
            'Terminate unencrypted SSL handshake requests immediately.',
            'Initiate deep flow traffic shaping rules.'
          ]
        },
        {
          id: 'T1020',
          name: 'Automated Exfiltration',
          description: 'Adversaries may deploy scripted mechanisms to scan local directories, collect customer ledgers, and automate upload actions.',
          categoryMapping: ['DDoS', 'Malware'],
          mitigationSteps: [
            'Apply volume quotas on active system endpoints.',
            'Enable heuristic data leakage prevention filters.',
            'Quarantine suspicious container egress gateways.'
          ]
        }
      ]
    }
  ], []);

  // Map active incidents to each technique helper
  const getMappedIncidents = (tech: MitreTechnique): Incident[] => {
    return incidents.filter(inc => 
      inc.status === 'active' && 
      tech.categoryMapping.includes(inc.category)
    );
  };

  const getSeverityColor = (incidentsList: Incident[]): { bg: string; border: string; text: string; glow: string; name: string } => {
    if (incidentsList.length === 0) {
      return { 
        bg: 'bg-slate-50 dark:bg-slate-900/60 hover:bg-slate-100 dark:hover:bg-slate-800/80', 
        border: 'border-slate-200 dark:border-slate-800', 
        text: 'text-slate-700 dark:text-slate-300 font-medium', 
        glow: '',
        name: 'Monitored'
      };
    }
    const hasCritical = incidentsList.some(i => i.severity === 'critical');
    const hasHigh = incidentsList.some(i => i.severity === 'high');
    const hasMedium = incidentsList.some(i => i.severity === 'medium');

    if (hasCritical) {
      return { 
        bg: 'bg-rose-100 dark:bg-rose-950/60 hover:bg-rose-200 dark:hover:bg-rose-900/60', 
        border: 'border-rose-300 dark:border-rose-500/50', 
        text: 'text-rose-900 dark:text-rose-300 font-bold', 
        glow: '',
        name: 'Critical'
      };
    }
    if (hasHigh) {
      return { 
        bg: 'bg-amber-100 dark:bg-amber-950/60 hover:bg-amber-200 dark:hover:bg-amber-900/60', 
        border: 'border-amber-300 dark:border-amber-500/50', 
        text: 'text-amber-900 dark:text-amber-300 font-bold', 
        glow: '',
        name: 'High'
      };
    }
    if (hasMedium) {
      return { 
        bg: 'bg-yellow-100 dark:bg-yellow-950/50 hover:bg-yellow-200 dark:hover:bg-yellow-900/50', 
        border: 'border-yellow-300 dark:border-yellow-500/50', 
        text: 'text-yellow-900 dark:text-yellow-300 font-bold', 
        glow: '',
        name: 'Medium'
      };
    }
    return { 
      bg: 'bg-blue-100 dark:bg-blue-950/50 hover:bg-blue-200 dark:hover:bg-blue-900/50', 
      border: 'border-blue-300 dark:border-blue-500/50', 
      text: 'text-blue-900 dark:text-blue-300 font-bold', 
      glow: '',
      name: 'Info'
    };
  };

  return (
    <div id="mitre-matrix-module" className="relative p-6 bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-[#334155] rounded-xl shadow-xs dark:shadow-sm overflow-hidden min-h-[500px]">
      {/* Background glow lines */}
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />
      
      {/* Header Info */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-900 pb-4 mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Shield className="w-5 h-5 text-indigo-400 animate-pulse" />
            <span className="text-[10px] text-slate-500 font-mono font-bold tracking-widest">ENTERPRISE SECOPS PORTAL</span>
          </div>
          <h2 className="text-lg font-bold text-white font-sans tracking-wide">MITRE ATT&CK® Kill-Chain Matrix</h2>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            Real-time telemetry mapping of active security incidents to the industry-standard MITRE adversarial tactics framework. Highlighted cells represent active exploitation attempts.
          </p>
        </div>
        
        {/* Status Indicators */}
        <div className="flex items-center gap-4 mt-3 md:mt-0 text-[10px] font-mono">
          <div className="flex items-center gap-1.5 text-rose-500">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            <span>CRITICAL ATTACK</span>
          </div>
          <div className="flex items-center gap-1.5 text-amber-500">
            <span className="w-2 h-2 rounded-full bg-amber-500" />
            <span>HIGH RISK</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-500">
            <span className="w-2 h-2 rounded-full bg-slate-800" />
            <span>MONITORED</span>
          </div>
        </div>
      </div>

      {/* Tactic Matrix Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {tactics.map((tactic) => {
          // Total active incidents for this entire tactic
          const tacticIncidents = tactic.techniques.flatMap(t => getMappedIncidents(t));
          const hasActive = tacticIncidents.length > 0;
          
          return (
            <div key={tactic.id} className="flex flex-col space-y-3">
              {/* Tactic Column Header */}
              <div className={`p-3 rounded-lg border flex flex-col justify-between font-mono transition-all ${
                hasActive 
                  ? 'bg-indigo-950/15 border-indigo-500/40 shadow-[0_0_8px_rgba(99,102,241,0.1)]' 
                  : 'bg-slate-900/10 border-slate-900'
              }`}>
                <div className="flex justify-between items-start gap-1">
                  <span className="text-[10px] text-slate-500 font-bold">{tactic.id}</span>
                  {hasActive && (
                    <span className="px-1.5 py-0.5 bg-indigo-500/15 text-indigo-400 text-[9px] font-bold rounded animate-pulse">
                      {tacticIncidents.length} ACT
                    </span>
                  )}
                </div>
                <h3 className="text-[11px] font-bold text-slate-200 mt-2 tracking-tight leading-tight uppercase font-sans">
                  {tactic.name}
                </h3>
              </div>

              {/* Technique Cells List */}
              <div className="space-y-2 flex-1">
                {tactic.techniques.map((tech) => {
                  const mapped = getMappedIncidents(tech);
                  const style = getSeverityColor(mapped);
                  
                  return (
                    <motion.div
                      whileHover={{ scale: 1.02, y: -1 }}
                      whileTap={{ scale: 0.99 }}
                      key={tech.id}
                      onClick={() => setSelectedTechnique({
                        tacticName: tactic.name,
                        technique: tech,
                        mappedIncidents: mapped
                      })}
                      className={`p-3 rounded-lg border ${style.bg} ${style.border} ${style.glow} transition-all cursor-pointer flex flex-col justify-between h-[100px] text-left relative overflow-hidden`}
                    >
                      {/* Active warning indicator background */}
                      {mapped.length > 0 && (
                        <div className="absolute top-0 right-0 w-8 h-8 bg-current opacity-[0.03] rotate-45 transform translate-x-3 -translate-y-3 pointer-events-none" />
                      )}

                      <div className="flex justify-between items-start">
                        <span className="text-[9px] text-slate-500 font-mono font-bold">{tech.id}</span>
                        {mapped.length > 0 && (
                          <span className={`w-1.5 h-1.5 rounded-full ${
                            tech.categoryMapping.includes('SQL Injection') ? 'bg-rose-500 animate-ping' :
                            tech.categoryMapping.includes('Port Scan') ? 'bg-amber-500 animate-pulse' : 'bg-cyan-500'
                          }`} />
                        )}
                      </div>

                      <div className="flex flex-col justify-end flex-1 mt-1">
                        <h4 className="text-[10px] font-bold text-slate-200 truncate font-sans tracking-tight" title={tech.name}>
                          {tech.name}
                        </h4>
                        <div className="flex items-center justify-between mt-1 text-[9px]">
                          {mapped.length > 0 ? (
                            <span className={`${style.text} flex items-center gap-1`}>
                              <Activity className="w-3 h-3 text-current" />
                              <span>{mapped.length} incident{mapped.length > 1 ? 's' : ''}</span>
                            </span>
                          ) : (
                            <span className="text-slate-600 font-mono font-normal">0 events</span>
                          )}
                          <span className="text-slate-500 font-mono text-[8px] hover:text-slate-300">DETAILS →</span>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* MITRE Threat Dossier / Inspection Drawer */}
      <AnimatePresence>
        {selectedTechnique && (
          <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm z-50 flex justify-end">
            {/* Overlay click to dismiss */}
            <div className="absolute inset-0 cursor-pointer" onClick={() => setSelectedTechnique(null)} />
            
            {/* Drawer container */}
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 220 }}
              className="relative w-full sm:w-[480px] h-full bg-slate-950 border-l border-slate-900 shadow-[0_0_50px_rgba(0,0,0,0.8)] flex flex-col z-50 font-mono text-xs overflow-hidden"
            >
              {/* Drawer Header */}
              <div className="p-4 border-b border-slate-900 bg-slate-900/30 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-indigo-400" />
                  <div>
                    <span className="text-[9px] text-slate-500 font-bold tracking-wider">MITRE MATRIX INSPECTOR</span>
                    <h3 className="text-xs text-white font-bold tracking-widest uppercase">TECHNIQUE DOSSIER</h3>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedTechnique(null)}
                  className="p-1 rounded-md bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition active:scale-95"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Scrollable Dossier Content */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                
                {/* Technique Basic Details */}
                <div className="p-4 bg-slate-900/20 border border-slate-900 rounded-lg">
                  <div className="flex items-center justify-between text-[10px] text-indigo-400 font-bold mb-1">
                    <span>TACTIC: {selectedTechnique.tacticName.toUpperCase()}</span>
                    <span>{selectedTechnique.technique.id}</span>
                  </div>
                  <h2 className="text-sm font-bold text-white mb-2">{selectedTechnique.technique.name}</h2>
                  <p className="text-slate-400 leading-relaxed text-[11px] font-sans">
                    {selectedTechnique.technique.description}
                  </p>
                </div>

                {/* Section: Linked Active Incidents */}
                <div className="space-y-2">
                  <div className="text-[10px] font-bold text-slate-400 flex items-center justify-between border-b border-slate-900 pb-1.5">
                    <span>ACTIVE ATTRIBUTES IN WORKSPACE LEDGER</span>
                    <span className="px-1.5 py-0.2 bg-rose-950/40 text-rose-400 rounded text-[9px]">
                      {selectedTechnique.mappedIncidents.length} Match
                    </span>
                  </div>

                  {selectedTechnique.mappedIncidents.length === 0 ? (
                    <div className="p-4 bg-slate-900/10 border border-slate-900 rounded-lg text-center text-slate-500 italic text-[11px]">
                      No active threat instances of this technique detected on network interfaces. Slating is clear.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-[220px] overflow-y-auto">
                      {selectedTechnique.mappedIncidents.map((inc) => (
                        <div key={inc.id} className="p-3 bg-[#030712] border border-slate-900 rounded-lg flex flex-col gap-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-bold text-slate-400">{inc.id}</span>
                            <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded ${
                              inc.severity === 'critical' ? 'bg-rose-950 text-rose-400 border border-rose-900/60' :
                              inc.severity === 'high' ? 'bg-amber-950 text-amber-400 border border-amber-900/60' : 'bg-slate-900 text-slate-300'
                            }`}>
                              {inc.severity.toUpperCase()}
                            </span>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-[10px] text-slate-500">
                            <div>Source IP: <span className="text-white font-bold">{inc.sourceIp} ({inc.countryCode})</span></div>
                            <div>Endpoint Target: <span className="text-cyan-400 truncate max-w-[130px] block">{inc.targetService}</span></div>
                          </div>
                          {inc.payload && (
                            <div className="p-2 bg-slate-950 rounded text-[9px] text-emerald-500/90 font-mono break-all border border-slate-900 leading-tight">
                              Payload signature: {inc.payload}
                            </div>
                          )}

                          {/* Quick Containment Actions inside Drawer */}
                          <div className="flex gap-2 pt-1">
                            {onBlockIp && (
                              <button
                                onClick={() => {
                                  onBlockIp(inc.sourceIp, inc.category);
                                  // Update state inside drawer locally
                                  setSelectedTechnique(prev => prev ? {
                                    ...prev,
                                    mappedIncidents: prev.mappedIncidents.filter(i => i.id !== inc.id)
                                  } : null);
                                }}
                                className="flex-1 py-1 rounded bg-rose-950/30 hover:bg-rose-950/50 text-rose-400 border border-rose-900/50 hover:border-rose-700 text-[9px] font-bold transition-all active:scale-[0.98] cursor-pointer"
                              >
                                BLOCK ORIGIN IP
                              </button>
                            )}
                            {onResolveIncident && (
                              <button
                                onClick={() => {
                                  onResolveIncident(inc.id);
                                  setSelectedTechnique(prev => prev ? {
                                    ...prev,
                                    mappedIncidents: prev.mappedIncidents.filter(i => i.id !== inc.id)
                                  } : null);
                                }}
                                className="flex-1 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 text-[9px] font-bold transition-all active:scale-[0.98] cursor-pointer"
                              >
                                MARK RESOLVED
                              </button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Section: Suggested Containment Playbooks */}
                <div className="space-y-2">
                  <div className="text-[10px] font-bold text-slate-400 border-b border-slate-900 pb-1.5">
                    RECOMMENDED CONTAINMENT ACTION PROTOCOLS (SOAR)
                  </div>
                  <div className="space-y-1.5">
                    {selectedTechnique.technique.mitigationSteps.map((step, idx) => (
                      <div key={idx} className="p-2 bg-slate-900/10 border border-slate-900 rounded flex items-start gap-2 text-[10px] text-slate-300 leading-tight">
                        <span className="text-indigo-400 font-bold mt-0.5">{idx + 1}.</span>
                        <span className="font-sans">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Section Warning / Audit */}
                <div className="p-3 bg-indigo-950/15 border border-indigo-900/40 rounded-lg text-[9px] text-slate-400 flex items-start gap-2">
                  <ShieldAlert className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                  <span className="leading-snug">
                    Audited under ShieldPulse Secure Core SLA criteria. Executing direct manual remediation actions registers in the SIEM audit stream. Refer to active Playbooks tab for automated orchestration sequences.
                  </span>
                </div>

              </div>

              {/* Drawer Footer */}
              <div className="p-4 border-t border-slate-900 bg-slate-900/30 flex items-center justify-between">
                <span className="text-[9px] text-slate-500 font-bold">SECURE OPERATIONAL TOKEN • VALIDATED</span>
                <button
                  onClick={() => setSelectedTechnique(null)}
                  className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 hover:text-white border border-slate-800 rounded-lg text-[10px] font-bold transition cursor-pointer"
                >
                  DISMISS DOSSIER
                </button>
              </div>

            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};
