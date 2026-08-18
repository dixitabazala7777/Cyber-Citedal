import React, { useMemo } from 'react';
import { Incident, SystemNode, FirewallRule } from '../types';
import { 
  Award, CheckCircle2, AlertTriangle, Download 
} from 'lucide-react';

interface ComplianceProps {
  incidents: Incident[];
  nodes: SystemNode[];
  rules: FirewallRule[];
  dbLinkStatus: string;
  onLogMessage: (msg: string) => void;
}

interface ComplianceControl {
  id: string;
  framework: string;
  category: string;
  name: string;
  description: string;
  status: 'COMPLIANT' | 'DEFICIENT';
  scoreImpact: number;
}

export const ComplianceGovernance: React.FC<ComplianceProps> = ({
  incidents,
  nodes,
  rules,
  dbLinkStatus,
  onLogMessage
}) => {
  // 1. Dynamic check predicates
  const isTlsActive = useMemo(() => {
    return nodes.some(n => n.status === 'operational');
  }, [nodes]);

  const hasNoThreats = useMemo(() => {
    return incidents.filter(i => i.status === 'active').length === 0;
  }, [incidents]);

  const isDbSynced = useMemo(() => {
    return dbLinkStatus.toLowerCase().includes('active');
  }, [dbLinkStatus]);

  const isFirewallConfigured = useMemo(() => {
    return rules.length > 0 || incidents.some(i => i.status === 'blocked');
  }, [rules, incidents]);

  // 2. Dynamic Score Calculation
  const dynamicScore = useMemo(() => {
    let base = 50;
    if (isTlsActive) base += 15;
    if (hasNoThreats) base += 15;
    if (isDbSynced) base += 10;
    if (isFirewallConfigured) base += 10;
    return Math.min(100, base);
  }, [isTlsActive, hasNoThreats, isDbSynced, isFirewallConfigured]);

  const frameworkScores = useMemo(() => {
    return {
      soc2: dynamicScore,
      nist: Math.min(100, Math.floor(dynamicScore * 1.02)),
      iso: Math.min(100, Math.floor(dynamicScore * 0.98)),
      gdpr: isDbSynced && hasNoThreats ? Math.min(100, Math.floor(dynamicScore * 1.05)) : Math.floor(dynamicScore * 0.85)
    };
  }, [dynamicScore, isDbSynced, hasNoThreats]);

  // 3. Define Compliance Controls List
  const controls: ComplianceControl[] = useMemo(() => [
    {
      id: 'SOC2-CC-1.1',
      framework: 'SOC 2 Type II',
      category: 'Trust Services Criteria - Security',
      name: 'Secure Transit & Handshaking',
      description: 'Enforce cryptographic transit protection (TLS 1.3 encapsulation) on edge networks and cloud gateway proxies.',
      status: isTlsActive ? 'COMPLIANT' : 'DEFICIENT',
      scoreImpact: 15
    },
    {
      id: 'NIST-PR.AC-1',
      framework: 'NIST CSF 2.0',
      category: 'Protect - Access Control',
      name: 'Intrusion Detection & Mitigation',
      description: 'Maintain zero active, uncontained critical or high-severity threat vulnerabilities across the infrastructure ledger.',
      status: hasNoThreats ? 'COMPLIANT' : 'DEFICIENT',
      scoreImpact: 15
    },
    {
      id: 'ISO-A.12.4.1',
      framework: 'ISO 27001:2022',
      category: 'Operations Security - Logging',
      name: 'Persistent Database Synchronizer',
      description: 'Synchronize threat analysis buffers with cloud-hosted database clusters for immutable auditing and history trails.',
      status: isDbSynced ? 'COMPLIANT' : 'DEFICIENT',
      scoreImpact: 10
    },
    {
      id: 'GDPR-ART-32',
      framework: 'GDPR Directive',
      category: 'Security of Personal Data',
      name: 'Active Ingress Firewall Shield',
      description: 'Deploy automated packet inspection and firewall filters targeting malicious SQL injection or anomalous data exfiltration vectors.',
      status: isFirewallConfigured ? 'COMPLIANT' : 'DEFICIENT',
      scoreImpact: 10
    }
  ], [isTlsActive, hasNoThreats, isDbSynced, isFirewallConfigured]);

  // 4. Export Cryptographically Signed Compliance Ledger
  const handleExportComplianceReport = async () => {
    try {
      const res = await fetch('/api/v1/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ framework: 'SOC2/NIST/ISO/GDPR', auditor: 'DeepShield Security Board' })
      });

      let jsonString: string;
      const filename = `deepshield_signed_compliance_report_${Date.now()}.json`;

      if (res.ok) {
        const data = await res.json();
        jsonString = JSON.stringify(data, null, 2);
        onLogMessage(`COMPLIANCE BOARD: Generated cryptographically signed compliance report! [HMAC SHA-256: ${data.report?.cryptographic_signature?.slice(0, 16)}...]`);
      } else {
        const compliancePayload = {
          compliance_report: {
            issuer: "DEEPSHIELD Enterprise Cybersecurity Compliance Board",
            certified_at: new Date().toISOString(),
            overall_readiness_score: `${dynamicScore}%`,
            individual_controls_audit: controls
          }
        };
        jsonString = JSON.stringify(compliancePayload, null, 2);
      }

      const blob = new Blob([jsonString], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      playSynthChime();
    } catch (e) {
      console.warn("Compliance export error:", e);
    }
  };

  const playSynthChime = () => {
    const AudioContextClass = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AudioContextClass) return;
    try {
      const ctx = new AudioContextClass();
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(523.25, now);
      osc.frequency.setValueAtTime(659.25, now + 0.1);
      osc.frequency.setValueAtTime(783.99, now + 0.2);
      gain.gain.setValueAtTime(0.02, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.5);
    } catch (e) {
      console.warn("Audio Context init failed", e);
    }
  };

  return (
    <div id="compliance-module" className="p-6 bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs dark:shadow-xl relative overflow-hidden min-h-[500px] text-slate-900 dark:text-slate-100">
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />
      
      {/* Header Panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-200 dark:border-slate-800 pb-4 mb-6 gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Award className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold tracking-widest uppercase">GOVERNANCE & AUDITING HUB</span>
          </div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white font-sans tracking-wide">Compliance & Governance Readiness</h2>
          <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 max-w-xl">
            Real-time compliance validation metrics tracked across major regulatory bodies. Score percentages recalculate dynamically as sandbox parameters, firewalls, and active threat instances update.
          </p>
        </div>

        {/* Export Auditor Data */}
        <button
          onClick={handleExportComplianceReport}
          className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-mono font-bold flex items-center justify-center gap-2 transition-all active:scale-95 shadow-md cursor-pointer"
        >
          <Download className="w-4 h-4 text-white" />
          EXPORT COMPLIANCE REPORT
        </button>
      </div>

      {/* Grid: Framework Progress Bars & Controls List */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Readiness Circular Progress Grid (Left 5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="text-[10px] font-bold text-slate-700 dark:text-slate-300 font-mono tracking-wider border-b border-slate-200 dark:border-slate-800 pb-2 uppercase">
            REGULATORY FRAMEWORK PERCENTAGES
          </div>

          <div className="grid grid-cols-2 gap-4">
            
            {/* SOC 2 Type II */}
            <div className="bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between h-[125px] shadow-xs">
              <div className="flex justify-between items-start font-mono">
                <span className="text-[10px] text-slate-700 dark:text-slate-400 font-bold">SOC 2 TYPE II</span>
                <span className="text-sm text-indigo-600 dark:text-indigo-400 font-extrabold">{frameworkScores.soc2}%</span>
              </div>
              <div className="w-full bg-slate-200 dark:bg-slate-900 h-2.5 rounded-full overflow-hidden mt-2 border border-slate-300 dark:border-slate-800">
                <div 
                  className="bg-indigo-600 h-full rounded-full transition-all duration-700"
                  style={{ width: `${frameworkScores.soc2}%` }}
                />
              </div>
              <span className="text-[9px] text-slate-500 dark:text-slate-400 font-mono mt-2 uppercase tracking-tight font-semibold">Trust Services Criteria</span>
            </div>

            {/* NIST CSF 2.0 */}
            <div className="bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between h-[125px] shadow-xs">
              <div className="flex justify-between items-start font-mono">
                <span className="text-[10px] text-slate-700 dark:text-slate-400 font-bold">NIST CSF 2.0</span>
                <span className="text-sm text-cyan-600 dark:text-cyan-400 font-extrabold">{frameworkScores.nist}%</span>
              </div>
              <div className="w-full bg-slate-200 dark:bg-slate-900 h-2.5 rounded-full overflow-hidden mt-2 border border-slate-300 dark:border-slate-800">
                <div 
                  className="bg-cyan-500 h-full rounded-full transition-all duration-700"
                  style={{ width: `${frameworkScores.nist}%` }}
                />
              </div>
              <span className="text-[9px] text-slate-500 dark:text-slate-400 font-mono mt-2 uppercase tracking-tight font-semibold">Identify & Protect</span>
            </div>

            {/* ISO 27001 */}
            <div className="bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between h-[125px] shadow-xs">
              <div className="flex justify-between items-start font-mono">
                <span className="text-[10px] text-slate-700 dark:text-slate-400 font-bold">ISO 27001</span>
                <span className="text-sm text-amber-600 dark:text-amber-400 font-extrabold">{frameworkScores.iso}%</span>
              </div>
              <div className="w-full bg-slate-200 dark:bg-slate-900 h-2.5 rounded-full overflow-hidden mt-2 border border-slate-300 dark:border-slate-800">
                <div 
                  className="bg-amber-500 h-full rounded-full transition-all duration-700"
                  style={{ width: `${frameworkScores.iso}%` }}
                />
              </div>
              <span className="text-[9px] text-slate-500 dark:text-slate-400 font-mono mt-2 uppercase tracking-tight font-semibold">InfoSec Controls</span>
            </div>

            {/* GDPR Compliance */}
            <div className="bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between h-[125px] shadow-xs">
              <div className="flex justify-between items-start font-mono">
                <span className="text-[10px] text-slate-700 dark:text-slate-400 font-bold">GDPR READINESS</span>
                <span className={`text-sm font-extrabold ${frameworkScores.gdpr >= 90 ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-600 dark:text-slate-400'}`}>{frameworkScores.gdpr}%</span>
              </div>
              <div className="w-full bg-slate-200 dark:bg-slate-900 h-2.5 rounded-full overflow-hidden mt-2 border border-slate-300 dark:border-slate-800">
                <div 
                  className={`h-full rounded-full transition-all duration-700 ${frameworkScores.gdpr >= 90 ? 'bg-emerald-500' : 'bg-slate-400'}`}
                  style={{ width: `${frameworkScores.gdpr}%` }}
                />
              </div>
              <span className="text-[9px] text-slate-500 dark:text-slate-400 font-mono mt-2 uppercase tracking-tight font-semibold">Privacy & Encryption</span>
            </div>

          </div>
        </div>

        {/* Detailed Controls Evaluation List (Right 7 Cols) */}
        <div className="lg:col-span-7 space-y-3">
          <div className="text-[10px] font-bold text-slate-700 dark:text-slate-300 font-mono tracking-wider border-b border-slate-200 dark:border-slate-800 pb-2 uppercase">
            DETAILED SECURITY CONTROLS SCORECARD
          </div>

          <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
            {controls.map((control) => {
              const isComp = control.status === 'COMPLIANT';
              
              return (
                <div 
                  key={control.id}
                  className={`p-3.5 rounded-xl border text-left flex items-start gap-3.5 transition-all shadow-xs ${
                    isComp 
                      ? 'bg-emerald-50/70 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/40' 
                      : 'bg-rose-50/70 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/40'
                  }`}
                >
                  <div className={`p-2 rounded-lg mt-0.5 ${isComp ? 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400' : 'bg-rose-100 dark:bg-rose-500/20 text-rose-700 dark:text-rose-400'}`}>
                    {isComp ? (
                      <CheckCircle2 className="w-4 h-4" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 animate-pulse" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center justify-between gap-1">
                      <span className="text-[10px] font-mono text-slate-600 dark:text-slate-400 font-bold uppercase">
                        {control.id} • {control.framework}
                      </span>
                      <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded uppercase border ${isComp ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800' : 'bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-800 animate-pulse'}`}>
                        {control.status}
                      </span>
                    </div>
                    
                    <h4 className="text-xs font-bold text-slate-900 dark:text-white mt-1 font-sans">
                      {control.name}
                    </h4>
                    
                    <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 font-sans leading-relaxed">
                      {control.description}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>
    </div>
  );
};

export default ComplianceGovernance;
