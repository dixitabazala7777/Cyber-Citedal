import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { SystemNode, FirewallRule, Incident } from '../types';
import { MitreMatrix } from './MitreMatrix';
import { SoarPlaybooks } from './SoarPlaybooks';
import { UebaDetector } from './UebaDetector';
import { ApiSecurity } from './ApiSecurity';
import { ComplianceGovernance } from './ComplianceGovernance';
import { KillChainTimeline } from './KillChainTimeline';
import { ChaosSimulator } from './ChaosSimulator';
import { HoneypotDashboard } from './HoneypotDashboard';
import { DigitalSignatureDetector } from './DigitalSignatureDetector';
import { 
  Shield, Zap, Eye, Braces, Award, ShieldCheck, Cpu, Crosshair, Flame, Bug, FileSignature
} from 'lucide-react';

interface SecOpsSuiteProps {
  incidents: Incident[];
  setIncidents: React.Dispatch<React.SetStateAction<Incident[]>>;
  onResolveIncident: (id: string) => void;
  onBlockIp: (ip: string, category: string) => void;
  nodes: SystemNode[];
  onIsolateNode: (id: string) => void;
  rules: FirewallRule[];
  setRules: React.Dispatch<React.SetStateAction<FirewallRule[]>>;
  dbLinkStatus: string;
  onLogMessage: (msg: string) => void;
  activeSubTabOverride?: SecOpsTab;
}

export type SecOpsTab = 'mitre' | 'digital-sig' | 'killchain' | 'soar' | 'ueba' | 'api-sec' | 'compliance' | 'chaos' | 'honeypot';

export const SecOpsSuite: React.FC<SecOpsSuiteProps> = ({
  incidents,
  setIncidents,
  onResolveIncident,
  onBlockIp,
  nodes,
  onIsolateNode,
  rules,
  setRules,
  dbLinkStatus,
  onLogMessage,
  activeSubTabOverride
}) => {
  const [activeSubTab, setActiveSubTab] = useState<SecOpsTab>(activeSubTabOverride || 'mitre');

  const subTabs = [
    { id: 'mitre', name: 'MITRE ATT&CK Matrix', icon: Shield, count: incidents.filter(i => i.status === 'active').length },
    { id: 'digital-sig', name: 'Digital Signatures', icon: FileSignature, count: 0 },
    { id: 'killchain', name: 'Kill-Chain Timeline', icon: Crosshair, count: 0 },
    { id: 'soar', name: 'SOAR Playbooks', icon: Zap, count: 0 },
    { id: 'ueba', name: 'UEBA Behavior', icon: Eye, count: 0 },
    { id: 'api-sec', name: 'API Security', icon: Braces, count: 0 },
    { id: 'compliance', name: 'Compliance', icon: Award, count: 0 },
    { id: 'chaos', name: 'Chaos Testing', icon: Flame, count: 0 },
    { id: 'honeypot', name: 'Honeypot Telemetry', icon: Bug, count: 0 }
  ];

  return (
    <div id="secops-suite-container" className="max-w-7xl w-full mx-auto px-4 mt-6 relative z-10 flex flex-col gap-5">
      
      {/* Sub Navigation Bar */}
      <div className="bg-white dark:bg-[#161b22] border border-slate-200 dark:border-[#30363d] rounded-xl p-2.5 flex flex-col md:flex-row justify-between items-center gap-3 shadow-xs dark:shadow-sm">
        <div className="flex flex-wrap gap-1.5 w-full md:w-auto">
          {subTabs.map((tab) => {
            const IconComp = tab.icon;
            const isSelected = activeSubTab === tab.id;
            
            return (
              <button
                key={tab.id}
                onClick={() => setActiveSubTab(tab.id as SecOpsTab)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-2 cursor-pointer ${
                  isSelected
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <IconComp className="w-3.5 h-3.5" />
                <span>{tab.name}</span>
                {tab.count > 0 && (
                  <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-semibold ${
                    isSelected ? 'bg-white text-blue-600' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                  }`}>
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Telemetry Indicator */}
        <div className="hidden lg:flex items-center gap-4 text-xs text-slate-400">
          <div className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-blue-400" />
            <span>SIEM Core: <strong className="text-slate-200">Active</strong></span>
          </div>
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Enclaves: <strong className="text-emerald-400">Operational</strong></span>
          </div>
        </div>
      </div>

      {/* Sub Tab View Container with Animation */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeSubTab}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          transition={{ duration: 0.15, ease: 'easeInOut' }}
        >
          {activeSubTab === 'mitre' && (
            <MitreMatrix 
              incidents={incidents} 
              onResolveIncident={onResolveIncident}
              onBlockIp={onBlockIp}
            />
          )}

          {activeSubTab === 'digital-sig' && (
            <DigitalSignatureDetector onLogMessage={onLogMessage} />
          )}

          {activeSubTab === 'soar' && (
            <SoarPlaybooks 
              nodes={nodes}
              onIsolateNode={onIsolateNode}
              rules={rules}
              setRules={setRules}
              incidents={incidents}
              setIncidents={setIncidents}
              onLogMessage={onLogMessage}
            />
          )}

          {activeSubTab === 'ueba' && (
            <UebaDetector onLogMessage={onLogMessage} />
          )}

          {activeSubTab === 'api-sec' && (
            <ApiSecurity onLogMessage={onLogMessage} />
          )}

          {activeSubTab === 'compliance' && (
            <ComplianceGovernance 
              incidents={incidents}
              nodes={nodes}
              rules={rules}
              dbLinkStatus={dbLinkStatus}
              onLogMessage={onLogMessage}
            />
          )}

          {activeSubTab === 'killchain' && (
            <KillChainTimeline
              incidents={incidents}
              onLogMessage={onLogMessage}
            />
          )}

          {activeSubTab === 'chaos' && (
            <ChaosSimulator onLogMessage={onLogMessage} />
          )}

          {activeSubTab === 'honeypot' && (
            <HoneypotDashboard 
              onLogMessage={onLogMessage}
              onBlockIp={(ip) => onBlockIp(ip, 'Honeypot Decoy Trap')}
            />
          )}
        </motion.div>
      </AnimatePresence>

    </div>
  );
};
