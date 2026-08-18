import React, { useState } from 'react';
import { z } from 'zod';
import { FirewallRule } from '../types';
import { Shield, Plus, Trash2, ToggleLeft, ToggleRight, Check, AlertCircle } from 'lucide-react';

interface FirewallRulesProps {
  rules: FirewallRule[];
  onAddRule: (rule: Omit<FirewallRule, 'id' | 'createdAt' | 'createdBy'>) => void;
  onToggleRule: (id: string) => void;
  onDeleteRule: (id: string) => void;
  autoContainmentEnabled: boolean;
  onToggleAutoContainment: (enabled: boolean) => void;
}

const ruleSchema = z.object({
  ipRange: z.string()
    .min(1, 'IP address or CIDR range is required')
    .refine((val) => {
      const ipCidrPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/[0-9]{1,2})?$/;
      return ipCidrPattern.test(val);
    }, 'Invalid IP/CIDR block format (e.g. 192.168.1.0/24 or 45.14.23.1)'),
  description: z.string().min(3, 'Description must be at least 3 characters long'),
  action: z.enum(['block', 'bypass', 'challenge'] as const)
});

export const FirewallRules: React.FC<FirewallRulesProps> = ({
  rules,
  onAddRule,
  onToggleRule,
  onDeleteRule,
  autoContainmentEnabled,
  onToggleAutoContainment
}) => {
  const [showAddForm, setShowAddForm] = useState(false);
  const [ipRange, setIpRange] = useState('');
  const [description, setDescription] = useState('');
  const [action, setAction] = useState<FirewallRule['action']>('block');
  const [formErrors, setFormErrors] = useState<{ ipRange?: string; description?: string }>({});
  const [successMsg, setSuccessMsg] = useState('');

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormErrors({});
    setSuccessMsg('');

    const validation = ruleSchema.safeParse({ ipRange, description, action });

    if (!validation.success) {
      const formattedErrors: typeof formErrors = {};
      validation.error.issues.forEach((issue) => {
        const path = issue.path[0] as 'ipRange' | 'description';
        formattedErrors[path] = issue.message;
      });
      setFormErrors(formattedErrors);
      return;
    }

    onAddRule({ ipRange, description, action, isActive: true });
    
    setIpRange('');
    setDescription('');
    setAction('block');
    setShowAddForm(false);
    setSuccessMsg('Firewall rule compiled successfully!');
    setTimeout(() => setSuccessMsg(''), 4000);
  };

  const getActionBadge = (act: FirewallRule['action']) => {
    switch (act) {
      case 'block':
        return 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/25';
      case 'challenge':
        return 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/25';
      case 'bypass':
        return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/25';
    }
  };

  return (
    <div id="firewall-rules-card" className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl flex flex-col h-full transition-colors duration-200">
      {/* Title Header */}
      <div className="flex justify-between items-start mb-4 gap-2">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-sky-500 dark:text-sky-400" />
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Active Firewall Policy Ruleset</h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">Manage packet filter block and bypass rules</p>
        </div>

        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium rounded-xl transition cursor-pointer shadow-xs"
        >
          <Plus className="w-3.5 h-3.5" />
          Add Rule
        </button>
      </div>

      {/* Auto-Containment Toggle Banner */}
      <div className="mb-4 px-3.5 py-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl flex items-center justify-between">
        <div className="space-y-0.5">
          <span className="text-xs font-semibold text-sky-600 dark:text-sky-400 flex items-center gap-1.5">
            <span className={`w-1.5 h-1.5 rounded-full ${autoContainmentEnabled ? 'bg-emerald-500 dark:bg-emerald-400 animate-pulse' : 'bg-slate-400 dark:bg-slate-600'}`} />
            Auto-Containment Engine
          </span>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">Auto-isolate IP addresses with reputation score &lt; 30</p>
        </div>
        <button
          onClick={() => onToggleAutoContainment(!autoContainmentEnabled)}
          className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition cursor-pointer"
        >
          {autoContainmentEnabled ? (
            <ToggleRight className="w-7 h-7 text-sky-500 dark:text-sky-400" />
          ) : (
            <ToggleLeft className="w-7 h-7 text-slate-400 dark:text-slate-600" />
          )}
        </button>
      </div>

      {successMsg && (
        <div className="mb-3 px-3 py-2 border border-emerald-500/25 bg-emerald-500/10 rounded-xl text-emerald-600 dark:text-emerald-400 text-xs flex items-center gap-2">
          <Check className="w-4 h-4" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Add Rule Form */}
      {showAddForm && (
        <form onSubmit={handleFormSubmit} className="mb-4 p-4 border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 rounded-xl space-y-3 text-xs font-mono">
          <h3 className="font-semibold text-slate-900 dark:text-slate-200 border-b border-slate-200 dark:border-slate-800 pb-1.5">New Policy Constructor</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="text-slate-600 dark:text-slate-400 text-[11px] block mb-1">IP Range / CIDR block</label>
              <input
                type="text"
                value={ipRange}
                onChange={(e) => setIpRange(e.target.value)}
                placeholder="e.g. 192.168.1.0/24"
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
              />
              {formErrors.ipRange && (
                <span className="text-rose-500 text-[10px] mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" />
                  {formErrors.ipRange}
                </span>
              )}
            </div>

            <div>
              <label className="text-slate-600 dark:text-slate-400 text-[11px] block mb-1">Action</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value as FirewallRule['action'])}
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500 cursor-pointer font-mono"
              >
                <option value="block">BLOCK</option>
                <option value="challenge">CHALLENGE</option>
                <option value="bypass">BYPASS</option>
              </select>
            </div>
          </div>

          <div>
            <label className="text-slate-600 dark:text-slate-400 text-[11px] block mb-1">Description</label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="e.g. Reject aggressive port probes"
              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
            />
            {formErrors.description && (
              <span className="text-rose-500 text-[10px] mt-1 flex items-center gap-1">
                <AlertCircle className="w-3 h-3" />
                {formErrors.description}
              </span>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={() => { setShowAddForm(false); setFormErrors({}); }}
              className="px-3 py-1 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded-lg transition cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-3.5 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded-lg font-medium transition cursor-pointer shadow-xs"
            >
              Compile & Inject
            </button>
          </div>
        </form>
      )}

      {/* Rules feed */}
      <div className="flex-1 space-y-2 overflow-y-auto max-h-[300px] pr-1">
        {rules.map((rule) => (
          <div
            key={rule.id}
            className={`p-3 rounded-xl border flex justify-between items-center bg-slate-50 dark:bg-slate-950 ${
              rule.isActive ? 'border-slate-200 dark:border-slate-800' : 'border-slate-200/50 dark:border-slate-800/50 opacity-60'
            }`}
          >
            <div className="font-mono text-xs space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-slate-900 dark:text-slate-100 font-semibold">{rule.ipRange}</span>
                <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${getActionBadge(rule.action)}`}>
                  {rule.action}
                </span>
              </div>
              <p className="text-slate-500 dark:text-slate-400 text-[11px] font-sans">{rule.description}</p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => onToggleRule(rule.id)}
                className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition cursor-pointer"
              >
                {rule.isActive ? (
                  <ToggleRight className="w-7 h-7 text-sky-500 dark:text-sky-400" />
                ) : (
                  <ToggleLeft className="w-7 h-7 text-slate-400 dark:text-slate-600" />
                )}
              </button>
              <button
                onClick={() => onDeleteRule(rule.id)}
                className="text-slate-400 hover:text-rose-500 transition cursor-pointer"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
