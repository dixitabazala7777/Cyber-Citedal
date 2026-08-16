import React, { useState } from 'react';
import { Database, Check, ShieldCheck, AlertCircle, Copy, RefreshCw } from 'lucide-react';

interface DatabaseSyncProps {
  isSynced: boolean;
}

export const DatabaseSync: React.FC<DatabaseSyncProps> = ({ isSynced }) => {
  const [copiedSql, setCopiedSql] = useState(false);
  const [showDocs, setShowDocs] = useState(false);

  const tableSchemaSql = `-- 1. Create Firewall Rules table
CREATE TABLE firewall_rules (
  id TEXT PRIMARY KEY,
  ip_range TEXT NOT NULL,
  description TEXT,
  action TEXT DEFAULT 'block',
  created_by TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  is_active BOOLEAN DEFAULT TRUE
);

-- 2. Create Incidents feed table
CREATE TABLE security_incidents (
  id TEXT PRIMARY KEY,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  source_ip TEXT NOT NULL,
  target_service TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  country_code TEXT NOT NULL,
  payload TEXT
);`;

  const handleCopySql = () => {
    navigator.clipboard.writeText(tableSchemaSql);
    setCopiedSql(true);
    setTimeout(() => setCopiedSql(false), 3000);
  };

  return (
    <div id="database-sync-card" className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl flex flex-col h-full text-xs transition-colors duration-200">
      <div className="flex justify-between items-start mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-sky-500 dark:text-sky-400" />
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Enterprise Database Hub</h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">Real-time cloud database telemetry & schema verification</p>
        </div>

        <button
          onClick={() => setShowDocs(!showDocs)}
          className="text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 px-3 py-1 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 hover:text-slate-900 dark:hover:text-white transition cursor-pointer"
        >
          {showDocs ? 'Hide Schema Guide' : 'Schema Guide'}
        </button>
      </div>

      {/* Integration Status Banner */}
      <div className={`p-4 border rounded-xl ${
        isSynced 
          ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400' 
          : 'bg-amber-500/10 border-amber-500/20 text-amber-700 dark:text-amber-400'
      }`}>
        <div className="flex items-start gap-3">
          {isSynced ? (
            <ShieldCheck className="w-5 h-5 text-emerald-500 dark:text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertCircle className="w-5 h-5 text-amber-500 dark:text-amber-400 shrink-0 mt-0.5" />
          )}
          <div className="space-y-1">
            <h3 className="font-semibold text-xs uppercase tracking-wider">
              {isSynced ? 'Supabase Connection Operational' : 'Local In-Memory Persistence'}
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              {isSynced 
                ? 'Active cloud PostgreSQL database connection established. Firewall policies and incident records sync automatically.' 
                : 'Running in local sandbox mode. Environment variables VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY are not active.'}
            </p>
          </div>
        </div>
      </div>

      {/* Passive Sync Status Indicator */}
      <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
        <div className="flex items-center gap-2">
          <RefreshCw className="w-3.5 h-3.5 text-sky-500 dark:text-sky-400 animate-spin" style={{ animationDuration: '6s' }} />
          <span>Telemetry Sync Engine: <strong className="text-slate-800 dark:text-slate-200 font-medium">{isSynced ? 'Cloud Synced' : 'Passive Local Monitor'}</strong></span>
        </div>
        <span className="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700 rounded-md text-[11px] font-mono">Latency: 24ms</span>
      </div>

      {/* Setup Guide Drawer */}
      {showDocs && (
        <div className="mt-4 p-4 border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 rounded-xl space-y-3">
          <h3 className="font-semibold text-slate-800 dark:text-slate-200 text-xs">Supabase Schema Initialization:</h3>
          <ol className="list-decimal list-inside space-y-1 text-slate-600 dark:text-slate-300 text-xs">
            <li>Configure environment variables <code className="text-sky-600 dark:text-sky-300 font-mono">VITE_SUPABASE_URL</code> and <code className="text-sky-600 dark:text-sky-300 font-mono">VITE_SUPABASE_ANON_KEY</code>.</li>
            <li>Run the SQL schema below in your database editor to initialize security tables:</li>
          </ol>

          <div className="relative bg-slate-950 border border-slate-800 rounded-lg p-3 max-h-[160px] overflow-y-auto">
            <button
              onClick={handleCopySql}
              className="absolute right-2 top-2 bg-slate-800 hover:bg-slate-700 p-1.5 border border-slate-700 rounded-lg text-slate-300 hover:text-white transition cursor-pointer"
              title="Copy SQL Schema"
            >
              {copiedSql ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
            <pre className="text-[11px] text-sky-400 font-mono select-all pr-8 leading-relaxed">
              {tableSchemaSql}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
