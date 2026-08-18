import React from 'react';
import { SystemNode } from '../types';
import { Server, Cpu, Percent, Zap, RefreshCw, ShieldAlert } from 'lucide-react';
import { BlastRadiusGraph } from './BlastRadiusGraph';

interface NodeManagerProps {
  nodes: SystemNode[];
  onRebootNode: (id: string) => void;
  onIsolateNode: (id: string) => void;
}

export const NodeManager: React.FC<NodeManagerProps> = ({
  nodes,
  onRebootNode,
  onIsolateNode
}) => {
  const getStatusColor = (status: SystemNode['status']) => {
    switch (status) {
      case 'operational':
        return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30 font-bold';
      case 'degraded':
        return 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30 font-bold animate-pulse';
      case 'offline':
        return 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30 font-bold';
      case 'isolated':
        return 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30 font-bold';
    }
  };

  const getLoadColor = (usage: number) => {
    if (usage > 85) return 'text-rose-600 dark:text-rose-400';
    if (usage > 65) return 'text-amber-600 dark:text-amber-400';
    return 'text-emerald-600 dark:text-emerald-400';
  };

  return (
    <div id="node-manager-card" className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs dark:shadow-xl flex flex-col h-full relative overflow-hidden transition-colors duration-200">
      {/* Header */}
      <div className="mb-4 pb-2 border-b border-slate-100 dark:border-slate-800/80">
        <div className="flex items-center gap-2">
          <div className="p-2 bg-sky-500/10 border border-sky-500/25 dark:border-sky-500/30 rounded-xl text-sky-600 dark:text-sky-400">
            <Server className="w-4 h-4" />
          </div>
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wide">Distributed Edge Gateway Nodes</h2>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Monitor, reboot, or isolate edge proxies and gateways</p>
      </div>

      {/* Nodes list */}
      <div className="flex-1 space-y-3 overflow-y-auto max-h-[350px] pr-1">
        {nodes.map((node) => (
          <div
            key={node.id}
            className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/90 hover:border-slate-300 dark:hover:border-slate-700 transition"
          >
            {/* Node Info & Status */}
            <div className="flex justify-between items-start gap-2">
              <div>
                <h4 className="text-xs font-bold text-slate-900 dark:text-slate-100 font-mono">{node.name}</h4>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">{node.region} • {node.id}</p>
              </div>
              <span className={`px-2.5 py-0.5 rounded-md text-[10px] uppercase tracking-wider border font-mono ${getStatusColor(node.status)}`}>
                {node.status}
              </span>
            </div>

            {/* Metrics */}
            <div className="grid grid-cols-3 gap-2 mt-3 text-[11px] font-mono border-t border-b border-slate-200 dark:border-slate-800/80 py-2.5 text-slate-700 dark:text-slate-300">
              <div className="flex items-center gap-1">
                <Cpu className="w-3.5 h-3.5 text-slate-400" />
                <span>CPU: <strong className={getLoadColor(node.cpuUsage)}>{node.cpuUsage}%</strong></span>
              </div>
              <div className="flex items-center gap-1">
                <Percent className="w-3.5 h-3.5 text-slate-400" />
                <span>MEM: <strong className={getLoadColor(node.memoryUsage)}>{node.memoryUsage}%</strong></span>
              </div>
              <div className="flex items-center gap-1">
                <Zap className="w-3.5 h-3.5 text-slate-400" />
                <span>PING: <strong className="text-sky-600 dark:text-sky-400 font-bold">{node.latency}ms</strong></span>
              </div>
            </div>

            {/* Load indicator */}
            <div className="w-full h-1.5 bg-slate-200 dark:bg-slate-900 rounded-full overflow-hidden mt-2 border border-slate-300 dark:border-slate-800">
              <div
                className={`h-full transition-all duration-500 rounded-full ${
                  node.cpuUsage > 85 ? 'bg-rose-500' : node.cpuUsage > 65 ? 'bg-amber-500' : 'bg-emerald-500 dark:bg-emerald-400'
                }`}
                style={{ width: `${node.cpuUsage}%` }}
              ></div>
            </div>

            {/* Actions */}
            <div className="flex justify-end gap-2 mt-3 text-xs font-mono pt-1">
              <button
                onClick={() => onRebootNode(node.id)}
                disabled={node.status === 'offline'}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800 rounded-xl transition cursor-pointer font-bold"
              >
                <RefreshCw className="w-3 h-3" />
                Reboot
              </button>
              <button
                onClick={() => onIsolateNode(node.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border transition cursor-pointer font-bold ${
                  node.status === 'isolated'
                    ? 'bg-sky-500/20 text-sky-700 dark:text-sky-300 border-sky-500/40'
                    : 'bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800'
                }`}
              >
                <ShieldAlert className="w-3 h-3" />
                {node.status === 'isolated' ? 'Re-Connect' : 'Isolate'}
              </button>
            </div>
          </div>
        ))}
      </div>

      <BlastRadiusGraph nodes={nodes} onIsolateNode={onIsolateNode} />
    </div>
  );
};
