import React, { useEffect, useRef, useState, useMemo } from 'react';
import { motion } from 'motion/react';
import * as d3 from 'd3';
import { Network, AlertTriangle, Shield, Wifi, Server, Radio } from 'lucide-react';
import { SystemNode } from '../types';

interface BlastRadiusGraphProps {
  nodes: SystemNode[];
  onIsolateNode: (id: string) => void;
}

interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  type: 'gateway' | 'service' | 'database' | 'cache';
  status: string;
  risk: number;
  ports: number[];
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  id: string;
  strength: number;
  encrypted: boolean;
}

const SERVICE_TOPOLOGY: { id: string; label: string; type: GraphNode['type']; ports: number[] }[] = [
  { id: 'api-gateway', label: 'API Gateway', type: 'gateway', ports: [443, 80, 8443] },
  { id: 'auth-svc', label: 'Auth Service', type: 'service', ports: [8081] },
  { id: 'user-svc', label: 'User Service', type: 'service', ports: [8082] },
  { id: 'payment-svc', label: 'Payment Engine', type: 'service', ports: [8083, 8443] },
  { id: 'notification-svc', label: 'Notification Hub', type: 'service', ports: [8084] },
  { id: 'postgres-primary', label: 'PostgreSQL Primary', type: 'database', ports: [5432] },
  { id: 'redis-cache', label: 'Redis Cache', type: 'cache', ports: [6379] },
  { id: 's3-storage', label: 'Object Storage', type: 'service', ports: [443] },
];

const LINKS: { source: string; target: string; encrypted: boolean }[] = [
  { source: 'api-gateway', target: 'auth-svc', encrypted: true },
  { source: 'api-gateway', target: 'user-svc', encrypted: true },
  { source: 'api-gateway', target: 'payment-svc', encrypted: true },
  { source: 'api-gateway', target: 'notification-svc', encrypted: true },
  { source: 'auth-svc', target: 'postgres-primary', encrypted: true },
  { source: 'auth-svc', target: 'redis-cache', encrypted: true },
  { source: 'user-svc', target: 'postgres-primary', encrypted: true },
  { source: 'payment-svc', target: 'postgres-primary', encrypted: true },
  { source: 'payment-svc', target: 'redis-cache', encrypted: false },
  { source: 'notification-svc', target: 'redis-cache', encrypted: true },
  { source: 'user-svc', target: 's3-storage', encrypted: true },
];

export const BlastRadiusGraph: React.FC<BlastRadiusGraphProps> = ({ nodes: gatewayNodes, onIsolateNode }) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [breachedNode, setBreachedNode] = useState<string | null>(null);

  // Compute blast radius
  const blastRadius = useMemo(() => {
    if (!breachedNode) return new Set<string>();
    const affected = new Set<string>();
    affected.add(breachedNode);
    // BFS: find all directly and indirectly connected nodes
    const queue = [breachedNode];
    while (queue.length > 0) {
      const current = queue.shift()!;
      for (const link of LINKS) {
        if (link.source === current && !affected.has(link.target)) {
          affected.add(link.target);
          queue.push(link.target);
        }
        if (link.target === current && !affected.has(link.source)) {
          affected.add(link.source);
          queue.push(link.source);
        }
      }
    }
    return affected;
  }, [breachedNode]);

  const blastRiskRating = useMemo(() => {
    if (!breachedNode) return 0;
    const ratio = blastRadius.size / SERVICE_TOPOLOGY.length;
    return Math.round(ratio * 100);
  }, [breachedNode, blastRadius]);

  // D3 Graph Rendering
  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;
    const width = containerRef.current.clientWidth;
    const height = 320;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    svg.attr('width', width).attr('height', height);

    const graphNodes: GraphNode[] = SERVICE_TOPOLOGY.map(s => ({
      id: s.id,
      label: s.label,
      type: s.type,
      status: blastRadius.has(s.id) ? 'compromised' : 'operational',
      risk: blastRadius.has(s.id) ? 85 : 10,
      ports: s.ports,
    }));

    const graphLinks: GraphLink[] = LINKS.map((l, i) => ({
      id: `link-${i}`,
      source: l.source,
      target: l.target,
      strength: l.encrypted ? 0.8 : 0.4,
      encrypted: l.encrypted,
    }));

    const simulation = d3.forceSimulation(graphNodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(graphLinks).id(d => d.id).distance(80).strength(0.5))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(30));

    // Draw links
    const link = svg.append('g')
      .selectAll('line')
      .data(graphLinks)
      .join('line')
      .attr('stroke', d => {
        const s = typeof d.source === 'object' ? (d.source as GraphNode).id : d.source;
        const t = typeof d.target === 'object' ? (d.target as GraphNode).id : d.target;
        if (blastRadius.has(s as string) && blastRadius.has(t as string)) return '#ef4444';
        return d.encrypted ? '#334155' : '#78350f';
      })
      .attr('stroke-width', d => {
        const s = typeof d.source === 'object' ? (d.source as GraphNode).id : d.source;
        const t = typeof d.target === 'object' ? (d.target as GraphNode).id : d.target;
        if (blastRadius.has(s as string) && blastRadius.has(t as string)) return 2;
        return 1;
      })
      .attr('stroke-dasharray', d => d.encrypted ? '0' : '4,4')
      .attr('stroke-opacity', 0.6);

    // Draw nodes
    const nodeColor = (d: GraphNode) => {
      if (d.id === breachedNode) return '#dc2626';
      if (blastRadius.has(d.id)) return '#f59e0b';
      return d.type === 'gateway' ? '#3b82f6' : d.type === 'database' ? '#8b5cf6' : d.type === 'cache' ? '#14b8a6' : '#64748b';
    };

    const node = svg.append('g')
      .selectAll('g')
      .data(graphNodes)
      .join('g')
      .style('cursor', 'pointer')
      .on('click', (_, d) => {
        setSelectedNode(d.id);
        setBreachedNode(prev => prev === d.id ? null : d.id);
      });

    // Outer glow for breached
    node.append('circle')
      .attr('r', d => d.id === breachedNode ? 22 : blastRadius.has(d.id) ? 18 : 0)
      .attr('fill', 'none')
      .attr('stroke', d => d.id === breachedNode ? '#dc2626' : '#f59e0b')
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.3)
      .attr('stroke-dasharray', '3,3');

    node.append('circle')
      .attr('r', d => d.id === breachedNode ? 16 : 12)
      .attr('fill', nodeColor)
      .attr('stroke', '#0f172a')
      .attr('stroke-width', 2)
      .attr('opacity', 0.9);

    node.append('text')
      .text(d => d.label)
      .attr('y', 24)
      .attr('text-anchor', 'middle')
      .attr('fill', '#94a3b8')
      .attr('font-size', '9px')
      .attr('font-family', 'monospace');

    simulation.on('tick', () => {
      link
        .attr('x1', d => (d.source as any).x)
        .attr('y1', d => (d.source as any).y)
        .attr('x2', d => (d.target as any).x)
        .attr('y2', d => (d.target as any).y);

      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => { simulation.stop(); };
  }, [breachedNode, blastRadius]);

  return (
    <div className="bg-[#0f172a]/60 border border-slate-800 rounded-xl p-4 mt-4">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-blue-400" />
          <span className="text-xs font-semibold text-slate-300">Zero-Trust Blast Radius Visualizer</span>
        </div>
        <div className="flex items-center gap-3 text-[10px] font-mono">
          {breachedNode && (
            <span className="flex items-center gap-1 text-rose-400">
              <AlertTriangle className="w-3 h-3" />
              Blast Radius: {blastRiskRating}% ({blastRadius.size}/{SERVICE_TOPOLOGY.length} services)
            </span>
          )}
          <span className="text-slate-600">Click a node to simulate breach</span>
        </div>
      </div>

      <div ref={containerRef} className="w-full bg-slate-950/50 rounded-lg border border-slate-800/50 overflow-hidden">
        <svg ref={svgRef} className="w-full" />
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3 mt-3 text-[9px] font-mono text-slate-600">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" /> Gateway</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-slate-500" /> Service</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-violet-500" /> Database</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-teal-500" /> Cache</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Breached</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-500" /> Affected</span>
      </div>
    </div>
  );
};
