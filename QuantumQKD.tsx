import React from 'react';
import { motion } from 'motion/react';
import { Shield, Cpu, Lock, CheckCircle2, BookOpen } from 'lucide-react';

interface QuantumQKDProps {
  onLogMessage?: (msg: string) => void;
}

const PQ_ALGORITHMS = [
  {
    name: 'ML-KEM (Kyber-1024)',
    type: 'Key Encapsulation (KEM)',
    status: 'NIST Standardized',
    useCase: 'Secure Handshakes & Session Keys',
    complexity: 'Lattice-based (Module-LWR)',
    speed: '12,450 ops/sec',
    securityLevel: 'AES-256 equivalent (Category 5)'
  },
  {
    name: 'ML-DSA (Dilithium-5)',
    type: 'Digital Signature',
    status: 'NIST Standardized',
    useCase: 'Identity Verification & Authentication',
    complexity: 'Lattice-based (Module-SIS)',
    speed: '8,120 ops/sec',
    securityLevel: 'Quantum Collision Resistant'
  },
  {
    name: 'FN-DSA (Falcon-1024)',
    type: 'Digital Signature',
    status: 'NIST Standardized',
    useCase: 'High-speed Edge Handshakes',
    complexity: 'Lattice-based (NTRU)',
    speed: '22,400 ops/sec (Ultra-low latency)',
    securityLevel: 'Category 5 Quantum Proof'
  },
  {
    name: 'SLH-DSA (SPHINCS+)',
    type: 'Stateful Signature',
    status: 'Backup Standard',
    useCase: 'Firmware Signatures & Cold Vaults',
    complexity: 'Hash-based Cryptography',
    speed: '340 ops/sec (Heavyweight)',
    securityLevel: 'Mathematically Indestructible'
  }
];

export const QuantumQKD: React.FC<QuantumQKDProps> = () => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6"
    >
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 shadow-sm">
        <div className="flex items-center justify-between mb-6 pb-4 border-b border-[#30363d]">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-blue-500/10 text-blue-400 rounded-lg border border-blue-500/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-50 flex items-center gap-2">
                NIST Post-Quantum Cryptographic Suite
                <span className="px-2 py-0.5 text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-md">
                  FIPS 203 / 204 Ready
                </span>
              </h2>
              <p className="text-sm text-slate-400">
                Post-quantum cryptographic specifications and standards reference matrix
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2 text-xs text-slate-400 bg-slate-800/60 px-3 py-1.5 rounded-lg border border-slate-700">
            <BookOpen className="w-4 h-4 text-slate-400" />
            <span>NIST PQC Standardization Round 4</span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {PQ_ALGORITHMS.map((algo) => (
            <div 
              key={algo.name}
              className="bg-[#21262d]/70 border border-[#30363d] rounded-lg p-4 hover:border-slate-500 transition-colors"
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-2">
                  <Cpu className="w-4 h-4 text-blue-400" />
                  <span className="font-medium text-slate-100">{algo.name}</span>
                </div>
                <span className="px-2 py-0.5 text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded">
                  {algo.status}
                </span>
              </div>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-400">Type:</span>
                  <span className="font-mono">{algo.type}</span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-400">Use Case:</span>
                  <span>{algo.useCase}</span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-400">Primitive:</span>
                  <span className="font-mono text-slate-300">{algo.complexity}</span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-400">Security:</span>
                  <span className="text-emerald-400 font-mono">{algo.securityLevel}</span>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-6 p-4 bg-slate-900/60 border border-slate-800 rounded-lg flex items-start space-x-3 text-xs text-slate-400">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-medium text-slate-200">Compliance & Migration Assurance:</span> All ingress handshakes are protected with hybrid key exchange protocols combining X25519 and ML-KEM-1024 according to IETF draft specifications.
          </div>
        </div>
      </div>
    </motion.div>
  );
};
