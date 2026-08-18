import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  FileSignature, KeyRound, ShieldCheck, ShieldAlert, CheckCircle2,
  AlertTriangle, XCircle, RefreshCw, Search,
  Fingerprint, Sparkles, Terminal, Copy, Check, Info, Lock
} from 'lucide-react';

interface SignatureRecord {
  id: string;
  timestamp: string;
  targetAsset: string;
  assetType: 'PE Binary' | 'Deb Package' | 'MSI Installer' | 'Kernel Driver' | 'JSON Web Signature' | 'Tarball Archive';
  issuer: string;
  rootCA: string;
  algorithm: 'RSA 4096' | 'RSA 2048' | 'ECDSA P-384' | 'ECDSA P-256' | 'Ed25519' | 'Dilithium3 (PQC)';
  hash: string;
  status: 'Valid' | 'Expired' | 'Revoked' | 'Untrusted CA' | 'Tampered';
  actionTaken: 'Allowed' | 'Quarantined' | 'Alerted';
  serialNumber: string;
  validFrom: string;
  validTo: string;
  ocspStatus: 'Good' | 'Revoked' | 'Unknown';
  timestampCounterSignature: boolean;
  rawSubject: string;
}

interface DigitalSignatureDetectorProps {
  onLogMessage: (msg: string) => void;
}

const INITIAL_SIGNATURES: SignatureRecord[] = [
  {
    id: 'SIG-9841',
    timestamp: 'Just now',
    targetAsset: 'deepshield-agent-v4.2.0.exe',
    assetType: 'PE Binary',
    issuer: 'DigiCert Trusted G4 Code Signing RSA4096',
    rootCA: 'DigiCert Global Root G4',
    algorithm: 'RSA 4096',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    status: 'Valid',
    actionTaken: 'Allowed',
    serialNumber: '0A:4B:99:E1:82:73:C0:5F',
    validFrom: '2025-01-15',
    validTo: '2027-01-15',
    ocspStatus: 'Good',
    timestampCounterSignature: true,
    rawSubject: 'CN=DeepShield Security Corp, O=DeepShield Inc, L=San Francisco, ST=CA, C=US'
  },
  {
    id: 'SIG-9840',
    timestamp: '2 mins ago',
    targetAsset: 'driver_hook_x64.sys',
    assetType: 'Kernel Driver',
    issuer: 'GlobalCert Ltd Kernel Signing Authority',
    rootCA: 'GlobalCert Primary Root',
    algorithm: 'RSA 2048',
    hash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
    status: 'Revoked',
    actionTaken: 'Quarantined',
    serialNumber: '7F:23:44:89:01:99:A1:CD',
    validFrom: '2024-03-10',
    validTo: '2026-03-10',
    ocspStatus: 'Revoked',
    timestampCounterSignature: false,
    rawSubject: 'CN=Unknown Kernel Publisher, O=Shenzhen Tech Ltd, C=CN (Revocation Reason: Private Key Compromise)'
  },
  {
    id: 'SIG-9839',
    timestamp: '8 mins ago',
    targetAsset: 'quantum_telemetry_mesh.bin',
    assetType: 'PE Binary',
    issuer: 'NIST FIPS 204 Post-Quantum Experimental CA',
    rootCA: 'Kyber/Dilithium Root Enclave',
    algorithm: 'Dilithium3 (PQC)',
    hash: '3a7bd3e2360a3d29eea436fcfb7e44c735d117f404415a6b96188865b0b6d445',
    status: 'Valid',
    actionTaken: 'Allowed',
    serialNumber: '11:AA:BB:CC:DD:EE:FF:00',
    validFrom: '2026-01-01',
    validTo: '2028-01-01',
    ocspStatus: 'Good',
    timestampCounterSignature: true,
    rawSubject: 'CN=Quantum Mesh Protocol, O=DeepShield Quantum Labs, C=US'
  },
  {
    id: 'SIG-9838',
    timestamp: '14 mins ago',
    targetAsset: 'update_tool_downloader.exe',
    assetType: 'PE Binary',
    issuer: 'Self-Signed: "CN=TempSignDev_CA"',
    rootCA: 'Untrusted Local Root',
    algorithm: 'RSA 2048',
    hash: '7d793037a0760186574b0282f2f435e70d71a4e4ec6a47990155a6549993306d',
    status: 'Untrusted CA',
    actionTaken: 'Quarantined',
    serialNumber: '00:00:00:00:00:00:00:01',
    validFrom: '2026-02-01',
    validTo: '2026-08-01',
    ocspStatus: 'Unknown',
    timestampCounterSignature: false,
    rawSubject: 'CN=TempSignDev_CA, O=Development Unverified, C=XX'
  },
  {
    id: 'SIG-9837',
    timestamp: '22 mins ago',
    targetAsset: 'patch_kb98214_sec.msi',
    assetType: 'MSI Installer',
    issuer: 'Microsoft Corporation Authenticode Authority',
    rootCA: 'Microsoft Root Certificate Authority 2011',
    algorithm: 'RSA 4096',
    hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    status: 'Valid',
    actionTaken: 'Allowed',
    serialNumber: '33:00:00:04:88:AC:32:1B',
    validFrom: '2024-05-12',
    validTo: '2027-05-12',
    ocspStatus: 'Good',
    timestampCounterSignature: true,
    rawSubject: 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, ST=WA, C=US'
  },
  {
    id: 'SIG-9836',
    timestamp: '35 mins ago',
    targetAsset: 'billing_sync_cli.bin',
    assetType: 'JSON Web Signature',
    issuer: 'Sectigo Public Code Signing CA R36',
    rootCA: 'Sectigo (Comodo) Root CA',
    algorithm: 'ECDSA P-256',
    hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    status: 'Expired',
    actionTaken: 'Alerted',
    serialNumber: '5C:11:89:EE:44:22:90:7A',
    validFrom: '2023-01-01',
    validTo: '2025-01-01',
    ocspStatus: 'Good',
    timestampCounterSignature: false,
    rawSubject: 'CN=Enterprise Billing Sync Services, O=Fintech Internal, C=US'
  },
  {
    id: 'SIG-9835',
    timestamp: '48 mins ago',
    targetAsset: 'nginx_edge_proxy.deb',
    assetType: 'Deb Package',
    issuer: 'Canonical Package Signing Authority P-384',
    rootCA: 'Ubuntu Debian Archive Root',
    algorithm: 'ECDSA P-384',
    hash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    status: 'Valid',
    actionTaken: 'Allowed',
    serialNumber: '9A:01:23:45:67:89:BC:DE',
    validFrom: '2025-06-01',
    validTo: '2028-06-01',
    ocspStatus: 'Good',
    timestampCounterSignature: true,
    rawSubject: 'CN=Canonical Ubuntu Signing, O=Canonical Ltd, L=London, C=GB'
  },
  {
    id: 'SIG-9834',
    timestamp: '1 hr ago',
    targetAsset: 'custom_monitoring_daemon',
    assetType: 'PE Binary',
    issuer: 'Tampered Signature (Hash digest mismatch with PKCS#7 envelope)',
    rootCA: 'Broken Trust Root',
    algorithm: 'RSA 2048',
    hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
    status: 'Tampered',
    actionTaken: 'Quarantined',
    serialNumber: 'DE:AD:BE:EF:00:11:22:33',
    validFrom: '2024-01-01',
    validTo: '2026-01-01',
    ocspStatus: 'Unknown',
    timestampCounterSignature: false,
    rawSubject: 'SIGNATURE_INTEGRITY_COMPROMISED: Embedded PE checksum does not match signed attribute'
  }
];

export const DigitalSignatureDetector: React.FC<DigitalSignatureDetectorProps> = ({ onLogMessage }) => {
  const [signatures, setSignatures] = useState<SignatureRecord[]>(INITIAL_SIGNATURES);
  const [filter, setFilter] = useState<'ALL' | 'VALID' | 'REVOKED' | 'EXPIRED' | 'UNTRUSTED' | 'TAMPERED'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRecord, setSelectedRecord] = useState<SignatureRecord | null>(null);

  // Policy switches
  const [strictCaChain, setStrictCaChain] = useState(true);
  const [autoBlockExpired, setAutoBlockExpired] = useState(true);
  const [enforceTimestamp, setEnforceTimestamp] = useState(true);
  const [isSyncingCrl, setIsSyncingCrl] = useState(false);
  const [crlSyncToast, setCrlSyncToast] = useState('');

  // Interactive Verification Engine Input
  const [hashInput, setHashInput] = useState('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  const [selectedAlg, setSelectedAlg] = useState<'SHA-256' | 'Authenticode' | 'GPG/PGP' | 'X.509 DER'>('SHA-256');
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{
    valid: boolean;
    subject: string;
    issuer: string;
    algorithm: string;
    trustScore: number;
    ocspStatus: string;
    details: string;
  } | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);

  // Metrics computation
  const totalAnalyzed = 14290;
  const validCount = 14269;
  const validPct = ((validCount / totalAnalyzed) * 100).toFixed(2);
  const revokedCount = 18;
  const anomalousCount = 3;

  const handleSyncCrl = () => {
    setIsSyncingCrl(true);
    setCrlSyncToast('');
    onLogMessage('DIGITAL SIGNATURE ENGINE: Querying CRL endpoints and OCSP responders for DigiCert, Sectigo, Microsoft, and Canonical...');
    
    setTimeout(() => {
      setIsSyncingCrl(false);
      setCrlSyncToast('CRL / OCSP Cache Synced: 2,410 serials updated across 3 edge gateway enclaves.');
      onLogMessage('DIGITAL SIGNATURE ENGINE: Revocation cache flush complete (2,410 serials validated).');
      setTimeout(() => setCrlSyncToast(''), 5000);
    }, 1200);
  };

  const handleRunVerification = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hashInput.trim()) return;

    setIsVerifying(true);
    setVerifyResult(null);
    onLogMessage(`DIGITAL SIGNATURE ENGINE: Parsing cryptographic payload hash [${hashInput.substring(0, 16)}...] via ${selectedAlg}`);

    setTimeout(() => {
      setIsVerifying(false);
      const isBad = hashInput.toLowerCase().includes('dead') || hashInput.toLowerCase().includes('bad') || hashInput.toLowerCase().includes('7d793');
      const isRevoked = hashInput.toLowerCase().includes('a591');

      if (isBad) {
        setVerifyResult({
          valid: false,
          subject: 'CN=Untrusted Development Entity, O=Unverified, C=XX',
          issuer: 'Self-Signed / Untrusted Local CA',
          algorithm: 'RSA 2048 (SHA-1 Digest Flagged)',
          trustScore: 12,
          ocspStatus: 'Untrusted Root Chain',
          details: 'CRITICAL: Certificate chain failed root validation. Not present in trusted Windows/Linux OS Trust Store.'
        });
        onLogMessage('DIGITAL SIGNATURE ENGINE: Verification Result: UNTRUSTED / SELF-SIGNED ROOT (Quarantined)');
      } else if (isRevoked) {
        setVerifyResult({
          valid: false,
          subject: 'CN=Compromised Kernel Publisher, O=Shenzhen Tech Ltd, C=CN',
          issuer: 'GlobalCert Ltd Kernel Signing Authority',
          algorithm: 'RSA 2048 (Authenticode PE)',
          trustScore: 0,
          ocspStatus: 'Revoked (CRL Reason: Key Compromise)',
          details: 'SECURITY ALERT: Serial 7F:23:44:89 listed on Active Certificate Revocation List (CRL). Binary blocked.'
        });
        onLogMessage('DIGITAL SIGNATURE ENGINE: Verification Result: REVOKED (OCSP Response Code: Revoked)');
      } else {
        setVerifyResult({
          valid: true,
          subject: 'CN=DeepShield Enterprise Infrastructure, O=DeepShield Inc, C=US',
          issuer: 'DigiCert Trusted G4 Code Signing RSA4096',
          algorithm: 'RSA 4096 (SHA-256 Authenticode + RFC 3161 Timestamp)',
          trustScore: 99.9,
          ocspStatus: 'Good (Next update in 24h)',
          details: 'CRYPTOGRAPHICALLY VALID: Signature intact, certificate chain fully validated to Trusted Root Authority.'
        });
        onLogMessage('DIGITAL SIGNATURE ENGINE: Verification Result: 100% VALID & TRUSTED (Allowed)');
      }
    }, 700);
  };

  const filteredSignatures = signatures.filter((s) => {
    const matchesSearch =
      s.targetAsset.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.issuer.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.hash.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.id.toLowerCase().includes(searchTerm.toLowerCase());

    if (!matchesSearch) return false;
    if (filter === 'ALL') return true;
    if (filter === 'VALID') return s.status === 'Valid';
    if (filter === 'REVOKED') return s.status === 'Revoked';
    if (filter === 'EXPIRED') return s.status === 'Expired';
    if (filter === 'UNTRUSTED') return s.status === 'Untrusted CA';
    if (filter === 'TAMPERED') return s.status === 'Tampered';
    return true;
  });

  const getStatusBadge = (status: SignatureRecord['status']) => {
    switch (status) {
      case 'Valid':
        return 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30';
      case 'Revoked':
        return 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30';
      case 'Expired':
        return 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30';
      case 'Untrusted CA':
        return 'bg-purple-500/15 text-purple-700 dark:text-purple-400 border-purple-500/30';
      case 'Tampered':
        return 'bg-red-600/20 text-red-600 dark:text-red-400 border-red-500/40 animate-pulse';
    }
  };

  const getActionBadge = (action: SignatureRecord['actionTaken']) => {
    switch (action) {
      case 'Allowed':
        return 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border border-emerald-500/20';
      case 'Quarantined':
        return 'text-rose-600 dark:text-rose-400 bg-rose-500/10 border border-rose-500/20 font-bold';
      case 'Alerted':
        return 'text-amber-600 dark:text-amber-400 bg-amber-500/10 border border-amber-500/20';
    }
  };

  return (
    <div id="digital-signature-detector" className="space-y-6">
      
      {/* 1. Header Banner */}
      <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs dark:shadow-xl relative overflow-hidden transition-colors duration-200">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-sky-500 via-indigo-500 to-emerald-500" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="p-3 bg-sky-500/10 text-sky-600 dark:text-sky-400 rounded-2xl border border-sky-500/25 dark:border-sky-500/30 shrink-0">
              <FileSignature className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-900 dark:text-white uppercase tracking-wider font-mono">
                  Digital Signature & PKI Integrity Inspector
                </h2>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/30">
                  X.509 / PKCS#7 / PQC
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-3xl">
                Continuous binary integrity verification, Authenticode validation, Certificate Revocation List (CRL) synchronization, and post-quantum cryptographic signature auditing.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              onClick={handleSyncCrl}
              disabled={isSyncingCrl}
              className="px-3.5 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-xl text-xs font-mono font-bold transition flex items-center gap-2 cursor-pointer shadow-xs"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isSyncingCrl ? 'animate-spin' : ''}`} />
              <span>{isSyncingCrl ? 'Syncing CRL...' : 'Sync CRL / OCSP Responders'}</span>
            </button>
          </div>
        </div>

        {crlSyncToast && (
          <motion.div
            initial={{ opacity: 0, y: -5 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-xs font-mono text-emerald-700 dark:text-emerald-300 flex items-center gap-2"
          >
            <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
            <span>{crlSyncToast}</span>
          </motion.div>
        )}
      </div>

      {/* 2. Key Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Analyzed */}
        <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400 mb-2">
            <span>TOTAL SIGNATURES</span>
            <KeyRound className="w-4 h-4 text-sky-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white tracking-tight">
            {totalAnalyzed.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-[11px] font-mono text-emerald-600 dark:text-emerald-400">
            <Sparkles className="w-3 h-3" />
            <span>+284 binaries audited today</span>
          </div>
        </div>

        {/* Card 2: Valid & Trusted */}
        <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400 mb-2">
            <span>VALID & TRUSTED</span>
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400">
              {validCount.toLocaleString()}
            </span>
            <span className="text-xs font-mono text-slate-500">({validPct}%)</span>
          </div>
          <div className="mt-2 text-[11px] font-mono text-slate-500 dark:text-slate-400">
            Trusted Root CA chain verified
          </div>
        </div>

        {/* Card 3: Invalid / Revoked */}
        <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400 mb-2">
            <span>INVALID / REVOKED</span>
            <AlertTriangle className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-600 dark:text-amber-400">
            {revokedCount} detected
          </div>
          <div className="mt-2 text-[11px] font-mono text-amber-700 dark:text-amber-300">
            12 Expired • 6 Revoked by CRL
          </div>
        </div>

        {/* Card 4: Anomalous / Self-Signed */}
        <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400 mb-2">
            <span>ANOMALOUS / UNTRUSTED</span>
            <ShieldAlert className="w-4 h-4 text-rose-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-600 dark:text-rose-400">
            {anomalousCount} flagged
          </div>
          <div className="mt-2 text-[11px] font-mono text-rose-600 dark:text-rose-400 font-bold">
            Quarantined in zero-trust sandbox
          </div>
        </div>
      </div>

      {/* 3. Real-Time Verification Engine & Algorithm Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Cols: Interactive Signature Verification Panel */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs dark:shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-sky-500/10 text-sky-600 dark:text-sky-400 rounded-xl border border-sky-500/25 dark:border-sky-500/30">
                <Terminal className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                  Live Hash & Authenticode Verification Engine
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Inspect binary digests against CRL registries, OCSP stapling, and certificate chains
                </p>
              </div>
            </div>
            <span className="hidden sm:inline-flex text-[10px] font-mono px-2 py-0.5 bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-400 rounded border border-slate-200 dark:border-slate-800">
              RFC 5280 / FIPS 140-3
            </span>
          </div>

          {/* Form */}
          <form onSubmit={handleRunVerification} className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <label className="text-[11px] font-mono text-slate-600 dark:text-slate-400 block mb-1">
                  PAYLOAD / BINARY DIGEST (SHA-256 / SHA-512)
                </label>
                <div className="relative">
                  <Fingerprint className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={hashInput}
                    onChange={(e) => setHashInput(e.target.value)}
                    placeholder="Enter 64-character hex hash or binary signature..."
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 focus:border-sky-500 rounded-xl pl-9 pr-3 py-2 text-xs font-mono text-slate-900 dark:text-white placeholder-slate-400 outline-none transition"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-600 dark:text-slate-400 block mb-1">
                  SIGNATURE FORMAT
                </label>
                <select
                  value={selectedAlg}
                  onChange={(e) => setSelectedAlg(e.target.value as any)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 focus:border-sky-500 rounded-xl px-3 py-2 text-xs font-mono text-slate-900 dark:text-white outline-none cursor-pointer"
                >
                  <option value="SHA-256">SHA-256 Payload Hash</option>
                  <option value="Authenticode">Microsoft Authenticode PE</option>
                  <option value="GPG/PGP">GPG / PGP Detached Signature</option>
                  <option value="X.509 DER">X.509 DER Certificate</option>
                </select>
              </div>
            </div>

            {/* Quick Hash Presets & Submit */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
              <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono text-slate-500">
                <span>Test Presets:</span>
                <button
                  type="button"
                  onClick={() => setHashInput('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')}
                  className="px-2 py-0.5 bg-slate-100 dark:bg-slate-950 hover:bg-slate-200 dark:hover:bg-slate-800 rounded border border-slate-200 dark:border-slate-800 text-sky-600 dark:text-sky-400 transition cursor-pointer"
                >
                  DeepShield Agent (Valid)
                </button>
                <button
                  type="button"
                  onClick={() => setHashInput('a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e')}
                  className="px-2 py-0.5 bg-slate-100 dark:bg-slate-950 hover:bg-slate-200 dark:hover:bg-slate-800 rounded border border-slate-200 dark:border-slate-800 text-rose-600 dark:text-rose-400 transition cursor-pointer"
                >
                  Driver Hook (Revoked)
                </button>
                <button
                  type="button"
                  onClick={() => setHashInput('7d793037a0760186574b0282f2f435e70d71a4e4ec6a47990155a6549993306d')}
                  className="px-2 py-0.5 bg-slate-100 dark:bg-slate-950 hover:bg-slate-200 dark:hover:bg-slate-800 rounded border border-slate-200 dark:border-slate-800 text-purple-600 dark:text-purple-400 transition cursor-pointer"
                >
                  TempDev (Self-Signed)
                </button>
              </div>

              <button
                type="submit"
                disabled={isVerifying}
                className="px-4 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-xl text-xs font-mono font-bold transition flex items-center gap-1.5 cursor-pointer shadow-xs"
              >
                {isVerifying ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Verifying Chain...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Verify Signature Integrity</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Verification Result Card */}
          {verifyResult && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className={`p-4 rounded-xl border text-xs font-mono space-y-3 ${
                verifyResult.valid
                  ? 'bg-emerald-500/10 border-emerald-500/30'
                  : 'bg-rose-500/10 border-rose-500/30'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  {verifyResult.valid ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                  ) : (
                    <XCircle className="w-5 h-5 text-rose-500" />
                  )}
                  <span className="font-bold text-sm text-slate-900 dark:text-white uppercase">
                    {verifyResult.valid ? 'Cryptographically Valid Signature' : 'Validation Failed • Threat Vector Identified'}
                  </span>
                </div>
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${
                  verifyResult.valid
                    ? 'bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border-emerald-500/40'
                    : 'bg-rose-500/20 text-rose-600 dark:text-rose-400 border-rose-500/40'
                }`}>
                  TRUST SCORE: {verifyResult.trustScore}/100
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] pt-1">
                <div>
                  <span className="text-slate-500 block">SUBJECT:</span>
                  <span className="text-slate-900 dark:text-white font-bold">{verifyResult.subject}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">ISSUING CA:</span>
                  <span className="text-slate-900 dark:text-white font-bold">{verifyResult.issuer}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">ALGORITHM & PADDING:</span>
                  <span className="text-sky-600 dark:text-cyan-400 font-bold">{verifyResult.algorithm}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">OCSP REVOCATION STATUS:</span>
                  <span className={verifyResult.valid ? 'text-emerald-600 dark:text-emerald-400 font-bold' : 'text-rose-600 dark:text-rose-400 font-bold'}>
                    {verifyResult.ocspStatus}
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200 dark:border-slate-800 text-[11px] text-slate-600 dark:text-slate-300">
                {verifyResult.details}
              </div>
            </motion.div>
          )}
        </div>

        {/* Right Col: Algorithm Breakdown & Policy Sandbox */}
        <div className="space-y-6">
          
          {/* Algorithm Breakdown Widget */}
          <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-slate-200 dark:border-slate-800">
              <span className="font-bold text-slate-900 dark:text-white uppercase tracking-wider text-[11px]">
                Cryptographic Distribution
              </span>
              <span className="text-[10px] text-sky-600 dark:text-sky-400 font-bold">100% Ingress</span>
            </div>

            <div className="space-y-2.5">
              <div>
                <div className="flex justify-between text-[10px] text-slate-600 dark:text-slate-400 mb-1">
                  <span>RSA 4096-bit (PKCS#1 v1.5 / PSS)</span>
                  <span className="font-bold text-slate-900 dark:text-white">68.4%</span>
                </div>
                <div className="w-full h-1.5 bg-slate-100 dark:bg-slate-950 rounded-full overflow-hidden">
                  <div className="bg-sky-500 h-full rounded-full" style={{ width: '68.4%' }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[10px] text-slate-600 dark:text-slate-400 mb-1">
                  <span>ECDSA P-384 / P-256 (Suite B)</span>
                  <span className="font-bold text-slate-900 dark:text-white">27.2%</span>
                </div>
                <div className="w-full h-1.5 bg-slate-100 dark:bg-slate-950 rounded-full overflow-hidden">
                  <div className="bg-indigo-500 h-full rounded-full" style={{ width: '27.2%' }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[10px] text-slate-600 dark:text-slate-400 mb-1">
                  <span>Ed25519 (EdDSA RFC 8032)</span>
                  <span className="font-bold text-slate-900 dark:text-white">3.8%</span>
                </div>
                <div className="w-full h-1.5 bg-slate-100 dark:bg-slate-950 rounded-full overflow-hidden">
                  <div className="bg-emerald-500 h-full rounded-full" style={{ width: '3.8%' }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[10px] text-slate-600 dark:text-slate-400 mb-1">
                  <span className="text-purple-600 dark:text-purple-400 font-bold">Post-Quantum Dilithium3 (FIPS 204)</span>
                  <span className="font-bold text-purple-600 dark:text-purple-400">0.6%</span>
                </div>
                <div className="w-full h-1.5 bg-slate-100 dark:bg-slate-950 rounded-full overflow-hidden">
                  <div className="bg-purple-500 h-full rounded-full" style={{ width: '0.6%' }} />
                </div>
              </div>
            </div>
          </div>

          {/* Quick Action & Policy Sandbox Controls */}
          <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs dark:shadow-xl space-y-3 font-mono text-xs">
            <div className="flex items-center gap-2 pb-2 border-b border-slate-200 dark:border-slate-800">
              <Lock className="w-4 h-4 text-sky-500" />
              <h3 className="font-bold text-slate-900 dark:text-white uppercase tracking-wider text-[11px]">
                Enforcement Policies
              </h3>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-slate-800 dark:text-slate-200 font-bold block text-[11px]">Strict CA Chain Validation</span>
                  <span className="text-[10px] text-slate-500">Require trusted public root store</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setStrictCaChain(!strictCaChain);
                    onLogMessage(`POLICY UPDATE: Strict CA Chain Enforcement set to ${!strictCaChain}`);
                  }}
                  className={`w-10 h-5 rounded-full transition-colors cursor-pointer relative p-0.5 ${
                    strictCaChain ? 'bg-sky-600' : 'bg-slate-300 dark:bg-slate-700'
                  }`}
                >
                  <div className={`w-4 h-4 rounded-full bg-white transition-transform ${strictCaChain ? 'translate-x-5' : 'translate-x-0'}`} />
                </button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <span className="text-slate-800 dark:text-slate-200 font-bold block text-[11px]">Auto-Block Expired / Self-Signed</span>
                  <span className="text-[10px] text-slate-500">Isolate invalid binaries at edge</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setAutoBlockExpired(!autoBlockExpired);
                    onLogMessage(`POLICY UPDATE: Auto-Block Expired/Self-Signed set to ${!autoBlockExpired}`);
                  }}
                  className={`w-10 h-5 rounded-full transition-colors cursor-pointer relative p-0.5 ${
                    autoBlockExpired ? 'bg-sky-600' : 'bg-slate-300 dark:bg-slate-700'
                  }`}
                >
                  <div className={`w-4 h-4 rounded-full bg-white transition-transform ${autoBlockExpired ? 'translate-x-5' : 'translate-x-0'}`} />
                </button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <span className="text-slate-800 dark:text-slate-200 font-bold block text-[11px]">RFC 3161 Timestamping</span>
                  <span className="text-[10px] text-slate-500">Enforce verified time token</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setEnforceTimestamp(!enforceTimestamp);
                    onLogMessage(`POLICY UPDATE: RFC 3161 Timestamp Enforcement set to ${!enforceTimestamp}`);
                  }}
                  className={`w-10 h-5 rounded-full transition-colors cursor-pointer relative p-0.5 ${
                    enforceTimestamp ? 'bg-sky-600' : 'bg-slate-300 dark:bg-slate-700'
                  }`}
                >
                  <div className={`w-4 h-4 rounded-full bg-white transition-transform ${enforceTimestamp ? 'translate-x-5' : 'translate-x-0'}`} />
                </button>
              </div>
            </div>
          </div>

        </div>

      </div>

      {/* 4. Live Signature Telemetry Table & Inspector */}
      <div className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs dark:shadow-xl space-y-4 font-mono text-xs">
        
        {/* Table Filter Controls */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              Live Ingress Signature Telemetry Log
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800">
              {filteredSignatures.length} records
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search binary, issuer, hash..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-900 dark:text-white placeholder-slate-400 outline-none focus:border-sky-500 transition w-48 sm:w-60"
              />
            </div>

            {/* Filter pills */}
            <div className="flex items-center bg-slate-100 dark:bg-slate-950 p-0.5 rounded-xl border border-slate-200 dark:border-slate-800 text-[10px] font-bold">
              {(['ALL', 'VALID', 'REVOKED', 'EXPIRED', 'UNTRUSTED', 'TAMPERED'] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`px-2 py-1 rounded-lg transition cursor-pointer ${
                    filter === f
                      ? 'bg-sky-600 text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Telemetry Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-[10px] text-slate-500 uppercase tracking-wider">
                <th className="py-2.5 px-3">Timestamp / ID</th>
                <th className="py-2.5 px-3">Target Asset / Binary</th>
                <th className="py-2.5 px-3">Issuer Authority / Root CA</th>
                <th className="py-2.5 px-3">Algorithm</th>
                <th className="py-2.5 px-3">Validation Status</th>
                <th className="py-2.5 px-3">Action Taken</th>
                <th className="py-2.5 px-3 text-right">Certificate Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-xs">
              {filteredSignatures.map((record) => (
                <tr
                  key={record.id}
                  onClick={() => setSelectedRecord(record)}
                  className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition cursor-pointer group"
                >
                  <td className="py-3 px-3">
                    <div className="font-bold text-slate-900 dark:text-white">{record.id}</div>
                    <div className="text-[10px] text-slate-500">{record.timestamp}</div>
                  </td>
                  <td className="py-3 px-3">
                    <div className="font-bold text-slate-900 dark:text-white group-hover:text-sky-600 dark:group-hover:text-sky-400 transition">
                      {record.targetAsset}
                    </div>
                    <div className="text-[10px] text-slate-500">{record.assetType}</div>
                  </td>
                  <td className="py-3 px-3">
                    <div className="text-slate-800 dark:text-slate-200 truncate max-w-xs" title={record.issuer}>
                      {record.issuer}
                    </div>
                    <div className="text-[10px] text-slate-500 truncate max-w-xs" title={record.rootCA}>
                      Root: {record.rootCA}
                    </div>
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800">
                      {record.algorithm}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${getStatusBadge(record.status)}`}>
                      {record.status.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] ${getActionBadge(record.actionTaken)}`}>
                      {record.actionTaken}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedRecord(record);
                      }}
                      className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 hover:bg-sky-500/20 hover:text-sky-600 dark:hover:text-sky-400 border border-slate-200 dark:border-slate-700 rounded-lg text-[10px] font-bold transition cursor-pointer"
                    >
                      Inspect X.509
                    </button>
                  </td>
                </tr>
              ))}

              {filteredSignatures.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 text-xs">
                    No digital signature telemetry records found matching your filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 5. Certificate Chain & Detail Inspector Modal */}
      <AnimatePresence>
        {selectedRecord && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              className="w-full max-w-2xl bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden font-mono text-xs max-h-[90vh] flex flex-col"
            >
              {/* Modal Header */}
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileSignature className="w-5 h-5 text-sky-500" />
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                      X.509 Digital Certificate Dossier
                    </h3>
                    <p className="text-[10px] text-slate-500">{selectedRecord.targetAsset} ({selectedRecord.id})</p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedRecord(null)}
                  className="p-1 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 hover:text-slate-900 dark:hover:text-white transition cursor-pointer"
                >
                  ✕
                </button>
              </div>

              {/* Modal Content */}
              <div className="p-5 overflow-y-auto space-y-4 flex-1">
                
                {/* Status Bar */}
                <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800">
                  <div>
                    <span className="text-[10px] text-slate-500 block">VALIDATION STATE</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border mt-0.5 inline-block ${getStatusBadge(selectedRecord.status)}`}>
                      {selectedRecord.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-slate-500 block">ACTION TAKEN</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] mt-0.5 inline-block ${getActionBadge(selectedRecord.actionTaken)}`}>
                      {selectedRecord.actionTaken}
                    </span>
                  </div>
                </div>

                {/* X.509 Attributes Table */}
                <div className="space-y-2 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 bg-slate-50/50 dark:bg-slate-950">
                  <div className="flex justify-between border-b border-slate-200 dark:border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Subject Distinguished Name:</span>
                    <span className="text-slate-900 dark:text-white font-bold text-right max-w-sm">{selectedRecord.rawSubject}</span>
                  </div>

                  <div className="flex justify-between border-b border-slate-200 dark:border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Issuing Certificate Authority:</span>
                    <span className="text-slate-900 dark:text-white font-bold text-right">{selectedRecord.issuer}</span>
                  </div>

                  <div className="flex justify-between border-b border-slate-200 dark:border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Root CA Anchor:</span>
                    <span className="text-sky-600 dark:text-cyan-400 font-bold">{selectedRecord.rootCA}</span>
                  </div>

                  <div className="flex justify-between border-b border-slate-200 dark:border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Serial Number:</span>
                    <span className="text-slate-800 dark:text-slate-200 font-bold">{selectedRecord.serialNumber}</span>
                  </div>

                  <div className="flex justify-between border-b border-slate-200 dark:border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Cryptographic Algorithm:</span>
                    <span className="text-slate-800 dark:text-slate-200 font-bold">{selectedRecord.algorithm}</span>
                  </div>

                  <div className="flex justify-between border-b border-slate-200 dark:border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Validity Period:</span>
                    <span className="text-slate-800 dark:text-slate-200 font-bold">{selectedRecord.validFrom} to {selectedRecord.validTo}</span>
                  </div>

                  <div className="flex justify-between border-b border-slate-200 dark:border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">RFC 3161 Counter-Signature Token:</span>
                    <span className={selectedRecord.timestampCounterSignature ? 'text-emerald-600 dark:text-emerald-400 font-bold' : 'text-slate-500 font-bold'}>
                      {selectedRecord.timestampCounterSignature ? 'Present & Validated' : 'None'}
                    </span>
                  </div>

                  <div className="flex justify-between">
                    <span className="text-slate-500">OCSP Revocation Status:</span>
                    <span className={selectedRecord.ocspStatus === 'Good' ? 'text-emerald-600 dark:text-emerald-400 font-bold' : 'text-rose-600 dark:text-rose-400 font-bold'}>
                      {selectedRecord.ocspStatus}
                    </span>
                  </div>
                </div>

                {/* Hash Digest Box */}
                <div>
                  <span className="text-[10px] text-slate-500 block mb-1">SHA-256 HASH DIGEST:</span>
                  <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px]">
                    <span className="text-sky-600 dark:text-cyan-400 break-all select-all">{selectedRecord.hash}</span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(selectedRecord.hash);
                        setCopiedHash(true);
                        setTimeout(() => setCopiedHash(false), 2000);
                      }}
                      className="ml-2 p-1.5 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-500 hover:text-slate-900 dark:hover:text-white transition cursor-pointer"
                      title="Copy Hash"
                    >
                      {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

              </div>

              {/* Modal Footer */}
              <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 flex items-center justify-between">
                <span className="text-[10px] text-slate-500">DeepShield X.509 PKI Verifier v4.2</span>
                <button
                  onClick={() => setSelectedRecord(null)}
                  className="px-4 py-1.5 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-xl text-xs font-bold transition cursor-pointer"
                >
                  Close Dossier
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
};
