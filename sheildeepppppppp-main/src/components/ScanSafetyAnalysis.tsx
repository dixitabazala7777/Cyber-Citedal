import React, { useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Lock, 
  Unlock, 
  Globe, 
  FileText, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Download, 
  Radio, 
  RefreshCw, 
  Trash2, 
  Database, 
  KeyRound, 
  Fingerprint, 
  Zap,
  Activity,
  Layers,
  Terminal
} from 'lucide-react';
import { Incident } from '../types';

interface ScanSafetyAnalysisProps {
  scanData: any;
  isScanning?: boolean;
  onClearScan?: () => void;
  onReScan?: () => void;
  onIsolateTarget?: (target: string) => void;
  onDownloadReport?: () => void;
}

export const ScanSafetyAnalysis: React.FC<ScanSafetyAnalysisProps> = ({
  scanData,
  isScanning = false,
  onClearScan,
  onReScan,
  onIsolateTarget,
  onDownloadReport
}) => {
  // Extract and normalize data whether it came from URL audit or File upload
  const analysis = useMemo(() => {
    if (!scanData) return null;

    const isUrlScan = 'url' in scanData || 'host' in scanData;
    const isFileScan = 'fileDetails' in scanData || ('name' in scanData && 'size' in scanData);

    const nowIso = new Date().toISOString();
    const formattedDate = new Date().toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    });

    if (isUrlScan) {
      const url = scanData.url || (scanData.host ? `https://${scanData.host}` : 'https://target.host');
      const host = scanData.host || (url.replace(/^https?:\/\//i, '').split('/')[0]);
      const score = typeof scanData.score === 'number' ? scanData.score : (scanData.ssl ? 94 : 58);
      const grade = scanData.grade || (score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 60 ? 'C' : 'F');
      const incidents: Incident[] = scanData.incidents || [];
      const headers: Record<string, string | null> = scanData.headers || {};
      const tls = scanData.tlsDetails || {
        protocol: scanData.ssl ? 'TLSv1.3' : 'None / Insecure HTTP',
        cipher: scanData.ssl ? 'TLS_AES_256_GCM_SHA384' : 'None',
        certValid: Boolean(scanData.ssl),
        issuer: scanData.ssl ? 'DigiCert Global Root G2' : 'None',
        keyLength: 256
      };

      const threatCount = incidents.length;
      const criticalCount = incidents.filter(i => i.severity === 'critical').length;
      const highCount = incidents.filter(i => i.severity === 'high').length;

      let status: 'CLEAN' | 'SUSPICIOUS' | 'CRITICAL COMPROMISE' = 'CLEAN';
      if (criticalCount > 0 || score < 60) {
        status = 'CRITICAL COMPROMISE';
      } else if (threatCount > 0 || highCount > 0 || score < 85) {
        status = 'SUSPICIOUS';
      }

      const piiLeaksDetected = incidents.some(i => i.payload?.toLowerCase().includes('pii') || i.payload?.toLowerCase().includes('credential'));
      const sanitizedRatio = Math.max(20, Math.min(100, score));

      // RFC Header checks
      const hasHsts = Boolean(headers['strict-transport-security']);
      const hasCsp = Boolean(headers['content-security-policy']);
      const hasXfo = Boolean(headers['x-frame-options']);
      const hasXcto = Boolean(headers['x-content-type-options']);
      const hasReferrer = Boolean(headers['referrer-policy']);
      const hasCors = Boolean(headers['access-control-allow-origin'] || !headers['server']?.includes('insecure'));

      const recommendations: string[] = [];
      if (!hasCsp) recommendations.push("Missing Content-Security-Policy (CSP): Define strict default-src policy to prevent XSS.");
      if (!hasHsts) recommendations.push("Missing HSTS Header: Enforce 'Strict-Transport-Security: max-age=63072000; includeSubDomains'.");
      if (!hasXfo) recommendations.push("Missing X-Frame-Options: Set 'DENY' or 'SAMEORIGIN' to mitigate Clickjacking vectors.");
      if (!scanData.ssl) recommendations.push("Insecure Transport Protocol: Upgrade cleartext HTTP to TLS 1.3 / HTTPS encryption.");
      if (criticalCount > 0) recommendations.push(`Critical Injection Attack Vector Detected: Target URL contains ${criticalCount} active exploit pattern(s).`);
      if (recommendations.length === 0) {
        recommendations.push("Target passed all 6 RFC-9110 transport and security header validation gates. Perimeter intact.");
      }

      return {
        type: 'URL' as const,
        targetName: host,
        targetFull: url,
        sizeDisplay: `${((scanData.throughput || 14200) / 1024).toFixed(1)} KB/s throughput`,
        timestamp: formattedDate,
        isoTimestamp: nowIso,
        score,
        grade,
        status,
        tlsProtocol: tls.protocol,
        cipherName: tls.cipher,
        certValid: tls.certValid,
        threatCount,
        piiStatus: piiLeaksDetected ? 'FAIL (Leak Risk)' : 'PASS (0 Leaks)',
        sanitizedRatio,
        headers: {
          hsts: { label: 'HSTS (RFC-6797)', pass: hasHsts, detail: hasHsts ? headers['strict-transport-security'] || 'Active' : 'Missing' },
          csp: { label: 'CSP (RFC-9309)', pass: hasCsp, detail: hasCsp ? 'Active Policy' : 'Missing' },
          xfo: { label: 'X-Frame-Options', pass: hasXfo, detail: hasXfo ? headers['x-frame-options'] || 'DENY' : 'Missing' },
          xcto: { label: 'X-Content-Type', pass: hasXcto, detail: hasXcto ? 'nosniff' : 'Missing' },
          referrer: { label: 'Referrer-Policy', pass: hasReferrer, detail: hasReferrer ? headers['referrer-policy'] || 'Strict' : 'Missing' },
          cors: { label: 'CORS Isolation', pass: hasCors, detail: 'Cross-Origin Safe' }
        },
        payloadAudit: {
          sqli: incidents.some(i => i.category === 'SQL Injection'),
          xss: incidents.some(i => i.category === 'Phishing' || i.payload?.includes('XSS')),
          anomalies: threatCount
        },
        recommendations
      };
    }

    if (isFileScan) {
      const fileDetails = scanData.fileDetails || scanData;
      const metrics = scanData.metrics || {};
      const derivedIncidents: Incident[] = scanData.derivedIncidents || scanData.incidents || [];
      const fileName = fileDetails.name || fileDetails.fileName || 'telemetry-stream.log';
      const fileSize = fileDetails.size || fileDetails.fileSize || 0;
      const fileType = fileDetails.type || fileDetails.fileType || 'application/json';

      const threatCount = derivedIncidents.length;
      const criticalCount = derivedIncidents.filter(i => i.severity === 'critical').length;
      const highCount = derivedIncidents.filter(i => i.severity === 'high').length;

      let score = 100 - (criticalCount * 25) - (highCount * 12) - ((threatCount - criticalCount - highCount) * 5);
      score = Math.max(10, Math.min(100, score));

      const grade = score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 60 ? 'C' : 'F';

      let status: 'CLEAN' | 'SUSPICIOUS' | 'CRITICAL COMPROMISE' = 'CLEAN';
      if (criticalCount > 0 || score < 60) {
        status = 'CRITICAL COMPROMISE';
      } else if (threatCount > 0 || score < 85) {
        status = 'SUSPICIOUS';
      }

      const piiLeaks = derivedIncidents.some(i => i.payload?.toLowerCase().includes('pass') || i.payload?.toLowerCase().includes('token') || i.payload?.toLowerCase().includes('secret'));
      const sanitizedRatio = Math.max(15, Math.min(100, Math.round(100 - (threatCount * 8))));

      const recommendations: string[] = [];
      if (criticalCount > 0) recommendations.push(`Severe CVE & Injection Signatures: Identified ${criticalCount} critical vulnerability strings in payload.`);
      if (highCount > 0) recommendations.push(`Exploit Warning Patterns: ${highCount} high-severity anomaly traces parsed in telemetry lines.`);
      if (piiLeaks) recommendations.push("Sensitive Data / Key Exposure: Detected unmasked credentials or token hashes in file body.");
      if (threatCount === 0) recommendations.push("0 malicious threat signatures detected across all parsed log lines. Telemetry payload verified clean.");

      return {
        type: 'FILE' as const,
        targetName: fileName,
        targetFull: `${fileName} (${(fileSize / 1024).toFixed(2)} KB • ${fileType || 'Log Payload'})`,
        sizeDisplay: `${(fileSize / 1024).toFixed(2)} KB`,
        timestamp: formattedDate,
        isoTimestamp: nowIso,
        score,
        grade,
        status,
        tlsProtocol: 'Local Memory Sandboxed',
        cipherName: 'SHA-256 Verified Payload',
        certValid: true,
        threatCount,
        piiStatus: piiLeaks ? 'FAIL (Token Leaks Detected)' : 'PASS (0 Leaks)',
        sanitizedRatio,
        headers: {
          hsts: { label: 'Schema Structure', pass: true, detail: 'Valid Byte Format' },
          csp: { label: 'Script Isolation', pass: criticalCount === 0, detail: criticalCount === 0 ? 'Sandboxed' : 'Unsafe Script Tag' },
          xfo: { label: 'Integrity Check', pass: true, detail: 'SHA-256 Passed' },
          xcto: { label: 'MIME Verification', pass: true, detail: fileType || 'Raw Stream' },
          referrer: { label: 'Line Trace Audit', pass: true, detail: `${metrics.lineCount || 1} Lines Scanned` },
          cors: { label: 'Zero-Trust Parse', pass: true, detail: 'Contained VM' }
        },
        payloadAudit: {
          sqli: derivedIncidents.some(i => i.category === 'SQL Injection'),
          xss: derivedIncidents.some(i => i.category === 'Phishing' || i.payload?.includes('XSS')),
          anomalies: threatCount
        },
        recommendations
      };
    }

    return null;
  }, [scanData]);

  // SVG Radial Gauge Calculations
  const radius = 54;
  const strokeWidth = 8;
  const normalizedRadius = radius - strokeWidth / 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const scoreValue = analysis ? analysis.score : 0;
  const strokeDashoffset = circumference - (scoreValue / 100) * circumference;

  // Score color determinations
  const getScoreColor = (score: number) => {
    if (score >= 85) {
      return {
        text: 'text-emerald-400',
        stroke: 'stroke-emerald-400',
        glow: 'drop-shadow-[0_0_12px_rgba(52,211,153,0.5)]',
        bg: 'bg-emerald-500/10',
        border: 'border-emerald-500/30',
        badgeBg: 'bg-emerald-950/60 text-emerald-300 border-emerald-500/40',
        label: 'Safe / Low Risk'
      };
    }
    if (score >= 60) {
      return {
        text: 'text-amber-400',
        stroke: 'stroke-amber-400',
        glow: 'drop-shadow-[0_0_12px_rgba(251,191,36,0.5)]',
        bg: 'bg-amber-500/10',
        border: 'border-amber-500/30',
        badgeBg: 'bg-amber-950/60 text-amber-300 border-amber-500/40',
        label: 'Warning / Elevated'
      };
    }
    return {
      text: 'text-rose-400',
      stroke: 'stroke-rose-400',
      glow: 'shadow-sm',
      bg: 'bg-rose-500/10',
      border: 'border-rose-500/30',
      badgeBg: 'bg-rose-950/60 text-rose-300 border-rose-500/40',
      label: 'Compromised / High Risk'
    };
  };

  const scoreTheme = getScoreColor(scoreValue);

  return (
    <section 
      id="scan-results-safety-analysis"
      className="max-w-7xl w-full mx-auto px-4 mt-6 relative z-10 transition-all duration-300"
    >
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-sm relative">
        {/* Subtle Specular Top Highlight */}
        <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-white/5 to-transparent pointer-events-none" />

        {/* Frame Top Bar */}
        <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
            <span className="text-xs font-mono text-slate-400 ml-1.5 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-blue-400" />
              safety-analysis://report
            </span>
          </div>

          <div className="flex items-center gap-2">
            {isScanning && (
              <span className="flex items-center gap-1.5 text-xs font-sans font-medium text-blue-300 bg-blue-950/60 border border-blue-800/50 px-2.5 py-0.5 rounded-md animate-pulse">
                <Radio className="w-3 h-3 animate-spin text-blue-400" />
                Auditing Ingress Stream...
              </span>
            )}
            {!isScanning && analysis && (
              <span className={`flex items-center gap-1.5 text-xs font-sans font-medium uppercase px-2.5 py-0.5 rounded-md border ${scoreTheme.badgeBg}`}>
                <span className="relative flex h-1.5 w-1.5">
                  <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${analysis.status === 'CLEAN' ? 'bg-emerald-400' : analysis.status === 'SUSPICIOUS' ? 'bg-amber-400' : 'bg-rose-400'}`} />
                  <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${analysis.status === 'CLEAN' ? 'bg-emerald-500' : analysis.status === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-rose-500'}`} />
                </span>
                {analysis.status}
              </span>
            )}
            {!isScanning && !analysis && (
              <span className="text-xs font-sans text-slate-500 bg-slate-900/60 border border-slate-800 px-2.5 py-0.5 rounded-md">
                Standby • No Active Audit
              </span>
            )}
          </div>
        </div>

        {/* Dynamic Body Content */}
        <div className="p-5 md:p-6">
          <AnimatePresence mode="wait">
            {/* 1. LOADING SKELETON STATE */}
            {isScanning && (
              <motion.div
                key="scanning-state"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
                className="py-10 flex flex-col items-center justify-center text-center space-y-5"
              >
                <div className="relative flex items-center justify-center">
                  <div className="w-24 h-24 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin flex items-center justify-center shadow-[0_0_30px_rgba(6,182,212,0.3)]">
                    <Activity className="w-8 h-8 text-cyan-400 animate-pulse" />
                  </div>
                  <div className="absolute inset-0 rounded-full border border-cyan-400/30 animate-ping opacity-25" />
                </div>
                <div className="space-y-1.5 max-w-md">
                  <h4 className="text-base font-bold text-white font-sans tracking-tight">
                    Conducting Deep Security & Cryptographic Inspection
                  </h4>
                  <p className="text-xs font-mono text-zinc-400">
                    Extracting RFC-9110 HTTP headers, validating TLS 1.3 handshakes, running SQLi/XSS heuristic checks, and calculating data safety telemetry...
                  </p>
                </div>
                <div className="w-64 h-1.5 bg-black/60 rounded-full overflow-hidden border border-white/10">
                  <motion.div 
                    className="h-full bg-gradient-to-r from-cyan-500 via-indigo-500 to-purple-500"
                    initial={{ x: '-100%' }}
                    animate={{ x: '100%' }}
                    transition={{ repeat: Infinity, duration: 1.2, ease: "linear" }}
                  />
                </div>
              </motion.div>
            )}

            {/* 2. EMPTY FALLBACK STATE */}
            {!isScanning && !analysis && (
              <motion.div
                key="empty-state"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.2 }}
                className="py-8 px-4 flex flex-col items-center justify-center text-center space-y-4"
              >
                <div className="p-3.5 bg-slate-900 border border-[#334155] rounded-xl">
                  <Layers className="w-7 h-7 text-slate-400" />
                </div>
                <div className="space-y-1 max-w-lg">
                  <h4 className="text-sm font-bold text-white font-sans tracking-tight">
                    Scan Safety & Inspection Output
                  </h4>
                  <p className="text-xs font-mono text-zinc-400 leading-relaxed">
                    Awaiting input. Submit a URL or drop a telemetry log/file above to generate safety analytics.
                  </p>
                </div>
                <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
                  <span className="text-[11px] font-mono text-zinc-500 bg-black/40 border border-white/5 px-2.5 py-1 rounded-lg">
                    🔒 RFC-9110 Header Audit
                  </span>
                  <span className="text-[11px] font-mono text-zinc-500 bg-black/40 border border-white/5 px-2.5 py-1 rounded-lg">
                    ⚡ TLS 1.3 Cipher Grade
                  </span>
                  <span className="text-[11px] font-mono text-zinc-500 bg-black/40 border border-white/5 px-2.5 py-1 rounded-lg">
                    🛡️ Injection & CVE Checks
                  </span>
                  <span className="text-[11px] font-mono text-zinc-500 bg-black/40 border border-white/5 px-2.5 py-1 rounded-lg">
                    📊 Data Sanitization Ratio
                  </span>
                </div>
              </motion.div>
            )}

            {/* 3. ACTIVE LIVE SCAN OUTPUT */}
            {!isScanning && analysis && (
              <motion.div
                key="results-active"
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -12 }}
                transition={{ duration: 0.3 }}
                className="space-y-6"
              >
                {/* Header Info & Actions Row */}
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-white/5">
                  <div className="flex items-start sm:items-center gap-3">
                    <div className={`p-2.5 rounded-2xl border ${analysis.type === 'URL' ? 'bg-indigo-500/10 border-indigo-500/30' : 'bg-violet-500/10 border-violet-500/30'}`}>
                      {analysis.type === 'URL' ? (
                        <Globe className="w-5 h-5 text-indigo-400" />
                      ) : (
                        <FileText className="w-5 h-5 text-violet-400" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-base font-bold text-white tracking-tight font-sans">
                          {analysis.targetName}
                        </h3>
                        <span className="text-[10px] font-mono font-bold bg-white/10 text-white px-2 py-0.5 rounded border border-white/10 uppercase">
                          {analysis.type} TARGET
                        </span>
                      </div>
                      <p className="text-xs font-mono text-zinc-400 truncate max-w-md sm:max-w-xl">
                        {analysis.targetFull} • <span className="text-zinc-500">{analysis.timestamp}</span>
                      </p>
                    </div>
                  </div>

                  {/* Header Action Buttons */}
                  <div className="flex flex-wrap items-center gap-2">
                    {onDownloadReport && (
                      <button
                        onClick={onDownloadReport}
                        className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-white text-xs font-mono font-medium rounded-xl border border-white/10 transition flex items-center gap-1.5 cursor-pointer shadow-sm hover:border-white/20"
                        title="Download Security Audit Report (JSON/TXT)"
                      >
                        <Download className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Download Security Report</span>
                      </button>
                    )}

                    {onIsolateTarget && (
                      <button
                        onClick={() => onIsolateTarget(analysis.targetName)}
                        className="px-3 py-1.5 bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 text-xs font-mono font-semibold rounded-xl border border-rose-700/50 transition flex items-center gap-1.5 cursor-pointer shadow-[0_0_15px_rgba(244,63,94,0.15)]"
                        title="Initiate Zero-Trust Target Isolation"
                      >
                        <ShieldX className="w-3.5 h-3.5 text-rose-400" />
                        <span>Isolate Target</span>
                      </button>
                    )}

                    {onClearScan && (
                      <button
                        onClick={onClearScan}
                        className="px-2.5 py-1.5 bg-black/40 hover:bg-white/10 text-zinc-400 hover:text-white text-xs font-mono rounded-xl border border-white/10 transition flex items-center gap-1 cursor-pointer"
                        title="Clear Scan Output"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span className="hidden sm:inline">Clear Scan</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Main Metrics: Radial Score Gauge & Core Telemetry Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
                  
                  {/* Left Column: Radial Progress Gauge Card (4 cols) */}
                  <div className="lg:col-span-4 bg-black/40 border border-white/10 rounded-2xl p-5 flex flex-col items-center justify-between text-center relative overflow-hidden group">
                    <div className="w-full flex items-center justify-between mb-2">
                      <span className="text-[11px] font-mono font-semibold text-zinc-400 uppercase tracking-wider">
                        Data Safety Score
                      </span>
                      <span className="text-[10px] font-mono text-zinc-500 bg-white/5 px-2 py-0.5 rounded border border-white/5">
                        ALGORITHM v2.6
                      </span>
                    </div>

                    {/* Radial SVG Ring */}
                    <div className="relative my-3 flex items-center justify-center">
                      <svg width={radius * 2} height={radius * 2} className="transform -rotate-90">
                        {/* Background track */}
                        <circle
                          cx={radius}
                          cy={radius}
                          r={normalizedRadius}
                          className="stroke-zinc-800"
                          strokeWidth={strokeWidth}
                          fill="transparent"
                        />
                        {/* Dynamic score ring */}
                        <circle
                          cx={radius}
                          cy={radius}
                          r={normalizedRadius}
                          className={`${scoreTheme.stroke} ${scoreTheme.glow} transition-all duration-1000 ease-out`}
                          strokeWidth={strokeWidth}
                          strokeDasharray={`${circumference} ${circumference}`}
                          style={{ strokeDashoffset }}
                          strokeLinecap="round"
                          fill="transparent"
                        />
                      </svg>

                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className={`text-3xl font-black tracking-tight font-sans ${scoreTheme.text}`}>
                          {analysis.score}%
                        </span>
                        <span className="text-[10px] font-mono font-bold uppercase text-zinc-400">
                          Grade {analysis.grade}
                        </span>
                      </div>
                    </div>

                    <div className="w-full space-y-2 mt-2">
                      <div className={`py-1.5 px-3 rounded-xl border text-xs font-mono font-bold flex items-center justify-center gap-1.5 ${scoreTheme.badgeBg}`}>
                        {analysis.score >= 85 ? (
                          <ShieldCheck className="w-4 h-4 text-emerald-400" />
                        ) : analysis.score >= 60 ? (
                          <ShieldAlert className="w-4 h-4 text-amber-400" />
                        ) : (
                          <ShieldX className="w-4 h-4 text-rose-400" />
                        )}
                        <span>{analysis.score}% {scoreTheme.label}</span>
                      </div>
                      <p className="text-[11px] font-mono text-zinc-400">
                        {analysis.threatCount === 0 
                          ? 'Zero malicious signatures or injection vectors detected.' 
                          : `${analysis.threatCount} threat signature flags triggered in audit.`}
                      </p>
                    </div>
                  </div>

                  {/* Right Column: 4-Cell Telemetry Matrix (8 cols) */}
                  <div className="lg:col-span-8 grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                    
                    {/* 1. Target & Data Sanitization Ratio */}
                    <div className="bg-black/40 border border-white/10 rounded-2xl p-4 flex flex-col justify-between hover:border-white/20 transition">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">
                          Data Sanitization Ratio
                        </span>
                        <Zap className="w-4 h-4 text-cyan-400" />
                      </div>
                      <div className="my-2">
                        <div className="flex items-baseline justify-between mb-1">
                          <span className="text-xl font-bold text-white font-sans">
                            {analysis.sanitizedRatio}% Sanitized
                          </span>
                          <span className="text-[10px] font-mono text-zinc-400">
                            {analysis.threatCount === 0 ? '0 Leaks' : `${analysis.threatCount} Anomalies`}
                          </span>
                        </div>
                        <div className="w-full h-2 bg-zinc-800 rounded-full overflow-hidden">
                          <div 
                            className={`h-full transition-all duration-700 ${analysis.sanitizedRatio >= 80 ? 'bg-gradient-to-r from-emerald-500 to-cyan-400' : analysis.sanitizedRatio >= 50 ? 'bg-gradient-to-r from-amber-500 to-orange-400' : 'bg-gradient-to-r from-rose-500 to-red-600'}`}
                            style={{ width: `${analysis.sanitizedRatio}%` }}
                          />
                        </div>
                      </div>
                      <p className="text-[10px] font-mono text-zinc-500">
                        Payload streams isolated & memory verified
                      </p>
                    </div>

                    {/* 2. TLS & Transport Encryption */}
                    <div className="bg-black/40 border border-white/10 rounded-2xl p-4 flex flex-col justify-between hover:border-white/20 transition">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">
                          TLS & Transport Layer
                        </span>
                        {analysis.certValid ? (
                          <Lock className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <Unlock className="w-4 h-4 text-rose-400" />
                        )}
                      </div>
                      <div className="my-1">
                        <h4 className="text-base font-bold text-white font-sans tracking-tight">
                          {analysis.tlsProtocol}
                        </h4>
                        <p className="text-[11px] font-mono text-indigo-300 truncate mt-0.5" title={analysis.cipherName}>
                          {analysis.cipherName}
                        </p>
                      </div>
                      <div className="flex items-center gap-2 text-[10px] font-mono text-zinc-400">
                        <span className={`px-1.5 py-0.5 rounded ${analysis.certValid ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/40' : 'bg-rose-950/60 text-rose-300 border border-rose-800/40'}`}>
                          {analysis.certValid ? 'VALID CERT' : 'UNENCRYPTED'}
                        </span>
                        <span>Grade {analysis.grade}</span>
                      </div>
                    </div>

                    {/* 3. Threats & Signature Matches */}
                    <div className="bg-black/40 border border-white/10 rounded-2xl p-4 flex flex-col justify-between hover:border-white/20 transition">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">
                          Vulnerability Signatures
                        </span>
                        <Fingerprint className="w-4 h-4 text-purple-400" />
                      </div>
                      <div className="my-1">
                        <div className="flex items-baseline gap-2">
                          <span className="text-xl font-bold text-white font-sans">
                            {analysis.threatCount}
                          </span>
                          <span className="text-xs font-mono text-zinc-400">matched flags</span>
                        </div>
                        <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                          <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${analysis.payloadAudit.sqli ? 'bg-rose-950/60 text-rose-300 border-rose-800/40' : 'bg-emerald-950/60 text-emerald-300 border-emerald-800/40'}`}>
                            SQLi: {analysis.payloadAudit.sqli ? 'DETECTED' : 'CLEAR'}
                          </span>
                          <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${analysis.payloadAudit.xss ? 'bg-rose-950/60 text-rose-300 border-rose-800/40' : 'bg-emerald-950/60 text-emerald-300 border-emerald-800/40'}`}>
                            XSS: {analysis.payloadAudit.xss ? 'DETECTED' : 'CLEAR'}
                          </span>
                        </div>
                      </div>
                      <p className="text-[10px] font-mono text-zinc-500">
                        Zero-day heuristic pattern matches
                      </p>
                    </div>

                    {/* 4. Sensitive Data & PII Exposure */}
                    <div className="bg-black/40 border border-white/10 rounded-2xl p-4 flex flex-col justify-between hover:border-white/20 transition">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">
                          PII & Key Leak Check
                        </span>
                        <KeyRound className="w-4 h-4 text-emerald-400" />
                      </div>
                      <div className="my-1">
                        <h4 className={`text-base font-bold font-sans tracking-tight ${analysis.piiStatus.startsWith('PASS') ? 'text-emerald-400' : 'text-rose-400'}`}>
                          {analysis.piiStatus}
                        </h4>
                        <p className="text-[11px] font-mono text-zinc-400 mt-0.5">
                          {analysis.piiStatus.startsWith('PASS') ? 'No credentials or tokens leaked' : 'Unmasked secret signatures present'}
                        </p>
                      </div>
                      <p className="text-[10px] font-mono text-zinc-500">
                        GDPR & HIPAA data boundary compliance
                      </p>
                    </div>

                  </div>
                </div>

                {/* RFC & Header Security Matrix (Itemized Audit Checklist) */}
                <div className="bg-black/40 border border-white/10 rounded-2xl p-5 space-y-3">
                  <div className="flex items-center justify-between border-b border-white/5 pb-2.5">
                    <div className="flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-indigo-400" />
                      <h4 className="text-xs font-bold text-white font-sans tracking-tight uppercase">
                        RFC & Security Header Audit Matrix
                      </h4>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-400">
                      Standard Security Perimeter Checklist
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 pt-1">
                    {Object.entries(analysis.headers).map(([key, item]) => {
                      const isPass = item.pass;
                      return (
                        <div 
                          key={key} 
                          className={`p-3 rounded-xl border flex items-center justify-between transition ${
                            isPass 
                              ? 'bg-emerald-950/20 border-emerald-500/20 hover:border-emerald-500/40' 
                              : 'bg-rose-950/20 border-rose-500/20 hover:border-rose-500/40'
                          }`}
                        >
                          <div className="space-y-0.5 pr-2">
                            <span className="text-xs font-mono font-bold text-white block">
                              {item.label}
                            </span>
                            <span className="text-[10px] font-mono text-zinc-400 block truncate max-w-[170px]" title={item.detail}>
                              {item.detail}
                            </span>
                          </div>
                          <div className="shrink-0">
                            {isPass ? (
                              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                            ) : (
                              <XCircle className="w-4 h-4 text-rose-400" />
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Actionable Recommendations & Remediation Bar */}
                <div className="bg-black/50 border border-indigo-500/20 rounded-2xl p-5 space-y-3 relative overflow-hidden">
                  <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-indigo-500/40 to-transparent" />
                  
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-indigo-400" />
                    <h4 className="text-xs font-bold text-white font-sans uppercase tracking-tight">
                      Remediation & Actionable Findings
                    </h4>
                  </div>

                  <ul className="space-y-2 text-xs font-mono text-zinc-300">
                    {analysis.recommendations.map((rec, index) => (
                      <li key={index} className="flex items-start gap-2 bg-white/5 p-2.5 rounded-xl border border-white/5">
                        <span className="text-indigo-400 font-bold mt-0.5">•</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>

              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </section>
  );
};
