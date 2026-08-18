import React, { useState, useRef } from 'react';
import { Globe, Upload, Search, RefreshCw, FileCode } from 'lucide-react';
import { Incident } from '../types';

interface TargetAnalysisHubProps {
  onScanComplete: (payload: { incidents?: Incident[]; throughput?: number; ssl?: boolean; latency?: number; host?: string; url?: string; grade?: string; headers?: Record<string, string> }) => void;
  onFileLoaded: (
    fileDetails: { name: string; size: number; type: string; fileName?: string; fileSize?: number; fileType?: string; imageHash?: string; dimensions?: string },
    derivedIncidents: Incident[],
    metrics: { throughput: number; fileSize: number; lineCount?: number; threatCount?: number; errorCount?: number; criticalCount?: number; highCount?: number }
  ) => void;
  onLogMessage: (msg: string) => void;
  onScanStart?: () => void;
}

export const TargetAnalysisHub: React.FC<TargetAnalysisHubProps> = ({
  onScanComplete,
  onFileLoaded,
  onLogMessage,
  onScanStart
}) => {
  const [urlInput, setUrlInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [activeFile, setActiveFile] = useState<{ name: string; size: number; type: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleScanUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim() || isScanning) return;

    setIsScanning(true);
    if (onScanStart) onScanStart();
    setActiveFile(null);
    onLogMessage(`INGRESS SCANNER: Executing security audit on ${urlInput}...`);

    try {
      const response = await fetch('/api/scan-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Target unreachable");
      }

      onScanComplete(data);
      onLogMessage(`INGRESS AUDIT COMPLETE: ${data.host} | Grade=${data.grade} | TLS=${data.ssl ? "Active" : "None"} | Latency=${data.latency}ms`);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      onLogMessage(`INGRESS AUDIT FAILURE: ${errMsg}`);
    } finally {
      setIsScanning(false);
    }
  };

  const processLogFile = async (fileName: string, fileSize: number, fileType: string, content: string) => {
    if (onScanStart) onScanStart();
    onLogMessage(`FILE PARSER: Submitting ${fileName} (${fileSize} bytes) to inspection pipeline...`);

    try {
      const res = await fetch('/api/parse-log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fileName, content })
      });

      if (res.ok) {
        const data = await res.json();
        interface ServerFinding {
          ip?: string;
          lineNum?: number;
          category?: string;
          severity: string;
          cveId?: string;
          description?: string;
        }
        const derivedIncidents: Incident[] = (data.findings || []).map((f: ServerFinding) => ({
          id: `INC-LOG-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
          timestamp: new Date().toISOString(),
          sourceIp: f.ip || '127.0.0.1',
          targetService: `${fileName} (Line ${f.lineNum})`,
          category: f.category === 'SQL Injection' ? 'SQL Injection' : f.category === 'XSS Script Injection' ? 'Phishing' : f.category === 'Authentication Failure' ? 'Brute Force' : 'Malware',
          severity: f.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'info',
          status: 'active',
          countryCode: 'US',
          payload: `[${f.cveId}] Line ${f.lineNum}: ${f.description}`,
        }));

        const metrics = {
          throughput: Math.floor(fileSize / 10),
          fileSize,
          lineCount: content.split('\n').length,
          threatCount: derivedIncidents.length,
          criticalCount: derivedIncidents.filter(i => i.severity === 'critical').length,
          highCount: derivedIncidents.filter(i => i.severity === 'high').length
        };

        onFileLoaded({ name: fileName, size: fileSize, type: fileType }, derivedIncidents, metrics);
        onLogMessage(`PARSER COMPLETE: Processed ${metrics.lineCount} lines. Identified ${metrics.threatCount} threat vectors.`);
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      onLogMessage(`PARSER ERROR: ${errMsg}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleFileSelect = (file: File) => {
    setActiveFile({ name: file.name, size: file.size, type: file.type });
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      processLogFile(file.name, file.size, file.type, content);
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  return (
    <div id="target-analysis-hub" className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs dark:shadow-xl space-y-4 transition-colors duration-200">
      <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800/80">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-sky-500/10 text-sky-600 dark:text-sky-400 rounded-xl border border-sky-500/25 dark:border-sky-500/30">
            <Search className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-slate-100 font-sans">Target URL Scanner & Telemetry Parser</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">Analyze target URLs, TLS parameters, or upload raw telemetry log files</p>
          </div>
        </div>
        <span className="hidden sm:inline-flex px-2.5 py-1 text-xs bg-slate-100 dark:bg-slate-950 text-sky-700 dark:text-sky-300 border border-slate-200 dark:border-slate-800 rounded-lg font-mono">
          RFC 9110 / TLS 1.3 Compliant
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Left: URL Security Audit Input */}
        <form onSubmit={handleScanUrl} className="space-y-4">
          <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 block">Target URL / Domain Endpoint</label>
          <div className="relative">
            <Globe className="w-4 h-4 text-slate-400 dark:text-slate-500 absolute left-3.5 top-3.5" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="e.g. https://api.enterprise.domain/v1/auth"
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 focus:border-sky-500/60 focus:ring-1 focus:ring-sky-500/30 rounded-xl pl-10 pr-28 py-2.5 text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-600 outline-none transition font-mono"
            />
            <button
              type="submit"
              disabled={isScanning || !urlInput.trim()}
              className="absolute right-1.5 top-1.5 px-4 py-1.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white dark:text-slate-950 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer shadow-xs"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Auditing...</span>
                </>
              ) : (
                <span>Run Audit</span>
              )}
            </button>
          </div>

          <div className="flex flex-wrap gap-2 text-[11px] text-slate-500 dark:text-slate-400 font-mono">
            <span>Quick Presets:</span>
            <button
              type="button"
              onClick={() => setUrlInput('https://api.cloudflare.com')}
              className="text-sky-600 dark:text-sky-400 hover:underline cursor-pointer"
            >
              Cloudflare API
            </button>
            <span>•</span>
            <button
              type="button"
              onClick={() => setUrlInput('https://github.com')}
              className="text-sky-600 dark:text-sky-400 hover:underline cursor-pointer"
            >
              GitHub Core
            </button>
          </div>
        </form>

        {/* Right: Drag and Drop Log Parser */}
        <div className="space-y-2">
          <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 block">Security Telemetry Log Parser</label>
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-5 text-center cursor-pointer transition flex flex-col items-center justify-center space-y-2 ${
              isDragging
                ? 'border-sky-500 bg-sky-500/10'
                : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 hover:border-slate-300 dark:hover:border-slate-700'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
              accept=".log,.txt,.json,.csv"
              className="hidden"
            />
            <Upload className="w-6 h-6 text-slate-400 dark:text-slate-500" />
            <div>
              <p className="text-xs text-slate-800 dark:text-slate-200 font-bold">Click or drop log file to inspect</p>
              <p className="text-[11px] text-slate-500">Supports <code className="text-slate-700 dark:text-slate-300 font-mono">.log</code>, <code className="text-slate-700 dark:text-slate-300 font-mono">.json</code>, <code className="text-slate-700 dark:text-slate-300 font-mono">.csv</code> formats</p>
            </div>
            {activeFile && (
              <div className="mt-2 px-3 py-1 bg-sky-500/15 border border-sky-500/30 rounded-lg text-[11px] font-mono text-sky-700 dark:text-sky-300 flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5" />
                <span>{activeFile.name} ({(activeFile.size / 1024).toFixed(1)} KB)</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
