import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Bot, 
  Send, 
  X, 
  Terminal, 
  Shield, 
  ChevronRight
} from 'lucide-react';

interface Message {
  id: string;
  sender: 'user' | 'bot';
  content: string;
  timestamp: Date;
}

interface AISecurityBotProps {
  activeState: {
    host?: string;
    url?: string;
    grade?: string;
    ssl?: boolean;
    latency?: number;
    throughput?: number;
    incidents?: { id: string; timestamp: string; sourceIp: string; targetService: string; category: string; severity: string; status: string; countryCode: string; payload: string; }[];
    fileDetails?: { fileName?: string; name?: string; size?: number; type?: string };
    metrics?: { throughput: number; fileSize: number };
  } | null;
  onLogMessage: (msg: string) => void;
}

export const AISecurityBot: React.FC<AISecurityBotProps> = ({ activeState, onLogMessage }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      sender: 'bot',
      content: "SOC Copilot active. Ready to analyze target payloads, trace threat vectors, or formulate Nginx/Apache/Express remediation policies.",
      timestamp: new Date()
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const chatEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  useEffect(() => {
    if (activeState) {
      const stateObj = activeState as {
        host?: string;
        url?: string;
        grade?: string;
        ssl?: boolean;
        latency?: number;
        throughput?: number;
        incidents?: { id: string; timestamp: string; sourceIp: string; targetService: string; category: string; severity: string; status: string; countryCode: string; payload: string; }[];
        fileDetails?: { fileName?: string; name?: string; size?: number; type?: string };
        metrics?: { throughput: number; fileSize: number };
      };
      const targetName = stateObj.host || stateObj.fileDetails?.fileName || stateObj.fileDetails?.name || "Uploaded Resource";
      const isClean = !stateObj.incidents || stateObj.incidents.length === 0;
      
      const messageContent = isClean
        ? `### 🎯 Target Telemetry Registered
**Source:** \`${targetName}\`
**Metrics:** Latency \`${stateObj.latency || 0}ms\` | Throughput \`${(stateObj.throughput || stateObj.metrics?.throughput || 0).toLocaleString()} B/s\`
**Status:** \`0 Threat Signatures Detected — Perimeter Nominal\`

All cross-origin policies and TLS certificates validated successfully.`
        : `### 🎯 Target Telemetry Registered
**Source:** \`${targetName}\`
**Metrics:** Latency \`${stateObj.latency || 0}ms\` | Throughput \`${(stateObj.throughput || stateObj.metrics?.throughput || 0).toLocaleString()} B/s\`
**Identified Risks:** \`${stateObj.incidents?.length || 0} Threat Signatures Flagged\`

Select a quick command below or query specific vector signatures.`;

      const systemMsg: Message = {
        id: `sys-loaded-${Date.now()}`,
        sender: 'bot',
        content: messageContent,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, systemMsg]);
      onLogMessage(`COPILOT: Synced active security state for "${targetName}"`);
    }
  }, [activeState, onLogMessage]);

  const handleSendMessage = async (text: string) => {
    if (!text.trim() || isTyping) return;

    const userMsg: Message = {
      id: `user-${Date.now()}`,
      sender: 'user',
      content: text,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMsg]);
    setInputMessage('');
    setIsTyping(true);

    try {
      const response = await fetch('/api/gemini/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [...messages, userMsg].map(m => ({
            role: m.sender === 'user' ? 'user' : 'model',
            content: m.content
          })),
          activeState
        })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Internal AI endpoint error");
      }

      setMessages(prev => [...prev, {
        id: `bot-${Date.now()}`,
        sender: 'bot',
        content: data.reply,
        timestamp: new Date()
      }]);
    } catch (err: unknown) {
      console.error(err);
      const errorWithMsg = err as { message?: string };
      setMessages(prev => [...prev, {
        id: `bot-err-${Date.now()}`,
        sender: 'bot',
        content: `⚠️ **Copilot Connection Error**: ${errorWithMsg.message || "Unable to reach security intelligence model. Please verify GEMINI_API_KEY."}`,
        timestamp: new Date()
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleQuickCommand = (cmd: string) => {
    let text = "";
    if (cmd === 'audit') {
      text = "Perform HTTP security header audit on the current target.";
    } else if (cmd === 'remediation') {
      text = "Suggest Apache, Nginx, or Express Helmet configuration rules to mitigate the identified header vulnerabilities.";
    } else if (cmd === 'threats') {
      text = "List and explain the line-by-line risk levels of all detected incidents in our active state.";
    } else if (cmd === 'report') {
      text = "Compile an executive security assessment report with risk score and remediation priorities.";
    }
    handleSendMessage(text);
  };

  return (
    <>
      {/* Floating Launcher Button */}
      <div className="fixed bottom-6 right-6 z-50">
        <motion.button
          onClick={() => setIsOpen(true)}
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
          className="flex items-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-slate-100 rounded-xl border border-slate-700 shadow-xl cursor-pointer text-xs font-semibold tracking-wide font-sans"
        >
          <div className="relative">
            <Shield className="w-4 h-4 text-sky-400" />
            {Boolean(activeState) && (
              <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-rose-500" />
            )}
          </div>
          <span>SOC Copilot</span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 bg-sky-500/15 text-sky-300 border border-sky-500/30 rounded">
            v4.2
          </span>
        </motion.button>
      </div>

      {/* Side Slide-Over Panel */}
      <AnimatePresence>
        {isOpen && (
          <div className="fixed inset-0 z-50 flex justify-end">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsOpen(false)}
              className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm"
            />

            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 220 }}
              className="relative w-full max-w-lg h-full bg-slate-950 border-l border-slate-800 shadow-2xl flex flex-col justify-between"
            >
              {/* Header */}
              <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/60">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 bg-sky-500/10 border border-sky-500/30 rounded-xl text-sky-400">
                    <Shield className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="font-bold text-slate-100 text-xs uppercase tracking-wider font-sans flex items-center gap-2">
                      SOC Operations Copilot
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    </h3>
                    <p className="text-[10px] text-slate-400 font-mono">TLS 1.3 Encrypted • Real-time Threat Intelligence</p>
                  </div>
                </div>
                <button
                  onClick={() => setIsOpen(false)}
                  className="p-1.5 hover:bg-slate-800 border border-slate-800 rounded-lg bg-slate-900 text-slate-400 hover:text-slate-200 transition cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Chat Window */}
              <div className="flex-1 p-5 overflow-y-auto space-y-4">
                <div className="space-y-4">
                  {messages.map((m) => (
                    <div
                      key={m.id}
                      className={`flex gap-3 max-w-[88%] ${m.sender === 'user' ? 'ml-auto flex-row-reverse' : ''}`}
                    >
                      <div className={`p-1.5 h-7 w-7 rounded-lg flex items-center justify-center shrink-0 border ${
                        m.sender === 'user' 
                          ? 'bg-sky-500/20 border-sky-500/40 text-sky-300' 
                          : 'bg-slate-900 border-slate-800 text-slate-400'
                      }`}>
                        <Terminal className="w-3.5 h-3.5" />
                      </div>

                      <div className={`rounded-xl p-3.5 text-xs font-mono leading-relaxed border ${
                        m.sender === 'user'
                          ? 'bg-sky-500/15 border-sky-500/30 text-sky-100'
                          : 'bg-slate-900/80 border-slate-800 text-slate-300'
                      }`}>
                        {m.content.startsWith("###") || m.content.includes("**") ? (
                          <div className="space-y-2 whitespace-pre-wrap">
                            {m.content.split('\n').map((line, idx) => {
                              if (line.startsWith('###')) {
                                return <h4 key={idx} className="text-xs font-bold text-slate-100 uppercase border-b border-slate-800 pb-1 mt-1 font-sans">{line.replace('###', '')}</h4>;
                              }
                              if (line.startsWith('**') && line.endsWith('**')) {
                                return <p key={idx} className="font-bold text-sky-300">{line.replace(/\*\*/g, '')}</p>;
                              }
                              if (line.startsWith('-')) {
                                return <li key={idx} className="ml-4 list-disc text-slate-400">{line.replace('-', '').trim()}</li>;
                              }
                              if (line.includes('`')) {
                                return (
                                  <p key={idx} className="text-slate-300">
                                    {line.split('`').map((chunk, cidx) => 
                                      cidx % 2 === 1 ? <code key={cidx} className="bg-slate-950 text-emerald-400 px-1 py-0.5 rounded border border-slate-800">{chunk}</code> : chunk
                                    )}
                                  </p>
                                );
                              }
                              return <p key={idx}>{line}</p>;
                            })}
                          </div>
                        ) : (
                          <p className="whitespace-pre-wrap">{m.content}</p>
                        )}
                        <span className="text-[9px] text-slate-500 mt-1.5 block text-right font-mono">
                          {m.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                      </div>
                    </div>
                  ))}

                  {isTyping && (
                    <div className="flex gap-3 max-w-[80%]">
                      <div className="p-1 h-7 w-7 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 flex items-center justify-center shrink-0">
                        <Bot className="w-3.5 h-3.5 animate-spin" />
                      </div>
                      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 text-xs text-slate-400 font-mono flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-bounce" style={{ animationDelay: '0ms' }} />
                        <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-bounce" style={{ animationDelay: '150ms' }} />
                        <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-bounce" style={{ animationDelay: '300ms' }} />
                        <span>Copilot querying threat database & policy models...</span>
                      </div>
                    </div>
                  )}

                  <div ref={chatEndRef} />
                </div>
              </div>

              {/* Bot Control Tools */}
              <div className="p-4 border-t border-slate-800 bg-slate-950 space-y-3">
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 uppercase tracking-widest border-b border-slate-900 pb-1.5">
                  <Terminal className="w-3 h-3 text-sky-400" />
                  <span>Analyst Query Shortcuts</span>
                </div>
                
                <div className="grid grid-cols-2 gap-2">
                  <button
                    disabled={!activeState}
                    onClick={() => handleQuickCommand('audit')}
                    className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-850 text-[10px] font-mono text-slate-300 disabled:opacity-40 transition cursor-pointer"
                  >
                    <span>Inspect security headers</span>
                    <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                  </button>
                  <button
                    disabled={!activeState}
                    onClick={() => handleQuickCommand('remediation')}
                    className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-850 text-[10px] font-mono text-slate-300 disabled:opacity-40 transition cursor-pointer"
                  >
                    <span>Remediation policy scripts</span>
                    <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                  </button>
                  <button
                    disabled={!activeState}
                    onClick={() => handleQuickCommand('threats')}
                    className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-850 text-[10px] font-mono text-slate-300 disabled:opacity-40 transition cursor-pointer"
                  >
                    <span>Explain vector payloads</span>
                    <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                  </button>
                  <button
                    disabled={!activeState}
                    onClick={() => handleQuickCommand('report')}
                    className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-850 text-[10px] font-mono text-slate-300 disabled:opacity-40 transition cursor-pointer"
                  >
                    <span>Generate executive summary</span>
                    <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                  </button>
                </div>

                {/* Query Input Bar */}
                <form 
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleSendMessage(inputMessage);
                  }}
                  className="flex items-center gap-2 mt-2 bg-slate-900 border border-slate-800 rounded-xl p-1.5"
                >
                  <input
                    type="text"
                    placeholder={activeState ? "Query SOC copilot on active target payload..." : "Run a target scan first or type query..."}
                    value={inputMessage}
                    onChange={(e) => setInputMessage(e.target.value)}
                    className="flex-1 bg-transparent text-xs text-slate-100 font-mono placeholder-slate-500 px-2.5 py-1 focus:outline-none"
                  />
                  <button
                    type="submit"
                    disabled={!inputMessage.trim() || isTyping}
                    className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-slate-950 font-bold text-xs cursor-pointer transition flex items-center justify-center"
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </form>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
};
