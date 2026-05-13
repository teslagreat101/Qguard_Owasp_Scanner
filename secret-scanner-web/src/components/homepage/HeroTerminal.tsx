"use client";
import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";

type LogEntry = { id: string; type: "info" | "warn" | "crit" | "ai" | "success"; text: string };
type Status = "scanning" | "alert" | "remediating" | "secure";

const CheckIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

const WarningIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);

function TerminalWindow({ command, logs, showCursor, status }: { command: string; logs: LogEntry[]; showCursor: boolean; status: Status }) {
  return (
    <div className="relative w-full mx-auto">
      <div className="relative rounded-xl overflow-hidden" style={{
        background: "linear-gradient(135deg, rgba(11,15,12,0.97) 0%, rgba(8,12,9,0.99) 100%)",
        border: "1px solid rgba(0,255,136,0.25)",
        boxShadow: "0 0 0 1px rgba(0,255,136,0.08), 0 20px 60px rgba(0,0,0,0.6), 0 0 50px rgba(0,255,136,0.08), inset 0 1px 0 rgba(255,255,255,0.03)"
      }}>
        <div className="flex items-center px-4 py-3 border-b" style={{ background: "rgba(11,15,12,0.9)", borderColor: "rgba(0,255,136,0.12)" }}>
          <div className="flex items-center gap-2 mr-4">
            <div className="w-3 h-3 rounded-full bg-red-500/80 shadow-[0_0_6px_rgba(239,68,68,0.5)]" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/80 shadow-[0_0_6px_rgba(234,179,8,0.5)]" />
            <div className="w-3 h-3 rounded-full bg-green-500/80 shadow-[0_0_6px_rgba(34,197,94,0.5)]" />
          </div>
          <div className="flex-1 text-center text-[10px] font-mono px-4 py-1 rounded-md flex items-center justify-between"
            style={{ background: "rgba(0,255,136,0.06)", color: "rgba(0,255,136,0.7)", border: "1px solid rgba(0,255,136,0.12)" }}>
            <span className="opacity-50">quantara-scanner://engine/v1.1/security-scan</span>
            <div className="flex items-center gap-2">
              <span className={`w-1.5 h-1.5 rounded-full ${status === "scanning" ? "bg-primary animate-pulse" : status === "alert" ? "bg-red-500 animate-ping" : status === "remediating" ? "bg-amber-400 animate-pulse" : "bg-primary"}`} />
              <span className="uppercase tracking-widest font-black text-[8px]">{status}</span>
            </div>
          </div>
        </div>

        <div className="relative p-5 min-h-[320px] font-mono text-sm overflow-hidden text-muted-foreground">
          <div className="absolute left-0 right-0 h-[2px] pointer-events-none z-10" style={{
            background: "linear-gradient(to right, transparent 0%, rgba(0,255,136,0.8) 50%, transparent 100%)",
            boxShadow: "0 0 20px rgba(0,255,136,0.6), 0 0 40px rgba(0,255,136,0.3)",
            animation: "scanBeam 3s ease-in-out infinite"
          }} />

          <div className="flex items-center gap-2 mb-4">
            <span className="text-primary font-bold">➜</span>
            <span className="text-[#00C853]">~</span>
            <span className="text-slate-200 text-xs md:text-sm">{command}</span>
            {showCursor && <span className="inline-block w-2 h-4 bg-primary ml-1" style={{ animation: "cursorBlink 1s step-end infinite" }} />}
          </div>

          <div className="space-y-2">
            {logs.map((log, index) => (
              <motion.div key={`${log.id}-${index}`} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.3 }} className="flex items-start gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider min-w-[60px] text-center" style={{
                  ...(log.type === "info" && { background: "rgba(0,255,136,0.1)", color: "#00FF88", border: "1px solid rgba(0,255,136,0.2)" }),
                  ...(log.type === "warn" && { background: "rgba(234,179,8,0.15)", color: "#facc15", border: "1px solid rgba(234,179,8,0.25)" }),
                  ...(log.type === "crit" && { background: "rgba(239,68,68,0.15)", color: "#f87171", border: "1px solid rgba(239,68,68,0.25)", boxShadow: "0 0 10px rgba(239,68,68,0.2)" }),
                  ...(log.type === "ai" && { background: "rgba(0,200,83,0.12)", color: "#00E676", border: "1px solid rgba(0,200,83,0.25)" }),
                  ...(log.type === "success" && { background: "rgba(0,255,136,0.12)", color: "#00FF88", border: "1px solid rgba(0,255,136,0.25)" })
                }}>[{log.type}]</span>
                <span className="pt-0.5 text-[11px] md:text-xs" style={{ color: log.type === "crit" ? "#fca5a5" : "#8A9B94" }}>{log.text}</span>
              </motion.div>
            ))}
          </div>
        </div>

        <div className="absolute inset-0 pointer-events-none rounded-xl" style={{
          background: "radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.4) 100%)",
          boxShadow: "inset 0 0 80px rgba(0,0,0,0.5)"
        }} />
      </div>
    </div>
  );
}

function AlertCard({ visible }: { visible: boolean }) {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div initial={{ opacity: 0, x: 50, scale: 0.9 }} animate={{ opacity: 1, x: 0, scale: 1 }} exit={{ opacity: 0, x: 30, scale: 0.95 }} transition={{ duration: 0.4 }} className="absolute right-0 top-4 z-20">
          <div className="rounded-lg p-4 w-48 md:w-56" style={{ background: "linear-gradient(135deg, rgba(127,29,29,0.9) 0%, rgba(69,10,10,0.95) 100%)", border: "1px solid rgba(239,68,68,0.4)", boxShadow: "0 10px 40px rgba(0,0,0,0.5), 0 0 30px rgba(239,68,68,0.2)" }}>
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-full shrink-0" style={{ background: "rgba(239,68,68,0.2)", animation: "pulse 2s infinite" }}>
                <div className="text-red-400"><WarningIcon /></div>
              </div>
              <div>
                <h3 className="text-red-200 font-bold text-xs mb-1">Critical Vulnerability</h3>
                <p className="text-red-300/80 text-[10px] leading-relaxed">SQL Injection detected in search parameter</p>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function StatusBadge({ visible }: { visible: boolean }) {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div initial={{ opacity: 0, y: 20, scale: 0.9 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 10, scale: 0.95 }} transition={{ duration: 0.3 }} className="absolute -bottom-3 left-6 z-20">
          <div className="rounded-lg py-2 px-4 flex items-center gap-3" style={{ background: "linear-gradient(135deg, rgba(0,40,20,0.95) 0%, rgba(0,60,30,0.95) 100%)", border: "1px solid rgba(0,255,136,0.4)", boxShadow: "0 10px 30px rgba(0,0,0,0.4), 0 0 20px rgba(0,255,136,0.2)" }}>
            <div className="p-1.5 rounded-full" style={{ background: "rgba(0,255,136,0.2)" }}>
              <div className="text-primary text-xs"><CheckIcon /></div>
            </div>
            <div>
              <p className="text-primary text-[8px] uppercase font-bold tracking-wider">Status</p>
              <p className="text-white text-xs font-bold">System Secure</p>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export default function NeuralHeroVisual() {
  const [command, setCommand] = useState("");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [status, setStatus] = useState<Status>("scanning");
  const [showCursor, setShowCursor] = useState(true);
  const [key, setKey] = useState(0);

  useEffect(() => {
    let active = true;
    const fullCommand = "quantara-scanner --repo enterprise-core --deep-scan --ai-remediate";
    const runSequence = async () => {
      setCommand(""); setLogs([]); setStatus("scanning");
      for (let i = 0; i <= fullCommand.length; i++) {
        if (!active) return;
        setCommand(fullCommand.slice(0, i));
        await new Promise(r => setTimeout(r, 35 + Math.random() * 20));
      }
      await new Promise(r => setTimeout(r, 400));
      const addLog = (log: LogEntry) => { if (!active) return; setLogs(prev => [...prev.slice(-6), log]); };
      addLog({ id: "1", type: "info", text: "Initializing OWASP Discovery Engine v1.1..." });
      await new Promise(r => setTimeout(r, 600));
      addLog({ id: "2", type: "info", text: "Target identified: AWS EKS Cluster (us-east-1)" });
      await new Promise(r => setTimeout(r, 900));
      addLog({ id: "3", type: "warn", text: "A01: Broken Access Control detected at /admin" });
      await new Promise(r => setTimeout(r, 1200));
      addLog({ id: "4", type: "crit", text: "A03: SQL Injection confirmed in search param" });
      setStatus("alert");
      await new Promise(r => setTimeout(r, 1500));
      addLog({ id: "5", type: "ai", text: "Analyzing exploit chain for remediation..." });
      setStatus("remediating");
      await new Promise(r => setTimeout(r, 1500));
      addLog({ id: "7", type: "success", text: "Remediation patch generated & applied." });
      setStatus("secure");
      await new Promise(r => setTimeout(r, 2000));
      addLog({ id: "8", type: "success", text: "✓ Security governance updated — Active shielding enabled." });
      await new Promise(r => setTimeout(r, 4000));
      if (active) setKey(k => k + 1);
    };
    runSequence();
    return () => { active = false; };
  }, [key]);

  useEffect(() => {
    const interval = setInterval(() => setShowCursor(prev => !prev), 530);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative w-full max-w-2xl px-4 md:px-0">
      <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
        className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full mb-6"
        style={{ background: "rgba(0,255,136,0.08)", border: "1px solid rgba(0,255,136,0.2)", boxShadow: "0 0 20px rgba(0,255,136,0.06)" }}>
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
        </span>
        <span className="text-primary text-[10px] font-semibold tracking-wide uppercase">AI Active Protection</span>
      </motion.div>
      <TerminalWindow command={command} logs={logs} showCursor={showCursor} status={status} />
      <div className="absolute right-0 top-12 hidden md:block translate-x-1/4">
        <AlertCard visible={status === "alert" || status === "remediating"} />
      </div>
      <StatusBadge visible={status === "secure"} />
    </div>
  );
}
