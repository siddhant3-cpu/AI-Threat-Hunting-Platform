import { useState, useEffect } from "react";

import { Play, RotateCcw, AlertTriangle, ShieldAlert, Terminal, RefreshCw } from "lucide-react";
import { api } from "../services/api";

export function Simulator() {
  const [running, setRunning] = useState<string | null>(null);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [feedback, setFeedback] = useState("");

  const addTerminalLine = (text: string) => {
    const time = new Date().toLocaleTimeString([], { hour12: false });
    setTerminalLogs(prev => [...prev, `[${time}] ${text}`].slice(-30)); // Keep last 30 lines
  };

  const handleTriggerSim = async (scenario: string) => {
    setRunning(scenario);
    setFeedback("");
    addTerminalLine(`INITIALIZING SIMULATOR: Dispatching threat vector payload [${scenario.toUpperCase()}]`);

    try {
      await api.triggerSimulation(scenario);
      addTerminalLine(`PAYLOAD INJECTED: Synthetic syslog/Sysmon stream registered.`);
      addTerminalLine(`ANALYZING PIPELINE: Ingesting logs -> Checking rules -> Correlating alerts...`);
      setFeedback(`Simulation triggered! Go check the Dashboard and Incidents panels.`);
    } catch (err) {
      addTerminalLine(`ERROR: Simulation pipeline dispatch failed: ${err}`);
      setFeedback("Failed to trigger simulation.");
    } finally {
      setRunning(null);
    }
  };

  const handleResetLab = async () => {
    if (!confirm("Are you sure you want to wipe all logs, alerts, and incidents?")) return;
    try {
      await api.resetSimulation();
      setTerminalLogs([]);
      addTerminalLine("SYSTEM RESET: Purged Elasticsearch indices and PostgreSQL incident database tables.");
      setFeedback("Lab environment reset clean.");
    } catch (err) {
      addTerminalLine(`ERROR: Lab purge failed: ${err}`);
    }
  };

  // Poll raw logs to populate terminal dynamically when simulator triggers logs ingestion
  useEffect(() => {
    const fetchRecentLogs = async () => {
      try {
        const logs = await api.huntLogs({ limit: 5 });
        if (logs.length > 0) {
          logs.reverse().forEach((log: any) => {
            const label = log.source.includes("Sysmon") ? "Sysmon" : log.source.includes("Security") ? "Security" : "Auditd";
            const msg = log.message || JSON.stringify(log.fields);
            addTerminalLine(`INGESTED [${label} ID:${log.event_id || 'N/A'}]: ${msg.substring(0, 85)}...`);
          });
        }
      } catch (err) {
        // Silently fail polling
      }
    };

    fetchRecentLogs();
    const interval = setInterval(fetchRecentLogs, 6000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6 flex flex-col h-[calc(100vh-140px)]">
      {/* Page Header */}
      <div className="flex items-center justify-between border-b border-cyber-border/40 pb-4 shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-cyber-text">
            <ShieldAlert className="text-red-500 glow-text-red animate-pulse" />
            Attack Simulation & Threat Lab
          </h1>
          <p className="text-sm text-cyber-muted">
            Launch controlled attack campaigns against virtual endpoints to test detection rules, analytics, and AI reports.
          </p>
        </div>
        <button
          onClick={handleResetLab}
          className="flex items-center gap-1.5 bg-red-950/20 hover:bg-red-950/40 border border-red-500/30 text-red-400 text-xs font-semibold rounded-lg px-3.5 py-2 transition-all active:translate-y-0.5"
        >
          <RotateCcw size={14} />
          Reset Lab Environment
        </button>
      </div>

      {/* Safety Notice Callout */}
      <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 flex gap-3 shrink-0">
        <AlertTriangle className="text-cyber-warning shrink-0 mt-0.5" size={20} />
        <div className="text-xs text-amber-200/90 leading-normal">
          <strong className="text-cyber-warning uppercase font-semibold tracking-wider">Educational Sandbox Mode:</strong>
          <p className="mt-1">
            Running these scenarios simulates attacker activity on protected assets. The platform generates realistic telemetry records (process creations, registry edits, network logs, failed logons) and ingests them into the log database. The Sigma Engine evaluates the telemetry dynamically and correlation threads compile alerts into high-severity incidents.
          </p>
        </div>
      </div>

      {/* Lab Simulation Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 shrink-0">
        
        {/* Scenario 1 */}
        <div className="glass-card p-5 rounded-xl border border-cyber-border flex flex-col justify-between h-56">
          <div>
            <div className="flex justify-between items-start">
              <h3 className="text-sm font-bold text-cyber-text">Windows SSH / RDP Brute Force</h3>
              <span className="text-[9px] font-mono font-semibold uppercase px-1.5 py-0.5 rounded bg-blue-500/10 text-cyber-accent">T1110</span>
            </div>
            <p className="text-[11px] text-cyber-muted mt-2 leading-relaxed">
              Fires 15 failed logins followed by 1 successful login from external source IP <code className="text-cyber-accent font-mono text-[10px]">203.0.113.19</code> under account <code className="text-cyber-text font-mono text-[10px]">admin</code> on host <code className="text-cyber-text font-mono text-[10px]">WS-PROD-01</code>, followed by recon commands.
            </p>
          </div>
          
          <button
            onClick={() => handleTriggerSim("brute_force")}
            disabled={running !== null}
            className="w-full mt-4 flex items-center justify-center gap-2 bg-slate-900 border border-cyber-border hover:border-cyber-accent text-cyber-text text-xs rounded-lg py-2.5 transition-colors font-medium active:translate-y-0.5 disabled:opacity-50"
          >
            {running === "brute_force" ? <RefreshCw className="animate-spin text-cyber-accent" size={14} /> : <Play size={14} />}
            Inject Brute Force Campaign
          </button>
        </div>

        {/* Scenario 2 */}
        <div className="glass-card p-5 rounded-xl border border-cyber-border flex flex-col justify-between h-56">
          <div>
            <div className="flex justify-between items-start">
              <h3 className="text-sm font-bold text-cyber-text">Windows Credential Dumping</h3>
              <span className="text-[9px] font-mono font-semibold uppercase px-1.5 py-0.5 rounded bg-blue-500/10 text-cyber-accent">T1003.001</span>
            </div>
            <p className="text-[11px] text-cyber-muted mt-2 leading-relaxed">
              Simulates download of Mimikatz binary, disabling LSA protection flags inside the Registry hive, and executing <code className="text-cyber-text font-mono text-[10px]">mimikatz.exe sekurlsa::logonpasswords</code> in command shells.
            </p>
          </div>
          
          <button
            onClick={() => handleTriggerSim("mimikatz")}
            disabled={running !== null}
            className="w-full mt-4 flex items-center justify-center gap-2 bg-slate-900 border border-cyber-border hover:border-cyber-accent text-cyber-text text-xs rounded-lg py-2.5 transition-colors font-medium active:translate-y-0.5 disabled:opacity-50"
          >
            {running === "mimikatz" ? <RefreshCw className="animate-spin text-cyber-accent" size={14} /> : <Play size={14} />}
            Inject Mimikatz Payload
          </button>
        </div>

        {/* Scenario 3 */}
        <div className="glass-card p-5 rounded-xl border border-cyber-border flex flex-col justify-between h-56">
          <div>
            <div className="flex justify-between items-start">
              <h3 className="text-sm font-bold text-cyber-text">Linux Server Reverse Shell</h3>
              <span className="text-[9px] font-mono font-semibold uppercase px-1.5 py-0.5 rounded bg-blue-500/10 text-cyber-accent">T1059.004</span>
            </div>
            <p className="text-[11px] text-cyber-muted mt-2 leading-relaxed">
              Simulates a Remote Code Execution vulnerability on a Linux PHP server spawning a web terminal shell redirecting stdout to C2 controller <code className="text-red-400 font-mono text-[10px]">198.51.100.45:4444</code> under user context <code className="text-cyber-text font-mono text-[10px]">www-data</code>.
            </p>
          </div>
          
          <button
            onClick={() => handleTriggerSim("reverse_shell")}
            disabled={running !== null}
            className="w-full mt-4 flex items-center justify-center gap-2 bg-slate-900 border border-cyber-border hover:border-cyber-accent text-cyber-text text-xs rounded-lg py-2.5 transition-colors font-medium active:translate-y-0.5 disabled:opacity-50"
          >
            {running === "reverse_shell" ? <RefreshCw className="animate-spin text-cyber-accent" size={14} /> : <Play size={14} />}
            Inject Reverse Shell Vector
          </button>
        </div>

      </div>

      {feedback && (
        <div className="bg-blue-500/10 border border-blue-500/20 text-cyber-accent text-xs rounded-lg p-3 shrink-0">
          {feedback}
        </div>
      )}

      {/* Interactive scrolling terminal output */}
      <div className="flex-1 min-h-0 glass-card rounded-xl border border-cyber-border/40 flex flex-col overflow-hidden">
        <div className="px-4 py-2 bg-slate-950/50 border-b border-cyber-border/40 text-[10px] font-bold text-cyber-muted tracking-wider uppercase flex items-center gap-2">
          <Terminal size={14} className="text-blue-400" />
          Ingestion Logging Console Feed
        </div>

        <div className="flex-1 overflow-y-auto p-4 bg-slate-950 font-mono text-[11px] text-green-400 space-y-1.5 selection:bg-slate-800">
          {terminalLogs.length === 0 ? (
            <div className="text-cyber-muted italic py-10 text-center">
              Waiting for threat vectors execution telemetry. Ready to capture log outputs.
            </div>
          ) : (
            terminalLogs.map((line, idx) => (
              <div key={idx} className="break-all whitespace-pre-wrap leading-normal">
                {line}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
