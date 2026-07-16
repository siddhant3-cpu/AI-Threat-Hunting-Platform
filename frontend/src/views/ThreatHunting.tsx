import { useEffect, useState } from "react";
import { Search, HardDrive, User, Terminal, Calendar, Code, ChevronRight, ChevronDown, RefreshCw } from "lucide-react";

import { api } from "../services/api";

export function ThreatHunting() {
  const [logs, setLogs] = useState<any[]>([]);
  const [search, setSearch] = useState("");
  const [host, setHost] = useState("");
  const [user, setUser] = useState("");
  const [source, setSource] = useState("");
  const [eventId, setEventId] = useState<number | "">("");
  const [loading, setLoading] = useState(false);
  const [expandedLog, setExpandedLog] = useState<number | null>(null);

  const executeHunt = async () => {
    setLoading(true);
    try {
      const data = await api.huntLogs({
        search: search || undefined,
        host: host || undefined,
        user: user || undefined,
        source: source || undefined,
        event_id: eventId !== "" ? Number(eventId) : undefined,
        limit: 100
      });
      setLogs(data);
    } catch (err) {
      console.error("Threat hunting query execution failed", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    executeHunt();
  }, []);

  const handleToggleExpand = (id: number) => {
    setExpandedLog(prev => (prev === id ? null : id));
  };

  const getEventName = (sourceName: string, eventId: number) => {
    if (sourceName.includes("Sysmon")) {
      switch (eventId) {
        case 1: return "Process Create";
        case 3: return "Network Connection";
        case 11: return "File Create";
        case 12: return "Registry Value Set";
        case 13: return "Registry Value Set";
        default: return `Sysmon Event ID ${eventId}`;
      }
    }
    if (sourceName.includes("Security")) {
      switch (eventId) {
        case 4624: return "Successful Logon";
        case 4625: return "Failed Logon";
        default: return `Windows Security ID ${eventId}`;
      }
    }
    if (sourceName.includes("auditd")) {
      return "Auditd Syscall Execve";
    }
    return "Generic Event Log";
  };

  return (
    <div className="space-y-6 h-[calc(100vh-140px)] flex flex-col">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2 text-cyber-text">
          <Terminal className="text-cyber-accent glow-text-blue" />
          SIEM Threat Hunting Console
        </h1>
        <p className="text-sm text-cyber-muted">
          Perform queries and threat hunting across indices of Windows Event logs, Sysmon events, and Auditd syslog.
        </p>
      </div>

      {/* Advanced Ingestion Query Search card */}
      <div className="glass-card p-5 rounded-xl space-y-4 border border-cyber-border/40 shrink-0">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-cyber-muted">
              <Search size={18} />
            </span>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by keyword, command line, filepath, hashes, IP addresses..."
              className="w-full bg-cyber-bg border border-cyber-border rounded-lg py-3 pl-11 pr-4 text-cyber-text placeholder:text-cyber-muted/50 focus:outline-none focus:border-cyber-accent/60 transition-colors text-sm"
              onKeyDown={(e) => e.key === "Enter" && executeHunt()}
            />
          </div>
          <button
            onClick={executeHunt}
            className="bg-cyber-accent hover:bg-cyber-accent/90 text-white text-sm font-semibold rounded-lg px-6 transition-colors active:translate-y-0.5"
          >
            Run Hunt Query
          </button>
        </div>

        {/* Filters Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="space-y-1.5">
            <label className="block text-cyber-muted font-semibold tracking-wide">Hostname</label>
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="e.g. WS-PROD-01"
              className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 focus:outline-none focus:border-cyber-accent text-cyber-text"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-cyber-muted font-semibold tracking-wide">Username</label>
            <input
              type="text"
              value={user}
              onChange={(e) => setUser(e.target.value)}
              placeholder="e.g. admin"
              className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 focus:outline-none focus:border-cyber-accent text-cyber-text"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-cyber-muted font-semibold tracking-wide">Log Source</label>
            <select
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 focus:outline-none focus:border-cyber-accent text-cyber-text"
            >
              <option value="">All Sources</option>
              <option value="Winlogbeat-Sysmon">Winlogbeat-Sysmon</option>
              <option value="Winlogbeat-Security">Winlogbeat-Security</option>
              <option value="Filebeat-auditd">Filebeat-auditd</option>
              <option value="Filebeat-syslog">Filebeat-syslog</option>
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="block text-cyber-muted font-semibold tracking-wide">Event ID</label>
            <input
              type="number"
              value={eventId}
              onChange={(e) => setEventId(e.target.value === "" ? "" : Number(e.target.value))}
              placeholder="e.g. 1 (Process Create)"
              className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 focus:outline-none focus:border-cyber-accent text-cyber-text"
            />
          </div>
        </div>
      </div>

      {/* Search results */}
      <div className="glass-card rounded-xl border border-cyber-border/40 flex-1 overflow-hidden flex flex-col">
        <div className="px-4 py-3 bg-slate-950/40 border-b border-cyber-border/40 text-xs font-semibold text-cyber-muted tracking-wider flex items-center justify-between">
          <span>HUNTING QUERY RESULTS</span>
          <span className="font-mono text-[10px]">{logs.length} Log Hits</span>
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center py-24 text-sm text-cyber-muted gap-2">
              <RefreshCw className="animate-spin text-cyber-accent" size={18} />
              <span>Scanning log indices...</span>
            </div>
          ) : logs.length === 0 ? (
            <div className="text-center py-24 text-xs text-cyber-muted">
              No logs matched the hunting criteria. Start a simulation run or clear search filters.
            </div>
          ) : (
            <div className="divide-y divide-cyber-border/30">
              {logs.map((log) => {
                const isExpanded = expandedLog === log.id;
                
                return (
                  <div key={log.id} className="transition-colors hover:bg-slate-900/10">
                    {/* Log main row */}
                    <div 
                      onClick={() => handleToggleExpand(log.id)}
                      className="px-4 py-3 flex flex-wrap md:flex-nowrap items-center gap-4 cursor-pointer text-xs"
                    >
                      <div className="text-cyber-muted select-none w-4">
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </div>
                      
                      {/* Timestamp */}
                      <div className="w-20 shrink-0 font-mono text-[10px] text-cyber-muted">
                        {new Date(log.timestamp).toLocaleTimeString([], { hour12: false })}
                      </div>

                      {/* Source */}
                      <div className="w-36 shrink-0 truncate font-mono text-[10px] text-blue-400">
                        {log.source}
                      </div>

                      {/* Event ID/Action Badge */}
                      <div className="w-36 shrink-0">
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-cyber-border text-slate-300 text-[10px] font-mono leading-none">
                          {getEventName(log.source, log.event_id)}
                        </span>
                      </div>

                      {/* Short Description */}
                      <div className="flex-1 min-w-0 text-cyber-text font-mono truncate text-[11px]">
                        {log.message || JSON.stringify(log.fields)}
                      </div>

                      {/* Meta attributes */}
                      <div className="flex items-center gap-3 shrink-0 text-cyber-muted text-[10px]">
                        {log.host && (
                          <span className="flex items-center gap-1">
                            <HardDrive size={12} />
                            {log.host}
                          </span>
                        )}
                        {log.user && (
                          <span className="flex items-center gap-1">
                            <User size={12} />
                            {log.user}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Detailed Expanded view */}
                    {isExpanded && (
                      <div className="px-12 pb-4 pt-1 bg-slate-950/20 border-t border-cyber-border/20 text-xs">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 my-2">
                          <div className="space-y-1.5">
                            <div className="font-semibold text-cyber-accent text-[10px] uppercase tracking-wider flex items-center gap-1">
                              <Calendar size={12} />
                              System Metadata
                            </div>
                            <table className="w-full text-[11px] font-mono text-cyber-muted">
                              <tbody>
                                <tr>
                                  <td className="py-1 w-24">Log ID:</td>
                                  <td className="text-cyber-text">{log.id}</td>
                                </tr>
                                <tr>
                                  <td className="py-1">Timestamp:</td>
                                  <td className="text-cyber-text">{new Date(log.timestamp).toUTCString()}</td>
                                </tr>
                                <tr>
                                  <td className="py-1">Log Source:</td>
                                  <td className="text-cyber-text">{log.source}</td>
                                </tr>
                                <tr>
                                  <td className="py-1">Windows Event ID:</td>
                                  <td className="text-cyber-text">{log.event_id ?? "N/A"}</td>
                                </tr>
                              </tbody>
                            </table>
                          </div>

                          <div className="space-y-1.5">
                            <div className="font-semibold text-cyber-accent text-[10px] uppercase tracking-wider flex items-center gap-1">
                              <Code size={12} />
                              Dynamic Payload Fields
                            </div>
                            <table className="w-full text-[11px] font-mono text-cyber-muted">
                              <tbody>
                                {Object.entries(log.fields || {}).map(([key, val]) => (
                                  <tr key={key}>
                                    <td className="py-1 w-32 truncate">{key}:</td>
                                    <td className="text-cyber-text break-all max-w-[200px]">{String(val)}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>

                        {/* Full message view */}
                        <div className="mt-3.5 space-y-1">
                          <div className="font-semibold text-cyber-muted text-[10px] uppercase tracking-wider">Raw Message Block</div>
                          <pre className="bg-slate-950 p-3 rounded border border-cyber-border/40 font-mono text-[11px] text-green-400 overflow-x-auto whitespace-pre-wrap break-all leading-normal">
                            {log.message || JSON.stringify(log.fields, null, 2)}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
