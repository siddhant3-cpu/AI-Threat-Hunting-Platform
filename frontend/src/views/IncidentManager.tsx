import { useEffect, useState } from "react";
import { 
  ShieldAlert, ShieldCheck, UserCheck, RefreshCw, FileText, 
  Bot, Clock, User, HardDrive, Hash, Globe, AlertTriangle, Send 
} from "lucide-react";
import { api } from "../services/api";

export function IncidentManager() {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [selectedInc, setSelectedInc] = useState<any>(null);
  const [filterStatus, setFilterStatus] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [newComment, setNewComment] = useState("");
  const [loading, setLoading] = useState(true);

  const [aiLoading, setAiLoading] = useState(false);
  const [intelData, setIntelData] = useState<Record<string, any>>({});
  const [intelLoading, setIntelLoading] = useState<Record<string, boolean>>({});

  const fetchIncidents = async (keepSelection = false) => {
    try {
      const data = await api.getIncidents({
        status: filterStatus || undefined,
        severity: filterSeverity || undefined
      });
      setIncidents(data);
      
      if (keepSelection && selectedInc) {
        // Refresh details for the currently selected incident
        const updated = await api.getIncident(selectedInc.id);
        setSelectedInc(updated);
      }
    } catch (err) {
      console.error("Failed to fetch incidents", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [filterStatus, filterSeverity]);

  const handleSelectIncident = async (inc: any) => {
    setLoading(true);
    try {
      const details = await api.getIncident(inc.id);
      setSelectedInc(details);
      setIntelData({}); // Clear old lookups
    } catch (err) {
      console.error("Failed to load incident detail", err);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateIncident = async (fields: any) => {
    if (!selectedInc) return;
    try {
      const updated = await api.updateIncident(selectedInc.id, fields);
      setSelectedInc({ ...selectedInc, ...updated });
      fetchIncidents(false);
    } catch (err) {
      console.error("Failed to update incident attributes", err);
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedInc || !newComment.trim()) return;
    try {
      const comment = await api.addComment(selectedInc.id, newComment);
      setSelectedInc({
        ...selectedInc,
        comments: [...(selectedInc.comments || []), comment]
      });
      setNewComment("");
    } catch (err) {
      console.error("Failed to add comment", err);
    }
  };

  const handleTriggerAI = async () => {
    if (!selectedInc) return;
    setAiLoading(true);
    try {
      const data = await api.triggerAiAnalysis(selectedInc.id);
      if (data.status === "success") {
        setSelectedInc({
          ...selectedInc,
          ai_summary: data.ai_summary,
          ai_playbook: data.ai_playbook
        });
        fetchIncidents(false);
      }
    } catch (err) {
      alert("AI analysis generation failed: " + err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleEnrichIOC = async (ioc: string) => {
    if (!ioc) return;
    setIntelLoading(prev => ({ ...prev, [ioc]: true }));
    try {
      const intel = await api.enrichIoc(ioc);
      setIntelData(prev => ({ ...prev, [ioc]: intel }));
    } catch (err) {
      console.error("IOC enrichment failed", err);
    } finally {
      setIntelLoading(prev => ({ ...prev, [ioc]: false }));
    }
  };

  // Helper to parse potential IOCs (IPs/Hashes/Domains) from alert logs
  const extractIOCs = (incident: any) => {
    const iocs = new Set<string>();
    if (!incident.alerts) return [];
    
    incident.alerts.forEach((alert: any) => {
      const details = alert.details || {};
      const fields = details.fields || {};
      
      // Look for IP fields
      if (fields.IpAddress) iocs.add(fields.IpAddress);
      if (fields.DestinationAddress) iocs.add(fields.DestinationAddress);
      
      // Look for hashes
      if (fields.Hashes) {
        const hashStr = fields.Hashes;
        const md5Match = hashStr.match(/MD5=([a-fA-F0-9]{32})/);
        const sha256Match = hashStr.match(/SHA256=([a-fA-F0-9]{64})/);
        if (md5Match) iocs.add(md5Match[1]);
        if (sha256Match) iocs.add(sha256Match[1]);
      }
    });
    
    return Array.from(iocs);
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev) {
      case "Critical": return "bg-red-500/10 text-red-400 border border-red-500/20";
      case "High": return "bg-orange-500/10 text-orange-400 border border-orange-500/20";
      case "Medium": return "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20";
      default: return "bg-blue-500/10 text-blue-400 border border-blue-500/20";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "Closed": return <ShieldCheck className="text-cyber-success" size={16} />;
      case "Remediated": return <UserCheck className="text-cyber-accent" size={16} />;
      case "Investigating": return <RefreshCw className="text-cyber-warning animate-spin" size={16} />;
      default: return <ShieldAlert className="text-cyber-danger" size={16} />;
    }
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 h-[calc(100vh-140px)]">
      
      {/* Incidents List (Left Side) */}
      <div className="xl:col-span-1 glass-card rounded-xl p-4 flex flex-col h-full border border-cyber-border/40">
        <div className="flex items-center justify-between border-b border-cyber-border/40 pb-3 mb-4">
          <h2 className="text-base font-semibold text-cyber-text">Correlated Incidents</h2>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-cyber-muted">
            {incidents.length} Found
          </span>
        </div>

        {/* Filters */}
        <div className="grid grid-cols-2 gap-3 mb-4 text-xs">
          <select 
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-cyber-bg border border-cyber-border rounded px-2.5 py-1.5 focus:outline-none focus:border-cyber-accent text-cyber-text"
          >
            <option value="">All Statuses</option>
            <option value="New">New</option>
            <option value="Investigating">Investigating</option>
            <option value="Remediated">Remediated</option>
            <option value="Closed">Closed</option>
          </select>
          <select 
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-cyber-bg border border-cyber-border rounded px-2.5 py-1.5 focus:outline-none focus:border-cyber-accent text-cyber-text"
          >
            <option value="">All Severities</option>
            <option value="Low">Low</option>
            <option value="Medium">Medium</option>
            <option value="High">High</option>
            <option value="Critical">Critical</option>
          </select>
        </div>

        {/* List items */}
        <div className="flex-1 overflow-y-auto space-y-3 pr-1">
          {loading ? (
            <div className="flex items-center justify-center py-20 text-xs text-cyber-muted gap-2">
              <RefreshCw className="animate-spin text-cyber-accent" size={16} />
              <span>Loading incidents...</span>
            </div>
          ) : incidents.length === 0 ? (
            <div className="text-center py-20 text-xs text-cyber-muted">
              No correlated security incidents match query limits.
            </div>
          ) : (
            incidents.map((inc) => (
              <div 
                key={inc.id}
                onClick={() => handleSelectIncident(inc)}
                className={`p-3.5 rounded-lg border text-left cursor-pointer transition-all ${
                  selectedInc && selectedInc.id === inc.id
                    ? "bg-blue-500/5 border-blue-500/40 shadow-md shadow-blue-500/5"
                    : "bg-slate-950/20 border-cyber-border/40 hover:bg-slate-900/20"
                }`}
              >
                <div className="flex justify-between items-start gap-2.5">
                  <div className="font-semibold text-xs text-cyber-text line-clamp-1 leading-relaxed">
                    #{inc.id}: {inc.title}
                  </div>
                  <span className={`text-[9px] font-mono px-2 py-0.5 shrink-0 rounded ${getSeverityBadgeClass(inc.severity)}`}>
                    {inc.severity}
                  </span>
                </div>
                
                <div className="flex items-center justify-between text-[10px] text-cyber-muted mt-2.5">
                  <div className="flex items-center gap-1">
                    {getStatusIcon(inc.status)}
                    <span>{inc.status}</span>
                  </div>
                  <span className="font-mono text-[9px]">
                    Risk: <strong className="text-cyber-text">{inc.risk_score}</strong>
                  </span>
                  <span>{new Date(inc.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Incident details panel (Right Side) */}
      <div className="xl:col-span-2 glass-card rounded-xl border border-cyber-border/40 flex flex-col h-full overflow-hidden">
        {selectedInc ? (
          <div className="flex-1 flex flex-col h-full overflow-hidden">
            {/* Header Action bar */}
            <div className="bg-slate-950/40 p-4 border-b border-cyber-border/40 flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider">
                  Incident Management Console
                </div>
                <div className="text-sm font-bold text-cyber-text mt-1">
                  #{selectedInc.id}: {selectedInc.title}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleTriggerAI}
                  disabled={aiLoading}
                  className="flex items-center gap-1.5 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 hover:border-blue-500/40 text-blue-400 text-xs font-semibold rounded-lg px-3 py-1.5 transition-all disabled:opacity-50"
                >
                  <Bot size={14} className={aiLoading ? "animate-pulse" : ""} />
                  {aiLoading ? "Consulting AI..." : "Request AI Brief"}
                </button>
                <button
                  onClick={() => api.downloadReport(selectedInc.id)}
                  className="flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 border border-cyber-border text-cyber-text text-xs rounded-lg px-3 py-1.5 transition-all"
                >
                  <FileText size={14} />
                  Export PDF
                </button>
              </div>
            </div>

            {/* Layout Split: Details Left / Analyst Chat Right */}
            <div className="flex-1 grid grid-cols-1 lg:grid-cols-5 overflow-hidden">
              {/* Detailed specs */}
              <div className="lg:col-span-3 overflow-y-auto p-5 space-y-6 border-r border-cyber-border/40">
                {/* Meta details list */}
                <div className="grid grid-cols-2 gap-4 bg-slate-950/20 p-4 rounded-lg border border-cyber-border/30">
                  <div className="space-y-1">
                    <div className="text-[9px] font-semibold text-cyber-muted uppercase tracking-wider">Asset Scope</div>
                    <div className="text-xs font-semibold flex items-center gap-1.5 text-cyber-text">
                      <HardDrive size={14} className="text-cyber-accent" />
                      {selectedInc.host_affected || "N/A"}
                    </div>
                  </div>
                  <div className="space-y-1">
                    <div className="text-[9px] font-semibold text-cyber-muted uppercase tracking-wider">User Identity</div>
                    <div className="text-xs font-semibold flex items-center gap-1.5 text-cyber-text">
                      <User size={14} className="text-cyber-accent" />
                      {selectedInc.user_affected || "N/A"}
                    </div>
                  </div>
                  <div className="space-y-1">
                    <div className="text-[9px] font-semibold text-cyber-muted uppercase tracking-wider">Assigned Owner</div>
                    <select
                      value={selectedInc.assigned_analyst || ""}
                      onChange={(e) => handleUpdateIncident({ assigned_analyst: e.target.value || null })}
                      className="bg-cyber-bg border border-cyber-border text-xs rounded px-2 py-0.5 text-cyber-text focus:outline-none focus:border-cyber-accent"
                    >
                      <option value="">Unassigned</option>
                      <option value="analyst">Analyst</option>
                      <option value="admin">Admin</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <div className="text-[9px] font-semibold text-cyber-muted uppercase tracking-wider">Operational Status</div>
                    <select
                      value={selectedInc.status}
                      onChange={(e) => handleUpdateIncident({ status: e.target.value })}
                      className="bg-cyber-bg border border-cyber-border text-xs rounded px-2 py-0.5 text-cyber-text focus:outline-none focus:border-cyber-accent"
                    >
                      <option value="New">New</option>
                      <option value="Investigating">Investigating</option>
                      <option value="Remediated">Remediated</option>
                      <option value="Closed">Closed</option>
                    </select>
                  </div>
                </div>

                {/* Threat Intel Indicators section */}
                {extractIOCs(selectedInc).length > 0 && (
                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-cyber-muted">Indicators of Compromise (IOCs)</h3>
                    <div className="space-y-2">
                      {extractIOCs(selectedInc).map((ioc) => {
                        const intel = intelData[ioc];
                        const loading = intelLoading[ioc];
                        
                        return (
                          <div key={ioc} className="bg-slate-900/40 border border-cyber-border/40 p-3 rounded-lg flex flex-col md:flex-row md:items-center md:justify-between gap-3 text-xs">
                            <div className="font-mono text-cyber-text truncate pr-2 flex items-center gap-1.5">
                              {ioc.length > 20 ? <Hash size={14} className="text-blue-400" /> : <Globe size={14} className="text-blue-400" />}
                              <span>{ioc}</span>
                            </div>
                            
                            {intel ? (
                              <div className="flex items-center gap-3">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  intel.reputation === "Malicious" ? "bg-red-500/20 text-red-400 border border-red-500/30" : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                                }`}>
                                  {intel.reputation} ({intel.threat_score}/100)
                                </span>
                                {intel.details?.country && (
                                  <span className="text-cyber-muted text-[10px]">
                                    Origin: {intel.details.country} ({intel.details.campaigns?.[0] || "Unknown Group"})
                                  </span>
                                )}
                              </div>
                            ) : (
                              <button
                                onClick={() => handleEnrichIOC(ioc)}
                                disabled={loading}
                                className="bg-slate-950 hover:bg-slate-900 border border-cyber-border/80 text-[10px] font-semibold text-cyber-text rounded px-2.5 py-1 transition-colors"
                              >
                                {loading ? "Querying..." : "Enrich Indicator"}
                              </button>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* AI Summary report section */}
                <div className="space-y-4">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-cyber-muted flex items-center gap-1.5">
                      <Bot size={15} className="text-blue-400" />
                      AI Investigation Assessment
                    </h3>
                    {selectedInc.ai_summary ? (
                      <div className="bg-blue-950/10 border border-blue-500/10 p-4 rounded-lg text-xs leading-relaxed text-slate-300 mt-2 whitespace-pre-wrap">
                        {selectedInc.ai_summary}
                      </div>
                    ) : (
                      <div className="bg-slate-900/20 border border-dashed border-cyber-border p-5 text-center text-xs text-cyber-muted rounded-lg mt-2">
                        No AI analysis request submitted for this case. Click "Request AI Brief" above to generate a brief.
                      </div>
                    )}
                  </div>

                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-cyber-muted">
                      Containment Playbook Actions
                    </h3>
                    {selectedInc.ai_playbook ? (
                      <div className="bg-red-950/5 border border-red-500/10 p-4 rounded-lg text-xs leading-relaxed text-slate-300 mt-2 whitespace-pre-wrap">
                        {selectedInc.ai_playbook}
                      </div>
                    ) : (
                      <div className="text-xs text-cyber-muted italic pl-1 mt-1">Playbook generates with AI report.</div>
                    )}
                  </div>
                </div>

                {/* Correlated Alerts timeline */}
                <div className="space-y-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-cyber-muted">Correlated Security Alerts Timeline</h3>
                  <div className="space-y-3">
                    {selectedInc.alerts?.map((alert: any, idx: number) => (
                      <div key={alert.id} className="bg-slate-950/20 border border-cyber-border/40 p-4 rounded-lg space-y-2 relative">
                        <div className="absolute top-4 right-4 flex items-center gap-2">
                          <span className={`text-[8px] uppercase px-1.5 py-0.5 rounded font-mono font-bold ${
                            alert.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                            alert.severity === 'High' ? 'bg-orange-500/20 text-orange-400' :
                            alert.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-blue-500/20 text-blue-400'
                          }`}>
                            {alert.severity}
                          </span>
                        </div>

                        <div className="text-xs font-bold text-cyber-text">
                          {idx + 1}. {alert.rule_name}
                        </div>
                        <p className="text-[11px] text-cyber-muted leading-relaxed">
                          {alert.description}
                        </p>
                        
                        {alert.mitre_techniques && (
                          <div className="flex gap-1.5 py-1">
                            {alert.mitre_techniques.map((t: string) => (
                              <span key={t} className="text-[8px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-cyber-accent border border-blue-500/20">
                                MITRE: {t}
                              </span>
                            ))}
                          </div>
                        )}

                        <div className="text-[10px] bg-slate-950/60 p-2.5 rounded font-mono text-cyber-muted text-[10px] break-all overflow-x-auto whitespace-pre">
                          {JSON.stringify(alert.details?.fields || alert.details, null, 2)}
                        </div>
                        
                        <div className="text-[9px] text-cyber-muted flex items-center gap-1.5">
                          <Clock size={12} />
                          <span>{new Date(alert.timestamp).toUTCString()}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Notes and comments timeline (Right Side of drawer) */}
              <div className="lg:col-span-2 flex flex-col h-full bg-slate-950/15 overflow-hidden">
                <div className="p-4 border-b border-cyber-border/40 text-xs font-bold uppercase tracking-wider text-cyber-muted">
                  Analyst Log Notes
                </div>
                
                {/* Notes List */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                  {(!selectedInc.comments || selectedInc.comments.length === 0) ? (
                    <div className="text-center py-20 text-[11px] text-cyber-muted">
                      No analyst entries log registered. Add annotations below.
                    </div>
                  ) : (
                    selectedInc.comments.map((comment: any) => (
                      <div key={comment.id} className="bg-slate-900/30 border border-cyber-border/30 rounded-lg p-3 space-y-1">
                        <div className="flex justify-between items-center text-[10px]">
                          <span className="font-semibold text-cyber-accent flex items-center gap-1">
                            <UserCheck size={12} />
                            {comment.author}
                          </span>
                          <span className="text-[9px] text-cyber-muted font-mono">
                            {new Date(comment.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-300 leading-relaxed break-words whitespace-pre-wrap">
                          {comment.content}
                        </p>
                      </div>
                    ))
                  )}
                </div>

                {/* Form input */}
                <form onSubmit={handleAddComment} className="p-3 border-t border-cyber-border/40 bg-slate-950/30 flex items-center gap-2">
                  <input
                    type="text"
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    placeholder="Enter analytical notes to timeline..."
                    className="flex-1 bg-cyber-bg border border-cyber-border rounded-lg py-2 px-3 text-xs text-cyber-text focus:outline-none focus:border-cyber-accent/60 placeholder:text-cyber-muted/50"
                  />
                  <button
                    type="submit"
                    className="bg-cyber-accent/90 hover:bg-cyber-accent p-2 rounded-lg text-white transition-colors active:translate-y-0.5 border border-blue-400/20 shadow"
                  >
                    <Send size={14} />
                  </button>
                </form>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-cyber-muted text-center">
            <AlertTriangle size={32} className="text-cyber-muted/40 mb-3 animate-pulse" />
            <h3 className="text-sm font-semibold">No Incident Selected</h3>
            <p className="text-xs mt-1 max-w-sm">
              Select an incident from the list panel to open the active investigation workspace, access threat intel, read AI briefs, and take mitigation actions.
            </p>
          </div>
        )}
      </div>

    </div>
  );
}
