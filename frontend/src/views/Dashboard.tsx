import { useEffect, useState } from "react";
import { Shield, AlertTriangle, Activity, RefreshCw, Radio, Compass } from "lucide-react";

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { api } from "../services/api";

export function Dashboard() {
  const [stats, setStats] = useState({ total_alerts: 0, active_incidents: 0, critical_alerts: 0, avg_risk_score: 0 });
  const [mitre, setMitre] = useState<any[]>([]);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async () => {
    try {
      const [sData, mData, tData, aData] = await Promise.all([
        api.getStats(),
        api.getMitreMatrix(),
        api.getTimeline(),
        api.getAlerts()
      ]);
      setStats(sData);
      setMitre(mData);
      setTimeline(tData);
      setAlerts(aData.slice(0, 5)); // Keep last 5
    } catch (err) {
      console.error("Failed to load dashboard metrics", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000); // Auto refresh every 5s
    return () => clearInterval(interval);
  }, []);

  // Standard static MITRE ATT&CK techniques we support mapping
  const staticMitreTechniques = [
    { id: "T1110", name: "Brute Force Logins", phase: "Credential Access" },
    { id: "T1003.001", name: "LSASS Memory Dumping", phase: "Credential Access" },
    { id: "T1547.001", name: "Registry Run Keys", phase: "Persistence" },
    { id: "T1053", name: "Scheduled Task Abuse", phase: "Persistence" },
    { id: "T1059.001", name: "PowerShell Scripting", phase: "Execution" },
    { id: "T1059.004", name: "Unix Shell execution", phase: "Execution" },
    { id: "T1569.002", name: "PsExec Service Abuse", phase: "Lateral Movement" },
    { id: "T1090", name: "Proxy C2 Tunneling", phase: "Command & Control" }
  ];

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case "Critical": return "bg-red-500/10 text-red-400 border-red-500/30";
      case "High": return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "Medium": return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
      default: return "bg-blue-500/10 text-blue-400 border-blue-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Dashboard Header */}
      <div className="flex items-center justify-between border-b border-cyber-border/40 pb-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-cyber-text">
            <Shield className="text-cyber-accent glow-text-blue" />
            Security Command Dashboard
          </h1>
          <p className="text-sm text-cyber-muted">
            Real-time security events correlation and Sigma-driven analytics.
          </p>
        </div>
        <button 
          onClick={() => { setLoading(true); fetchDashboardData(); }}
          className="flex items-center gap-2 bg-slate-900 border border-cyber-border hover:border-cyber-accent/60 text-cyber-text text-xs rounded-lg px-3.5 py-2 transition-all active:translate-y-0.5"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Refresh Stats
        </button>
      </div>

      <div className="rounded-2xl border border-cyber-border/50 bg-gradient-to-br from-blue-500/15 via-slate-900/70 to-slate-950 p-5 shadow-[0_0_30px_rgba(59,130,246,0.08)]">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="text-[10px] uppercase tracking-[0.35em] text-cyber-accent font-semibold">
              Threat posture
            </div>
            <h2 className="mt-1 text-xl font-semibold text-cyber-text">
              Elevated visibility across the attack surface
            </h2>
            <p className="mt-1 text-sm text-cyber-muted">
              Analysts can quickly review detections, correlate incidents, and respond to live attack simulations.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {['Credential theft', 'PowerShell abuse', 'Persistence'].map((tag) => (
              <span key={tag} className="rounded-full border border-cyber-border/50 bg-slate-950/70 px-3 py-1 text-[11px] text-cyber-muted">
                {tag}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
        <div className="glass-card glass-card-hover p-5 rounded-2xl flex items-center justify-between border border-slate-800/70 bg-gradient-to-br from-slate-900/90 to-slate-950/70">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-cyber-muted">Total Security Alerts</div>
            <div className="text-3xl font-bold mt-1.5 text-cyber-text">{stats.total_alerts}</div>
          </div>
          <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-cyber-accent glow-text-blue">
            <Radio size={22} className="animate-pulse" />
          </div>
        </div>

        <div className="glass-card glass-card-hover p-5 rounded-2xl flex items-center justify-between border border-slate-800/70 bg-gradient-to-br from-slate-900/90 to-slate-950/70">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-cyber-muted">Active Incidents</div>
            <div className="text-3xl font-bold mt-1.5 text-orange-400">{stats.active_incidents}</div>
          </div>
          <div className="w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center text-orange-400">
            <AlertTriangle size={22} />
          </div>
        </div>

        <div className="glass-card glass-card-hover p-5 rounded-2xl flex items-center justify-between border border-slate-800/70 bg-gradient-to-br from-slate-900/90 to-slate-950/70">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-cyber-muted">Critical Events</div>
            <div className="text-3xl font-bold mt-1.5 text-red-500">{stats.critical_alerts}</div>
          </div>
          <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-500">
            <Activity size={22} />
          </div>
        </div>

        <div className="glass-card glass-card-hover p-5 rounded-2xl flex items-center justify-between border border-slate-800/70 bg-gradient-to-br from-slate-900/90 to-slate-950/70">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-cyber-muted">Avg Risk Score</div>
            <div className="text-3xl font-bold mt-1.5 text-cyber-text">{stats.avg_risk_score}</div>
          </div>
          <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <Compass size={22} />
          </div>
        </div>
      </div>

      {/* Charts section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alerts Timeline */}
        <div className="glass-card p-5 rounded-xl lg:col-span-2">
          <h2 className="text-base font-semibold mb-4 text-cyber-text">Threat Timeline Trend (24h)</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeline} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: "#0b0f19", borderColor: "rgba(255,255,255,0.1)", color: "#f8fafc" }}
                  itemStyle={{ fontSize: "12px" }}
                  labelStyle={{ fontSize: "12px", color: "#94a3b8" }}
                />
                <Line type="monotone" dataKey="total" name="Alerts" stroke="#3b82f6" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Global Attack Map Sim */}
        <div className="glass-card p-5 rounded-xl flex flex-col justify-between">
          <h2 className="text-base font-semibold text-cyber-text">Simulated Attack Origins</h2>
          <div className="relative h-44 my-4 flex items-center justify-center border border-cyber-border/40 bg-slate-950/40 rounded-lg overflow-hidden">
            {/* Pulsing Target Radar in center */}
            <div className="absolute w-24 h-24 rounded-full border border-blue-500/20 animate-ping"></div>
            <div className="absolute w-12 h-12 rounded-full border border-blue-500/40 flex items-center justify-center">
              <span className="w-2.5 h-2.5 rounded-full bg-cyber-accent animate-pulse"></span>
            </div>
            
            {/* Attack Source Indicators */}
            <div className="absolute top-8 left-8 text-center animate-bounce">
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 border border-red-500/30 text-red-400">RU C2</span>
              <div className="w-2 h-2 rounded-full bg-red-500 mx-auto mt-1 animate-pulse"></div>
            </div>
            <div className="absolute bottom-10 right-10 text-center animate-bounce delay-300">
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 border border-red-500/30 text-red-400">CN Scan</span>
              <div className="w-2 h-2 rounded-full bg-red-500 mx-auto mt-1 animate-pulse"></div>
            </div>
            
            {/* SVG Connecting Attack Lines */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none">
              <path d="M 32 40 Q 110 50 144 88" stroke="#ef4444" strokeWidth="1.5" fill="none" strokeDasharray="5,5" className="animate-dash" />
              <path d="M 230 140 Q 180 110 144 88" stroke="#ef4444" strokeWidth="1.5" fill="none" strokeDasharray="5,5" className="animate-dash" />
            </svg>
            
            <div className="absolute bottom-2 left-2 text-[10px] text-cyber-muted font-mono flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
              Live Attack Simulation Feeds Active
            </div>
          </div>
          
          <div className="space-y-2.5 text-xs">
            <div className="flex justify-between border-b border-cyber-border/40 pb-2">
              <span className="text-cyber-muted">Attacking IP</span>
              <span className="font-mono text-cyber-text">Location</span>
              <span className="font-mono text-cyber-text">Target Host</span>
            </div>
            <div className="flex justify-between">
              <span className="text-red-400 font-mono">198.51.100.45</span>
              <span className="text-cyber-muted">Moscow, RU</span>
              <span className="font-mono text-cyber-muted">WS-PROD-01</span>
            </div>
            <div className="flex justify-between">
              <span className="text-red-400 font-mono">203.0.113.19</span>
              <span className="text-cyber-muted">Beijing, CN</span>
              <span className="font-mono text-cyber-muted">linux-srv-01</span>
            </div>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix & Threat Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* MITRE ATT&CK Matrix Matrix */}
        <div className="glass-card p-5 rounded-xl lg:col-span-2">
          <h2 className="text-base font-semibold mb-1 text-cyber-text">MITRE ATT&CK® Matrix Heatmap</h2>
          <p className="text-xs text-cyber-muted mb-4">Correlation of triggered techniques mapped to tactical categories.</p>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {staticMitreTechniques.map((tech) => {
              // Find matching technique counts
              const matched = mitre.find(m => m.technique === tech.id);
              const count = matched ? matched.count : 0;
              const sev = matched ? matched.severity : "None";
              
              return (
                <div 
                  key={tech.id} 
                  className={`p-3.5 rounded-lg border flex flex-col justify-between h-24 transition-all ${
                    count > 0 
                      ? getSeverityColor(sev) + " border border-current"
                      : "bg-slate-900/30 border-cyber-border/50 text-cyber-muted"
                  }`}
                >
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-wider opacity-85">{tech.phase}</div>
                    <div className="text-xs font-bold mt-1 text-cyber-text line-clamp-1">{tech.name}</div>
                  </div>
                  <div className="flex items-center justify-between mt-2">
                    <span className="text-[10px] font-mono opacity-60">{tech.id}</span>
                    {count > 0 && (
                      <span className="text-xs font-bold px-2 py-0.5 rounded bg-slate-950/60 font-mono">
                        {count} Event{count > 1 ? 's' : ''}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Live Alerts Stream */}
        <div className="glass-card p-5 rounded-xl">
          <h2 className="text-base font-semibold mb-4 text-cyber-text">Recent Alerts Stream</h2>
          <div className="space-y-3.5">
            {alerts.length === 0 ? (
              <div className="text-center py-10 text-xs text-cyber-muted flex flex-col items-center justify-center gap-2">
                <Shield size={24} className="opacity-40 animate-pulse text-cyber-accent" />
                <span>No alerts registered yet. Trigger a lab attack flow to inject logs.</span>
              </div>
            ) : (
              alerts.map((alert) => (
                <div key={alert.id} className="border-l-2 border-cyber-accent pl-3 py-1 space-y-1">
                  <div className="flex justify-between items-start">
                    <span className="text-xs font-bold text-cyber-text">{alert.rule_name}</span>
                    <span className={`text-[9px] uppercase px-1.5 py-0.5 rounded font-mono font-bold ${
                      alert.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                      alert.severity === 'High' ? 'bg-orange-500/20 text-orange-400' :
                      alert.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>
                      {alert.severity}
                    </span>
                  </div>
                  <div className="text-[10px] text-cyber-muted">
                    Asset: <span className="font-mono text-cyber-text">{alert.host || 'N/A'}</span> • User: <span className="text-cyber-text">{alert.user || 'N/A'}</span>
                  </div>
                  <div className="text-[9px] text-cyber-muted font-mono">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
