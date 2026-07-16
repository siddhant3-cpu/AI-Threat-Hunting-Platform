import { useEffect, useState } from "react";
import { 
  ShieldAlert, Shield, Terminal, Play, LogOut, 
  Menu, X, Radio, Compass 
} from "lucide-react";

import { Login } from "./views/Login";
import { Dashboard } from "./views/Dashboard";
import { IncidentManager } from "./views/IncidentManager";
import { ThreatHunting } from "./views/ThreatHunting";
import { Rules } from "./views/Rules";
import { Simulator } from "./views/Simulator";
import { api } from "./services/api";

type Tab = "dashboard" | "incidents" | "hunting" | "rules" | "simulator";

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [username, setUsername] = useState("");
  const [role, setRole] = useState("");
  const [activeTab, setActiveTab] = useState<Tab>("dashboard");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const checkAuth = () => {
    const authed = api.isAuthenticated();
    setIsAuthenticated(authed);
    if (authed) {
      const user = api.getUser();
      setUsername(user.username || "Analyst");
      setRole(user.role || "Analyst");
    }
  };

  useEffect(() => {
    checkAuth();
    
    // Listen for 401 logs auth changes
    window.addEventListener("auth-change", checkAuth);
    return () => window.removeEventListener("auth-change", checkAuth);
  }, []);

  const handleLogout = () => {
    api.logout();
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <Login onLoginSuccess={checkAuth} />;
  }

  const renderActiveView = () => {
    switch (activeTab) {
      case "dashboard":
        return <Dashboard />;
      case "incidents":
        return <IncidentManager />;
      case "hunting":
        return <ThreatHunting />;
      case "rules":
        return <Rules />;
      case "simulator":
        return <Simulator />;
      default:
        return <Dashboard />;
    }
  };

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: <Radio size={16} /> },
    { id: "incidents", label: "Incident Manager", icon: <ShieldAlert size={16} /> },
    { id: "hunting", label: "Threat Hunting", icon: <Terminal size={16} /> },
    { id: "rules", label: "Sigma Rules", icon: <Compass size={16} /> },
    { id: "simulator", label: "Simulation Lab", icon: <Play size={16} /> },
  ] as const;

  return (
    <div className="min-h-screen bg-cyber-bg text-cyber-text flex flex-col relative">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-900/5 via-cyber-bg to-cyber-bg pointer-events-none"></div>

      {/* Main Header */}
      <header className="sticky top-0 bg-slate-950/80 backdrop-blur-md border-b border-cyber-border/40 z-40 shrink-0">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-cyber-accent glow-text-blue">
              <Shield size={20} />
            </div>
            <div>
              <span className="font-bold text-sm tracking-wide text-cyber-text uppercase">
                ASATL Platform
              </span>
              <span className="hidden md:inline-block text-[10px] font-semibold text-cyber-accent bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded ml-2 uppercase font-mono tracking-wider">
                Active SOC Sandbox
              </span>
            </div>
          </div>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center gap-1.5">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-all border ${
                  activeTab === item.id
                    ? "bg-blue-500/10 border-blue-500/30 text-cyber-accent glow-text-blue"
                    : "border-transparent text-cyber-muted hover:text-cyber-text hover:bg-slate-900/35"
                }`}
              >
                {item.icon}
                {item.label}
              </button>
            ))}
          </nav>

          {/* Right Header Info */}
          <div className="hidden md:flex items-center gap-4">
            <div className="text-right">
              <div className="text-xs font-semibold text-cyber-text flex items-center gap-1.5 justify-end">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-success animate-pulse"></span>
                {username}
              </div>
              <div className="text-[9px] font-mono text-cyber-muted uppercase tracking-wider">
                {role} Context
              </div>
            </div>

            <button
              onClick={handleLogout}
              className="bg-slate-900 border border-cyber-border hover:border-red-500/40 text-cyber-muted hover:text-red-400 p-2 rounded-lg transition-all active:translate-y-0.5"
              title="Terminate Auth Session"
            >
              <LogOut size={15} />
            </button>
          </div>

          {/* Mobile Menu Trigger */}
          <div className="flex md:hidden items-center gap-3">
            <button
              onClick={handleLogout}
              className="bg-slate-900 border border-cyber-border text-cyber-muted p-2 rounded-lg"
            >
              <LogOut size={15} />
            </button>
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="bg-slate-900 border border-cyber-border text-cyber-text p-2 rounded-lg"
            >
              {mobileMenuOpen ? <X size={16} /> : <Menu size={16} />}
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-slate-950/95 backdrop-blur-md border-b border-cyber-border/40 p-4 space-y-2.5 z-30 shrink-0">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setActiveTab(item.id);
                setMobileMenuOpen(false);
              }}
              className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm rounded-lg border ${
                activeTab === item.id
                  ? "bg-blue-500/10 border-blue-500/20 text-cyber-accent font-semibold"
                  : "border-transparent text-cyber-muted hover:bg-slate-900"
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </div>
      )}

      {/* Main View Area */}
      <main className="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 overflow-hidden flex flex-col justify-stretch">
        <div className="mb-5 rounded-2xl border border-cyber-border/40 bg-slate-950/65 px-4 py-3.5 shadow-[0_0_35px_rgba(59,130,246,0.08)]">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="text-[10px] uppercase tracking-[0.3em] text-cyber-accent font-semibold">
                Live operations center
              </div>
              <div className="text-sm text-cyber-text font-medium">
                Monitoring identities, endpoints, and suspicious behavior in near real time.
              </div>
            </div>
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-300">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
              Signal feed healthy
            </div>
          </div>
        </div>
        {renderActiveView()}
      </main>

      {/* Platform Status Footer */}
      <footer className="bg-slate-950/20 border-t border-cyber-border/30 h-10 shrink-0 flex items-center">
        <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 flex justify-between text-[9px] font-mono text-cyber-muted tracking-wider uppercase">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyber-success animate-ping"></span>
            Agent Telemetry Listener: Connected
          </div>
          <div>
            ASATL Platform V1.0.0
          </div>
        </div>
      </footer>
    </div>
  );
}
