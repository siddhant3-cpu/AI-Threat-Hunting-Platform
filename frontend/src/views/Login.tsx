import React, { useState } from "react";
import { Shield, Lock, User, AlertCircle } from "lucide-react";
import { api } from "../services/api";

interface LoginProps {
  onLoginSuccess: () => void;
}

export function Login({ onLoginSuccess }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await api.login(username, password);
      onLoginSuccess();
    } catch (err: any) {
      setError(err.message || "Failed to authenticate with security gateway.");
    } finally {
      setLoading(false);
    }
  };

  const handlePreFill = (user: string, pass: string) => {
    setUsername(user);
    setPassword(pass);
  };

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-4 relative radar-grid">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-blue-900/10 via-cyber-bg to-cyber-bg pointer-events-none"></div>
      
      <div className="w-full max-w-md glass-card p-8 rounded-2xl border border-cyber-border/40 relative glow-border-blue">
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center mb-4 text-cyber-accent glow-text-blue">
            <Shield size={36} />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-center bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
            SOC Operations Gateway
          </h1>
          <p className="text-sm text-cyber-muted mt-1">
            AI-Powered Threat Hunting & Detection Platform
          </p>
        </div>

        {error && (
          <div className="mb-6 bg-red-500/10 border border-red-500/20 text-cyber-danger text-sm rounded-lg p-3 flex items-start gap-2.5">
            <AlertCircle size={18} className="shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-cyber-muted mb-2">
              Security Analyst ID
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                <User size={18} />
              </span>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full bg-cyber-bg/50 border border-cyber-border rounded-lg py-2.5 pl-10 pr-4 text-cyber-text placeholder:text-cyber-muted/50 focus:outline-none focus:border-cyber-accent/60 transition-colors"
                placeholder="analyst or admin"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-cyber-muted mb-2">
              Analyst Passkey
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                <Lock size={18} />
              </span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-cyber-bg/50 border border-cyber-border rounded-lg py-2.5 pl-10 pr-4 text-cyber-text placeholder:text-cyber-muted/50 focus:outline-none focus:border-cyber-accent/60 transition-colors"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-cyber-accent/90 hover:bg-cyber-accent text-white font-medium rounded-lg py-3 tracking-wide shadow-lg shadow-cyber-accent/20 hover:shadow-cyber-accent/30 transition-all border border-blue-400/20 active:translate-y-0.5 disabled:opacity-50"
          >
            {loading ? "Decrypting Session..." : "Authorize Portal"}
          </button>
        </form>

        <div className="mt-8 border-t border-cyber-border/40 pt-6">
          <p className="text-xs text-cyber-muted mb-3 font-semibold uppercase tracking-wider">
            Bootstrap Credentials
          </p>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <button
              onClick={() => handlePreFill("analyst", "cybersecurity2026")}
              className="bg-slate-900/40 hover:bg-slate-900 border border-cyber-border rounded-lg p-2.5 text-left transition-colors"
            >
              <div className="font-semibold text-cyber-accent">Role: Analyst</div>
              <div className="text-cyber-muted">analyst / cybersecurity2026</div>
            </button>
            <button
              onClick={() => handlePreFill("admin", "admin123")}
              className="bg-slate-900/40 hover:bg-slate-900 border border-cyber-border rounded-lg p-2.5 text-left transition-colors"
            >
              <div className="font-semibold text-red-400">Role: Admin</div>
              <div className="text-cyber-muted">admin / admin123</div>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
