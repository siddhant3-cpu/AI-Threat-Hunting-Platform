import React, { useEffect, useState } from "react";
import { Code, Trash, Shield, Plus, ToggleLeft, ToggleRight, X, Terminal, HelpCircle } from "lucide-react";
import { api } from "../services/api";

export function Rules() {
  const [rules, setRules] = useState<any[]>([]);
  const [selectedRule, setSelectedRule] = useState<any>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [loading, setLoading] = useState(true);

  // Form Fields
  const [title, setTitle] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [category, setCategory] = useState("process_creation");
  const [severity, setSeverity] = useState("Medium");
  const [description, setDescription] = useState("");
  const [yamlContent, setYamlContent] = useState("");
  const [formError, setFormError] = useState("");

  const loadRules = async () => {
    try {
      const data = await api.getRules();
      setRules(data);
      if (data.length > 0 && !selectedRule) {
        setSelectedRule(data[0]);
      }
    } catch (err) {
      console.error("Failed to load rules", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleToggle = async (rule: any) => {
    try {
      const updated = await api.toggleRule(rule.id);
      setRules(prev => prev.map(r => r.id === rule.id ? updated : r));
      if (selectedRule && selectedRule.id === rule.id) {
        setSelectedRule(updated);
      }
    } catch (err) {
      console.error("Failed to toggle rule state", err);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this custom Sigma rule?")) return;
    try {
      await api.deleteRule(id);
      setRules(prev => prev.filter(r => r.id !== id));
      if (selectedRule && selectedRule.id === id) {
        setSelectedRule(null);
      }
    } catch (err) {
      console.error("Failed to delete rule", err);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");

    if (!ruleId.trim() || !title.trim() || !yamlContent.trim()) {
      setFormError("All required fields must be completed.");
      return;
    }

    try {
      const newRule = await api.createRule({
        id: ruleId.trim(),
        title: title.trim(),
        category,
        severity,
        description: description.trim(),
        yaml_content: yamlContent,
        status: "active"
      });
      
      setRules(prev => [...prev, newRule]);
      setSelectedRule(newRule);
      setShowCreateModal(false);
      
      // Reset form
      setTitle("");
      setRuleId("");
      setCategory("process_creation");
      setSeverity("Medium");
      setDescription("");
      setYamlContent("");
    } catch (err: any) {
      setFormError(err.message || "Failed to create rule. Verify your YAML syntax.");
    }
  };

  const getPresetTemplate = () => {
    const template = `title: Detect Custom Malicious Process Creation
id: custom_process_detect_${Math.floor(Math.random() * 1000)}
status: active
description: Detects custom hacker tool commands execution.
category: process_creation
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    CommandLine|contains:
      - 'hacktool_command'
      - 'shadow_exec'
    Image|endswith:
      - '\\hacker_agent.exe'
  condition: selection
severity: High
tags:
  - attack.execution
  - attack.t1059`;
    setYamlContent(template.trim());
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[calc(100vh-140px)]">
      
      {/* Left side list */}
      <div className="lg:col-span-1 glass-card rounded-xl p-4 flex flex-col h-full border border-cyber-border/40">
        <div className="flex items-center justify-between border-b border-cyber-border/40 pb-3 mb-4 shrink-0">
          <h2 className="text-base font-semibold text-cyber-text">Sigma Rules Repository</h2>
          <button
            onClick={() => { setShowCreateModal(true); setFormError(""); }}
            className="flex items-center gap-1.5 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 text-blue-400 text-xs font-semibold rounded px-2.5 py-1.5 transition-colors active:translate-y-0.5"
          >
            <Plus size={14} />
            Create Rule
          </button>
        </div>

        {/* Search list */}
        <div className="flex-1 overflow-y-auto space-y-2.5 pr-1">
          {loading ? (
            <div className="text-center py-10 text-xs text-cyber-muted">Loading rules database...</div>
          ) : rules.length === 0 ? (
            <div className="text-center py-10 text-xs text-cyber-muted font-mono">No rules registered.</div>
          ) : (
            rules.map((rule) => (
              <div
                key={rule.id}
                onClick={() => setSelectedRule(rule)}
                className={`p-3 rounded-lg border text-left cursor-pointer transition-all flex items-center justify-between gap-4 ${
                  selectedRule && selectedRule.id === rule.id
                    ? "bg-blue-500/5 border-blue-500/40"
                    : "bg-slate-950/20 border-cyber-border/40 hover:bg-slate-900/20"
                }`}
              >
                <div className="min-w-0">
                  <div className="font-bold text-xs text-cyber-text truncate">{rule.title}</div>
                  <div className="text-[10px] text-cyber-muted font-mono mt-1">
                    ID: {rule.id} • Category: {rule.category}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className={`text-[8px] font-mono px-1.5 py-0.5 rounded ${
                    rule.severity === "Critical" ? "bg-red-500/10 text-red-400 border border-red-500/20" :
                    rule.severity === "High" ? "bg-orange-500/10 text-orange-400 border border-orange-500/20" :
                    rule.severity === "Medium" ? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20" :
                    "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                  }`}>
                    {rule.severity}
                  </span>
                  
                  {rule.status === "active" ? (
                    <Shield className="text-cyber-success" size={14} />
                  ) : (
                    <Shield className="text-cyber-muted opacity-50" size={14} />
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Right side editor/YAML viewer */}
      <div className="lg:col-span-2 glass-card rounded-xl border border-cyber-border/40 flex flex-col h-full overflow-hidden">
        {selectedRule ? (
          <div className="flex-grow flex flex-col h-full overflow-hidden">
            {/* Action Bar */}
            <div className="bg-slate-950/40 p-4 border-b border-cyber-border/40 flex items-center justify-between shrink-0">
              <div>
                <div className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider">RULE COMPILER PANEL</div>
                <h3 className="text-sm font-bold text-cyber-text mt-1 truncate">{selectedRule.title}</h3>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => handleToggle(selectedRule)}
                  className="flex items-center gap-1.5 bg-slate-900 border border-cyber-border text-cyber-text text-xs rounded px-3 py-1.5 hover:border-cyber-accent/60 transition-colors"
                >
                  {selectedRule.status === "active" ? (
                    <>
                      <ToggleRight className="text-cyber-success" size={16} />
                      Active
                    </>
                  ) : (
                    <>
                      <ToggleLeft className="text-cyber-muted" size={16} />
                      Inactive
                    </>
                  )}
                </button>
                {/* Only delete rules that aren't the disk-based core rules (disk rule IDs: powershell_encoded, mimikatz_detection, reverse_shell, etc.) */}
                {!["powershell_encoded", "mimikatz_detection", "reverse_shell", "registry_persistence", "failed_login", "psexec_activity"].includes(selectedRule.id) && (
                  <button
                    onClick={() => handleDelete(selectedRule.id)}
                    className="flex items-center gap-1 bg-red-950/20 hover:bg-red-950/40 border border-red-500/30 text-red-400 text-xs rounded px-3 py-1.5 transition-colors"
                  >
                    <Trash size={14} />
                    Delete Rule
                  </button>
                )}
              </div>
            </div>

            {/* Content view */}
            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              <div className="text-xs text-slate-300 leading-relaxed max-w-2xl">
                <span className="font-semibold text-cyber-muted uppercase tracking-wider block text-[10px] mb-1">Description</span>
                {selectedRule.description || "No description provided."}
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-cyber-muted uppercase tracking-wider text-[10px]">YAML Definition</span>
                  <span className="text-[10px] font-mono text-cyber-accent">Sigma Syntax Highlighting</span>
                </div>
                <pre className="bg-slate-950 p-4 rounded-lg border border-cyber-border/40 font-mono text-[11px] text-green-400 overflow-x-auto leading-relaxed shadow-inner">
                  {selectedRule.yaml_content}
                </pre>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-cyber-muted">
            <Code size={32} className="text-cyber-muted/30 mb-3 animate-pulse" />
            <h3 className="text-sm font-semibold">No Rule Selected</h3>
            <p className="text-xs mt-1">Select a rule from the repository panel to inspect its compiled configuration.</p>
          </div>
        )}
      </div>

      {/* Create Custom Rule Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="glass-card w-full max-w-3xl rounded-xl border border-cyber-border/60 overflow-hidden flex flex-col max-h-[90vh] shadow-2xl relative glow-border-blue animate-scaleUp">
            
            <div className="flex items-center justify-between p-4 border-b border-cyber-border/40 bg-slate-950/40">
              <h3 className="text-sm font-bold text-cyber-text flex items-center gap-2">
                <Terminal size={16} className="text-cyber-accent" />
                Add Custom Sigma Rule
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="text-cyber-muted hover:text-cyber-text">
                <X size={18} />
              </button>
            </div>

            {formError && (
              <div className="m-4 bg-red-500/10 border border-red-500/20 text-cyber-danger text-xs rounded p-3">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreateRule} className="flex-grow overflow-y-auto p-5 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="space-y-4">
                <div className="space-y-1">
                  <label className="block text-cyber-muted font-semibold tracking-wide">Unique Rule ID (slug)</label>
                  <input
                    type="text"
                    value={ruleId}
                    onChange={(e) => setRuleId(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ""))}
                    required
                    placeholder="e.g. encoded_powershell_custom"
                    className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-accent"
                  />
                </div>

                <div className="space-y-1">
                  <label className="block text-cyber-muted font-semibold tracking-wide">Rule Title</label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                    placeholder="e.g. Custom PowerShell Ingestion Warning"
                    className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-accent"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="block text-cyber-muted font-semibold tracking-wide">Category</label>
                    <select
                      value={category}
                      onChange={(e) => setCategory(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-accent"
                    >
                      <option value="process_creation">process_creation</option>
                      <option value="network_connection">network_connection</option>
                      <option value="registry_modification">registry_modification</option>
                      <option value="authentication">authentication</option>
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="block text-cyber-muted font-semibold tracking-wide">Severity</label>
                    <select
                      value={severity}
                      onChange={(e) => setSeverity(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-accent"
                    >
                      <option value="Low">Low</option>
                      <option value="Medium">Medium</option>
                      <option value="High">High</option>
                      <option value="Critical">Critical</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="block text-cyber-muted font-semibold tracking-wide">Rule Description</label>
                  <textarea
                    rows={3}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Briefly detail what security behavior this rule is designed to block..."
                    className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-accent"
                  />
                </div>

                <div className="bg-slate-900/60 p-3.5 rounded border border-cyber-border/40 flex items-start gap-2.5">
                  <HelpCircle className="text-cyber-accent mt-0.5 shrink-0" size={16} />
                  <div className="text-[10px] text-cyber-muted leading-relaxed">
                    <strong className="text-cyber-text font-bold">Writing Guide:</strong>
                    <p className="mt-1">
                      Sigma condition is evaluated against key-values. Use the modifier syntax <code className="font-mono text-cyan-400">|contains</code>, <code className="font-mono text-cyan-400">|endswith</code>, or <code className="font-mono text-cyan-400">|startswith</code> to test fields in process execution logs.
                    </p>
                  </div>
                </div>
              </div>

              {/* YAML Editor */}
              <div className="space-y-1.5 flex flex-col h-full">
                <div className="flex justify-between items-center">
                  <label className="block text-cyber-muted font-semibold tracking-wide">Raw YAML Definition</label>
                  <button
                    type="button"
                    onClick={getPresetTemplate}
                    className="text-[10px] font-semibold text-cyber-accent hover:underline"
                  >
                    Load Template
                  </button>
                </div>
                <textarea
                  rows={14}
                  value={yamlContent}
                  onChange={(e) => setYamlContent(e.target.value)}
                  required
                  placeholder="Paste your rule YAML content here..."
                  className="w-full flex-grow bg-slate-950 border border-cyber-border rounded-lg p-3 font-mono text-[10px] text-green-400 focus:outline-none focus:border-cyber-accent"
                />
              </div>

              <div className="col-span-1 md:col-span-2 border-t border-cyber-border/40 pt-4 mt-2 flex justify-end gap-3 shrink-0">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="bg-slate-900 border border-cyber-border hover:border-cyber-accent/60 text-cyber-text font-semibold rounded px-4 py-2 transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-cyber-accent hover:bg-cyber-accent/90 text-white font-semibold rounded px-6 py-2 transition-all active:translate-y-0.5"
                >
                  Save and Compile
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
