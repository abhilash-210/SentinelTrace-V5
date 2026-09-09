/**
 * pages/DetectionRules.jsx
 * -------------------------
 * Detection Rule Registry & Canonical Field Dependency Mapping dashboard.
 *
 * Sprint 6A — Detection Rule Registry & Canonical Field Dependency Mapping.
 *
 * Features:
 * - Detection rule listing with severity/status filters
 * - Rule detail inspection modal with full dependency graph
 * - Canonical field impact analysis panel
 * - Interactive dependency DAG visualization
 * - MITRE ATT&CK tactic/technique display
 */

import React, { useState, useEffect, useCallback, useRef } from "react";
import { useAuth } from "../context/AuthContext";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ── Severity badge colors ────────────────────────────────────────────────────
const severityColors = {
  CRITICAL: "bg-red-950/70 border-red-500/50 text-red-300",
  HIGH: "bg-orange-950/70 border-orange-500/50 text-orange-300",
  MEDIUM: "bg-yellow-950/70 border-yellow-500/50 text-yellow-300",
  LOW: "bg-emerald-950/70 border-emerald-500/50 text-emerald-300",
};

const statusColors = {
  DRAFT: "bg-slate-800/70 border-slate-500/50 text-slate-300",
  ACTIVE: "bg-emerald-950/70 border-emerald-500/50 text-emerald-300",
  DEPRECATED: "bg-red-950/50 border-red-700/40 text-red-400",
};

const depTypeColors = {
  REQUIRED: "bg-rose-950/60 border-rose-500/40 text-rose-300",
  OPTIONAL: "bg-sky-950/60 border-sky-500/40 text-sky-300",
  ENRICHMENT: "bg-violet-950/60 border-violet-500/40 text-violet-300",
};

function Badge({ text, colorClass }) {
  return (
    <span
      className={`inline-block text-[9px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded-md border ${colorClass}`}
    >
      {text}
    </span>
  );
}

// ── Simple DAG Visualization ─────────────────────────────────────────────────
function DependencyGraph({ graph }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    if (!graph || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;

    const ruleNodes = graph.nodes.filter((n) => n.type === "rule");
    const fieldNodes = graph.nodes.filter((n) => n.type === "field");

    const W = canvas.parentElement.clientWidth || 800;
    const H = Math.max(400, Math.max(ruleNodes.length, fieldNodes.length) * 60 + 100);

    canvas.width = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, W, H);

    // Position nodes
    const positions = {};
    const ruleX = W * 0.22;
    const fieldX = W * 0.78;
    const ruleSpacing = Math.min(60, (H - 80) / Math.max(ruleNodes.length, 1));
    const fieldSpacing = Math.min(60, (H - 80) / Math.max(fieldNodes.length, 1));
    const ruleStartY = (H - ruleNodes.length * ruleSpacing) / 2 + 20;
    const fieldStartY = (H - fieldNodes.length * fieldSpacing) / 2 + 20;

    ruleNodes.forEach((n, i) => {
      positions[n.id] = { x: ruleX, y: ruleStartY + i * ruleSpacing };
    });
    fieldNodes.forEach((n, i) => {
      positions[n.id] = { x: fieldX, y: fieldStartY + i * fieldSpacing };
    });

    // Draw edges
    graph.edges.forEach((edge) => {
      const from = positions[edge.source];
      const to = positions[edge.target];
      if (!from || !to) return;

      ctx.beginPath();
      ctx.moveTo(from.x + 80, from.y);
      const cpx1 = from.x + 80 + (to.x - from.x - 80) * 0.4;
      const cpx2 = from.x + 80 + (to.x - from.x - 80) * 0.6;
      ctx.bezierCurveTo(cpx1, from.y, cpx2, to.y, to.x - 60, to.y);
      ctx.strokeStyle =
        edge.dependency_type === "REQUIRED"
          ? "rgba(244,63,94,0.45)"
          : edge.dependency_type === "OPTIONAL"
          ? "rgba(56,189,248,0.35)"
          : "rgba(167,139,250,0.3)";
      ctx.lineWidth = edge.dependency_type === "REQUIRED" ? 2 : 1.5;
      ctx.stroke();

      // Arrowhead
      const angle = Math.atan2(to.y - from.y, to.x - 60 - (from.x + 80));
      const ax = to.x - 60;
      const ay = to.y;
      ctx.beginPath();
      ctx.moveTo(ax, ay);
      ctx.lineTo(ax - 8 * Math.cos(angle - 0.35), ay - 8 * Math.sin(angle - 0.35));
      ctx.lineTo(ax - 8 * Math.cos(angle + 0.35), ay - 8 * Math.sin(angle + 0.35));
      ctx.closePath();
      ctx.fillStyle = ctx.strokeStyle;
      ctx.fill();
    });

    // Draw rule nodes
    ruleNodes.forEach((n) => {
      const { x, y } = positions[n.id];
      const sevColor =
        n.severity === "CRITICAL"
          ? "#f43f5e"
          : n.severity === "HIGH"
          ? "#f97316"
          : n.severity === "MEDIUM"
          ? "#eab308"
          : "#10b981";

      ctx.fillStyle = "rgba(15,23,42,0.85)";
      ctx.strokeStyle = sevColor;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.roundRect(x - 80, y - 16, 160, 32, 8);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = "#e2e8f0";
      ctx.font = "bold 10px monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      const label = n.label.length > 20 ? n.label.slice(0, 18) + "…" : n.label;
      ctx.fillText(label, x, y);
    });

    // Draw field nodes
    fieldNodes.forEach((n) => {
      const { x, y } = positions[n.id];
      ctx.fillStyle = "rgba(15,23,42,0.85)";
      ctx.strokeStyle = "#22d3ee";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.roundRect(x - 55, y - 14, 110, 28, 6);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = "#22d3ee";
      ctx.font = "bold 10px monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(n.label, x, y);
    });

    // Legend
    ctx.font = "bold 9px monospace";
    ctx.textAlign = "left";
    const legY = H - 25;
    ctx.fillStyle = "rgba(244,63,94,0.7)";
    ctx.fillRect(10, legY, 12, 3);
    ctx.fillStyle = "#94a3b8";
    ctx.fillText("REQUIRED", 26, legY + 3);

    ctx.fillStyle = "rgba(56,189,248,0.6)";
    ctx.fillRect(100, legY, 12, 3);
    ctx.fillStyle = "#94a3b8";
    ctx.fillText("OPTIONAL", 116, legY + 3);

    ctx.fillStyle = "rgba(167,139,250,0.5)";
    ctx.fillRect(200, legY, 12, 3);
    ctx.fillStyle = "#94a3b8";
    ctx.fillText("ENRICHMENT", 216, legY + 3);
  }, [graph]);

  return (
    <div className="w-full overflow-x-auto rounded-xl border border-white/10 bg-sentinel-950/60">
      <canvas ref={canvasRef} className="w-full" />
    </div>
  );
}

// ── Main Page Component ──────────────────────────────────────────────────────
export default function DetectionRules() {
  const { token, user } = useAuth();
  const [rules, setRules] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [selectedRule, setSelectedRule] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [impactField, setImpactField] = useState(null);
  const [impactData, setImpactData] = useState(null);
  const [impactLoading, setImpactLoading] = useState(false);
  const [graph, setGraph] = useState(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("rules"); // rules | graph | impact
  const [canonicalFields, setCanonicalFields] = useState([]);

  const authHeaders = { Authorization: `Bearer ${token}` };

  // ── Fetch detection rules ───────────────────────────────────────────────
  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      let url = `${API}/api/v1/detection-rules?limit=100`;
      if (statusFilter) url += `&status=${statusFilter}`;
      if (severityFilter) url += `&severity=${severityFilter}`;
      const res = await fetch(url, { headers: authHeaders });
      if (res.ok) {
        const data = await res.json();
        setRules(data.items || []);
        setTotal(data.total || 0);
      }
    } catch (e) {
      console.error("Failed to fetch detection rules:", e);
    } finally {
      setLoading(false);
    }
  }, [token, statusFilter, severityFilter]);

  useEffect(() => { fetchRules(); }, [fetchRules]);

  // ── Fetch canonical fields ──────────────────────────────────────────────
  useEffect(() => {
    fetch(`${API}/api/v1/detection-rules/canonical-fields`, { headers: authHeaders })
      .then((r) => r.ok ? r.json() : null)
      .then((data) => data && setCanonicalFields(data.canonical_fields || []))
      .catch(() => {});
  }, [token]);

  // ── Fetch rule detail ───────────────────────────────────────────────────
  const openDetail = async (ruleId) => {
    setDetailLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/detection-rules/${ruleId}`, { headers: authHeaders });
      if (res.ok) setSelectedRule(await res.json());
    } catch (e) {
      console.error("Failed to fetch rule detail:", e);
    } finally {
      setDetailLoading(false);
    }
  };

  // ── Fetch dependency graph ──────────────────────────────────────────────
  const fetchGraph = async () => {
    setGraphLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/detection-rules/dependency-graph`, { headers: authHeaders });
      if (res.ok) setGraph(await res.json());
    } catch (e) {
      console.error("Failed to fetch dependency graph:", e);
    } finally {
      setGraphLoading(false);
    }
  };

  // ── Fetch field impact ──────────────────────────────────────────────────
  const fetchImpact = async (field) => {
    setImpactField(field);
    setImpactLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/detection-rules/impact/${field}`, { headers: authHeaders });
      if (res.ok) setImpactData(await res.json());
    } catch (e) {
      console.error("Failed to fetch impact:", e);
    } finally {
      setImpactLoading(false);
    }
  };

  // ── Computed Stats ──────────────────────────────────────────────────────
  const activeCount = rules.filter((r) => r.status === "ACTIVE").length;
  const draftCount = rules.filter((r) => r.status === "DRAFT").length;
  const criticalCount = rules.filter((r) => r.severity === "CRITICAL").length;

  return (
    <main className="flex-1 overflow-y-auto bg-sentinel-950 p-6 space-y-6 animate-fade-in">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white font-mono tracking-tight flex items-center gap-2">
            <span className="text-2xl">🎯</span> Detection Rule Registry
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Sprint 6A · Canonical Field Dependency Mapping & MITRE ATT&CK Integration
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-500">
            {total} rule{total !== 1 ? "s" : ""} registered
          </span>
        </div>
      </div>

      {/* ── KPI Cards ───────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total Rules", value: total, color: "accent-cyan" },
          { label: "Active", value: activeCount, color: "emerald-400" },
          { label: "Draft", value: draftCount, color: "slate-400" },
          { label: "Critical", value: criticalCount, color: "red-400" },
        ].map((kpi) => (
          <div
            key={kpi.label}
            className="p-4 rounded-xl bg-sentinel-900/60 border border-white/5 backdrop-blur-sm"
          >
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">{kpi.label}</p>
            <p className={`text-2xl font-bold font-mono mt-1 text-${kpi.color}`}>{kpi.value}</p>
          </div>
        ))}
      </div>

      {/* ── Tab Navigation ──────────────────────────────────────────────────── */}
      <div className="flex gap-1 bg-sentinel-900/40 rounded-xl p-1 border border-white/5 w-fit">
        {[
          { id: "rules", label: "📋 Rules Registry" },
          { id: "graph", label: "🕸️ Dependency Graph" },
          { id: "impact", label: "💥 Impact Analysis" },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => {
              setActiveTab(tab.id);
              if (tab.id === "graph" && !graph) fetchGraph();
            }}
            className={`px-4 py-2 rounded-lg text-xs font-mono transition cursor-pointer ${
              activeTab === tab.id
                ? "bg-accent-cyan/15 text-accent-cyan font-bold border border-accent-cyan/30"
                : "text-slate-400 hover:text-white hover:bg-white/5"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Tab Content ─────────────────────────────────────────────────────── */}

      {/* Rules Tab */}
      {activeTab === "rules" && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex gap-3 items-center">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-sentinel-900/80 border border-white/10 text-slate-300 text-xs font-mono px-3 py-2 rounded-lg"
            >
              <option value="">All Status</option>
              <option value="DRAFT">DRAFT</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="DEPRECATED">DEPRECATED</option>
            </select>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-sentinel-900/80 border border-white/10 text-slate-300 text-xs font-mono px-3 py-2 rounded-lg"
            >
              <option value="">All Severity</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {/* Rules Table */}
          {loading ? (
            <div className="flex justify-center py-12">
              <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-white/10 bg-sentinel-900/40 backdrop-blur-sm">
              <table className="w-full text-xs font-mono">
                <thead>
                  <tr className="border-b border-white/10 text-slate-500 uppercase tracking-wider">
                    <th className="text-left px-4 py-3">Rule</th>
                    <th className="text-left px-3 py-3">Vendor</th>
                    <th className="text-center px-3 py-3">Severity</th>
                    <th className="text-center px-3 py-3">Status</th>
                    <th className="text-center px-3 py-3">Deps</th>
                    <th className="text-left px-3 py-3">MITRE Tactic</th>
                    <th className="text-center px-3 py-3">Ver</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr
                      key={rule.rule_id}
                      onClick={() => openDetail(rule.rule_id)}
                      className="border-b border-white/5 hover:bg-white/[0.03] transition cursor-pointer group"
                    >
                      <td className="px-4 py-3">
                        <div>
                          <p className="text-slate-200 font-bold group-hover:text-accent-cyan transition">
                            {rule.rule_name}
                          </p>
                          <p className="text-[10px] text-slate-600 mt-0.5">{rule.rule_id}</p>
                        </div>
                      </td>
                      <td className="px-3 py-3 text-slate-400">{rule.vendor_name}</td>
                      <td className="px-3 py-3 text-center">
                        <Badge text={rule.severity} colorClass={severityColors[rule.severity] || severityColors.MEDIUM} />
                      </td>
                      <td className="px-3 py-3 text-center">
                        <Badge text={rule.status} colorClass={statusColors[rule.status] || statusColors.DRAFT} />
                      </td>
                      <td className="px-3 py-3 text-center text-accent-cyan font-bold">{rule.dependency_count}</td>
                      <td className="px-3 py-3 text-slate-400 text-[10px]">{rule.mitre_tactic || "—"}</td>
                      <td className="px-3 py-3 text-center text-slate-500">v{rule.version}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Graph Tab */}
      {activeTab === "graph" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs text-slate-400">
              Canonical Field Dependency DAG — Rules depend on OCSF fields for evaluation
            </p>
            <button
              onClick={fetchGraph}
              className="px-3 py-1.5 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan text-xs font-mono hover:bg-accent-cyan/20 transition cursor-pointer"
            >
              🔄 Refresh
            </button>
          </div>
          {graphLoading ? (
            <div className="flex justify-center py-12">
              <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
            </div>
          ) : graph ? (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-sentinel-900/60 border border-white/5">
                  <span className="text-[10px] text-slate-500 uppercase">Rule Nodes</span>
                  <p className="text-lg font-bold text-accent-cyan font-mono">{graph.total_rules}</p>
                </div>
                <div className="p-3 rounded-lg bg-sentinel-900/60 border border-white/5">
                  <span className="text-[10px] text-slate-500 uppercase">Field Nodes</span>
                  <p className="text-lg font-bold text-emerald-400 font-mono">{graph.total_fields}</p>
                </div>
              </div>
              <DependencyGraph graph={graph} />
            </>
          ) : (
            <p className="text-sm text-slate-500 text-center py-8">No graph data available.</p>
          )}
        </div>
      )}

      {/* Impact Tab */}
      {activeTab === "impact" && (
        <div className="space-y-4">
          <p className="text-xs text-slate-400">
            Select a canonical field to see which detection rules depend on it.
            Useful when a semantic policy change could affect downstream rules.
          </p>
          <div className="flex flex-wrap gap-2">
            {canonicalFields.map((field) => (
              <button
                key={field}
                onClick={() => fetchImpact(field)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition cursor-pointer ${
                  impactField === field
                    ? "bg-accent-cyan/15 border-accent-cyan/40 text-accent-cyan font-bold"
                    : "bg-sentinel-900/60 border-white/10 text-slate-400 hover:text-white hover:bg-white/5"
                }`}
              >
                {field}
              </button>
            ))}
          </div>

          {impactLoading ? (
            <div className="flex justify-center py-8">
              <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
            </div>
          ) : impactData ? (
            <div className="space-y-3">
              <div className="p-4 rounded-xl bg-sentinel-900/60 border border-white/5">
                <div className="flex items-center gap-3">
                  <span className="text-accent-cyan font-mono font-bold text-sm">{impactData.canonical_field}</span>
                  <span className="text-xs text-slate-500">→</span>
                  <span className="text-sm font-bold text-white font-mono">
                    {impactData.total_dependent_rules} dependent rule{impactData.total_dependent_rules !== 1 ? "s" : ""}
                  </span>
                </div>
              </div>

              {impactData.impacted_rules.length > 0 ? (
                <div className="overflow-x-auto rounded-xl border border-white/10 bg-sentinel-900/40">
                  <table className="w-full text-xs font-mono">
                    <thead>
                      <tr className="border-b border-white/10 text-slate-500 uppercase tracking-wider">
                        <th className="text-left px-4 py-2">Rule</th>
                        <th className="text-left px-3 py-2">Vendor</th>
                        <th className="text-center px-3 py-2">Severity</th>
                        <th className="text-center px-3 py-2">Status</th>
                        <th className="text-center px-3 py-2">Dep Type</th>
                      </tr>
                    </thead>
                    <tbody>
                      {impactData.impacted_rules.map((r) => (
                        <tr key={r.rule_id} className="border-b border-white/5">
                          <td className="px-4 py-2 text-slate-200">{r.rule_name}</td>
                          <td className="px-3 py-2 text-slate-400">{r.vendor_name}</td>
                          <td className="px-3 py-2 text-center">
                            <Badge text={r.severity} colorClass={severityColors[r.severity] || severityColors.MEDIUM} />
                          </td>
                          <td className="px-3 py-2 text-center">
                            <Badge text={r.status} colorClass={statusColors[r.status] || statusColors.DRAFT} />
                          </td>
                          <td className="px-3 py-2 text-center">
                            <Badge text={r.dependency_type} colorClass={depTypeColors[r.dependency_type] || depTypeColors.REQUIRED} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-slate-500 text-center py-4">
                  No detection rules depend on <span className="text-accent-cyan font-mono">{impactData.canonical_field}</span>.
                </p>
              )}
            </div>
          ) : (
            <p className="text-sm text-slate-500 text-center py-8">
              Click a canonical field above to run impact analysis.
            </p>
          )}
        </div>
      )}

      {/* ── Rule Detail Modal ───────────────────────────────────────────────── */}
      {selectedRule && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
          onClick={() => setSelectedRule(null)}
        >
          <div
            className="bg-sentinel-900/95 border border-white/10 rounded-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto p-6 space-y-5 shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-lg font-bold text-white font-mono flex items-center gap-2">
                  <span className="text-xl">🎯</span> {selectedRule.rule_name}
                </h2>
                <p className="text-[10px] text-slate-500 font-mono mt-1">{selectedRule.rule_id} · v{selectedRule.version}</p>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                className="text-slate-500 hover:text-white text-lg leading-none cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Badges */}
            <div className="flex gap-2 flex-wrap">
              <Badge text={selectedRule.severity} colorClass={severityColors[selectedRule.severity] || severityColors.MEDIUM} />
              <Badge text={selectedRule.status} colorClass={statusColors[selectedRule.status] || statusColors.DRAFT} />
              <Badge text={selectedRule.vendor_name} colorClass="bg-slate-800/70 border-slate-600 text-slate-300" />
            </div>

            {/* Description */}
            {selectedRule.description && (
              <div className="p-3 rounded-lg bg-sentinel-950/80 border border-white/5">
                <p className="text-[10px] text-slate-500 uppercase mb-1">Description</p>
                <p className="text-xs text-slate-300 leading-relaxed">{selectedRule.description}</p>
              </div>
            )}

            {/* MITRE ATT&CK */}
            {(selectedRule.mitre_tactic || selectedRule.mitre_technique) && (
              <div className="p-3 rounded-lg bg-red-950/20 border border-red-500/20">
                <p className="text-[10px] text-red-400 uppercase mb-2 font-bold">🗡️ MITRE ATT&CK Mapping</p>
                {selectedRule.mitre_tactic && (
                  <p className="text-xs text-slate-300">
                    <span className="text-red-400 font-bold">Tactic:</span> {selectedRule.mitre_tactic}
                  </p>
                )}
                {selectedRule.mitre_technique && (
                  <p className="text-xs text-slate-300 mt-1">
                    <span className="text-red-400 font-bold">Technique:</span> {selectedRule.mitre_technique}
                  </p>
                )}
              </div>
            )}

            {/* Dependencies */}
            <div className="space-y-2">
              <p className="text-[10px] text-slate-500 uppercase font-bold">
                Canonical Field Dependencies ({selectedRule.dependency_count})
              </p>
              {selectedRule.dependencies && selectedRule.dependencies.length > 0 ? (
                <div className="space-y-1.5">
                  {selectedRule.dependencies.map((dep) => (
                    <div
                      key={dep.dependency_id}
                      className="flex items-center gap-3 p-2.5 rounded-lg bg-sentinel-950/60 border border-white/5"
                    >
                      <span className="text-accent-cyan font-mono font-bold text-xs">{dep.canonical_field}</span>
                      <Badge text={dep.dependency_type} colorClass={depTypeColors[dep.dependency_type] || depTypeColors.REQUIRED} />
                      {dep.description && (
                        <span className="text-[10px] text-slate-500 ml-auto truncate max-w-[200px]">
                          {dep.description}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic">No dependencies registered.</p>
              )}
            </div>

            {/* Metadata */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-2.5 rounded-lg bg-sentinel-950/60 border border-white/5">
                <p className="text-[10px] text-slate-500 uppercase">Created By</p>
                <p className="text-xs text-slate-300 font-mono mt-0.5">{selectedRule.created_by || "System"}</p>
              </div>
              <div className="p-2.5 rounded-lg bg-sentinel-950/60 border border-white/5">
                <p className="text-[10px] text-slate-500 uppercase">Created At</p>
                <p className="text-xs text-slate-300 font-mono mt-0.5">
                  {selectedRule.created_at ? new Date(selectedRule.created_at).toLocaleString() : "—"}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
