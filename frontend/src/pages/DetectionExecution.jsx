/**
 * pages/DetectionExecution.jsx
 * ----------------------------
 * Real-Time Detection Rule Execution Engine Dashboard.
 *
 * Sprint 7A — Real-Time Detection Rule Execution Engine.
 *
 * Sections:
 * A — Pipeline Hero (Interactive Step Flow)
 * B — KPI Summary Cards (Real API Telemetry)
 * C — Governed Execution Registry (Filtering & Detail Inspection)
 * D — Condition Explainability (Atomic Rule Logic Breakdown)
 * E — Partial Telemetry Evaluation Showcase (Missing Field Explanations)
 * F — Interactive "Run Active Detections" Console
 * G — 10-Stage Cryptographic & Governance Traceability Modal
 */

import React, { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext";
import { API_V1_URL } from "../apiConfig";

const API_BASE = API_V1_URL;

export default function DetectionExecution() {
  const { user, token } = useAuth();

  // State
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [executions, setExecutions] = useState([]);
  const [normalizedEvents, setNormalizedEvents] = useState([]);
  const [activeRules, setActiveRules] = useState([]);

  // Filters
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [filterRule, setFilterRule] = useState("ALL");
  const [filterMatched, setFilterMatched] = useState("ALL");

  // Selection & Modal States
  const [selectedExecution, setSelectedExecution] = useState(null);
  const [inspectModalOpen, setInspectModalOpen] = useState(false);
  const [traceModalOpen, setTraceModalOpen] = useState(false);
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceData, setTraceData] = useState(null);

  // Execution Trigger Panel State
  const [selectedEventId, setSelectedEventId] = useState("");
  const [executingBatch, setExecutingBatch] = useState(false);
  const [batchResult, setBatchResult] = useState(null);
  const [successToast, setSuccessToast] = useState("");

  const authHeaders = {
    Authorization: `Bearer ${token || localStorage.getItem("sentinel_token") || ""}`,
    "Content-Type": "application/json",
  };

  // ── 1. Fetch Core Data ───────────────────────────────────────────────────────
  const fetchExecutions = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Build query string
      const params = new URLSearchParams({ limit: "100", offset: "0" });
      if (filterStatus !== "ALL") params.append("execution_status", filterStatus);
      if (filterRule !== "ALL") params.append("rule_id", filterRule);
      if (filterMatched !== "ALL") params.append("matched", filterMatched === "MATCHED" ? "true" : "false");

      const [execRes, normRes, ruleRes] = await Promise.all([
        fetch(`${API_BASE}/detection-executions?${params.toString()}`, { headers: authHeaders }),
        fetch(`${API_BASE}/normalized-events?limit=50`, { headers: authHeaders }),
        fetch(`${API_BASE}/detection-rules?limit=50`, { headers: authHeaders }),
      ]);

      if (!execRes.ok) throw new Error(`HTTP ${execRes.status}: Failed to fetch executions`);
      const execData = await execRes.json();
      setExecutions(execData.executions || []);

      if (normRes.ok) {
        const normData = await normRes.json();
        const evts = normData.items || normData.events || normData.normalized_events || (Array.isArray(normData) ? normData : []);
        const evList = Array.isArray(evts) ? evts : [];
        setNormalizedEvents(evList);
        if (evList.length > 0) {
          setSelectedEventId(evList[0].normalized_event_id || "");
        }
      }

      if (ruleRes.ok) {
        const ruleData = await ruleRes.json();
        const rList = ruleData.rules || ruleData || [];
        setActiveRules(Array.isArray(rList) ? rList : []);
      }
    } catch (err) {
      setError(err.message || "Failed to load execution data.");
    } finally {
      setLoading(false);
    }
  }, [filterStatus, filterRule, filterMatched, token]);

  useEffect(() => {
    fetchExecutions();
  }, [fetchExecutions]);

  // ── 2. Run All Active Detections for Event ──────────────────────────────────
  const handleRunActiveDetections = async () => {
    if (!selectedEventId) return;
    try {
      setExecutingBatch(true);
      setBatchResult(null);
      setError(null);

      const resp = await fetch(`${API_BASE}/normalized-events/${selectedEventId}/run-detections`, {
        method: "POST",
        headers: authHeaders,
      });

      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${resp.status} Execution failed`);
      }

      const result = await resp.json();
      setBatchResult(result);
      setSuccessToast(`Successfully evaluated ${result.rules_evaluated} active detection rule(s)!`);
      setTimeout(() => setSuccessToast(""), 4000);
      fetchExecutions();
    } catch (err) {
      setError(err.message);
    } finally {
      setExecutingBatch(false);
    }
  };

  // ── 3. Load 10-Stage Provenance Trace ────────────────────────────────────────
  const handleOpenTrace = async (executionId) => {
    try {
      setTraceLoading(true);
      setTraceData(null);
      setTraceModalOpen(true);

      const resp = await fetch(`${API_BASE}/detection-executions/${executionId}/trace`, {
        headers: authHeaders,
      });

      if (!resp.ok) throw new Error(`HTTP ${resp.status} Trace retrieval failed`);
      const data = await resp.json();
      setTraceData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setTraceLoading(false);
    }
  };

  // Compute Live KPIs
  const totalExecutions = executions.length;
  const matchCount = executions.filter((e) => e.execution_status === "MATCH").length;
  const noMatchCount = executions.filter((e) => e.execution_status === "NO_MATCH").length;
  const partialCount = executions.filter((e) => e.execution_status === "PARTIAL").length;
  const errorCount = executions.filter((e) => e.execution_status === "ERROR").length;

  const canExecute = user?.role === "ADMIN" || user?.role === "SECURITY_ANALYST";

  return (
    <main className="flex-1 overflow-y-auto bg-sentinel-950 p-6 space-y-6 text-slate-100 font-sans">
      {/* ── HEADER ─────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 flex items-center justify-center text-xl shadow-lg shadow-cyan-500/10">
              ⚡
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Detection Execution Engine
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono font-medium">
                  Sprint 7A
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Execute governed detection logic against normalized telemetry with complete deterministic provenance.
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={fetchExecutions}
            className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 hover:border-slate-600 text-slate-300 hover:text-white text-xs font-medium transition flex items-center gap-2 shadow-sm"
          >
            <span>🔄</span> Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Toast Notification */}
      {successToast && (
        <div className="p-3 rounded-xl bg-emerald-950/80 border border-emerald-500/50 text-emerald-200 text-xs flex items-center justify-between animate-fade-in shadow-lg shadow-emerald-950/50">
          <div className="flex items-center gap-2">
            <span>✅</span>
            <span>{successToast}</span>
          </div>
          <button onClick={() => setSuccessToast("")} className="text-emerald-400 hover:text-white text-xs">
            ✕
          </button>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-950/80 border border-rose-500/50 text-rose-200 text-xs flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-white text-xs font-mono">
            ✕
          </button>
        </div>
      )}

      {/* ── SECTION A — PIPELINE HERO ───────────────────────────────────────── */}
      <section className="p-5 rounded-2xl bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-slate-950 border border-slate-800/80 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 font-mono flex items-center gap-2">
            <span>⚙️</span> Real-Time Declarative Execution Pipeline
          </h2>
          <span className="text-[11px] text-slate-400 font-mono">Engine Version: v5.7.0 (Deterministic DSL)</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-1">
          {[
            { step: "01", name: "Normalized Event", desc: "Canonical OCSF Record", icon: "📄", color: "border-slate-700 bg-slate-900/70" },
            { step: "02", name: "ACTIVE Governed Rule", desc: "Status = ACTIVE Only", icon: "🏛️", color: "border-indigo-500/30 bg-indigo-950/20" },
            { step: "03", name: "Field Resolution", desc: "Non-Guessing Canonical", icon: "🔍", color: "border-cyan-500/30 bg-cyan-950/20" },
            { step: "04", name: "Condition Evaluation", desc: "Deterministic JSON DSL", icon: "⚖️", color: "border-amber-500/30 bg-amber-950/20" },
            { step: "05", name: "MATCH / NO_MATCH", desc: "PARTIAL on Missing Telemetry", icon: "🎯", color: "border-emerald-500/30 bg-emerald-950/20" },
            { step: "06", name: "Execution Trace", desc: "10-Stage Audit Lineage", icon: "🔗", color: "border-purple-500/30 bg-purple-950/20" },
          ].map((node, i) => (
            <div key={i} className={`p-3.5 rounded-xl border ${node.color} flex flex-col justify-between space-y-2 relative shadow-md transition-all hover:translate-y-[-2px]`}>
              <div className="flex items-center justify-between">
                <span className="text-lg">{node.icon}</span>
                <span className="text-[10px] font-mono text-slate-400">{node.step}</span>
              </div>
              <div>
                <p className="text-xs font-bold text-slate-100">{node.name}</p>
                <p className="text-[10px] text-slate-400 leading-tight mt-0.5">{node.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── SECTION B — KPI SUMMARY CARDS ───────────────────────────────────── */}
      <section className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
        {[
          { label: "Total Executions", value: totalExecutions, color: "text-slate-100", border: "border-slate-800", bg: "bg-slate-900/60", icon: "⚡" },
          { label: "Logic Matches", value: matchCount, color: "text-emerald-400", border: "border-emerald-500/30", bg: "bg-emerald-950/20", icon: "🎯" },
          { label: "Clean Non-Matches", value: noMatchCount, color: "text-slate-300", border: "border-slate-700/50", bg: "bg-slate-900/40", icon: "⚪" },
          { label: "Partial Evaluations", value: partialCount, color: "text-amber-400", border: "border-amber-500/30", bg: "bg-amber-950/20", icon: "⚠️" },
          { label: "Execution Errors", value: errorCount, color: "text-rose-400", border: "border-rose-500/30", bg: "bg-rose-950/20", icon: "❌" },
        ].map((kpi, idx) => (
          <div key={idx} className={`p-4 rounded-xl border ${kpi.border} ${kpi.bg} shadow-md flex flex-col justify-between`}>
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-medium">{kpi.label}</span>
              <span>{kpi.icon}</span>
            </div>
            <p className={`text-2xl font-black font-mono mt-2 ${kpi.color}`}>{loading ? "..." : kpi.value}</p>
          </div>
        ))}
      </section>

      {/* ── SECTION F — RUN DETECTIONS PANEL ────────────────────────────────── */}
      <section className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800/90 shadow-lg space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2 font-mono">
              <span>🚀</span> Run Active Governed Detections
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Select a normalized security event to execute all approved ACTIVE detection rules in real-time.
            </p>
          </div>
          {!canExecute && (
            <span className="text-[11px] px-2.5 py-1 rounded-lg bg-amber-950/60 border border-amber-500/40 text-amber-300 font-mono">
              🔒 Read-Only Role ({user?.role || "VIEWER"})
            </span>
          )}
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="flex-1">
            <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
              Select Target Normalized Event:
            </label>
            <select
              value={selectedEventId}
              onChange={(e) => setSelectedEventId(e.target.value)}
              className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500 transition"
            >
              {normalizedEvents.map((ev) => (
                <option key={ev.normalized_event_id} value={ev.normalized_event_id}>
                  {ev.normalized_event_id} — {ev.class_name} [{ev.action || "N/A"}] (Port: {ev.dst_port || "N/A"})
                </option>
              ))}
            </select>
          </div>

          <div className="sm:self-end">
            <button
              onClick={handleRunActiveDetections}
              disabled={!canExecute || executingBatch || !selectedEventId}
              className={`w-full sm:w-auto px-5 py-2.5 rounded-xl font-medium text-xs transition flex items-center justify-center gap-2 shadow-lg ${
                canExecute && !executingBatch
                  ? "bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-cyan-500/20"
                  : "bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700"
              }`}
            >
              {executingBatch ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Evaluating Rules...</span>
                </>
              ) : (
                <>
                  <span>⚡</span>
                  <span>RUN ACTIVE DETECTIONS</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Batch Execution Results Summary */}
        {batchResult && (
          <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/30 shadow-inner space-y-2 animate-fade-in">
            <div className="flex items-center justify-between text-xs font-mono text-cyan-400">
              <span className="font-bold">Execution Batch Summary for: {batchResult.normalized_event_id}</span>
              <span>Total Evaluated: {batchResult.rules_evaluated}</span>
            </div>
            <div className="grid grid-cols-4 gap-2 pt-1">
              <div className="p-2 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-center">
                <p className="text-[10px] text-slate-400 font-mono">MATCHES</p>
                <p className="text-base font-bold text-emerald-400 font-mono">{batchResult.matches}</p>
              </div>
              <div className="p-2 rounded-lg bg-slate-900 border border-slate-700 text-center">
                <p className="text-[10px] text-slate-400 font-mono">NO MATCH</p>
                <p className="text-base font-bold text-slate-300 font-mono">{batchResult.no_matches}</p>
              </div>
              <div className="p-2 rounded-lg bg-amber-950/30 border border-amber-500/30 text-center">
                <p className="text-[10px] text-slate-400 font-mono">PARTIAL</p>
                <p className="text-base font-bold text-amber-400 font-mono">{batchResult.partial}</p>
              </div>
              <div className="p-2 rounded-lg bg-rose-950/30 border border-rose-500/30 text-center">
                <p className="text-[10px] text-slate-400 font-mono">ERRORS</p>
                <p className="text-base font-bold text-rose-400 font-mono">{batchResult.errors}</p>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* ── SECTION E — PARTIAL EVALUATION HIGHLIGHT ────────────────────────── */}
      <section className="p-4 rounded-2xl bg-gradient-to-r from-amber-950/30 via-slate-900/60 to-slate-900 border border-amber-500/30 shadow-md space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-base">💡</span>
          <h3 className="text-xs font-bold font-mono text-amber-300 uppercase tracking-wide">
            Telemetry Completeness Invariant: PARTIAL != NO_MATCH
          </h3>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          When an approved rule evaluates against security logs lacking mandatory telemetry fields (e.g. evaluating an
          authentication brute-force rule on a stateless firewall deny log lacking <code className="text-amber-300 bg-amber-950/60 px-1 py-0.5 rounded font-mono">authentication.outcome</code>),
          the engine deliberately records <span className="font-bold text-amber-400">PARTIAL</span>. Incomplete telemetry does not prove the detection logic was false;
          silently classifying it as <span className="text-slate-400 font-mono">NO_MATCH</span> would mask blindspots.
        </p>
      </section>

      {/* ── SECTION C — EXECUTION REGISTRY ──────────────────────────────────── */}
      <section className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800/90 shadow-lg space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2 font-mono">
              <span>📋</span> Governed Execution Records
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Append-only registry of deterministic rule executions sealed with SHA-256 idempotency fingerprints.
            </p>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-300 text-xs font-mono"
            >
              <option value="ALL">All Statuses</option>
              <option value="MATCH">MATCH</option>
              <option value="NO_MATCH">NO_MATCH</option>
              <option value="PARTIAL">PARTIAL</option>
              <option value="ERROR">ERROR</option>
            </select>

            <select
              value={filterRule}
              onChange={(e) => setFilterRule(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-300 text-xs font-mono"
            >
              <option value="ALL">All Rules</option>
              {activeRules.map((r) => (
                <option key={r.rule_id} value={r.rule_id}>
                  {r.rule_name || r.rule_id}
                </option>
              ))}
            </select>

            <select
              value={filterMatched}
              onChange={(e) => setFilterMatched(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-300 text-xs font-mono"
            >
              <option value="ALL">Matched: Any</option>
              <option value="MATCHED">Matched (True)</option>
              <option value="UNMATCHED">Unmatched (False)</option>
            </select>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="text-[11px] uppercase bg-slate-950/80 text-slate-400 font-mono border-b border-slate-800">
              <tr>
                <th className="py-3 px-3">Execution ID</th>
                <th className="py-3 px-3">Rule & Version</th>
                <th className="py-3 px-3">Target Event</th>
                <th className="py-3 px-3 text-center">Status</th>
                <th className="py-3 px-3 text-center">Matched</th>
                <th className="py-3 px-3">Executed At</th>
                <th className="py-3 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {executions.length === 0 ? (
                <tr>
                  <td colSpan="7" className="text-center py-8 text-slate-500 font-mono text-xs">
                    {loading ? "Loading execution records..." : "No execution records match the active filters."}
                  </td>
                </tr>
              ) : (
                executions.map((ex) => {
                  const statusColors = {
                    MATCH: "bg-emerald-950/70 border-emerald-500/50 text-emerald-300",
                    NO_MATCH: "bg-slate-950/70 border-slate-700 text-slate-400",
                    PARTIAL: "bg-amber-950/70 border-amber-500/50 text-amber-300",
                    ERROR: "bg-rose-950/70 border-rose-500/50 text-rose-300",
                  };
                  return (
                    <tr key={ex.execution_id} className="hover:bg-slate-800/30 transition">
                      <td className="py-3 px-3 font-mono font-medium text-cyan-400">{ex.execution_id}</td>
                      <td className="py-3 px-3">
                        <div className="font-medium text-slate-200">{ex.execution_details?.rule_name || ex.rule_id}</div>
                        <div className="text-[11px] font-mono text-slate-500">
                          {ex.rule_version_id} (v{ex.rule_version_number})
                        </div>
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-slate-400">
                        {ex.normalized_event_id}
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span
                          className={`inline-block px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${
                            statusColors[ex.execution_status] || "bg-slate-900 text-slate-400"
                          }`}
                        >
                          {ex.execution_status}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center font-mono">
                        {ex.matched ? (
                          <span className="text-emerald-400 font-bold">TRUE</span>
                        ) : (
                          <span className="text-slate-500">FALSE</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-slate-400 font-mono text-[11px]">
                        {ex.executed_at ? new Date(ex.executed_at).toLocaleString() : "N/A"}
                      </td>
                      <td className="py-3 px-3 text-right space-x-2">
                        <button
                          onClick={() => {
                            setSelectedExecution(ex);
                            setInspectModalOpen(true);
                          }}
                          className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
                        >
                          🔍 Inspect
                        </button>
                        <button
                          onClick={() => handleOpenTrace(ex.execution_id)}
                          className="px-2.5 py-1 rounded-lg bg-cyan-950/60 border border-cyan-500/40 hover:bg-cyan-900/60 text-cyan-300 text-xs font-mono transition"
                        >
                          🔗 Trace
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── SECTION D — INSPECT CONDITION EXPLAINABILITY MODAL ───────────────── */}
      {inspectModalOpen && selectedExecution && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 space-y-5 overflow-y-auto max-h-[90vh]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2 font-mono">
                  <span>🔬</span> Condition Explainability Breakdown
                </h3>
                <p className="text-xs text-slate-400 mt-0.5 font-mono">
                  Execution ID: {selectedExecution.execution_id}
                </p>
              </div>
              <button
                onClick={() => setInspectModalOpen(false)}
                className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition"
              >
                ✕
              </button>
            </div>

            {/* Rule & Event Binding Meta */}
            <div className="grid grid-cols-2 gap-3 text-xs bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono">
              <div>
                <span className="text-slate-500 block">Rule Name:</span>
                <span className="text-slate-200 font-semibold">{selectedExecution.execution_details?.rule_name || selectedExecution.rule_id}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Rule Version Hash:</span>
                <span className="text-cyan-400 truncate block">{selectedExecution.execution_details?.version_hash || "N/A"}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Target Normalized Event:</span>
                <span className="text-slate-200">{selectedExecution.normalized_event_id}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Execution Status:</span>
                <span className={`font-bold ${selectedExecution.matched ? "text-emerald-400" : "text-amber-400"}`}>
                  {selectedExecution.execution_status} (Matched: {selectedExecution.matched ? "TRUE" : "FALSE"})
                </span>
              </div>
            </div>

            {/* Conditions List */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold font-mono text-cyan-400 uppercase">
                Atomic Conditions Evaluated ({selectedExecution.condition_results?.length || 0})
              </h4>

              {(!selectedExecution.condition_results || selectedExecution.condition_results.length === 0) ? (
                <p className="text-xs text-slate-500 font-mono">No granular condition records attached.</p>
              ) : (
                selectedExecution.condition_results.map((c, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-cyan-300 font-bold">
                        Condition {idx + 1}: <span className="text-white">{c.canonical_field}</span>
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          c.condition_result === "TRUE"
                            ? "bg-emerald-950 border border-emerald-500/40 text-emerald-300"
                            : c.condition_result === "MISSING"
                            ? "bg-amber-950 border border-amber-500/40 text-amber-300"
                            : "bg-rose-950 border border-rose-500/40 text-rose-300"
                        }`}
                      >
                        {c.condition_result}
                      </span>
                    </div>

                    <div className="grid grid-cols-3 gap-2 font-mono text-[11px] bg-slate-900/80 p-2 rounded-lg">
                      <div>
                        <span className="text-slate-500 block">Comparison:</span>
                        <span className="text-amber-400">{c.comparison_operator}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Expected:</span>
                        <span className="text-slate-200">{JSON.stringify(c.expected_value)}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Observed:</span>
                        <span className="text-cyan-300">{c.observed_value !== null ? JSON.stringify(c.observed_value) : "<MISSING>"}</span>
                      </div>
                    </div>

                    {c.explanation && (
                      <p className="text-[11px] text-slate-400 leading-snug italic pt-1">
                        "{c.explanation}"
                      </p>
                    )}
                  </div>
                ))
              )}
            </div>

            {/* Explanation Footer */}
            {selectedExecution.execution_explanation && (
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                <span className="text-slate-400 block font-mono text-[10px] uppercase">Engine Decision Statement:</span>
                <p className="text-slate-200 mt-1 leading-relaxed">{selectedExecution.execution_explanation}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── SECTION G — 10-STAGE PROVENANCE TRACE MODAL ─────────────────────── */}
      {traceModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 space-y-5 overflow-y-auto max-h-[90vh]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2 font-mono">
                  <span>🔗</span> 10-Stage Execution Provenance Trace
                </h3>
                <p className="text-xs text-slate-400 mt-0.5 font-mono">
                  End-to-end cryptographic and governance lineage verification.
                </p>
              </div>
              <button
                onClick={() => setTraceModalOpen(false)}
                className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition"
              >
                ✕
              </button>
            </div>

            {traceLoading ? (
              <div className="py-12 text-center space-y-3 font-mono text-slate-400 text-xs">
                <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto" />
                <p>Generating cryptographic provenance chain...</p>
              </div>
            ) : traceData ? (
              <div className="space-y-4">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between font-mono text-xs">
                  <span>Execution: <strong className="text-cyan-400">{traceData.execution_id}</strong></span>
                  <span>Status: <strong className={traceData.matched ? "text-emerald-400" : "text-amber-400"}>{traceData.execution_status}</strong></span>
                  <span>Engine: <strong className="text-slate-300">{traceData.execution_engine_version}</strong></span>
                </div>

                <div className="space-y-3 relative before:absolute before:inset-0 before:left-3.5 before:w-0.5 before:bg-slate-800">
                  {traceData.stages?.map((stage) => (
                    <div key={stage.stage_number} className="relative flex items-start gap-4 pl-8">
                      <div className="absolute left-1.5 top-2 w-5 h-5 rounded-full bg-slate-900 border-2 border-cyan-500 text-[10px] font-mono font-bold flex items-center justify-center text-cyan-300">
                        {stage.stage_number}
                      </div>

                      <div className="flex-1 p-3.5 rounded-xl bg-slate-950/90 border border-slate-800/80 shadow-sm space-y-1.5">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-bold font-mono text-slate-100">
                            {stage.stage_name}
                          </h4>
                          <span className="text-[10px] font-mono text-slate-500">Stage {stage.stage_number} of 10</span>
                        </div>
                        <p className="text-[11px] text-slate-400">{stage.description}</p>
                        <pre className="p-2 rounded-lg bg-slate-900 text-[10px] font-mono text-cyan-300 overflow-x-auto">
                          {JSON.stringify(stage.data, null, 2)}
                        </pre>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-rose-400 font-mono">Failed to load trace.</p>
            )}
          </div>
        </div>
      )}
    </main>
  );
}
