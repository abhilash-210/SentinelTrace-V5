/**
 * pages/DetectionTrust.jsx
 * ------------------------
 * Detection Rule Trust Evaluation & Semantic Drift Binding dashboard.
 *
 * Sprint 6B — Detection Rule Trust Evaluation & Semantic Drift Binding.
 *
 * Core Cybersecurity Question:
 * "Can we still trust our detection rules when underlying canonical fields undergo semantic drift?"
 *
 * Sections:
 * - A: Trust Overview Hero with pipeline visualization
 * - B: Trust KPI Cards (live metrics)
 * - C: Detection Rule Trust Registry (table with scores, status badges, and inspect action)
 * - D: Semantic Drift Impact & Blast Radius Flow
 * - E: Trust Score Explainability & Mathematical Deduction Panel
 * - F: Dependency Risk Inspector
 * - G: Detection Trust Alerts Triage Center
 * - H: End-to-End Trust Trace Provenance Modal
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";

const API_BASE = "/api/v1";

export default function DetectionTrust() {
  const { token, user, hasPermission } = useAuth();

  // Data states
  const [evaluations, setEvaluations] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [kpis, setKpis] = useState(null);
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filter states
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [alertStatusFilter, setAlertStatusFilter] = useState("ALL");
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("ALL");

  // Selection states for inspection & modals
  const [selectedEvaluation, setSelectedEvaluation] = useState(null);
  const [selectedTrace, setSelectedTrace] = useState(null);
  const [traceLoading, setTraceLoading] = useState(false);
  const [evaluatingRuleId, setEvaluatingRuleId] = useState(null);
  const [selectedScenarioField, setSelectedScenarioField] = useState("action.result");

  const authHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };

  // Fetch initial data
  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [evalsRes, alertsRes, kpiRes, rulesRes] = await Promise.all([
        fetch(`${API_BASE}/detection-rule-trust`, { headers: authHeaders }),
        fetch(`${API_BASE}/detection-trust-alerts`, { headers: authHeaders }),
        fetch(`${API_BASE}/detection-rule-trust/kpis/summary`, { headers: authHeaders }),
        fetch(`${API_BASE}/detection-rules`, { headers: authHeaders }),
      ]);

      if (!evalsRes.ok || !alertsRes.ok || !kpiRes.ok) {
        throw new Error("Failed to fetch detection trust intelligence data.");
      }

      const evalsData = await evalsRes.json();
      const alertsData = await alertsRes.json();
      const kpiData = await kpiRes.json();
      const rulesData = rulesRes.ok ? await rulesRes.json() : [];

      setEvaluations(evalsData);
      setAlerts(alertsData);
      setKpis(kpiData);
      setRules(rulesData);

      if (evalsData.length > 0 && !selectedEvaluation) {
        setSelectedEvaluation(evalsData[0]);
      }
    } catch (err) {
      console.error(err);
      setError(err.message || "Failed to load trust evaluation data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [token]);

  // Handle Manual Evaluation
  const handleEvaluateRule = async (ruleId) => {
    setEvaluatingRuleId(ruleId);
    try {
      const res = await fetch(`${API_BASE}/detection-rules/${ruleId}/evaluate-trust`, {
        method: "POST",
        headers: authHeaders,
      });
      if (!res.ok) throw new Error("Evaluation request failed");
      await fetchData();
    } catch (err) {
      alert(`Evaluation error: ${err.message}`);
    } finally {
      setEvaluatingRuleId(null);
    }
  };

  // Handle Alert Status Update (Triage)
  const handleUpdateAlertStatus = async (alertId, newStatus) => {
    try {
      const res = await fetch(`${API_BASE}/detection-trust-alerts/${alertId}/status`, {
        method: "PATCH",
        headers: authHeaders,
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error("Failed to update alert status");
      await fetchData();
    } catch (err) {
      alert(`Alert update error: ${err.message}`);
    }
  };

  // Fetch End-to-End Trust Trace
  const handleOpenTrace = async (evaluationId) => {
    setTraceLoading(true);
    setSelectedTrace(null);
    try {
      const res = await fetch(`${API_BASE}/detection-rule-trust/${evaluationId}/trace`, {
        headers: authHeaders,
      });
      if (!res.ok) throw new Error("Failed to load trust provenance trace");
      const traceData = await res.json();
      setSelectedTrace(traceData);
    } catch (err) {
      alert(`Trace error: ${err.message}`);
    } finally {
      setTraceLoading(false);
    }
  };

  // Status helper styles
  const getStatusBadge = (status) => {
    switch (status) {
      case "TRUSTED":
        return (
          <span className="px-2.5 py-1 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 inline-flex">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            TRUSTED
          </span>
        );
      case "DEGRADED":
        return (
          <span className="px-2.5 py-1 rounded text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/30 flex items-center gap-1.5 inline-flex">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
            DEGRADED
          </span>
        );
      case "AT_RISK":
        return (
          <span className="px-2.5 py-1 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1.5 inline-flex">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
            AT RISK
          </span>
        );
      case "INVALID":
        return (
          <span className="px-2.5 py-1 rounded text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1.5 inline-flex">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
            INVALID
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 rounded text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/30 flex items-center gap-1.5 inline-flex">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
            UNKNOWN
          </span>
        );
    }
  };

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case "CRITICAL":
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950/60 text-rose-400 border border-rose-600/40">CRITICAL</span>;
      case "HIGH":
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950/60 text-amber-400 border border-amber-600/40">HIGH</span>;
      case "MEDIUM":
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-yellow-950/60 text-yellow-400 border border-yellow-600/40">MEDIUM</span>;
      case "LOW":
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-950/60 text-blue-400 border border-blue-600/40">LOW</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-800 text-slate-400">NONE</span>;
    }
  };

  const getScoreColor = (score) => {
    if (score >= 0.90) return "text-emerald-400";
    if (score >= 0.70) return "text-blue-400";
    if (score >= 0.40) return "text-amber-400";
    return "text-rose-400";
  };

  // Filtered evaluations
  const filteredEvaluations = evaluations.filter((item) => {
    const matchesStatus = statusFilter === "ALL" || item.trust_status === statusFilter;
    const matchesSearch =
      searchQuery === "" ||
      item.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.rule_name && item.rule_name.toLowerCase().includes(searchQuery.toLowerCase())) ||
      item.canonical_field.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesStatus && matchesSearch;
  });

  // Filtered alerts
  const filteredAlerts = alerts.filter((item) => {
    const matchesStatus = alertStatusFilter === "ALL" || item.status === alertStatusFilter;
    const matchesSeverity = alertSeverityFilter === "ALL" || item.severity === alertSeverityFilter;
    return matchesStatus && matchesSeverity;
  });

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto min-h-screen">
      {/* ── SECTION A: HERO HEADER & PIPELINE ───────────────────────────────── */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-indigo-950/40 border border-slate-800 p-8 shadow-2xl backdrop-blur-md">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                Sprint 6B Live
              </span>
              <span className="text-xs text-slate-500">Continuous Zero-Trust Evaluation</span>
            </div>
            <h1 className="text-3xl font-bold text-slate-100 tracking-tight flex items-center gap-3">
              <span>🎯</span> Detection Rule Trust Intelligence
            </h1>
            <p className="text-slate-400 text-sm mt-2 max-w-2xl leading-relaxed">
              Semantic drift can silently distort the security meaning of log fields. SentinelTrace continuously evaluates whether detection rules remain mathematically and semantically trustworthy.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchData}
              disabled={loading}
              className="px-4 py-2.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition shadow flex items-center gap-2 cursor-pointer"
            >
              <span>🔄</span> Refresh Intelligence
            </button>
          </div>
        </div>

        {/* Visual Pipeline Flow */}
        <div className="mt-8 pt-6 border-t border-slate-800/80">
          <div className="text-xs font-medium text-slate-400 mb-3 flex items-center justify-between">
            <span className="text-slate-400 font-semibold tracking-wide">SEMANTIC-TO-DETECTION TRUST PIPELINE</span>
            <span className="text-[11px] text-slate-500 font-mono">Zero Trust Principle: UNKNOWN ≠ SAFE</span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
            <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50 flex flex-col justify-between">
              <div className="text-slate-400 font-medium">1. Semantic Drift</div>
              <div className="text-slate-200 font-semibold mt-1">Classification Check</div>
              <div className="text-[10px] text-slate-500 mt-2">Compatible / Ambiguous / Incompatible</div>
            </div>
            <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50 flex flex-col justify-between">
              <div className="text-slate-400 font-medium">2. Affected Field</div>
              <div className="text-indigo-300 font-semibold mt-1">Protected Asset Policy</div>
              <div className="text-[10px] text-slate-500 mt-2">Escalates Risk if Protected</div>
            </div>
            <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50 flex flex-col justify-between">
              <div className="text-slate-400 font-medium">3. Dependency DAG</div>
              <div className="text-sky-300 font-semibold mt-1">Isolated Blast Radius</div>
              <div className="text-[10px] text-slate-500 mt-2">Targets only dependent rules</div>
            </div>
            <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50 flex flex-col justify-between">
              <div className="text-slate-400 font-medium">4. Trust Evaluation</div>
              <div className="text-emerald-300 font-semibold mt-1">Deterministic Math</div>
              <div className="text-[10px] text-slate-500 mt-2">Score [0.00 – 1.00] & Deductions</div>
            </div>
            <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50 flex flex-col justify-between">
              <div className="text-slate-400 font-medium">5. Detection Trust Alert</div>
              <div className="text-rose-300 font-semibold mt-1">Actionable Triage</div>
              <div className="text-[10px] text-slate-500 mt-2">DEGRADED / AT RISK / INVALID</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── SECTION B: KPI METRIC CARDS ──────────────────────────────────────── */}
      {kpis && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
          <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800 backdrop-blur">
            <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Evaluations</div>
            <div className="text-2xl font-bold text-slate-100 mt-1">{kpis.total_evaluations}</div>
            <div className="text-[10px] text-slate-500 mt-1">Historical Decisions</div>
          </div>
          <div className="bg-slate-900/80 p-4 rounded-xl border border-emerald-900/30 bg-emerald-950/10 backdrop-blur">
            <div className="text-[11px] font-medium text-emerald-400 uppercase tracking-wider">Trusted</div>
            <div className="text-2xl font-bold text-emerald-300 mt-1">{kpis.trusted_rules_count}</div>
            <div className="text-[10px] text-emerald-500/70 mt-1">Score 0.90 – 1.00</div>
          </div>
          <div className="bg-slate-900/80 p-4 rounded-xl border border-blue-900/30 bg-blue-950/10 backdrop-blur">
            <div className="text-[11px] font-medium text-blue-400 uppercase tracking-wider">Degraded</div>
            <div className="text-2xl font-bold text-blue-300 mt-1">{kpis.degraded_rules_count}</div>
            <div className="text-[10px] text-blue-500/70 mt-1">Score 0.70 – 0.89</div>
          </div>
          <div className="bg-slate-900/80 p-4 rounded-xl border border-amber-900/30 bg-amber-950/10 backdrop-blur">
            <div className="text-[11px] font-medium text-amber-400 uppercase tracking-wider">At Risk</div>
            <div className="text-2xl font-bold text-amber-300 mt-1">{kpis.at_risk_rules_count}</div>
            <div className="text-[10px] text-amber-500/70 mt-1">Score 0.40 – 0.69</div>
          </div>
          <div className="bg-slate-900/80 p-4 rounded-xl border border-rose-900/30 bg-rose-950/10 backdrop-blur">
            <div className="text-[11px] font-medium text-rose-400 uppercase tracking-wider">Invalid</div>
            <div className="text-2xl font-bold text-rose-300 mt-1">{kpis.invalid_rules_count}</div>
            <div className="text-[10px] text-rose-500/70 mt-1">Score 0.00 – 0.39</div>
          </div>
          <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800 backdrop-blur">
            <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Unknown</div>
            <div className="text-2xl font-bold text-slate-300 mt-1">{kpis.unknown_rules_count}</div>
            <div className="text-[10px] text-slate-500 mt-1">Zero Trust Applied</div>
          </div>
          <div className="bg-slate-900/80 p-4 rounded-xl border border-rose-600/40 bg-rose-950/20 backdrop-blur">
            <div className="text-[11px] font-medium text-rose-400 uppercase tracking-wider">Open Alerts</div>
            <div className="text-2xl font-bold text-rose-400 mt-1">{kpis.open_alerts_count}</div>
            <div className="text-[10px] text-rose-400/70 mt-1">{kpis.critical_alerts_count} Critical</div>
          </div>
        </div>
      )}

      {/* ── SECTION C & D: MAIN REGISTRY & EXPLAINABILITY ──────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Detection Rule Trust Registry */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900/80 rounded-xl border border-slate-800 p-5 shadow-lg">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5">
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span>📋</span> Detection Rule Trust Registry
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">Real-time trust scores and evaluation history per rule</p>
              </div>

              {/* Status Filter Tabs */}
              <div className="flex flex-wrap gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
                {["ALL", "TRUSTED", "DEGRADED", "AT_RISK", "INVALID"].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setStatusFilter(tab)}
                    className={`px-3 py-1 rounded font-medium transition cursor-pointer ${
                      statusFilter === tab
                        ? "bg-indigo-600 text-white shadow"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {tab.replace("_", " ")}
                  </button>
                ))}
              </div>
            </div>

            {/* Search Input */}
            <div className="mb-4">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by rule ID, title, or canonical field..."
                className="w-full bg-slate-950/70 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition"
              />
            </div>

            {/* Evaluations Table */}
            <div className="overflow-x-auto rounded-lg border border-slate-800/80">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Detection Rule</th>
                    <th className="py-3 px-3">Vendor Scope</th>
                    <th className="py-3 px-3">Dependent Field</th>
                    <th className="py-3 px-3">Trust State</th>
                    <th className="py-3 px-3">Trust Score</th>
                    <th className="py-3 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
                  {filteredEvaluations.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="py-8 text-center text-slate-500">
                        No detection rule trust evaluations match the selected filters.
                      </td>
                    </tr>
                  ) : (
                    filteredEvaluations.map((item) => (
                      <tr
                        key={item.evaluation_id}
                        onClick={() => setSelectedEvaluation(item)}
                        className={`hover:bg-slate-800/40 transition cursor-pointer ${
                          selectedEvaluation?.evaluation_id === item.evaluation_id
                            ? "bg-indigo-950/30 border-l-2 border-indigo-500"
                            : ""
                        }`}
                      >
                        <td className="py-3 px-4 font-mono font-medium text-slate-200">
                          <div>{item.rule_name || item.rule_id}</div>
                          <div className="text-[10px] text-slate-500 font-sans">{item.rule_id}</div>
                        </td>
                        <td className="py-3 px-3 text-slate-300">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-[11px] text-slate-300">
                            {item.vendor_name || "Generic"}
                          </span>
                        </td>
                        <td className="py-3 px-3 font-mono text-slate-300">
                          <span className="px-2 py-0.5 rounded bg-slate-950 text-[11px] text-indigo-300 border border-slate-800">
                            {item.canonical_field}
                          </span>
                        </td>
                        <td className="py-3 px-3">{getStatusBadge(item.trust_status)}</td>
                        <td className="py-3 px-3">
                          <div className="flex items-center gap-2">
                            <span className={`font-mono font-bold ${getScoreColor(item.trust_score)}`}>
                              {(item.trust_score * 100).toFixed(0)}%
                            </span>
                            <div className="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${
                                  item.trust_score >= 0.9
                                    ? "bg-emerald-400"
                                    : item.trust_score >= 0.7
                                    ? "bg-blue-400"
                                    : item.trust_score >= 0.4
                                    ? "bg-amber-400"
                                    : "bg-rose-400"
                                }`}
                                style={{ width: `${item.trust_score * 100}%` }}
                              ></div>
                            </div>
                          </div>
                        </td>
                        <td className="py-3 px-3 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleOpenTrace(item.evaluation_id);
                              }}
                              className="px-2.5 py-1 rounded text-[11px] font-medium bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 transition cursor-pointer"
                            >
                              Trace
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleEvaluateRule(item.rule_id);
                              }}
                              disabled={evaluatingRuleId === item.rule_id}
                              className="px-2.5 py-1 rounded text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer"
                            >
                              {evaluatingRuleId === item.rule_id ? "..." : "Re-Eval"}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* ── SECTION D: BLAST RADIUS & DEPENDENCY ISOLATION VISUALIZER ───── */}
          <div className="bg-slate-900/80 rounded-xl border border-slate-800 p-5 shadow-lg">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>🌐</span> Semantic Drift Blast Radius & Dependency Isolation
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Select a canonical field to simulate drift and observe strictly isolated downstream impacts.
                </p>
              </div>

              <select
                value={selectedScenarioField}
                onChange={(e) => setSelectedScenarioField(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded px-2.5 py-1.5 focus:outline-none focus:border-indigo-500"
              >
                <option value="action.result">action.result (Protected - Ambiguous Drift)</option>
                <option value="authentication.outcome">authentication.outcome (Protected - Unmapped)</option>
                <option value="disposition">disposition (Compatible Mapping)</option>
                <option value="dns_query">dns_query (Exact - Unaffected / Isolated)</option>
              </select>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-slate-950/60 rounded-lg border border-slate-800">
              {/* Field Drift Node */}
              <div className="p-3 bg-slate-900 rounded border border-indigo-500/30 flex flex-col justify-between">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-indigo-400 font-semibold">Originating Field</div>
                  <div className="text-sm font-mono font-bold text-slate-100 mt-1">{selectedScenarioField}</div>
                  <div className="text-xs text-slate-400 mt-2">
                    {selectedScenarioField === "action.result" && "Classified as AMBIGUOUS (-0.25) on Protected Asset (-0.15)"}
                    {selectedScenarioField === "authentication.outcome" && "Classified as UNMAPPED (-0.40) on Critical Asset (-0.30)"}
                    {selectedScenarioField === "disposition" && "Classified as COMPATIBLE (-0.10)"}
                    {selectedScenarioField === "dns_query" && "Classified as EXACT (0.00) — Zero Drift"}
                  </div>
                </div>
                <div className="mt-3 text-[11px] font-mono text-indigo-300">Target DAG Filter Active</div>
              </div>

              {/* Blast Radius Node */}
              <div className="p-3 bg-slate-900 rounded border border-slate-800 flex flex-col justify-between">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold">Dependent Rules in Blast Radius</div>
                  <div className="space-y-1.5 mt-2">
                    {selectedScenarioField === "action.result" && (
                      <>
                        <div className="text-xs text-amber-300 font-mono flex items-center justify-between">
                          <span>drule_win_sec_logon</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-400">AT RISK</span>
                        </div>
                        <div className="text-xs text-amber-300 font-mono flex items-center justify-between">
                          <span>drule_cisco_asa_permit</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-400">AT RISK</span>
                        </div>
                      </>
                    )}
                    {selectedScenarioField === "authentication.outcome" && (
                      <div className="text-xs text-rose-300 font-mono flex items-center justify-between">
                        <span>drule_linux_ssh_brute</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-400">INVALID</span>
                      </div>
                    )}
                    {selectedScenarioField === "disposition" && (
                      <div className="text-xs text-blue-300 font-mono flex items-center justify-between">
                        <span>drule_fw_deny_scan</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-950 text-blue-400">DEGRADED</span>
                      </div>
                    )}
                    {selectedScenarioField === "dns_query" && (
                      <div className="text-xs text-emerald-300 font-mono flex items-center justify-between">
                        <span>drule_suri_dns_tunnel</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400">TRUSTED</span>
                      </div>
                    )}
                  </div>
                </div>
                <div className="mt-3 text-[10px] text-slate-500">Only subscribed rules are evaluated.</div>
              </div>

              {/* Isolation Proof Node */}
              <div className="p-3 bg-emerald-950/20 rounded border border-emerald-500/30 flex flex-col justify-between">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-emerald-400 font-semibold">Dependency Isolation Proof</div>
                  <div className="text-xs text-emerald-200 mt-2 leading-relaxed">
                    Rules independent of <span className="font-mono text-white">{selectedScenarioField}</span> remain <strong>100% TRUSTED</strong>. No global cascading failures.
                  </div>
                </div>
                <div className="mt-3 text-[11px] font-semibold text-emerald-400 flex items-center gap-1.5">
                  <span>🛡️</span> Zero Collateral Trust Degradation
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Col: SECTION E - Explainability Panel & SECTION F - Dependency Inspector */}
        <div className="space-y-6">
          {/* SECTION E: Trust Score Explainability Panel */}
          <div className="bg-slate-900/80 rounded-xl border border-slate-800 p-5 shadow-lg">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 mb-1">
              <span>🧠</span> Trust Score Explainability
            </h2>
            <p className="text-xs text-slate-400 mb-4">Step-by-step mathematical deductions and context rationale</p>

            {selectedEvaluation ? (
              <div className="space-y-4 text-xs">
                {/* Rule Header */}
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 font-medium">{selectedEvaluation.rule_id}</span>
                    {getStatusBadge(selectedEvaluation.trust_status)}
                  </div>
                  <div className="text-sm font-semibold text-slate-200 mt-1">
                    {selectedEvaluation.rule_name || "Detection Rule Evaluation"}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    Evaluated Field: <span className="font-mono text-indigo-300">{selectedEvaluation.canonical_field}</span>
                  </div>
                </div>

                {/* Score Big Display */}
                <div className="p-4 bg-slate-950/80 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-xs text-slate-400 uppercase tracking-wider">Final Trust Score</div>
                    <div className={`text-3xl font-extrabold font-mono mt-1 ${getScoreColor(selectedEvaluation.trust_score)}`}>
                      {(selectedEvaluation.trust_score * 100).toFixed(0)}%
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-slate-400">Risk Classification</div>
                    <div className="mt-1">{getSeverityBadge(selectedEvaluation.risk_level)}</div>
                  </div>
                </div>

                {/* Mathematical Deductions List */}
                <div>
                  <div className="text-xs font-semibold text-slate-300 mb-2">Mathematical Deductions:</div>
                  <div className="space-y-1.5 p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px]">
                    {selectedEvaluation.evaluation_reasons?.map((reason, idx) => (
                      <div
                        key={idx}
                        className={`flex items-start gap-2 ${
                          reason.includes("-") || reason.includes("CRITICAL")
                            ? "text-rose-400"
                            : reason.includes("Base") || reason.includes("Final")
                            ? "text-slate-200 font-bold"
                            : "text-slate-400"
                        }`}
                      >
                        <span className="text-slate-600">›</span>
                        <span>{reason}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Narrative Explanation */}
                <div>
                  <div className="text-xs font-semibold text-slate-300 mb-1.5">Cybersecurity Explanation:</div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 text-slate-300 text-xs leading-relaxed">
                    {selectedEvaluation.explanation}
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    onClick={() => handleOpenTrace(selectedEvaluation.evaluation_id)}
                    className="w-full py-2.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition shadow cursor-pointer flex items-center justify-center gap-2"
                  >
                    <span>🔍</span> View Complete Provenance Trace
                  </button>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-slate-500 text-xs">
                Select a detection rule from the registry to inspect its trust deductions.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── SECTION G: DETECTION TRUST ALERTS TRIAGE ───────────────────────── */}
      <div className="bg-slate-900/80 rounded-xl border border-slate-800 p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <span>🚨</span> Detection Trust Alerts Triage Center
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Live alerts generated when detection rules undergo trust degradation or invalidation
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Status Filter */}
            <select
              value={alertStatusFilter}
              onChange={(e) => setAlertStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded px-3 py-1.5 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">OPEN Only</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>

            {/* Severity Filter */}
            <select
              value={alertSeverityFilter}
              onChange={(e) => setAlertSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded px-3 py-1.5 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="overflow-x-auto rounded-lg border border-slate-800/80">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-3">Alert Type</th>
                <th className="py-3 px-3">Affected Rule</th>
                <th className="py-3 px-3">Canonical Field</th>
                <th className="py-3 px-3">Trust State</th>
                <th className="py-3 px-3">Triage Status</th>
                <th className="py-3 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-8 text-center text-slate-500">
                    No detection trust alerts match the selected filters.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr key={alert.alert_id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4">{getSeverityBadge(alert.severity)}</td>
                    <td className="py-3 px-3 font-mono font-medium text-slate-200">{alert.alert_type}</td>
                    <td className="py-3 px-3 text-slate-300 font-mono">{alert.rule_id}</td>
                    <td className="py-3 px-3 font-mono text-indigo-300">{alert.affected_field}</td>
                    <td className="py-3 px-3">{getStatusBadge(alert.trust_status)}</td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                          alert.status === "OPEN"
                            ? "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                            : alert.status === "ACKNOWLEDGED"
                            ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                            : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                        }`}
                      >
                        {alert.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {alert.status === "OPEN" && (
                          <button
                            onClick={() => handleUpdateAlertStatus(alert.alert_id, "ACKNOWLEDGED")}
                            className="px-2.5 py-1 rounded text-[11px] font-medium bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition cursor-pointer"
                          >
                            Acknowledge
                          </button>
                        )}
                        {alert.status !== "RESOLVED" && (
                          <button
                            onClick={() => handleUpdateAlertStatus(alert.alert_id, "RESOLVED")}
                            className="px-2.5 py-1 rounded text-[11px] font-medium bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 transition cursor-pointer"
                          >
                            Resolve
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── SECTION H: END-TO-END TRUST TRACE PROVENANCE MODAL ──────────────── */}
      {selectedTrace && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                    Sprint 6B Trace
                  </span>
                  <h2 className="text-xl font-bold text-slate-100">End-to-End Trust Trace Provenance</h2>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  10-Stage Cryptographic & Semantic Provenance Chain for Rule{" "}
                  <span className="font-mono text-indigo-300">{selectedTrace.rule_id}</span>
                </p>
              </div>

              <button
                onClick={() => setSelectedTrace(null)}
                className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Trace Steps Chain */}
            <div className="space-y-4">
              {selectedTrace.provenance_chain?.map((step) => (
                <div
                  key={step.step_number}
                  className="p-4 bg-slate-950 rounded-xl border border-slate-800/80 flex flex-col md:flex-row md:items-start gap-4 relative"
                >
                  <div className="w-8 h-8 rounded-full bg-indigo-600/20 border border-indigo-500/40 text-indigo-400 flex items-center justify-center font-bold font-mono text-sm shrink-0">
                    {step.step_number}
                  </div>

                  <div className="flex-1">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                      <div className="text-xs uppercase tracking-wider font-bold text-indigo-400">
                        {step.stage_name}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">{step.entity_id}</div>
                    </div>

                    <div className="text-sm font-semibold text-slate-200 mt-1">{step.summary}</div>

                    {/* Step Details Code Block */}
                    <div className="mt-3 p-3 bg-slate-900/90 rounded border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
                      <pre>{JSON.stringify(step.details, null, 2)}</pre>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedTrace(null)}
                className="px-5 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition cursor-pointer"
              >
                Close Provenance Trace
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
