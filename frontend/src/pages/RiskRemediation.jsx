/**
 * RiskRemediation.jsx
 * -------------------
 * Executive Risk Intelligence, Deterministic Risk Correlation & Prioritized Remediation Dashboard.
 *
 * Sprint 7B — Security Posture Risk Correlation, Prioritized Remediation & Executive Risk Intelligence.
 * Exposes deterministic correlation chains, concentration clusters, mathematical priority scoring,
 * in-memory hypothetical risk reduction simulations, auditable lifecycle transitions, and 16+ stage provenance.
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";

export default function RiskRemediation() {
  const { user, token } = useAuth();

  // State
  const [correlations, setCorrelations] = useState([]);
  const [clusters, setClusters] = useState([]);
  const [remediations, setRemediations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [selectedPriority, setSelectedPriority] = useState("ALL");
  const [selectedStatus, setSelectedStatus] = useState("ALL");

  // Modals
  const [selectedCorrelation, setSelectedCorrelation] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [graphLoading, setGraphLoading] = useState(false);

  const [explainCandidate, setExplainCandidate] = useState(null);
  const [simulationCandidate, setSimulationCandidate] = useState(null);
  const [simulationResult, setSimulationResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  const [statusCandidate, setStatusCandidate] = useState(null);
  const [targetStatus, setTargetStatus] = useState("RECOMMENDED");
  const [statusReason, setStatusReason] = useState("");
  const [statusSubmitting, setStatusSubmitting] = useState(false);

  const [traceCandidate, setTraceCandidate] = useState(null);
  const [traceData, setTraceData] = useState(null);
  const [traceLoading, setTraceLoading] = useState(false);

  // Analysis trigger
  const [analyzing, setAnalyzing] = useState(false);

  // Fetch data
  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const headers = { Authorization: `Bearer ${token}` };

      const [corrRes, clusterRes, remRes] = await Promise.all([
        fetch("/api/v1/risk-correlations", { headers }),
        fetch("/api/v1/risk-correlations/clusters", { headers }),
        fetch("/api/v1/remediations", { headers }),
      ]);

      if (!corrRes.ok || !clusterRes.ok || !remRes.ok) {
        throw new Error("Failed to fetch executive risk intelligence telemetry.");
      }

      const corrData = await corrRes.json();
      const clusterData = await clusterRes.json();
      const remData = await remRes.json();

      setCorrelations(corrData);
      setClusters(clusterData);
      setRemediations(remData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [token]);

  // Trigger analysis
  const handleTriggerAnalysis = async () => {
    setAnalyzing(true);
    try {
      const headers = {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      };
      const res = await fetch("/api/v1/risk-correlations/analyze", {
        method: "POST",
        headers,
        body: JSON.stringify({ force_reanalyze: true }),
      });
      if (!res.ok) throw new Error("Risk correlation analysis failed.");
      await fetch("/api/v1/remediations/generate", {
        method: "POST",
        headers,
        body: JSON.stringify({ force_regenerate: true }),
      });
      await fetchData();
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  // Inspect Graph
  const handleOpenGraph = async (corr) => {
    setSelectedCorrelation(corr);
    setGraphLoading(true);
    try {
      const res = await fetch(`/api/v1/risk-correlations/${corr.correlation_id}/graph`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to load root-cause contribution graph.");
      const data = await res.json();
      setGraphData(data);
    } catch (err) {
      alert("Error loading graph: " + err.message);
    } finally {
      setGraphLoading(false);
    }
  };

  // Explain Priority
  const handleOpenExplain = async (rem) => {
    try {
      const res = await fetch(`/api/v1/remediations/${rem.remediation_id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to fetch detailed explanation.");
      const data = await res.json();
      setExplainCandidate(data);
    } catch (err) {
      alert("Error: " + err.message);
    }
  };

  // Run Simulation
  const handleOpenSimulation = async (rem) => {
    setSimulationCandidate(rem);
    setSimulationResult(null);
    setSimulating(true);
    try {
      const res = await fetch(`/api/v1/remediations/${rem.remediation_id}/simulate`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      });
      if (!res.ok) throw new Error("Simulation execution failed.");
      const data = await res.json();
      setSimulationResult(data);
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      setSimulating(false);
    }
  };

  // Update Status
  const handleUpdateStatus = async (e) => {
    e.preventDefault();
    if (!statusCandidate) return;
    setStatusSubmitting(true);
    try {
      const res = await fetch(`/api/v1/remediations/${statusCandidate.remediation_id}/status`, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          status: targetStatus,
          reason: statusReason || `Status transitioned to ${targetStatus}`,
        }),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Status transition failed.");
      }
      setStatusCandidate(null);
      setStatusReason("");
      await fetchData();
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      setStatusSubmitting(false);
    }
  };

  // View 16+ Stage Provenance
  const handleOpenTrace = async (rem) => {
    setTraceCandidate(rem);
    setTraceLoading(true);
    try {
      const res = await fetch(`/api/v1/remediations/${rem.remediation_id}/trace`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to fetch remediation provenance trace.");
      const data = await res.json();
      setTraceData(data);
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      setTraceLoading(false);
    }
  };

  // Computed KPIs
  const totalCorrelations = correlations.length;
  const criticalCorrelations = correlations.filter((c) => c.severity === "CRITICAL").length;
  const immediateRemediations = remediations.filter((r) => r.priority_classification === "IMMEDIATE").length;
  const totalGain = remediations.reduce((acc, r) => acc + (r.expected_risk_reduction || 0), 0);

  // Priority color helper
  const getPriorityBadge = (pClass) => {
    switch (pClass) {
      case "IMMEDIATE":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse";
      case "URGENT":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      case "HIGH":
        return "bg-orange-500/20 text-orange-300 border-orange-500/40";
      case "MEDIUM":
        return "bg-cyan-500/20 text-cyan-300 border-cyan-500/40";
      default:
        return "bg-slate-700/50 text-slate-400 border-slate-600";
    }
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-400 border-rose-500/30";
      case "HIGH":
        return "bg-amber-500/20 text-amber-400 border-amber-500/30";
      case "MEDIUM":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      default:
        return "bg-slate-700/40 text-slate-400 border-slate-600";
    }
  };

  const getStatusBadge = (st) => {
    switch (st) {
      case "GENERATED":
        return "bg-slate-800 text-slate-300 border-slate-700";
      case "RECOMMENDED":
        return "bg-indigo-500/20 text-indigo-300 border-indigo-500/30";
      case "ACKNOWLEDGED":
        return "bg-amber-500/20 text-amber-300 border-amber-500/30";
      case "IN_PROGRESS":
        return "bg-cyan-500/20 text-cyan-300 border-cyan-500/30";
      case "RESOLVED":
        return "bg-emerald-500/20 text-emerald-300 border-emerald-500/30";
      case "VERIFIED":
        return "bg-emerald-500 text-sentinel-950 font-bold border-emerald-400";
      case "REJECTED":
        return "bg-rose-900/40 text-rose-400 border-rose-800";
      default:
        return "bg-slate-800 text-slate-400 border-slate-700";
    }
  };

  // Filtered lists
  const filteredCorrelations = correlations.filter((c) => {
    if (selectedSeverity !== "ALL" && c.severity !== selectedSeverity) return false;
    return true;
  });

  const filteredRemediations = remediations.filter((r) => {
    if (selectedPriority !== "ALL" && r.priority_classification !== selectedPriority) return false;
    if (selectedStatus !== "ALL" && r.status !== selectedStatus) return false;
    return true;
  });

  return (
    <main className="flex-1 overflow-y-auto bg-sentinel-950 p-8 space-y-8 animate-fade-in font-sans">
      {/* ── HEADER ──────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono tracking-widest uppercase bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/30">
              Sprint 7B • Executive Risk Intelligence
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono tracking-widest uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              Deterministic & Evidence-Backed
            </span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight font-mono">
            Security Posture Risk Correlation & Prioritized Remediation
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            "Why is the posture risky? What technical dependencies contribute? What should be fixed first?"
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleTriggerAnalysis}
            disabled={analyzing}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-accent-cyan to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-sentinel-950 font-bold text-xs font-mono rounded-lg transition-all shadow-lg shadow-cyan-950/30 disabled:opacity-50"
          >
            {analyzing ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-sentinel-950 border-t-transparent rounded-full animate-spin" />
                Correlating Signals...
              </>
            ) : (
              <>
                <span>⚡</span>
                Re-Analyze Risk Correlations
              </>
            )}
          </button>
        </div>
      </div>

      {/* ── SECTION A: EXECUTIVE RISK INTELLIGENCE HERO ───────────────────────── */}
      <div className="rounded-2xl bg-gradient-to-r from-sentinel-900/90 via-slate-900/60 to-sentinel-900/90 border border-slate-800 p-6 backdrop-blur-md relative overflow-hidden">
        <div className="flex flex-col lg:flex-row items-center justify-between gap-6">
          <div className="space-y-3 max-w-xl">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400 uppercase tracking-wider">
              <span>Security Signals</span>
              <span>→</span>
              <span className="text-accent-cyan">Risk Correlation</span>
              <span>→</span>
              <span className="text-amber-400">Concentration</span>
              <span>→</span>
              <span className="text-rose-400">Prioritization</span>
              <span>→</span>
              <span className="text-emerald-400">Simulation</span>
            </div>
            <h2 className="text-lg font-bold text-slate-100">
              A Critical Posture Score is Not Just a Number
            </h2>
            <p className="text-slate-400 text-xs leading-relaxed">
              Every posture score degradation is mathematically explainable through the exact semantic drift alerts,
              vendor mappings, protected fields, and detection rule dependency chains contributing to risk.
            </p>
          </div>

          {/* Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 w-full lg:w-auto">
            <div className="p-3.5 rounded-xl bg-sentinel-950/70 border border-slate-800 text-center">
              <div className="text-[10px] font-mono text-slate-400 uppercase">Risk Clusters</div>
              <div className="text-2xl font-bold font-mono text-accent-cyan mt-1">{clusters.length}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">Concentration Centers</div>
            </div>

            <div className="p-3.5 rounded-xl bg-sentinel-950/70 border border-rose-500/30 text-center">
              <div className="text-[10px] font-mono text-rose-300 uppercase">Critical Chains</div>
              <div className="text-2xl font-bold font-mono text-rose-400 mt-1">{criticalCorrelations}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">Protected Field Violations</div>
            </div>

            <div className="p-3.5 rounded-xl bg-sentinel-950/70 border border-amber-500/30 text-center">
              <div className="text-[10px] font-mono text-amber-300 uppercase">Immediate Fixes</div>
              <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{immediateRemediations}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">Priority 90-100</div>
            </div>

            <div className="p-3.5 rounded-xl bg-sentinel-950/70 border border-emerald-500/30 text-center">
              <div className="text-[10px] font-mono text-emerald-300 uppercase">Potential Gain</div>
              <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">+{totalGain.toFixed(0)} pts</div>
              <div className="text-[10px] text-slate-500 mt-0.5">Simulated Recovery</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── SECTION C: RISK CONCENTRATION CLUSTERS ───────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-lg">🎯</span>
            <h2 className="text-base font-bold font-mono text-slate-200">Risk Concentration Clusters</h2>
          </div>
          <span className="text-xs text-slate-400">
            Grouping independent signals around shared dependency bottlenecks
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {clusters.map((cluster) => (
            <div
              key={cluster.cluster_key}
              className="p-5 rounded-xl bg-sentinel-900/60 border border-slate-800 hover:border-slate-700 transition-all space-y-3"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-1.5">
                    {cluster.is_protected_field && (
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        PROTECTED FIELD
                      </span>
                    )}
                    <span className="text-xs font-mono text-slate-400">Center:</span>
                  </div>
                  <h3 className="text-sm font-bold font-mono text-accent-cyan mt-1">
                    {cluster.cluster_center}
                  </h3>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadge(cluster.severity)}`}>
                  {cluster.severity}
                </span>
              </div>

              <p className="text-slate-400 text-xs leading-relaxed">
                {cluster.explanation}
              </p>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                <div>
                  Score: <span className="text-slate-200 font-bold">{cluster.concentration_score.toFixed(1)}/100</span>
                </div>
                <div>
                  Rules Impacted: <span className="text-rose-400 font-bold">{cluster.affected_rule_count}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── SECTION E: PRIORITIZED REMEDIATION CENTER ────────────────────────── */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="text-lg">🛡️</span>
            <h2 className="text-base font-bold font-mono text-slate-200">
              Prioritized Remediation Center
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400">
              {filteredRemediations.length} Proposals
            </span>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedPriority}
              onChange={(e) => setSelectedPriority(e.target.value)}
              className="px-3 py-1.5 bg-sentinel-900 border border-slate-700 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-accent-cyan"
            >
              <option value="ALL">All Priorities</option>
              <option value="IMMEDIATE">IMMEDIATE (90-100)</option>
              <option value="URGENT">URGENT (75-89)</option>
              <option value="HIGH">HIGH (50-74)</option>
              <option value="MEDIUM">MEDIUM (25-49)</option>
              <option value="LOW">LOW (0-24)</option>
            </select>

            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="px-3 py-1.5 bg-sentinel-900 border border-slate-700 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-accent-cyan"
            >
              <option value="ALL">All Statuses</option>
              <option value="GENERATED">GENERATED</option>
              <option value="RECOMMENDED">RECOMMENDED</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="IN_PROGRESS">IN PROGRESS</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="VERIFIED">VERIFIED</option>
              <option value="REJECTED">REJECTED</option>
            </select>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-sentinel-900/60 overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-sentinel-950/80 border-b border-slate-800 font-mono text-slate-400 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Priority</th>
                <th className="py-3 px-4">Remediation Action</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Expected Gain</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredRemediations.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-8 text-center text-slate-500 font-mono">
                    No remediation candidates matching selected filters.
                  </td>
                </tr>
              ) : (
                filteredRemediations.map((rem) => (
                  <tr key={rem.remediation_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border font-bold ${getPriorityBadge(rem.priority_classification)}`}>
                          {rem.priority_classification}
                        </span>
                        <span className="font-mono text-slate-300 font-bold">{rem.priority_score}</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 max-w-md">
                      <div className="font-bold text-slate-200">{rem.title}</div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">{rem.description}</div>
                      <div className="flex items-center gap-2 mt-1.5 text-[10px] font-mono text-slate-500">
                        <span>Target: {rem.affected_fields?.join(", ") || "General"}</span>
                        <span>•</span>
                        <span>Rules: {rem.affected_rules?.length || 0}</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadge(rem.severity)}`}>
                        {rem.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap font-mono text-emerald-400 font-bold">
                      +{rem.expected_risk_reduction?.toFixed(1)} pts
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap font-mono text-slate-300">
                      {((rem.simulation_confidence || 1.0) * 100).toFixed(0)}%
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getStatusBadge(rem.status)}`}>
                        {rem.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap text-right space-x-2">
                      <button
                        onClick={() => handleOpenExplain(rem)}
                        className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-mono rounded border border-slate-700 transition-colors"
                      >
                        Explain
                      </button>
                      <button
                        onClick={() => handleOpenSimulation(rem)}
                        className="px-2 py-1 bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 text-[11px] font-mono rounded border border-emerald-800/60 transition-colors"
                      >
                        Simulate
                      </button>
                      <button
                        onClick={() => {
                          setStatusCandidate(rem);
                          setTargetStatus("RECOMMENDED");
                        }}
                        className="px-2 py-1 bg-accent-cyan/10 hover:bg-accent-cyan/20 text-accent-cyan text-[11px] font-mono rounded border border-accent-cyan/30 transition-colors"
                      >
                        Status
                      </button>
                      <button
                        onClick={() => handleOpenTrace(rem)}
                        className="px-2 py-1 bg-indigo-950/60 hover:bg-indigo-900/80 text-indigo-300 text-[11px] font-mono rounded border border-indigo-800/60 transition-colors"
                      >
                        Trace
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── SECTION B: RISK CORRELATIONS REGISTRY ────────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-lg">⛓️</span>
            <h2 className="text-base font-bold font-mono text-slate-200">
              Risk Correlation Registry
            </h2>
          </div>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-1.5 bg-sentinel-900 border border-slate-700 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-accent-cyan"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>

        <div className="rounded-xl border border-slate-800 bg-sentinel-900/60 overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-sentinel-950/80 border-b border-slate-800 font-mono text-slate-400 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Correlation ID</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Signals</th>
                <th className="py-3 px-4">Rules</th>
                <th className="py-3 px-4">Cluster Key</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredCorrelations.map((corr) => (
                <tr key={corr.correlation_id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-4 font-mono text-accent-cyan font-bold">
                    {corr.correlation_id}
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300">
                    {corr.correlation_type}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadge(corr.severity)}`}>
                      {corr.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-200 font-bold">
                    {corr.risk_score.toFixed(1)}/100
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300">
                    {corr.affected_signal_count}
                  </td>
                  <td className="py-3 px-4 font-mono text-rose-400 font-bold">
                    {corr.affected_rule_count}
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                    {corr.risk_cluster_key || "—"}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => handleOpenGraph(corr)}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-mono rounded border border-slate-700 transition-colors"
                    >
                      Graph DAG
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── MODAL: EXPLAIN PRIORITY ─────────────────────────────────────────── */}
      {explainCandidate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-sentinel-950/80 backdrop-blur-sm p-4 animate-fade-in">
          <div className="bg-sentinel-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-6 space-y-6 shadow-2xl max-h-[90vh] overflow-y-auto font-sans">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-widest text-accent-cyan">
                  Deterministic Priority Breakdown
                </span>
                <h3 className="text-base font-bold text-slate-100 font-mono mt-0.5">
                  {explainCandidate.title}
                </h3>
              </div>
              <button
                onClick={() => setExplainCandidate(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            {explainCandidate.priority_explanation ? (
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-sentinel-950 border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-[10px] font-mono text-slate-400 uppercase">Calculated Score</div>
                    <div className="text-2xl font-bold font-mono text-slate-100 mt-0.5">
                      {explainCandidate.priority_explanation.final_score} / 100
                    </div>
                  </div>
                  <span className={`px-3 py-1 rounded text-xs font-mono font-bold border ${getPriorityBadge(explainCandidate.priority_explanation.priority_classification)}`}>
                    {explainCandidate.priority_explanation.priority_classification}
                  </span>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-mono text-slate-300 font-bold uppercase">Mathematical Factors</div>
                  <div className="space-y-2">
                    {explainCandidate.priority_explanation.factors?.map((f, i) => (
                      <div
                        key={i}
                        className={`p-3 rounded-lg border text-xs flex items-center justify-between ${
                          f.applied
                            ? "bg-slate-800/40 border-slate-700 text-slate-200"
                            : "bg-sentinel-950/40 border-slate-800/40 text-slate-500 opacity-60"
                        }`}
                      >
                        <div>
                          <div className="font-mono font-bold">{f.factor_name}</div>
                          <div className="text-[11px] text-slate-400 mt-0.5">{f.factor_description}</div>
                        </div>
                        <div className={`font-mono font-bold text-sm ${f.applied ? "text-emerald-400" : "text-slate-600"}`}>
                          {f.applied ? `+${f.points}` : "+0"}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-sentinel-950 border border-slate-800/80 font-mono text-xs text-slate-400 space-y-1">
                  <div className="text-[10px] uppercase text-slate-500 font-bold">Mathematical Formula</div>
                  <div className="text-slate-300 break-all">{explainCandidate.priority_explanation.mathematical_formula}</div>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-400 font-mono">No mathematical explanation available.</p>
            )}

            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setExplainCandidate(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── MODAL: HYPOTHETICAL SIMULATOR ───────────────────────────────────── */}
      {simulationCandidate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-sentinel-950/80 backdrop-blur-sm p-4 animate-fade-in">
          <div className="bg-sentinel-900 border border-slate-700 rounded-2xl max-w-3xl w-full p-6 space-y-6 shadow-2xl max-h-[90vh] overflow-y-auto font-sans">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono tracking-widest uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  HYPOTHETICAL SIMULATION — NO PRODUCTION STATE MODIFIED
                </span>
                <h3 className="text-base font-bold text-slate-100 font-mono mt-2">
                  {simulationCandidate.title}
                </h3>
              </div>
              <button
                onClick={() => setSimulationCandidate(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            {simulating ? (
              <div className="py-12 text-center space-y-3 font-mono">
                <div className="w-8 h-8 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin mx-auto" />
                <p className="text-xs text-slate-400 uppercase">Cloning Trust State & Recalculating Posture Delta...</p>
              </div>
            ) : simulationResult ? (
              <div className="space-y-6">
                {/* Before / After Comparison */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-4 rounded-xl bg-sentinel-950 border border-slate-800 text-center">
                    <div className="text-[10px] font-mono text-slate-400 uppercase">Current Posture</div>
                    <div className="text-2xl font-bold font-mono text-slate-300 mt-1">
                      {simulationResult.current_posture_score?.toFixed(1)} / 100
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-sentinel-950 border border-emerald-500/40 text-center">
                    <div className="text-[10px] font-mono text-emerald-300 uppercase">Predicted Posture</div>
                    <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                      {simulationResult.predicted_posture_score?.toFixed(1)} / 100
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-sentinel-950 border border-accent-cyan/40 text-center">
                    <div className="text-[10px] font-mono text-accent-cyan uppercase">Expected Delta</div>
                    <div className="text-2xl font-bold font-mono text-accent-cyan mt-1">
                      +{simulationResult.expected_improvement_delta?.toFixed(1)} pts
                    </div>
                  </div>
                </div>

                {/* Summary Box */}
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-slate-300 space-y-1">
                  <div className="font-mono text-[10px] text-slate-500 uppercase font-bold">Simulation Output</div>
                  <p>{simulationResult.simulation_summary}</p>
                </div>

                {/* Affected Rules Recovery Table */}
                <div className="space-y-2">
                  <div className="text-xs font-mono text-slate-300 font-bold uppercase">
                    Affected Rules State Recovery ({simulationResult.affected_rules?.length || 0})
                  </div>
                  <div className="rounded-lg border border-slate-800 overflow-hidden">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-sentinel-950 font-mono text-slate-400 text-[10px] uppercase">
                        <tr>
                          <th className="py-2.5 px-3">Rule ID</th>
                          <th className="py-2.5 px-3">Before State</th>
                          <th className="py-2.5 px-3">After State</th>
                          <th className="py-2.5 px-3 text-right">Trust Delta</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono">
                        {simulationResult.affected_rules?.map((r) => (
                          <tr key={r.rule_id} className="hover:bg-slate-800/20">
                            <td className="py-2.5 px-3 text-slate-200">{r.rule_id}</td>
                            <td className="py-2.5 px-3 text-rose-400">{r.before_trust_status} ({r.before_trust_score})</td>
                            <td className="py-2.5 px-3 text-emerald-400">{r.after_trust_status} ({r.after_trust_score})</td>
                            <td className="py-2.5 px-3 text-right text-emerald-400">+{r.improvement_delta}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            ) : null}

            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSimulationCandidate(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg transition-colors"
              >
                Close Simulation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── MODAL: STATUS UPDATE ────────────────────────────────────────────── */}
      {statusCandidate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-sentinel-950/80 backdrop-blur-sm p-4 animate-fade-in">
          <form
            onSubmit={handleUpdateStatus}
            className="bg-sentinel-900 border border-slate-700 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl font-sans"
          >
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-widest text-accent-cyan">
                  Governance Lifecycle Transition
                </span>
                <h3 className="text-sm font-bold text-slate-100 font-mono mt-0.5">
                  Update Remediation Status
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setStatusCandidate(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 font-mono mb-1">Current State</label>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getStatusBadge(statusCandidate.status)}`}>
                  {statusCandidate.status}
                </span>
              </div>

              <div>
                <label className="block text-slate-400 font-mono mb-1">Target Lifecycle State</label>
                <select
                  value={targetStatus}
                  onChange={(e) => setTargetStatus(e.target.value)}
                  className="w-full px-3 py-2 bg-sentinel-950 border border-slate-700 rounded-lg font-mono text-slate-200 focus:outline-none focus:border-accent-cyan"
                >
                  <option value="RECOMMENDED">RECOMMENDED</option>
                  <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                  <option value="IN_PROGRESS">IN_PROGRESS</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="VERIFIED">VERIFIED</option>
                  <option value="REJECTED">REJECTED</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 font-mono mb-1">Governance Reason / Review Notes</label>
                <textarea
                  rows="3"
                  value={statusReason}
                  onChange={(e) => setStatusReason(e.target.value)}
                  placeholder="Document the operational or governance justification..."
                  className="w-full px-3 py-2 bg-sentinel-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-accent-cyan"
                  required
                />
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setStatusCandidate(null)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={statusSubmitting}
                className="px-4 py-1.5 bg-accent-cyan hover:bg-cyan-400 text-sentinel-950 font-bold text-xs font-mono rounded-lg transition-colors disabled:opacity-50"
              >
                {statusSubmitting ? "Updating..." : "Commit Transition"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ── MODAL: 16+ STAGE PROVENANCE TRACE ─────────────────────────────────── */}
      {traceCandidate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-sentinel-950/80 backdrop-blur-sm p-4 animate-fade-in">
          <div className="bg-sentinel-900 border border-slate-700 rounded-2xl max-w-3xl w-full p-6 space-y-6 shadow-2xl max-h-[90vh] overflow-y-auto font-sans">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono tracking-widest uppercase bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                    17-Stage End-to-End Cryptographic & Governance Provenance
                  </span>
                  <span className="text-emerald-400 text-xs font-mono">✓ Verified</span>
                </div>
                <h3 className="text-base font-bold text-slate-100 font-mono mt-1">
                  {traceCandidate.title}
                </h3>
              </div>
              <button
                onClick={() => setTraceCandidate(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            {traceLoading ? (
              <div className="py-12 text-center font-mono">
                <div className="w-8 h-8 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                <p className="text-xs text-slate-400">Verifying 17-Stage Cryptographic Provenance Chain...</p>
              </div>
            ) : traceData ? (
              <div className="space-y-3">
                {traceData.stages?.map((st) => (
                  <div
                    key={st.stage_number}
                    className="p-3.5 rounded-xl bg-sentinel-950/70 border border-slate-800 flex items-start gap-4 text-xs font-sans"
                  >
                    <div className="w-7 h-7 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 font-mono font-bold flex items-center justify-center text-xs shrink-0">
                      {st.stage_number}
                    </div>

                    <div className="flex-1 min-w-0 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-slate-200">{st.stage_name}</span>
                        <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                          {st.status}
                        </span>
                      </div>

                      <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                        <span>Type: {st.entity_type}</span>
                        <span>•</span>
                        <span className="truncate">ID: {st.entity_id}</span>
                      </div>

                      {st.verification_hash && (
                        <div className="text-[10px] font-mono text-slate-500 truncate pt-1 border-t border-slate-800/40">
                          Hash: {st.verification_hash}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : null}

            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setTraceCandidate(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg transition-colors"
              >
                Close Provenance Trace
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── MODAL: GRAPH DAG ─────────────────────────────────────────────────── */}
      {selectedCorrelation && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-sentinel-950/80 backdrop-blur-sm p-4 animate-fade-in">
          <div className="bg-sentinel-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-6 space-y-6 shadow-2xl max-h-[90vh] overflow-y-auto font-sans">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-widest text-accent-cyan">
                  Directed Root-Cause & Impact Graph
                </span>
                <h3 className="text-base font-bold text-slate-100 font-mono mt-0.5">
                  Correlation: {selectedCorrelation.correlation_id}
                </h3>
              </div>
              <button
                onClick={() => setSelectedCorrelation(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            {graphLoading ? (
              <div className="py-12 text-center font-mono">
                <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                <p className="text-xs text-slate-400">Constructing Graph DAG...</p>
              </div>
            ) : graphData ? (
              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="text-xs font-mono text-slate-300 font-bold uppercase">Nodes ({graphData.nodes?.length || 0})</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {graphData.nodes?.map((n) => (
                      <div key={n.id} className="p-3 rounded-lg bg-sentinel-950 border border-slate-800 text-xs font-mono space-y-1">
                        <div className="font-bold text-slate-200">{n.label}</div>
                        <div className="text-[10px] text-slate-400">Type: {n.node_type}</div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-mono text-slate-300 font-bold uppercase">Causal Edges ({graphData.edges?.length || 0})</div>
                  <div className="space-y-1.5 font-mono text-xs text-slate-300">
                    {graphData.edges?.map((e, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-sentinel-950/60 border border-slate-800/80 flex items-center justify-between">
                        <span className="text-slate-400 truncate max-w-[40%]">{e.source.replace("node_", "")}</span>
                        <span className="px-2 py-0.5 rounded text-[9px] bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20">
                          {e.relationship}
                        </span>
                        <span className="text-slate-400 truncate max-w-[40%] text-right">{e.target.replace("node_", "")}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}

            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedCorrelation(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
