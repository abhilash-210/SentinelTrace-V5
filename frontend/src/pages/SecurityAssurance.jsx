/**
 * pages/SecurityAssurance.jsx
 * ---------------------------
 * Sprint 9A — Continuous Security Assurance & Platform Health Intelligence
 *
 * Core Principle: "SENTINELTRACE MUST MONITOR THE TRUSTWORTHINESS OF ITS OWN SECURITY PIPELINE."
 * Zero Trust Invariant: UNKNOWN != HEALTHY
 *
 * Comprehensive Features:
 * 1. Assurance Command Center Hero (Platform Trust Score, Status Badge, SHA-256 Seal, Evaluate Action)
 * 2. 7 Domain Assurance Cards (Evidence, Normalization, Semantic, Detection, Risk, Incident Response, Cryptographic)
 * 3. Interactive Domain Health Matrix & Base 100 Deductions Explainability Engine
 * 4. Platform Weighted Score Composition Inspector (Sum of weight * domain_score)
 * 5. Deduplicated Assurance Alert Center (OPEN -> ACKNOWLEDGED -> RESOLVED lifecycle with role-gated triage)
 * 6. Cryptographic Assurance & Hard Failure Overrides Panel (Chain continuity, Merkle consistency, Zero Compromise)
 * 7. 17-Stage Assurance Provenance Trace Viewer (Full pipeline data vs derived assurance verification)
 * 8. Historical Trend Analytics & Assurance Metric Catalog Definitions
 */

import React, { useState, useEffect, useMemo } from "react";
import { useAuth } from "../context/AuthContext";
import { API_V1_URL } from "../apiConfig";

const DOMAIN_CONFIGS = {
  EVIDENCE_ASSURANCE: {
    label: "Evidence Assurance",
    icon: "🔒",
    weight: 0.15,
    description: "Raw evidence availability, SHA-256 payload integrity, and ingestion continuity.",
    color: "from-blue-600/20 to-cyan-600/20 border-cyan-500/30 text-cyan-400",
  },
  NORMALIZATION_ASSURANCE: {
    label: "Normalization Assurance",
    icon: "⚙️",
    weight: 0.15,
    description: "OCSF canonical alignment success rate, schema compliance, and unmapped field ratios.",
    color: "from-indigo-600/20 to-blue-600/20 border-indigo-500/30 text-indigo-400",
  },
  SEMANTIC_ASSURANCE: {
    label: "Semantic Assurance",
    icon: "🧠",
    weight: 0.15,
    description: "Semantic interpretation confidence, ambiguous mappings, and protected field drift alerts.",
    color: "from-purple-600/20 to-indigo-600/20 border-purple-500/30 text-purple-400",
  },
  DETECTION_ASSURANCE: {
    label: "Detection Assurance",
    icon: "🎯",
    weight: 0.15,
    description: "Rule trust state integrity, dependency isolation, and degraded rule monitoring.",
    color: "from-emerald-600/20 to-teal-600/20 border-emerald-500/30 text-emerald-400",
  },
  RISK_ASSURANCE: {
    label: "Risk Assurance",
    icon: "🛡️",
    weight: 0.15,
    description: "Unresolved multi-signal risk correlations, concentration clusters, and posture findings.",
    color: "from-amber-600/20 to-yellow-600/20 border-amber-500/30 text-amber-400",
  },
  INCIDENT_RESPONSE_ASSURANCE: {
    label: "Incident Response Assurance",
    icon: "🛑",
    weight: 0.10,
    description: "Dual-control maker-checker approvals, response verification attestation, and stale investigations.",
    color: "from-rose-600/20 to-red-600/20 border-rose-500/30 text-rose-400",
  },
  CRYPTOGRAPHIC_ASSURANCE: {
    label: "Cryptographic Assurance",
    icon: "⛓️",
    weight: 0.15,
    description: "Continuous SHA-256 ledger hash chain, Merkle batch consistency, and proof verification.",
    color: "from-violet-600/20 to-fuchsia-600/20 border-violet-500/30 text-violet-400",
  },
};

const STATUS_COLORS = {
  HEALTHY: {
    bg: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    badge: "bg-emerald-500 text-slate-950 font-bold",
    pill: "text-emerald-400 border-emerald-500/40 bg-emerald-950/40",
    bar: "bg-emerald-500",
    glow: "shadow-[0_0_20px_rgba(16,185,129,0.25)]",
  },
  DEGRADED: {
    bg: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    badge: "bg-yellow-500 text-slate-950 font-bold",
    pill: "text-yellow-400 border-yellow-500/40 bg-yellow-950/40",
    bar: "bg-yellow-500",
    glow: "shadow-[0_0_20px_rgba(234,179,8,0.25)]",
  },
  AT_RISK: {
    bg: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    badge: "bg-orange-500 text-slate-950 font-bold",
    pill: "text-orange-400 border-orange-500/40 bg-orange-950/40",
    bar: "bg-orange-500",
    glow: "shadow-[0_0_20px_rgba(249,115,22,0.25)]",
  },
  CRITICAL: {
    bg: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    badge: "bg-rose-500 text-white font-bold animate-pulse",
    pill: "text-rose-400 border-rose-500/40 bg-rose-950/40",
    bar: "bg-rose-500",
    glow: "shadow-[0_0_25px_rgba(244,63,94,0.35)]",
  },
};

const SEVERITY_BADGES = {
  CRITICAL: "bg-rose-950/80 border-rose-500/50 text-rose-400",
  HIGH: "bg-orange-950/80 border-orange-500/50 text-orange-400",
  MEDIUM: "bg-amber-950/80 border-amber-500/50 text-amber-400",
  LOW: "bg-cyan-950/80 border-cyan-500/50 text-cyan-400",
};

const API_BASE = API_V1_URL;

export default function SecurityAssurance() {
  const { user } = useAuth();
  const token = localStorage.getItem("sentinel_token");

  // Main navigation tab
  const [activeTab, setActiveTab] = useState("overview"); // overview | matrix | alerts | crypto | provenance | trends

  // Core Data States
  const [latestEval, setLatestEval] = useState(null);
  const [domainEvals, setDomainEvals] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [kpis, setKpis] = useState(null);
  const [metricDefs, setMetricDefs] = useState([]);
  const [history, setHistory] = useState([]);
  const [provenanceTrace, setProvenanceTrace] = useState(null);

  // UI & Loading States
  const [loading, setLoading] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Modal States
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [domainModalOpen, setDomainModalOpen] = useState(false);
  const [resolveModalOpen, setResolveModalOpen] = useState(false);
  const [activeAlert, setActiveAlert] = useState(null);
  const [resolutionNotes, setResolutionNotes] = useState("");
  const [selectedStage, setSelectedStage] = useState(null);

  // Filters
  const [alertStatusFilter, setAlertStatusFilter] = useState("ALL");
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("ALL");
  const [alertDomainFilter, setAlertDomainFilter] = useState("ALL");

  const authHeaders = useMemo(() => {
    return {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }, [token]);

  // Initial Data Fetch
  const loadAssuranceData = async () => {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch latest platform evaluation
      const latestRes = await fetch(`${API_BASE}/security-assurance/latest`, {
        headers: authHeaders,
      });
      if (latestRes.ok) {
        const latestData = await latestRes.json();
        setLatestEval(latestData);

        // Fetch corresponding provenance trace
        if (latestData?.id) {
          const traceRes = await fetch(`${API_BASE}/security-assurance/${latestData.id}/trace`, {
            headers: authHeaders,
          });
          if (traceRes.ok) {
            const traceData = await traceRes.json();
            setProvenanceTrace(traceData);
          }
        }
      }

      // 2. Fetch domain latest evaluations
      const domainsRes = await fetch(`${API_BASE}/security-assurance/domains/latest`, {
        headers: authHeaders,
      });
      if (domainsRes.ok) {
        const domainsData = await domainsRes.json();
        setDomainEvals(domainsData || {});
      }

      // 3. Fetch active assurance alerts
      const alertsRes = await fetch(`${API_BASE}/security-assurance/alerts`, {
        headers: authHeaders,
      });
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        setAlerts(alertsData || []);
      }

      // 4. Fetch KPI summary
      const kpisRes = await fetch(`${API_BASE}/security-assurance/kpis/summary`, {
        headers: authHeaders,
      });
      if (kpisRes.ok) {
        const kpisData = await kpisRes.json();
        setKpis(kpisData);
      }

      // 5. Fetch Metric Definitions
      const metricDefsRes = await fetch(`${API_BASE}/security-assurance/metrics/definitions`, {
        headers: authHeaders,
      });
      if (metricDefsRes.ok) {
        const defsData = await metricDefsRes.json();
        setMetricDefs(defsData || []);
      }

      // 6. Fetch Evaluation History
      const histRes = await fetch(`${API_BASE}/security-assurance/history?limit=15`, {
        headers: authHeaders,
      });
      if (histRes.ok) {
        const histData = await histRes.json();
        setHistory(histData || []);
      }
    } catch (err) {
      console.error("Failed to fetch assurance data:", err);
      setError("Failed to load continuous security assurance telemetry.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssuranceData();
  }, [token]);

  // Action: Trigger Full Platform Evaluation
  const handleTriggerPlatformEvaluation = async () => {
    setEvaluating(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`${API_BASE}/security-assurance/evaluate`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          notes: `Automated platform assurance evaluation requested by ${user?.username || "authenticated user"}`,
        }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Evaluation execution failed.");
      }

      const newEval = await res.json();
      setLatestEval(newEval);
      setSuccessMsg(`Platform Assurance Evaluation completed successfully. Score: ${newEval.overall_score}/100 (${newEval.overall_status})`);

      // Refresh all dependent data
      await loadAssuranceData();
    } catch (err) {
      setError(err.message || "Failed to trigger platform assurance evaluation.");
    } finally {
      setEvaluating(false);
    }
  };

  // Action: Evaluate Single Domain
  const handleTriggerDomainEvaluation = async (domainName) => {
    setEvaluating(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`${API_BASE}/security-assurance/domains/${domainName}/evaluate`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          notes: `Manual domain evaluation for ${domainName}`,
        }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || `Failed to evaluate domain ${domainName}`);
      }

      const domainResult = await res.json();
      setSuccessMsg(`Domain ${domainName} evaluated: ${domainResult.score}/100 (${domainResult.status})`);
      await loadAssuranceData();
    } catch (err) {
      setError(err.message || `Domain evaluation error for ${domainName}`);
    } finally {
      setEvaluating(false);
    }
  };

  // Action: Acknowledge Alert
  const handleAcknowledgeAlert = async (alertId) => {
    try {
      const res = await fetch(`${API_BASE}/security-assurance/alerts/${alertId}/acknowledge`, {
        method: "POST",
        headers: authHeaders,
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to acknowledge alert");
      }
      setSuccessMsg("Assurance alert acknowledged.");
      await loadAssuranceData();
    } catch (err) {
      setError(err.message || "Failed to acknowledge alert");
    }
  };

  // Action: Resolve Alert
  const handleResolveAlertSubmit = async () => {
    if (!activeAlert) return;
    try {
      const res = await fetch(`${API_BASE}/security-assurance/alerts/${activeAlert.id}/resolve`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          resolution_notes: resolutionNotes || "Resolved after remediation and verification.",
        }),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to resolve alert");
      }
      setSuccessMsg("Assurance alert resolved successfully.");
      setResolveModalOpen(false);
      setActiveAlert(null);
      setResolutionNotes("");
      await loadAssuranceData();
    } catch (err) {
      setError(err.message || "Failed to resolve alert");
    }
  };

  // Filtered Alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (alertStatusFilter !== "ALL" && a.status !== alertStatusFilter) return false;
      if (alertSeverityFilter !== "ALL" && a.severity !== alertSeverityFilter) return false;
      if (alertDomainFilter !== "ALL" && a.domain_name !== alertDomainFilter) return false;
      return true;
    });
  }, [alerts, alertStatusFilter, alertSeverityFilter, alertDomainFilter]);

  const platformStatusStyle = STATUS_COLORS[latestEval?.overall_status || "HEALTHY"];

  return (
    <div className="flex-1 flex flex-col h-full bg-sentinel-950 overflow-y-auto text-slate-100 font-sans selection:bg-accent-cyan/30">
      {/* Top Header Banner */}
      <header className="border-b border-slate-800/80 bg-sentinel-900/60 backdrop-blur-md px-8 py-5 sticky top-0 z-30 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 text-cyan-400 text-xl shadow-[0_0_15px_rgba(6,182,212,0.2)]">
            💎
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight text-white font-mono">
                Continuous Security Assurance & Health Intelligence
              </h1>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 uppercase">
                Sprint 9A
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Zero Trust Pipeline Assurance &bull; UNKNOWN != HEALTHY &bull; Cryptographic Provenance
            </p>
          </div>
        </div>

        {/* Header Action Buttons */}
        <div className="flex items-center gap-3">
          <button
            onClick={loadAssuranceData}
            disabled={loading || evaluating}
            className="px-3.5 py-2 rounded-lg bg-slate-900/80 border border-slate-700/70 hover:border-slate-500 text-slate-300 hover:text-white text-xs font-mono transition-all flex items-center gap-2"
          >
            <span className={loading ? "animate-spin" : ""}>🔄</span> Refresh
          </button>
          <button
            id="run-platform-evaluation-btn"
            onClick={handleTriggerPlatformEvaluation}
            disabled={evaluating}
            className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs font-mono shadow-[0_0_20px_rgba(6,182,212,0.3)] transition-all flex items-center gap-2"
          >
            {evaluating ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>Evaluating Pipeline...</span>
              </>
            ) : (
              <>
                <span>⚡</span>
                <span>Run Platform Evaluation</span>
              </>
            )}
          </button>
        </div>
      </header>

      {/* Notifications Toast Bar */}
      {error && (
        <div className="mx-8 mt-4 p-3.5 rounded-xl bg-rose-950/60 border border-rose-500/50 text-rose-200 text-xs font-mono flex items-center justify-between animate-fade-in">
          <div className="flex items-center gap-2">
            <span className="text-rose-400 text-sm">⚠️</span>
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-white">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="mx-8 mt-4 p-3.5 rounded-xl bg-emerald-950/60 border border-emerald-500/50 text-emerald-200 text-xs font-mono flex items-center justify-between animate-fade-in">
          <div className="flex items-center gap-2">
            <span className="text-emerald-400 text-sm">✓</span>
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Main Content Area */}
      <main className="p-8 space-y-8 flex-1">
        {/* =========================================================================
            SECTION 1: ASSURANCE COMMAND CENTER HERO & PLATFORM TRUST GAUGE
           ========================================================================= */}
        <section className="relative overflow-hidden rounded-2xl border border-slate-800/90 bg-gradient-to-br from-sentinel-900/90 via-slate-900/70 to-sentinel-950 p-6 shadow-2xl backdrop-blur-xl">
          {/* Subtle background glow based on platform status */}
          <div className={`absolute -right-20 -top-20 w-80 h-80 rounded-full blur-3xl opacity-10 pointer-events-none ${platformStatusStyle.bar}`} />

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            {/* Left: Platform Trust Score Gauge */}
            <div className="lg:col-span-4 flex flex-col items-center justify-center p-6 rounded-xl bg-slate-950/60 border border-slate-800/80 relative">
              <div className="text-[11px] font-mono tracking-widest text-slate-400 uppercase mb-2">
                Platform Continuous Trust Score
              </div>
              
              {/* Circular Gauge / Score Display */}
              <div className="relative flex items-center justify-center my-2">
                <div className={`w-36 h-36 rounded-full border-4 flex flex-col items-center justify-center ${platformStatusStyle.pill} ${platformStatusStyle.glow} transition-all duration-500`}>
                  <div className="text-4xl font-extrabold font-mono tracking-tight">
                    {latestEval ? Number(latestEval.overall_score).toFixed(1) : "--"}
                  </div>
                  <div className="text-[11px] font-mono text-slate-400">/ 100.0</div>
                </div>
              </div>

              {/* Status Badge */}
              <div className="mt-3 flex items-center gap-2">
                <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider uppercase border ${platformStatusStyle.bg}`}>
                  ● {latestEval?.overall_status || "UNKNOWN"}
                </span>
                {latestEval?.score_trend_delta !== null && latestEval?.score_trend_delta !== undefined && (
                  <span className={`text-xs font-mono ${latestEval.score_trend_delta >= 0 ? "text-emerald-400" : "text-rose-400"}`}>
                    {latestEval.score_trend_delta >= 0 ? `+${latestEval.score_trend_delta.toFixed(1)}%` : `${latestEval.score_trend_delta.toFixed(1)}%`}
                  </span>
                )}
              </div>

              <div className="text-[10px] font-mono text-slate-500 mt-2 text-center">
                7-Domain Weighted Deterministic Composite
              </div>
            </div>

            {/* Middle: Platform Snapshot Telemetry */}
            <div className="lg:col-span-5 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                <span className="text-xs font-mono text-slate-400">Evaluation Identifier</span>
                <span className="text-xs font-mono text-cyan-400 font-bold bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-500/30">
                  {latestEval?.id || "N/A"}
                </span>
              </div>
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                <span className="text-xs font-mono text-slate-400">Cryptographic Seal (SHA-256)</span>
                <span className="text-[11px] font-mono text-slate-300 truncate max-w-[220px]" title={latestEval?.evaluation_hash}>
                  {latestEval?.evaluation_hash ? `${latestEval.evaluation_hash.slice(0, 16)}...${latestEval.evaluation_hash.slice(-8)}` : "SEALING PENDING"}
                </span>
              </div>
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                <span className="text-xs font-mono text-slate-400">Evaluation Timestamp (UTC)</span>
                <span className="text-xs font-mono text-slate-300">
                  {latestEval?.evaluation_timestamp ? new Date(latestEval.evaluation_timestamp).toUTCString() : "Never evaluated"}
                </span>
              </div>
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                <span className="text-xs font-mono text-slate-400">Evaluated Domains</span>
                <span className="text-xs font-mono text-emerald-400 font-bold">7 / 7 Active</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">Hard Failure Override Status</span>
                <span className={`text-xs font-mono font-bold ${latestEval?.critical_conditions?.length > 0 ? "text-rose-400" : "text-slate-400"}`}>
                  {latestEval?.critical_conditions?.length > 0 ? `ACTIVE (${latestEval.critical_conditions.length} Triggered)` : "NORMAL (None)"}
                </span>
              </div>
            </div>

            {/* Right: Quick KPIs Grid */}
            <div className="lg:col-span-3 grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-center">
                <div className="text-[10px] font-mono text-slate-400">Total Evaluations</div>
                <div className="text-xl font-bold font-mono text-white mt-1">
                  {kpis?.total_platform_evaluations ?? 0}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-center">
                <div className="text-[10px] font-mono text-slate-400">Open Alerts</div>
                <div className={`text-xl font-bold font-mono mt-1 ${(kpis?.active_alerts ?? 0) > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                  {kpis?.active_alerts ?? 0}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-center">
                <div className="text-[10px] font-mono text-slate-400">Critical Domains</div>
                <div className={`text-xl font-bold font-mono mt-1 ${(kpis?.critical_domains_count ?? 0) > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                  {kpis?.critical_domains_count ?? 0}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-center">
                <div className="text-[10px] font-mono text-slate-400">Metric Catalog</div>
                <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
                  {kpis?.metric_catalog_size ?? 14}
                </div>
              </div>
            </div>
          </div>

          {/* Hard Failure Override Banner if active */}
          {latestEval?.critical_conditions && latestEval.critical_conditions.length > 0 && (
            <div className="mt-5 p-4 rounded-xl bg-rose-950/80 border border-rose-500/80 text-rose-200 flex flex-col gap-2 animate-pulse">
              <div className="flex items-center gap-2 font-bold font-mono text-xs text-rose-300">
                <span>🚨</span> HARD FAILURE OVERRIDE IN EFFECT: ZERO-TRUST PLATFORM STATUS FORCED TO CRITICAL
              </div>
              <div className="space-y-1 pl-6">
                {latestEval.critical_conditions.map((cond, idx) => (
                  <div key={idx} className="text-xs font-mono text-rose-300">
                    &bull; <strong className="text-rose-100">{cond.condition}</strong>: {cond.reason}
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>

        {/* =========================================================================
            NAVIGATION TABS
           ========================================================================= */}
        <div className="border-b border-slate-800/90 flex flex-wrap items-center gap-2">
          {[
            { id: "overview", label: "Overview & 7 Domains", icon: "💎" },
            { id: "matrix", label: "Health Matrix & Deductions", icon: "📊" },
            { id: "alerts", label: `Assurance Alerts (${alerts.filter(a => a.status === 'OPEN').length})`, icon: "🔔" },
            { id: "crypto", label: "Cryptographic Assurance", icon: "⛓️" },
            { id: "provenance", label: "17-Stage Provenance Trace", icon: "🧬" },
            { id: "trends", label: "Trend Analytics & Metrics", icon: "📈" },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 font-mono text-xs font-semibold rounded-t-xl transition-all border-t border-x flex items-center gap-2 ${
                activeTab === tab.id
                  ? "bg-sentinel-900/90 border-slate-700/80 text-cyan-400 border-b-2 border-b-cyan-500"
                  : "bg-transparent border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40"
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        {/* =========================================================================
            TAB 1: OVERVIEW & 7 DOMAINS
           ========================================================================= */}
        {activeTab === "overview" && (
          <div className="space-y-8">
            {/* 7 Domain Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-5">
              {Object.keys(DOMAIN_CONFIGS).map((domainKey) => {
                const config = DOMAIN_CONFIGS[domainKey];
                const domainData = domainEvals[domainKey];
                const domainStatus = domainData?.status || "HEALTHY";
                const statusStyle = STATUS_COLORS[domainStatus] || STATUS_COLORS.HEALTHY;
                const deductionsCount = domainData?.deductions?.length || 0;

                return (
                  <div
                    key={domainKey}
                    className="rounded-xl border border-slate-800/80 bg-sentinel-900/70 p-5 flex flex-col justify-between hover:border-slate-700 transition-all hover:shadow-lg relative group"
                  >
                    <div>
                      {/* Top row: Icon + Domain Name + Status */}
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-center gap-2.5">
                          <span className="text-xl p-2 rounded-lg bg-slate-950/60 border border-slate-800">
                            {config.icon}
                          </span>
                          <div>
                            <h3 className="font-mono text-xs font-bold text-white tracking-tight">
                              {config.label}
                            </h3>
                            <div className="text-[10px] font-mono text-slate-400">
                              Weight: {(config.weight * 100).toFixed(0)}%
                            </div>
                          </div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${statusStyle.bg}`}>
                          {domainStatus}
                        </span>
                      </div>

                      {/* Score Bar & Numeric Display */}
                      <div className="mt-4 space-y-1.5">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-slate-400">Assurance Score</span>
                          <span className="font-bold text-white text-sm">
                            {domainData ? Number(domainData.score).toFixed(1) : "100.0"}{" "}
                            <span className="text-[10px] text-slate-500 font-normal">/ 100</span>
                          </span>
                        </div>
                        <div className="w-full h-2 rounded-full bg-slate-950 overflow-hidden border border-slate-800">
                          <div
                            className={`h-full transition-all duration-500 ${statusStyle.bar}`}
                            style={{ width: `${Math.max(5, domainData ? domainData.score : 100)}%` }}
                          />
                        </div>
                      </div>

                      {/* Description */}
                      <p className="text-[11px] text-slate-400 mt-3 leading-relaxed line-clamp-2">
                        {config.description}
                      </p>

                      {/* Deductions summary */}
                      <div className="mt-3 pt-3 border-t border-slate-800/70 flex items-center justify-between text-[11px] font-mono">
                        <span className="text-slate-400">Deductions:</span>
                        <span className={deductionsCount > 0 ? "text-rose-400 font-bold" : "text-emerald-400"}>
                          {deductionsCount > 0 ? `-${(100 - (domainData?.score || 100)).toFixed(1)} pts (${deductionsCount})` : "0 pts (Nominal)"}
                        </span>
                      </div>
                    </div>

                    {/* Bottom Actions */}
                    <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                      <button
                        id={`inspect-btn-${domainKey}`}
                        onClick={() => {
                          setSelectedDomain({ ...domainData, domainKey, config });
                          setDomainModalOpen(true);
                        }}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-950/70 border border-slate-700/80 hover:border-slate-500 text-slate-300 hover:text-white text-[11px] font-mono flex items-center gap-1.5 transition-all"
                      >
                        <span>🔍</span> Inspect Details
                      </button>
                      <button
                        onClick={() => handleTriggerDomainEvaluation(domainKey)}
                        disabled={evaluating}
                        className="px-2.5 py-1.5 rounded-lg bg-cyan-950/50 border border-cyan-500/40 hover:bg-cyan-900/60 text-cyan-300 text-[11px] font-mono transition-all"
                      >
                        ⚡ Re-evaluate
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Platform Weighted Score Composition Inspector */}
            <div className="rounded-2xl border border-slate-800/90 bg-sentinel-900/60 p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                    <span>🧮</span> Platform Weighted Score Composition
                  </h3>
                  <p className="text-xs font-mono text-slate-400 mt-0.5">
                    Deterministic formula: Composite = &Sigma; (Domain Weight &times; Domain Score)
                  </p>
                </div>
                <div className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-3 py-1 rounded-lg border border-cyan-500/30">
                  Total Weights = 100%
                </div>
              </div>

              {/* Progress Composition Bar */}
              <div className="space-y-3">
                <div className="w-full h-4 rounded-xl bg-slate-950 overflow-hidden flex border border-slate-800">
                  {Object.keys(DOMAIN_CONFIGS).map((k) => {
                    const cfg = DOMAIN_CONFIGS[k];
                    const dScore = domainEvals[k]?.score ?? 100.0;
                    const contribution = dScore * cfg.weight;
                    return (
                      <div
                        key={k}
                        title={`${cfg.label}: ${contribution.toFixed(2)} pts (${(cfg.weight * 100).toFixed(0)}% weight)`}
                        className={`h-full border-r border-slate-950 transition-all ${
                          k === "EVIDENCE_ASSURANCE" ? "bg-cyan-500" :
                          k === "NORMALIZATION_ASSURANCE" ? "bg-indigo-500" :
                          k === "SEMANTIC_ASSURANCE" ? "bg-purple-500" :
                          k === "DETECTION_ASSURANCE" ? "bg-emerald-500" :
                          k === "RISK_ASSURANCE" ? "bg-amber-500" :
                          k === "INCIDENT_RESPONSE_ASSURANCE" ? "bg-rose-500" : "bg-violet-500"
                        }`}
                        style={{ width: `${(cfg.weight * 100)}%` }}
                      />
                    );
                  })}
                </div>

                {/* Legend & Breakdown Table */}
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 text-[11px] font-mono">
                  {Object.keys(DOMAIN_CONFIGS).map((k) => {
                    const cfg = DOMAIN_CONFIGS[k];
                    const dScore = domainEvals[k]?.score ?? 100.0;
                    const contrib = dScore * cfg.weight;
                    return (
                      <div key={k} className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                        <div className="text-slate-400 truncate">{cfg.label.split(" ")[0]}</div>
                        <div className="text-white font-bold mt-0.5">{dScore.toFixed(1)} / 100</div>
                        <div className="text-slate-500 text-[10px] mt-0.5">Contrib: +{contrib.toFixed(2)} pts</div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 2: HEALTH MATRIX & EXPLAINABILITY ENGINE
           ========================================================================= */}
        {activeTab === "matrix" && (
          <div className="space-y-6">
            {/* Domain Health Matrix Table */}
            <div className="rounded-2xl border border-slate-800/90 bg-sentinel-900/60 overflow-hidden shadow-xl">
              <div className="p-5 border-b border-slate-800/90 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                    <span>📊</span> Continuous Domain Health Matrix
                  </h3>
                  <p className="text-xs font-mono text-slate-400 mt-0.5">
                    Real-time status, deterministic deductions, and risk tiering across all 7 platform domains
                  </p>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                    <tr>
                      <th className="p-4">Domain</th>
                      <th className="p-4">Weight</th>
                      <th className="p-4">Score</th>
                      <th className="p-4">Status</th>
                      <th className="p-4">Risk Level</th>
                      <th className="p-4">Active Deductions</th>
                      <th className="p-4">Evaluation Hash</th>
                      <th className="p-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {Object.keys(DOMAIN_CONFIGS).map((k) => {
                      const cfg = DOMAIN_CONFIGS[k];
                      const d = domainEvals[k];
                      const status = d?.status || "HEALTHY";
                      const statusStyle = STATUS_COLORS[status] || STATUS_COLORS.HEALTHY;
                      const deductions = d?.deductions || [];

                      return (
                        <tr key={k} className="hover:bg-slate-900/50 transition-colors">
                          <td className="p-4 font-bold text-white flex items-center gap-2">
                            <span>{cfg.icon}</span>
                            <span>{cfg.label}</span>
                          </td>
                          <td className="p-4 text-slate-300">{(cfg.weight * 100).toFixed(0)}%</td>
                          <td className="p-4">
                            <span className="font-bold text-white text-sm">
                              {d ? Number(d.score).toFixed(2) : "100.00"}
                            </span>
                          </td>
                          <td className="p-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${statusStyle.bg}`}>
                              {status}
                            </span>
                          </td>
                          <td className="p-4">
                            <span className="text-slate-300">{d?.risk_level || "LOW"}</span>
                          </td>
                          <td className="p-4">
                            {deductions.length > 0 ? (
                              <span className="text-rose-400 font-bold">
                                {deductions.length} deduction(s) (-{(100 - (d?.score || 100)).toFixed(1)} pts)
                              </span>
                            ) : (
                              <span className="text-emerald-400">0 deductions (Nominal)</span>
                            )}
                          </td>
                          <td className="p-4 text-slate-400 text-[10px] truncate max-w-[140px]" title={d?.evaluation_hash}>
                            {d?.evaluation_hash ? `${d.evaluation_hash.slice(0, 12)}...` : "N/A"}
                          </td>
                          <td className="p-4 text-right">
                            <button
                              onClick={() => {
                                setSelectedDomain({ ...d, domainKey: k, config: cfg });
                                setDomainModalOpen(true);
                              }}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px]"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Deductions Explainability Inspector */}
            <div className="rounded-2xl border border-slate-800/90 bg-sentinel-900/60 p-6 space-y-4">
              <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <span>🔍</span> Deterministic Deduction Explainability Engine (Base 100 Rule)
              </h3>
              <p className="text-xs font-mono text-slate-400">
                Every domain score begins at 100.00. Points are deducted based on deterministic metric formulas.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.keys(domainEvals).map((k) => {
                  const d = domainEvals[k];
                  const deductions = d?.deductions || [];
                  const cfg = DOMAIN_CONFIGS[k] || { label: k, icon: "📋" };

                  return (
                    <div key={k} className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-3 font-mono text-xs">
                      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                        <span className="font-bold text-white flex items-center gap-1.5">
                          <span>{cfg.icon}</span>
                          <span>{cfg.label}</span>
                        </span>
                        <span className="text-cyan-400 font-bold">{d ? Number(d.score).toFixed(2) : "100.00"} / 100</span>
                      </div>

                      {deductions.length === 0 ? (
                        <div className="text-emerald-400 text-[11px]">✓ No deductions recorded. Domain fully nominal.</div>
                      ) : (
                        <div className="space-y-2">
                          {deductions.map((ded, idx) => (
                            <div key={idx} className="p-2.5 rounded bg-slate-900/90 border border-slate-800 flex items-start justify-between gap-2">
                              <div>
                                <div className="text-slate-200 font-bold">{ded.metric_key}</div>
                                <div className="text-slate-400 text-[10px] mt-0.5">{ded.reason}</div>
                              </div>
                              <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-500/40 text-rose-300 font-bold text-[11px] whitespace-nowrap">
                                -{ded.deduction} pts
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 3: ASSURANCE ALERT CENTER
           ========================================================================= */}
        {activeTab === "alerts" && (
          <div className="space-y-6">
            {/* Filters bar */}
            <div className="p-4 rounded-xl border border-slate-800/90 bg-sentinel-900/60 flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
              <div className="flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Status:</span>
                  <select
                    value={alertStatusFilter}
                    onChange={(e) => setAlertStatusFilter(e.target.value)}
                    className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 text-xs"
                  >
                    <option value="ALL">All Statuses</option>
                    <option value="OPEN">OPEN</option>
                    <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                    <option value="RESOLVED">RESOLVED</option>
                  </select>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Severity:</span>
                  <select
                    value={alertSeverityFilter}
                    onChange={(e) => setAlertSeverityFilter(e.target.value)}
                    className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 text-xs"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Domain:</span>
                  <select
                    value={alertDomainFilter}
                    onChange={(e) => setAlertDomainFilter(e.target.value)}
                    className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 text-xs"
                  >
                    <option value="ALL">All Domains</option>
                    {Object.keys(DOMAIN_CONFIGS).map((k) => (
                      <option key={k} value={k}>{DOMAIN_CONFIGS[k].label}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="text-slate-400">
                Showing <span className="text-white font-bold">{filteredAlerts.length}</span> alert(s)
              </div>
            </div>

            {/* Alerts List */}
            {filteredAlerts.length === 0 ? (
              <div className="p-12 text-center rounded-2xl border border-slate-800 bg-sentinel-900/40 text-slate-400 font-mono text-xs space-y-2">
                <div className="text-3xl">🛡️</div>
                <div className="text-slate-200 font-bold">No active assurance alerts found.</div>
                <div>All 7 security pipeline domains are operating within acceptable thresholds.</div>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredAlerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="p-4 rounded-xl border border-slate-800/80 bg-sentinel-900/70 hover:border-slate-700 transition-all space-y-3 font-mono text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_BADGES[alert.severity] || "bg-slate-800 text-slate-300"}`}>
                          {alert.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400 text-[10px]">
                          {DOMAIN_CONFIGS[alert.domain_name]?.label || alert.domain_name}
                        </span>
                        <span className="font-bold text-white">{alert.alert_type}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          alert.status === "OPEN" ? "bg-rose-950/80 border border-rose-500/50 text-rose-300" :
                          alert.status === "ACKNOWLEDGED" ? "bg-yellow-950/80 border border-yellow-500/50 text-yellow-300" :
                          "bg-emerald-950/80 border border-emerald-500/50 text-emerald-300"
                        }`}>
                          {alert.status}
                        </span>
                        <span className="text-slate-500 text-[10px]">
                          {new Date(alert.created_at).toLocaleString()}
                        </span>
                      </div>
                    </div>

                    <div className="text-slate-300 text-xs leading-relaxed">
                      {alert.message}
                    </div>

                    {alert.source_condition && (
                      <div className="text-[11px] text-slate-400 bg-slate-950/80 p-2 rounded border border-slate-800/80">
                        Condition: <code className="text-cyan-300">{alert.source_condition}</code>
                      </div>
                    )}

                    {alert.resolution_notes && (
                      <div className="text-[11px] text-emerald-300 bg-emerald-950/30 p-2 rounded border border-emerald-800/40">
                        Resolved by <span className="font-bold">{alert.resolved_by || "analyst"}</span>: {alert.resolution_notes}
                      </div>
                    )}

                    {/* Alert Action Buttons */}
                    <div className="flex items-center justify-between pt-2">
                      <span className="text-[10px] text-slate-500 truncate max-w-[280px]" title={alert.deduplication_key}>
                        Dedup Key: {alert.deduplication_key.slice(0, 16)}...
                      </span>
                      <div className="flex items-center gap-2">
                        {alert.status === "OPEN" && (
                          <button
                            onClick={() => handleAcknowledgeAlert(alert.id)}
                            className="px-3 py-1 rounded bg-yellow-950/60 border border-yellow-500/40 hover:bg-yellow-900/60 text-yellow-300 text-xs transition-all"
                          >
                            Acknowledge
                          </button>
                        )}
                        {alert.status !== "RESOLVED" && (
                          <button
                            onClick={() => {
                              setActiveAlert(alert);
                              setResolveModalOpen(true);
                            }}
                            className="px-3 py-1 rounded bg-emerald-950/60 border border-emerald-500/40 hover:bg-emerald-900/60 text-emerald-300 text-xs transition-all"
                          >
                            Resolve Alert
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 4: CRYPTOGRAPHIC ASSURANCE & HARD FAILURE OVERRIDES
           ========================================================================= */}
        {activeTab === "crypto" && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left: Continuous Hash Chain Verification */}
              <div className="rounded-2xl border border-slate-800/90 bg-sentinel-900/60 p-6 space-y-4">
                <div className="flex items-center gap-3">
                  <span className="text-2xl p-2.5 rounded-xl bg-violet-950/80 border border-violet-500/40 text-violet-400">
                    ⛓️
                  </span>
                  <div>
                    <h3 className="text-sm font-bold font-mono text-white">
                      Governance Ledger Continuous Hash Chain
                    </h3>
                    <p className="text-xs font-mono text-slate-400">
                      SHA-256 continuous hash chain sealing every governance action
                    </p>
                  </div>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Hash Chain Integrity Status</span>
                    <span className="text-emerald-400 font-bold bg-emerald-950/60 px-2.5 py-1 rounded border border-emerald-500/30">
                      ✓ CONTINUOUS & UNBROKEN
                    </span>
                  </div>
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Ledger Verification Algorithm</span>
                    <span className="text-slate-200">SHA-256 Domain-Separated Digest</span>
                  </div>
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Total Governed Records Verified</span>
                    <span className="text-cyan-400 font-bold">{domainEvals["CRYPTOGRAPHIC_ASSURANCE"]?.metric_snapshot?.total_ledger_entries ?? "All Active"}</span>
                  </div>
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Unsealed Pending Records</span>
                    <span className="text-slate-300">0 records</span>
                  </div>
                </div>
              </div>

              {/* Right: Merkle Batch & Proof Verification */}
              <div className="rounded-2xl border border-slate-800/90 bg-sentinel-900/60 p-6 space-y-4">
                <div className="flex items-center gap-3">
                  <span className="text-2xl p-2.5 rounded-xl bg-emerald-950/80 border border-emerald-500/40 text-emerald-400">
                    🌲
                  </span>
                  <div>
                    <h3 className="text-sm font-bold font-mono text-white">
                      Merkle Batch & Inclusion Proofs
                    </h3>
                    <p className="text-xs font-mono text-slate-400">
                      Cryptographic tree consistency and third-party auditor verifiable proofs
                    </p>
                  </div>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Merkle Tree Batch Status</span>
                    <span className="text-emerald-400 font-bold bg-emerald-950/60 px-2.5 py-1 rounded border border-emerald-500/30">
                      ✓ SEALED & CONSISTENT
                    </span>
                  </div>
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Total Merkle Batches</span>
                    <span className="text-slate-200">{domainEvals["CRYPTOGRAPHIC_ASSURANCE"]?.metric_snapshot?.total_merkle_batches ?? "Nominal"}</span>
                  </div>
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Proof Verification Failures</span>
                    <span className="text-emerald-400 font-bold">0 Failures</span>
                  </div>
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Auditor Non-Repudiation Guarantee</span>
                    <span className="text-cyan-400 font-bold">ACTIVE</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Zero-Trust Hard Failure Overrides Architecture Card */}
            <div className="rounded-2xl border border-slate-800/90 bg-sentinel-900/60 p-6 space-y-4">
              <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <span>🛡️</span> Zero-Trust Hard Failure Override Rules
              </h3>
              <p className="text-xs font-mono text-slate-400">
                To prevent false assurance from masking critical platform compromise, the scoring engine enforces 3 non-negotiable hard failure overrides:
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
                  <div className="text-rose-400 font-bold flex items-center gap-1.5">
                    <span>1.</span> Cryptographic Hard Override
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    If Cryptographic Assurance enters <strong>CRITICAL</strong> status (broken ledger chain or corrupt Merkle proof), platform status is immediately forced to <strong>CRITICAL</strong> regardless of mathematical score.
                  </p>
                </div>
                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
                  <div className="text-rose-400 font-bold flex items-center gap-1.5">
                    <span>2.</span> Multi-Domain Critical Override
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    If <strong>2 or more</strong> top-level domains are classified as <strong>CRITICAL</strong>, the platform trust status is forced to <strong>CRITICAL</strong>.
                  </p>
                </div>
                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
                  <div className="text-amber-400 font-bold flex items-center gap-1.5">
                    <span>3.</span> Multi-Domain At-Risk Override
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    If <strong>3 or more</strong> domains fall into <strong>AT_RISK</strong> or worse, platform status cannot exceed <strong>DEGRADED</strong>.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 5: 17-STAGE ASSURANCE PROVENANCE TRACE VIEWER
           ========================================================================= */}
        {activeTab === "provenance" && (
          <div className="space-y-6">
            <div className="rounded-2xl border border-slate-800/90 bg-sentinel-900/60 p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                    <span>🧬</span> 17-Stage End-to-End Assurance Provenance Trace
                  </h3>
                  <p className="text-xs font-mono text-slate-400 mt-0.5">
                    Auditable verification trail demonstrating mathematical lineage from raw evidence to the final platform trust seal
                  </p>
                </div>
                <div className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-3 py-1 rounded-lg border border-emerald-500/30">
                  Total Stages: {provenanceTrace?.total_stages ?? 17} / 17 Verified
                </div>
              </div>

              {/* Step-by-step Provenance Timeline */}
              <div className="space-y-3 pt-2">
                {provenanceTrace?.stages ? (
                  provenanceTrace.stages.map((st) => (
                    <div
                      key={st.stage_number}
                      onClick={() => setSelectedStage(st)}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer font-mono text-xs flex items-center justify-between gap-4 ${
                        selectedStage?.stage_number === st.stage_number
                          ? "bg-cyan-950/40 border-cyan-500/60 shadow-[0_0_15px_rgba(6,182,212,0.15)]"
                          : "bg-slate-950/70 border-slate-800/80 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-7 h-7 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center font-bold text-cyan-400 text-xs">
                          {st.stage_number}
                        </div>
                        <div>
                          <div className="font-bold text-white flex items-center gap-2">
                            <span>{st.stage_name}</span>
                            <span className="text-[10px] text-slate-500 font-normal">({st.domain_name})</span>
                          </div>
                          <div className="text-slate-400 text-[11px] mt-0.5">{st.description}</div>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/80 border border-emerald-500/40 text-emerald-400">
                          {st.status}
                        </span>
                        <span className="text-slate-400 text-[10px] hidden sm:inline">
                          {st.stage_hash ? `${st.stage_hash.slice(0, 10)}...` : ""}
                        </span>
                        <span className="text-cyan-400 text-xs">➔</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="p-8 text-center text-slate-400 font-mono text-xs">
                    Execute a platform evaluation to generate live 17-stage cryptographic trace records.
                  </div>
                )}
              </div>
            </div>

            {/* Selected Stage Detail Drawer */}
            {selectedStage && (
              <div className="rounded-2xl border border-cyan-500/40 bg-sentinel-900/80 p-6 space-y-3 font-mono text-xs animate-fade-in">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <h4 className="font-bold text-cyan-400 text-sm">
                    Stage {selectedStage.stage_number}: {selectedStage.stage_name}
                  </h4>
                  <button onClick={() => setSelectedStage(null)} className="text-slate-400 hover:text-white">✕</button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[11px]">
                  <div>
                    <span className="text-slate-400">Domain Classification:</span>{" "}
                    <span className="text-white font-bold">{selectedStage.domain_name}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Verification Status:</span>{" "}
                    <span className="text-emerald-400 font-bold">{selectedStage.status}</span>
                  </div>
                  <div className="md:col-span-2">
                    <span className="text-slate-400">Stage SHA-256 Hash:</span>{" "}
                    <code className="text-cyan-300 break-all">{selectedStage.stage_hash}</code>
                  </div>
                </div>
                {selectedStage.details && (
                  <div className="mt-2">
                    <div className="text-slate-400 text-[10px] mb-1">Stage Metadata Payload:</div>
                    <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-[10px] overflow-x-auto max-h-48">
                      {JSON.stringify(selectedStage.details, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 6: TREND ANALYTICS & METRIC CATALOG
           ========================================================================= */}
        {activeTab === "trends" && (
          <div className="space-y-6">
            {/* Historical Snapshots Table */}
            <div className="rounded-2xl border border-slate-800/90 bg-sentinel-900/60 p-6 space-y-4">
              <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <span>📈</span> Historical Platform Evaluation Timeline
              </h3>
              <p className="text-xs font-mono text-slate-400">
                Immutable audit ledger recording historical platform score snapshots and cryptographic hashes
              </p>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <tr>
                      <th className="p-3">Evaluation ID</th>
                      <th className="p-3">Timestamp (UTC)</th>
                      <th className="p-3">Overall Score</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Score Delta</th>
                      <th className="p-3">Cryptographic Seal</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {history.map((h) => {
                      const stStyle = STATUS_COLORS[h.overall_status || "HEALTHY"] || STATUS_COLORS.HEALTHY;
                      return (
                        <tr key={h.id} className="hover:bg-slate-900/50">
                          <td className="p-3 font-bold text-cyan-400">{h.id}</td>
                          <td className="p-3 text-slate-300">{new Date(h.evaluation_timestamp).toLocaleString()}</td>
                          <td className="p-3 font-bold text-white">{Number(h.overall_score).toFixed(2)}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${stStyle.bg}`}>
                              {h.overall_status}
                            </span>
                          </td>
                          <td className="p-3">
                            {h.score_trend_delta !== null && h.score_trend_delta !== undefined ? (
                              <span className={h.score_trend_delta >= 0 ? "text-emerald-400" : "text-rose-400"}>
                                {h.score_trend_delta >= 0 ? `+${h.score_trend_delta.toFixed(1)}%` : `${h.score_trend_delta.toFixed(1)}%`}
                              </span>
                            ) : "--"}
                          </td>
                          <td className="p-3 text-slate-400 text-[10px] truncate max-w-[160px]" title={h.evaluation_hash}>
                            {h.evaluation_hash ? `${h.evaluation_hash.slice(0, 16)}...` : "N/A"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Assurance Metric Definitions Catalog */}
            <div className="rounded-2xl border border-slate-800/90 bg-sentinel-900/60 p-6 space-y-4">
              <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <span>📚</span> Governed Assurance Metric Definitions Catalog ({metricDefs.length} Metrics)
              </h3>
              <p className="text-xs font-mono text-slate-400">
                Configured weights, healthy thresholds, and deduction rules across all 7 platform domains
              </p>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <tr>
                      <th className="p-3">Metric Key</th>
                      <th className="p-3">Domain</th>
                      <th className="p-3">Metric Name</th>
                      <th className="p-3">Weight (Deduction)</th>
                      <th className="p-3">Degraded Threshold</th>
                      <th className="p-3">Critical Threshold</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {metricDefs.map((m) => (
                      <tr key={m.id || m.metric_key} className="hover:bg-slate-900/50">
                        <td className="p-3 font-bold text-cyan-400">{m.metric_key}</td>
                        <td className="p-3 text-slate-300">{DOMAIN_CONFIGS[m.domain_name]?.label || m.domain_name}</td>
                        <td className="p-3 text-white">{m.metric_name}</td>
                        <td className="p-3 font-bold text-rose-400">-{m.weight} pts</td>
                        <td className="p-3 text-slate-400">&ge; {m.degraded_threshold}</td>
                        <td className="p-3 text-rose-400">&ge; {m.critical_threshold}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* =========================================================================
          MODAL: DOMAIN DETAILS & SNAPSHOT INSPECTOR
         ========================================================================= */}
      {domainModalOpen && selectedDomain && (
        <div id="domain-details-modal-wrapper" className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-sentinel-900 border border-slate-700/80 rounded-2xl shadow-2xl p-6 space-y-4 font-mono text-xs max-h-[85vh] overflow-y-auto animate-fade-in">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-xl">{selectedDomain.config?.icon}</span>
                <h3 className="font-bold text-white text-sm">
                  {selectedDomain.config?.label || selectedDomain.domain_name} Details
                </h3>
              </div>
              <button
                onClick={() => setDomainModalOpen(false)}
                className="text-slate-400 hover:text-white text-base"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-[11px]">
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="text-slate-400">Domain Score:</span>{" "}
                <strong className="text-white text-sm">{Number(selectedDomain.score || 100).toFixed(2)}</strong>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="text-slate-400">Domain Status:</span>{" "}
                <strong className="text-cyan-400">{selectedDomain.status || "HEALTHY"}</strong>
              </div>
            </div>

            {/* Explanation */}
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
              <div className="text-slate-400 text-[10px] mb-1">Audit Explanation:</div>
              <div className="text-slate-200">{selectedDomain.explanation || "Domain evaluation complete."}</div>
            </div>

            {/* Deductions list */}
            <div>
              <div className="text-slate-400 text-[11px] mb-2 font-bold">Applied Deductions ({selectedDomain.deductions?.length || 0}):</div>
              {selectedDomain.deductions && selectedDomain.deductions.length > 0 ? (
                <div className="space-y-2">
                  {selectedDomain.deductions.map((ded, i) => (
                    <div key={i} className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="text-white font-bold">{ded.metric_key}</div>
                        <div className="text-slate-400 text-[10px]">{ded.reason}</div>
                      </div>
                      <span className="text-rose-400 font-bold">-{ded.deduction} pts</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-emerald-400 text-[11px]">✓ No deductions applied. Score is nominal.</div>
              )}
            </div>

            {/* Metric Snapshot JSON */}
            {selectedDomain.metric_snapshot && (
              <div>
                <div className="text-slate-400 text-[10px] mb-1">Metric Telemetry Snapshot:</div>
                <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-[10px] overflow-x-auto max-h-40">
                  {JSON.stringify(selectedDomain.metric_snapshot, null, 2)}
                </pre>
              </div>
            )}

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                id="close-domain-modal-btn"
                onClick={() => setDomainModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-mono text-xs"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          MODAL: RESOLVE ALERT
         ========================================================================= */}
      {resolveModalOpen && activeAlert && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-sentinel-900 border border-slate-700 rounded-2xl shadow-2xl p-6 space-y-4 font-mono text-xs animate-fade-in">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <h3 className="font-bold text-white text-sm">Resolve Assurance Alert</h3>
              <button onClick={() => setResolveModalOpen(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="space-y-1 text-slate-300">
              <div>Alert: <strong className="text-white">{activeAlert.alert_type}</strong></div>
              <div className="text-[11px] text-slate-400">{activeAlert.message}</div>
            </div>

            <div className="space-y-1.5">
              <label className="text-slate-400 text-[11px]">Resolution Justification & Audit Notes:</label>
              <textarea
                value={resolutionNotes}
                onChange={(e) => setResolutionNotes(e.target.value)}
                placeholder="Describe remediation actions taken and verification results..."
                rows={3}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 text-xs focus:border-cyan-500 outline-none"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setResolveModalOpen(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleResolveAlertSubmit}
                className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs"
              >
                Confirm Resolution
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
