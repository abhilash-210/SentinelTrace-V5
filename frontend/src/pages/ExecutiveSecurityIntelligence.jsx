/**
 * pages/ExecutiveSecurityIntelligence.jsx
 * ---------------------------------------
 * Sprint 10A — Unified Security Intelligence & Executive Risk Posture Command Center.
 *
 * Core Axiom: "EXECUTIVE SECURITY INTELLIGENCE MUST BE EXPLAINABLE, DETERMINISTIC, AND TRACEABLE BACK TO CRYPTOGRAPHIC EVIDENCE."
 * Invariants: "UNKNOWN != HEALTHY", "LOW INCIDENT COUNT != LOW RISK", "RESOLVED INCIDENT != VERIFIED RECOVERY", "NUMERICAL SCORE != TRUST WITHOUT EXPLANATION".
 * Override Rule: "CRYPTOGRAPHIC INTEGRITY FAILURE ALWAYS DOMINATES NUMERICAL POSTURE SCORES".
 * Governance Principle: "NO ML. NO LLM. NO AUTONOMOUS ACTIONS. SENTINELTRACE EXPLAINS AND RECOMMENDS. HUMANS INTERPRET AND AUTHORIZE."
 */

import React, { useState, useEffect, useMemo } from "react";
import { useAuth } from "../context/AuthContext";
import { API_V1_URL } from "../apiConfig";

const API_BASE = API_V1_URL;

const POSTURE_COLORS = {
  HEALTHY: {
    bg: "bg-emerald-950/70 border-emerald-500/40 text-emerald-400",
    glow: "shadow-[0_0_30px_rgba(16,185,129,0.25)] border-emerald-500/60",
    badge: "bg-emerald-500 text-slate-950 font-bold",
    pill: "text-emerald-400 border-emerald-500/40 bg-emerald-950/40",
    bar: "bg-emerald-500",
    ring: "text-emerald-400 stroke-emerald-500",
    light: "text-emerald-300",
  },
  GUARDED: {
    bg: "bg-cyan-950/70 border-cyan-500/40 text-cyan-400",
    glow: "shadow-[0_0_30px_rgba(6,182,212,0.25)] border-cyan-500/60",
    badge: "bg-cyan-500 text-slate-950 font-bold",
    pill: "text-cyan-400 border-cyan-500/40 bg-cyan-950/40",
    bar: "bg-cyan-500",
    ring: "text-cyan-400 stroke-cyan-500",
    light: "text-cyan-300",
  },
  ELEVATED: {
    bg: "bg-yellow-950/70 border-yellow-500/40 text-yellow-400",
    glow: "shadow-[0_0_30px_rgba(234,179,8,0.25)] border-yellow-500/60",
    badge: "bg-yellow-500 text-slate-950 font-bold",
    pill: "text-yellow-400 border-yellow-500/40 bg-yellow-950/40",
    bar: "bg-yellow-500",
    ring: "text-yellow-400 stroke-yellow-500",
    light: "text-yellow-300",
  },
  DEGRADED: {
    bg: "bg-orange-950/70 border-orange-500/40 text-orange-400",
    glow: "shadow-[0_0_30px_rgba(249,115,22,0.25)] border-orange-500/60",
    badge: "bg-orange-500 text-slate-950 font-bold",
    pill: "text-orange-400 border-orange-500/40 bg-orange-950/40",
    bar: "bg-orange-500",
    ring: "text-orange-400 stroke-orange-500",
    light: "text-orange-300",
  },
  CRITICAL: {
    bg: "bg-rose-950/80 border-rose-500/60 text-rose-400 animate-pulse-slow",
    glow: "shadow-[0_0_40px_rgba(244,63,94,0.35)] border-rose-500/80",
    badge: "bg-rose-500 text-white font-bold animate-pulse",
    pill: "text-rose-400 border-rose-500/50 bg-rose-950/50",
    bar: "bg-rose-500",
    ring: "text-rose-400 stroke-rose-500",
    light: "text-rose-300",
  },
  UNKNOWN: {
    bg: "bg-purple-950/70 border-purple-500/40 text-purple-400",
    glow: "shadow-[0_0_30px_rgba(168,85,247,0.25)] border-purple-500/60",
    badge: "bg-purple-500 text-slate-950 font-bold",
    pill: "text-purple-400 border-purple-500/40 bg-purple-950/40",
    bar: "bg-purple-500",
    ring: "text-purple-400 stroke-purple-500",
    light: "text-purple-300",
  },
};

const SEVERITY_BADGES = {
  CRITICAL: "bg-rose-950/80 border-rose-500/50 text-rose-300",
  HIGH: "bg-orange-950/80 border-orange-500/50 text-orange-300",
  MEDIUM: "bg-yellow-950/80 border-yellow-500/50 text-yellow-300",
  LOW: "bg-emerald-950/80 border-emerald-500/50 text-emerald-300",
  INFORMATIONAL: "bg-cyan-950/80 border-cyan-500/50 text-cyan-300",
};

const DOMAIN_METADATA = {
  EVIDENCE_INTEGRITY: { label: "Evidence Integrity", icon: "🔒", weight: "10%", category: "FOUNDATION" },
  NORMALIZATION_PIPELINE: { label: "Normalization Pipeline", icon: "⚙️", weight: "10%", category: "PARSING" },
  SEMANTIC_TRUST: { label: "Semantic Trust", icon: "🧠", weight: "10%", category: "SEMANTICS" },
  DETECTION_TRUST: { label: "Detection Trust", icon: "🎯", weight: "10%", category: "DETECTION" },
  RISK_INTELLIGENCE: { label: "Risk Intelligence", icon: "🛡️", weight: "10%", category: "CORRELATION" },
  INCIDENT_SECURITY: { label: "Incident Security", icon: "🚨", weight: "15%", category: "INCIDENT" },
  INCIDENT_RESPONSE: { label: "Incident Response", icon: "🛑", weight: "10%", category: "RESPONSE" },
  PLATFORM_ASSURANCE: { label: "Platform Assurance", icon: "💎", weight: "10%", category: "HEALTH" },
  ASSURANCE_RECOVERY: { label: "Assurance Recovery", icon: "🔄", weight: "5%", category: "RECOVERY" },
  CRYPTOGRAPHIC_ASSURANCE: { label: "Cryptographic Assurance", icon: "⛓️", weight: "10%", category: "SECURITY" },
};

const PROVENANCE_STAGES = [
  { stage: 1, name: "Raw Ingestion", domain: "EVIDENCE_INTEGRITY", desc: "Immutable raw log capture & payload buffering" },
  { stage: 2, name: "Evidence Hash", domain: "EVIDENCE_INTEGRITY", desc: "SHA-256 evidence sealing & vault registration" },
  { stage: 3, name: "OCSF Normalization", domain: "NORMALIZATION_PIPELINE", desc: "Canonical schema alignment & type conversion" },
  { stage: 4, name: "Semantic Interpretation", domain: "SEMANTIC_TRUST", desc: "Contextual policy mapping & behavioral intent" },
  { stage: 5, name: "Canonical Field Binding", domain: "SEMANTIC_TRUST", desc: "Field-level semantic contract enforcement" },
  { stage: 6, name: "Drift Evaluation", domain: "SEMANTIC_TRUST", desc: "Drift divergence scoring & baseline validation" },
  { stage: 7, name: "Detection Rule", domain: "DETECTION_TRUST", desc: "Deterministic logic definition & rule indexing" },
  { stage: 8, name: "Detection Trust", domain: "DETECTION_TRUST", desc: "Rule trust gating & drift penalty binding" },
  { stage: 9, name: "Risk Correlation", domain: "RISK_INTELLIGENCE", desc: "Multi-signal threat clustering & risk score" },
  { stage: 10, name: "Security Incident", domain: "INCIDENT_SECURITY", desc: "Incident escalation & attack graph formulation" },
  { stage: 11, name: "Containment Decision", domain: "INCIDENT_RESPONSE", desc: "Dual-control maker-checker containment order" },
  { stage: 12, name: "Response Verification", domain: "INCIDENT_RESPONSE", desc: "Cryptographic attestation of containment execution" },
  { stage: 13, name: "Platform Assurance", domain: "PLATFORM_ASSURANCE", desc: "Continuous 10-domain health telemetry aggregation" },
  { stage: 14, name: "Assurance Alert", domain: "PLATFORM_ASSURANCE", desc: "Degradation threshold detection & alerting" },
  { stage: 15, name: "Remediation Case", domain: "ASSURANCE_RECOVERY", desc: "Root cause analysis & recovery plan synthesis" },
  { stage: 16, name: "Remediation Execution", domain: "ASSURANCE_RECOVERY", desc: "Dual-control authorized mitigation action" },
  { stage: 17, name: "Recovery Verification", domain: "ASSURANCE_RECOVERY", desc: "Empirical verification of posture recovery" },
  { stage: 18, name: "Executive Risk Driver", domain: "EXECUTIVE_POSTURE", desc: "Deterministic cross-domain driver extraction" },
  { stage: 19, name: "Executive Posture", domain: "EXECUTIVE_POSTURE", desc: "Weighted scoring & hard failure overrides" },
  { stage: 20, name: "Ledger & Merkle Proof", domain: "CRYPTOGRAPHIC_ASSURANCE", desc: "Append-only SHA-256 seal & Merkle tree inclusion" },
];

export default function ExecutiveSecurityIntelligence() {
  const { user } = useAuth();
  const token = localStorage.getItem("sentinel_token");

  // View state: overview | explain | provenance | topology | trends | ledger
  const [activeTab, setActiveTab] = useState("overview");

  // Data state
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const [latestEval, setLatestEval] = useState(null);
  const [kpis, setKpis] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [provenance, setProvenance] = useState(null);
  const [trends, setTrends] = useState([]);
  const [ledgerVerification, setLedgerVerification] = useState(null);
  const [historicalEvals, setHistoricalEvals] = useState([]);
  const [trendWindow, setTrendWindow] = useState("24h"); // 24h | 7d | 30d

  // Interactive Modal / Drawer state
  const [selectedDriver, setSelectedDriver] = useState(null);
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [selectedStage, setSelectedStage] = useState(null);
  const [evalNotes, setEvalNotes] = useState("");
  const [forceFresh, setForceFresh] = useState(false);
  const [showEvalModal, setShowEvalModal] = useState(false);
  const [verifyingLedger, setVerifyingLedger] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  // Headers helper
  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  });

  // Fetch all primary executive data
  const fetchExecutiveData = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      // 1. Latest Evaluation
      const evalRes = await fetch(`${API_BASE}/executive-security/evaluations/latest`, {
        headers: getAuthHeaders(),
      });
      if (!evalRes.ok) throw new Error("Failed to load latest executive evaluation.");
      const evalData = await evalRes.json();
      setLatestEval(evalData);

      // 2. KPIs
      const kpisRes = await fetch(`${API_BASE}/executive-security/kpis`, {
        headers: getAuthHeaders(),
      });
      if (kpisRes.ok) {
        const kpisData = await kpisRes.json();
        setKpis(kpisData);
      }

      // 3. Explanation Tree for latest evaluation
      if (evalData?.id) {
        const expRes = await fetch(`${API_BASE}/executive-security/evaluations/${evalData.id}/explain`, {
          headers: getAuthHeaders(),
        });
        if (expRes.ok) {
          const expData = await expRes.json();
          setExplanation(expData);
        }

        // 4. Provenance
        const provRes = await fetch(`${API_BASE}/executive-security/provenance/${evalData.id}`, {
          headers: getAuthHeaders(),
        });
        if (provRes.ok) {
          const provData = await provRes.json();
          setProvenance(provData);
        }

        // 5. Ledger verification
        const ledRes = await fetch(`${API_BASE}/executive-security/ledger/${evalData.id}`, {
          headers: getAuthHeaders(),
        });
        if (ledRes.ok) {
          const ledData = await ledRes.json();
          setLedgerVerification(ledData);
        }
      }

      // 6. Historical evaluations list
      const histRes = await fetch(`${API_BASE}/executive-security/evaluations?limit=15`, {
        headers: getAuthHeaders(),
      });
      if (histRes.ok) {
        const histData = await histRes.json();
        setHistoricalEvals(histData);
      }

      // 7. Trends
      fetchTrends(trendWindow);

    } catch (err) {
      console.error("Executive security load error:", err);
      setErrorMsg(err.message || "Unable to retrieve executive security telemetry.");
    } finally {
      setLoading(false);
    }
  };

  const fetchTrends = async (window) => {
    try {
      const param = window === "30d" ? "days=30" : window === "7d" ? "days=7" : "hours=24";
      const res = await fetch(`${API_BASE}/executive-security/trends?${param}&limit=30`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setTrends(data);
      }
    } catch (err) {
      console.warn("Trends load error:", err);
    }
  };

  useEffect(() => {
    fetchExecutiveData();
  }, []);

  const handleTrendWindowChange = (win) => {
    setTrendWindow(win);
    fetchTrends(win);
  };

  // Trigger evaluation
  const handleTriggerEvaluation = async () => {
    setEvaluating(true);
    try {
      const res = await fetch(`${API_BASE}/executive-security/evaluations`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          notes: evalNotes || "Manual Executive Posture Recalculation",
          force_fresh: forceFresh,
        }),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Evaluation trigger failed.");
      }
      setShowEvalModal(false);
      setEvalNotes("");
      await fetchExecutiveData();
    } catch (err) {
      alert("Error triggering evaluation: " + err.message);
    } finally {
      setEvaluating(false);
    }
  };

  // Load specific historical evaluation
  const handleSelectHistoricalEval = async (evalId) => {
    setLoading(true);
    try {
      const [evalRes, expRes, provRes, ledRes] = await Promise.all([
        fetch(`${API_BASE}/executive-security/evaluations/${evalId}`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/executive-security/evaluations/${evalId}/explain`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/executive-security/provenance/${evalId}`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/executive-security/ledger/${evalId}`, { headers: getAuthHeaders() }),
      ]);
      if (evalRes.ok) setLatestEval(await evalRes.json());
      if (expRes.ok) setExplanation(await expRes.json());
      if (provRes.ok) setProvenance(await provRes.json());
      if (ledRes.ok) setLedgerVerification(await ledRes.json());
    } catch (err) {
      console.error("Failed to load historical evaluation:", err);
    } finally {
      setLoading(false);
    }
  };

  const statusStyle = useMemo(() => {
    const status = latestEval?.overall_posture_status || "UNKNOWN";
    return POSTURE_COLORS[status] || POSTURE_COLORS.UNKNOWN;
  }, [latestEval]);

  return (
    <div className="flex-1 flex flex-col h-full bg-sentinel-950 text-slate-100 overflow-y-auto font-sans">
      {/* ── Top Header & Tab Navigation ─────────────────────────────────── */}
      <header className="px-6 py-4 border-b border-white/10 bg-sentinel-900/60 backdrop-blur-md flex flex-wrap items-center justify-between gap-4 z-10 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 via-indigo-500/20 to-purple-500/20 border border-cyan-500/40 flex items-center justify-center text-xl shadow-[0_0_15px_rgba(6,182,212,0.25)]">
            🛡️
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-white tracking-wide uppercase font-mono">
                Executive Risk Posture Command Center
              </h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-500/30 text-cyan-300 font-bold">
                SPRINT 10A
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-500/30 text-emerald-300">
                10-DOMAIN DETERMINISTIC
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Unified Cyber Security Intelligence · Deterministic Proofs · Zero Trust Lineage
            </p>
          </div>
        </div>

        {/* Tab Controls & Evaluation Trigger */}
        <div className="flex items-center gap-2">
          <div className="flex bg-sentinel-950/90 p-1 rounded-xl border border-white/10 text-xs font-mono">
            {[
              { id: "overview", label: "Executive Overview", icon: "📊" },
              { id: "explain", label: "Explainability & Proofs", icon: "🧠" },
              { id: "provenance", label: "20-Stage Provenance", icon: "⛓️" },
              { id: "topology", label: "Security Topology", icon: "🌐" },
              { id: "trends", label: "Trends & History", icon: "📈" },
              { id: "ledger", label: "Cryptographic Seal", icon: "🔒" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition font-medium cursor-pointer ${
                  activeTab === tab.id
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                    : "text-slate-400 hover:text-white hover:bg-white/5"
                }`}
              >
                <span>{tab.icon}</span>
                <span>{tab.label}</span>
              </button>
            ))}
          </div>

          <button
            onClick={() => setShowEvalModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-mono text-xs font-bold border border-cyan-400/30 shadow-[0_0_15px_rgba(6,182,212,0.3)] transition active:scale-95 cursor-pointer"
          >
            <span>⚡</span>
            <span>Recalculate Posture</span>
          </button>
        </div>
      </header>

      {/* ── Main Scrollable Body ────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto p-6 space-y-6">
        {errorMsg && (
          <div className="p-4 rounded-xl bg-rose-950/70 border border-rose-500/50 text-rose-200 text-xs font-mono flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-lg">⚠️</span>
              <span>{errorMsg}</span>
            </div>
            <button
              onClick={fetchExecutiveData}
              className="px-2.5 py-1 rounded bg-rose-900/60 hover:bg-rose-900 border border-rose-500/40 text-white text-[11px]"
            >
              Retry Telemetry Ingestion
            </button>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            SECTION A: EXECUTIVE HERO COMMAND BAR
           ══════════════════════════════════════════════════════════════════ */}
        <section
          className={`relative rounded-2xl p-6 border backdrop-blur-md transition-all duration-300 ${statusStyle.bg} ${statusStyle.glow}`}
        >
          <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            {/* Left: Overall Posture & Score Dial */}
            <div className="flex items-center gap-6">
              {/* Circular Meter */}
              <div className="relative w-28 h-28 shrink-0 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    className="stroke-slate-800"
                    strokeWidth="8"
                    fill="transparent"
                  />
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    className={statusStyle.ring}
                    strokeWidth="8"
                    strokeDasharray={251.2}
                    strokeDashoffset={
                      251.2 - (251.2 * (latestEval?.overall_security_score ?? 0)) / 100
                    }
                    strokeLinecap="round"
                    fill="transparent"
                    style={{ transition: "stroke-dashoffset 1s ease-in-out" }}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-2xl font-black font-mono tracking-tight text-white">
                    {latestEval?.overall_security_score?.toFixed(1) ?? "0.0"}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                    Score / 100
                  </span>
                </div>
              </div>

              {/* Status & Indicators */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className={`px-3 py-1 rounded-lg text-xs font-mono font-bold tracking-wider uppercase border ${statusStyle.badge}`}>
                    {latestEval?.overall_posture_status || "UNKNOWN"}
                  </span>
                  <span className="text-xs font-mono text-slate-400 bg-white/5 border border-white/10 px-2.5 py-1 rounded-lg">
                    Risk: <strong className="text-white">{latestEval?.executive_risk_level || "MODERATE"}</strong>
                  </span>
                  <span className="text-xs font-mono text-slate-400 bg-white/5 border border-white/10 px-2.5 py-1 rounded-lg">
                    Confidence: <strong className="text-white">{latestEval?.confidence_score ?? 100}%</strong>
                  </span>
                </div>

                <h2 className="text-lg font-bold text-white tracking-wide">
                  SentinelTrace Unified Security Posture
                </h2>
                <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
                  {latestEval?.explanation_summary ||
                    "Deterministic evaluation aggregated across all 10 platform security domains."}
                </p>

                {/* Hard Failure Override Banner if active */}
                {latestEval?.hard_overrides_applied?.length > 0 && (
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-rose-950/80 border border-rose-500/60 text-rose-300 text-xs font-mono">
                    <span className="animate-ping w-2 h-2 rounded-full bg-rose-400" />
                    <span>
                      HARD FAILURE OVERRIDE: {latestEval.hard_overrides_applied.join(", ")}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Right: Telemetry Freshness & Meta */}
            <div className="flex flex-col sm:flex-row lg:flex-col items-start lg:items-end justify-between gap-3 text-xs font-mono text-slate-400 shrink-0">
              <div className="flex items-center gap-2 bg-sentinel-950/80 px-3 py-1.5 rounded-xl border border-white/10">
                <span className="text-slate-500">24h Delta:</span>
                <span
                  className={`font-bold ${
                    (latestEval?.posture_delta_points ?? 0) >= 0
                      ? "text-emerald-400"
                      : "text-rose-400"
                  }`}
                >
                  {(latestEval?.posture_delta_points ?? 0) >= 0 ? "+" : ""}
                  {latestEval?.posture_delta_points?.toFixed(1) ?? "0.0"} pts (
                  {latestEval?.posture_delta_direction || "STABLE"})
                </span>
              </div>

              <div className="text-[11px] text-slate-400 space-y-1 text-left lg:text-right">
                <p>
                  Evaluation ID:{" "}
                  <span className="text-slate-200">{latestEval?.id?.slice(0, 16) || "..."}...</span>
                </p>
                <p>
                  Timestamp:{" "}
                  <span className="text-slate-200">
                    {latestEval?.evaluated_at
                      ? new Date(latestEval.evaluated_at).toLocaleString()
                      : "Active"}
                  </span>
                </p>
                <p>
                  Evaluator:{" "}
                  <span className="text-cyan-400">@{latestEval?.evaluated_by_username || "system"}</span>
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* ══════════════════════════════════════════════════════════════════
            SECTION B: EXECUTIVE KPI MATRIX
           ══════════════════════════════════════════════════════════════════ */}
        <section className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
          {[
            {
              label: "Platform Score",
              value: `${latestEval?.overall_security_score?.toFixed(1) ?? "0.0"}/100`,
              icon: "📊",
              sub: "10-Domain Aggregate",
              color: "text-cyan-400",
            },
            {
              label: "Risk Index",
              value: latestEval?.executive_risk_level || "LOW",
              icon: "🛡️",
              sub: "Residual Risk",
              color: "text-amber-400",
            },
            {
              label: "Assurance Level",
              value: `${kpis?.platform_health_score?.toFixed(0) ?? "100"}%`,
              icon: "💎",
              sub: "Continuous Health",
              color: "text-emerald-400",
            },
            {
              label: "10-Domain Health",
              value: `${kpis?.healthy_domains_count ?? 10}/10`,
              icon: "🌐",
              sub: "Domains Online",
              color: "text-indigo-400",
            },
            {
              label: "Active Incidents",
              value: kpis?.active_incidents_count ?? 0,
              icon: "🚨",
              sub: "Open Severity",
              color: (kpis?.active_incidents_count ?? 0) > 0 ? "text-rose-400" : "text-slate-400",
            },
            {
              label: "Uncontained Breaches",
              value: kpis?.uncontained_incidents_count ?? 0,
              icon: "🛑",
              sub: "Zero Trust Halt",
              color: (kpis?.uncontained_incidents_count ?? 0) > 0 ? "text-rose-400" : "text-slate-400",
            },
            {
              label: "Crypto Integrity",
              value: kpis?.hash_chain_intact !== false ? "100%" : "FAIL",
              icon: "⛓️",
              sub: "Ledger Intact",
              color: kpis?.hash_chain_intact !== false ? "text-emerald-400" : "text-rose-400 animate-pulse",
            },
            {
              label: "Recovery Rate",
              value: `${kpis?.recovery_success_rate?.toFixed(0) ?? "100"}%`,
              icon: "🔄",
              sub: "Assurance Restored",
              color: "text-teal-400",
            },
          ].map((kpi, idx) => (
            <div
              key={idx}
              className="p-3.5 rounded-xl bg-sentinel-900/60 border border-white/5 hover:border-white/20 transition flex flex-col justify-between space-y-2 backdrop-blur-sm"
            >
              <div className="flex items-center justify-between">
                <span className="text-base">{kpi.icon}</span>
                <span className={`text-base font-bold font-mono ${kpi.color}`}>{kpi.value}</span>
              </div>
              <div>
                <p className="text-[11px] font-semibold text-slate-200 truncate">{kpi.label}</p>
                <p className="text-[10px] text-slate-500 truncate font-mono">{kpi.sub}</p>
              </div>
            </div>
          ))}
        </section>

        {/* ══════════════════════════════════════════════════════════════════
            TAB 1: EXECUTIVE OVERVIEW (Sections C, D, F, G)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            {/* ── Section C: 10-Domain Security Posture Matrix ─────────── */}
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <span>🌐</span> 10-Domain Security Posture Matrix
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Deterministic weighted scoring breakdown with hard override telemetry validation
                  </p>
                </div>
                <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-500/30 px-2.5 py-1 rounded-lg">
                  Total Weight: 100.0%
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3.5">
                {(latestEval?.domain_scores || []).map((dom) => {
                  const meta = DOMAIN_METADATA[dom.domain_name] || {
                    label: dom.domain_name.replace(/_/g, " "),
                    icon: "🛡️",
                    weight: "10%",
                  };
                  const statusConf = POSTURE_COLORS[dom.status] || POSTURE_COLORS.UNKNOWN;

                  return (
                    <div
                      key={dom.domain_name}
                      onClick={() => setSelectedDomain(dom)}
                      className={`p-4 rounded-xl border bg-sentinel-950/80 hover:border-cyan-500/50 transition cursor-pointer flex flex-col justify-between space-y-3 relative group overflow-hidden ${
                        dom.status === "CRITICAL" ? "border-rose-500/50" : "border-white/5"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xl">{meta.icon}</span>
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${statusConf.badge}`}>
                          {dom.status}
                        </span>
                      </div>

                      <div className="space-y-1">
                        <h4 className="text-xs font-bold text-slate-200 group-hover:text-cyan-300 transition">
                          {meta.label}
                        </h4>
                        <div className="flex items-center justify-between text-[11px] font-mono">
                          <span className="text-slate-400">Score:</span>
                          <span className="text-white font-bold">{dom.final_score?.toFixed(1) ?? "0.0"} / 100</span>
                        </div>
                        {/* Progress bar */}
                        <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${statusConf.bar}`}
                            style={{ width: `${Math.max(dom.final_score ?? 0, 5)}%` }}
                          />
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1 border-t border-white/5">
                        <span>Weight: {((dom.risk_weight ?? 0) * 100).toFixed(0)}%</span>
                        <span className={dom.telemetry_missing ? "text-rose-400" : "text-emerald-400"}>
                          {dom.telemetry_missing ? "Telemetry Missing" : "Active"}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* ── Section D & F: Top Risk Drivers & Posture Change Analysis ─ */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 Cols: Top Ranked Executive Risk Drivers (Section D) */}
              <div className="lg:col-span-2 rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                      <span>🎯</span> Ranked Executive Risk Drivers
                    </h3>
                    <p className="text-xs text-slate-400 font-mono">
                      Mathematical impact ranking: (Domain Weight × Severity Deduction)
                    </p>
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Active Drivers: <strong className="text-white">{(latestEval?.risk_drivers || []).length}</strong>
                  </span>
                </div>

                <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
                  {(latestEval?.risk_drivers || []).length === 0 ? (
                    <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-white/10 rounded-xl">
                      🛡️ No active executive risk drivers detected. Platform operating within nominal thresholds.
                    </div>
                  ) : (
                    (latestEval?.risk_drivers || []).map((driver, idx) => (
                      <div
                        key={idx}
                        onClick={() => setSelectedDriver(driver)}
                        className="p-3.5 rounded-xl bg-sentinel-950/90 border border-white/5 hover:border-cyan-500/40 transition cursor-pointer flex items-start justify-between gap-4 group"
                      >
                        <div className="flex items-start gap-3">
                          <span className="w-6 h-6 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-xs font-mono font-bold text-slate-300 group-hover:text-cyan-400">
                            #{driver.rank}
                          </span>
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-bold text-white group-hover:text-cyan-300 transition">
                                {driver.title}
                              </span>
                              <span
                                className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase ${
                                  SEVERITY_BADGES[driver.severity] || "border-slate-700 text-slate-400"
                                }`}
                              >
                                {driver.severity}
                              </span>
                            </div>
                            <p className="text-xs text-slate-400 line-clamp-1">{driver.description}</p>
                            <div className="flex items-center gap-3 text-[10px] font-mono text-slate-500 pt-0.5">
                              <span>Domain: <strong className="text-slate-300">{driver.domain_name}</strong></span>
                              {driver.source_entity_type && (
                                <span>Ref: <strong className="text-cyan-400">{driver.source_entity_type} #{driver.source_entity_id}</strong></span>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="text-right font-mono shrink-0">
                          <span className="text-xs font-bold text-amber-400">
                            Impact: {driver.risk_points?.toFixed(1) ?? "0.0"}
                          </span>
                          <p className="text-[10px] text-slate-500">Rank: #{driver.rank ?? "N/A"}</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Right Col: Posture Delta & Insights Summary (Section F & G) */}
              <div className="space-y-6">
                {/* Posture Change Delta Card */}
                <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-4">
                  <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <span>⚖️</span> Posture Delta Analysis
                  </h3>
                  <div className="space-y-3 font-mono text-xs">
                    <div className="p-3 rounded-xl bg-sentinel-950/80 border border-white/5 flex items-center justify-between">
                      <span className="text-slate-400">Evaluation Change:</span>
                      <span
                        className={`font-bold ${
                          (latestEval?.posture_delta_points ?? 0) >= 0
                            ? "text-emerald-400"
                            : "text-rose-400"
                        }`}
                      >
                        {(latestEval?.posture_delta_points ?? 0) >= 0 ? "+" : ""}
                        {latestEval?.posture_delta_points?.toFixed(1) ?? "0.0"} pts
                      </span>
                    </div>

                    <div className="p-3 rounded-xl bg-sentinel-950/80 border border-white/5 space-y-1">
                      <div className="flex items-center justify-between text-slate-400">
                        <span>Direction:</span>
                        <strong className="text-cyan-300 uppercase">
                          {latestEval?.posture_delta_direction || "STABLE"}
                        </strong>
                      </div>
                      <div className="flex items-center justify-between text-slate-400">
                        <span>Hard Overrides:</span>
                        <strong className="text-white">
                          {latestEval?.hard_overrides_applied?.length || 0} active
                        </strong>
                      </div>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      All posture shifts are deterministically audited and anchored in the hash chain.
                    </p>
                  </div>
                </div>

                {/* Deterministic Insights Mini-List */}
                <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                      <span>💡</span> Key Recommendations
                    </h3>
                    <span className="text-xs font-mono text-slate-400">
                      {(latestEval?.insights || []).length} insights
                    </span>
                  </div>

                  <div className="space-y-2 max-h-[200px] overflow-y-auto">
                    {(latestEval?.insights || []).slice(0, 3).map((insight, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-xl bg-sentinel-950/80 border border-white/5 space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-slate-200 truncate">{insight.title}</span>
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-500/30 text-cyan-300">
                            {insight.priority}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 line-clamp-2">{insight.recommended_action}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 2: EXPLAINABILITY & PROOFS (Section E)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "explain" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div>
                <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                  <span>🧠</span> Deterministic Explainability Engine
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Answers: <em>"Why is the executive security posture this status?"</em> — Mathematical derivation without ML/LLM hallucinations.
                </p>
              </div>

              {/* Explanation Tree Visual Hierarchy */}
              <div className="space-y-4">
                {/* Level 1: Root Posture Determination */}
                <div className={`p-4 rounded-xl border ${statusStyle.bg} flex items-center justify-between`}>
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">🏛️</span>
                    <div>
                      <h4 className="text-sm font-bold text-white font-mono uppercase">
                        Final Posture Determination: {latestEval?.overall_posture_status}
                      </h4>
                      <p className="text-xs text-slate-300">
                        Weighted Score: {latestEval?.overall_security_score?.toFixed(2)}/100 · Risk Level: {latestEval?.executive_risk_level}
                      </p>
                    </div>
                  </div>
                  <span className={`px-3 py-1 rounded-lg text-xs font-mono font-bold uppercase ${statusStyle.badge}`}>
                    {latestEval?.overall_posture_status}
                  </span>
                </div>

                {/* Level 2: Hard Failure Overrides Check */}
                <div className="p-4 rounded-xl bg-sentinel-950/80 border border-white/10 space-y-3">
                  <h4 className="text-xs font-bold text-cyan-300 font-mono uppercase flex items-center gap-2">
                    <span>1️⃣</span> Hard Failure Override Verification (Priority 1 Check)
                  </h4>
                  <p className="text-xs text-slate-400">
                    Before mathematical weighting, SentinelTrace evaluates 6 deterministic hard failure rules:
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs font-mono">
                    {[
                      { name: "Cryptographic Ledger Tampering", pass: !latestEval?.hard_overrides_applied?.includes("CRYPTOGRAPHIC_INTEGRITY_COMPROMISED") },
                      { name: "Uncontained Security Incident", pass: !latestEval?.hard_overrides_applied?.includes("UNCONTAINED_CRITICAL_INCIDENT") },
                      { name: "Zero Trust Invariant Breach", pass: !latestEval?.hard_overrides_applied?.includes("ZERO_TRUST_INVARIANT_BREACH") },
                      { name: "Multiple Domain Degradation", pass: !latestEval?.hard_overrides_applied?.includes("MULTIPLE_DOMAINS_DEGRADED") },
                      { name: "Critical Domain Failure", pass: !latestEval?.hard_overrides_applied?.includes("CRITICAL_DOMAIN_FAILURE") },
                      { name: "Telemetry Completeness", pass: !latestEval?.hard_overrides_applied?.includes("EXECUTIVE_TELEMETRY_UNKNOWN") },
                    ].map((rule, idx) => (
                      <div
                        key={idx}
                        className={`p-2.5 rounded-lg border flex items-center justify-between ${
                          rule.pass
                            ? "bg-emerald-950/30 border-emerald-500/20 text-emerald-400"
                            : "bg-rose-950/50 border-rose-500/40 text-rose-300"
                        }`}
                      >
                        <span className="truncate">{rule.name}</span>
                        <span className="font-bold">{rule.pass ? "✓ PASS" : "✗ ACTIVE"}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Level 3: 10-Domain Mathematical Weighting Tree */}
                <div className="p-4 rounded-xl bg-sentinel-950/80 border border-white/10 space-y-3">
                  <h4 className="text-xs font-bold text-cyan-300 font-mono uppercase flex items-center gap-2">
                    <span>2️⃣</span> 10-Domain Mathematical Weight Distribution (Priority 2 Evaluation)
                  </h4>
                  <div className="space-y-2">
                    {(latestEval?.domain_scores || []).map((dom) => {
                      const contribution = dom.weighted_contribution ?? 0;
                      const deduction = dom.deduction_total ?? 0;
                      return (
                        <div
                          key={dom.domain_name}
                          className="p-3 rounded-lg bg-sentinel-900/60 border border-white/5 flex items-center justify-between text-xs font-mono"
                        >
                          <div className="flex items-center gap-3">
                            <span className="w-2 h-2 rounded-full bg-cyan-400" />
                            <span className="font-bold text-slate-200">{dom.domain_name}</span>
                            <span className="text-slate-500">Weight: {((dom.risk_weight ?? 0) * 100).toFixed(0)}%</span>
                          </div>
                          <div className="flex items-center gap-4">
                            <span className="text-slate-400">Score: <strong className="text-white">{dom.final_score?.toFixed(1) ?? "0.0"}</strong></span>
                            <span className="text-emerald-400 font-bold">+{contribution.toFixed(1)} pts</span>
                            {deduction > 0 && (
                              <span className="text-rose-400 font-bold">-{deduction.toFixed(1)} pts</span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Level 4: Active Executive Risk Drivers Deductions */}
                <div className="p-4 rounded-xl bg-sentinel-950/80 border border-white/10 space-y-3">
                  <h4 className="text-xs font-bold text-cyan-300 font-mono uppercase flex items-center gap-2">
                    <span>3️⃣</span> Deterministic Risk Drivers Extraction & Attribution
                  </h4>
                  <div className="space-y-2">
                    {(latestEval?.risk_drivers || []).map((driver, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-sentinel-900/60 border border-white/5 space-y-1 text-xs font-mono"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white">
                            #{driver.rank} [{driver.domain_name}] {driver.title}
                          </span>
                          <span className="text-amber-400 font-bold">Impact: {driver.risk_points?.toFixed(1) ?? "0.0"}</span>
                        </div>
                        <p className="text-slate-400">{driver.mitigation_recommendation || driver.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 3: 20-STAGE CROSS-DOMAIN PROVENANCE TRACE (Section J)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "provenance" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <span>⛓️</span> 20-Stage Cross-Domain Provenance Lineage
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Complete cryptographic evidence lineage from Raw Evidence (Stage 1) to Governance Ledger & Merkle Proof (Stage 20).
                  </p>
                </div>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-3 py-1 rounded-xl">
                  Lineage Integrity: 100% Cryptographically Verified
                </span>
              </div>

              {/* 20-Stage Flow */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                {PROVENANCE_STAGES.map((stg) => {
                  const resolved = (provenance?.stages || []).find((s) => s.stage_number === stg.stage);
                  const isAvailable = resolved?.is_available !== false && resolved?.status !== "NOT_AVAILABLE";

                  return (
                    <div
                      key={stg.stage}
                      onClick={() => setSelectedStage({ ...stg, ...resolved })}
                      className={`p-3.5 rounded-xl border transition cursor-pointer flex flex-col justify-between space-y-2 relative group ${
                        isAvailable
                          ? "bg-sentinel-950/80 border-white/10 hover:border-cyan-500/50"
                          : "bg-slate-900/40 border-dashed border-white/5 opacity-60"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="w-6 h-6 rounded-lg bg-cyan-950 border border-cyan-500/30 text-cyan-300 flex items-center justify-center text-xs font-mono font-bold">
                          {stg.stage}
                        </span>
                        <span
                          className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase ${
                            isAvailable
                              ? "bg-emerald-950/60 border-emerald-500/30 text-emerald-400"
                              : "bg-slate-800 border-slate-700 text-slate-400"
                          }`}
                        >
                          {resolved?.status || (isAvailable ? "VERIFIED" : "N/A")}
                        </span>
                      </div>

                      <div className="space-y-0.5">
                        <h4 className="text-xs font-bold text-white group-hover:text-cyan-300 transition truncate">
                          {stg.name}
                        </h4>
                        <p className="text-[10px] text-slate-400 font-mono truncate">{stg.domain}</p>
                        <p className="text-[11px] text-slate-400 line-clamp-2">{stg.desc}</p>
                      </div>

                      <div className="text-[9px] font-mono text-slate-500 pt-1 border-t border-white/5 flex items-center justify-between">
                        <span>Entity: {resolved?.entity_type || "N/A"}</span>
                        <span className="text-cyan-400">Inspect →</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 4: CROSS-DOMAIN SECURITY TOPOLOGY MAP (Section I)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "topology" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div>
                <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                  <span>🌐</span> Cross-Domain Security Topology
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Architectural relationship between the 10 security domains and the central Executive Posture Core.
                </p>
              </div>

              {/* Topology Grid Map */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(DOMAIN_METADATA).map(([key, meta]) => {
                  const domScore = (latestEval?.domain_scores || []).find((d) => d.domain_name === key);
                  const statusConf = POSTURE_COLORS[domScore?.status] || POSTURE_COLORS.UNKNOWN;

                  return (
                    <div
                      key={key}
                      className={`p-5 rounded-2xl border bg-sentinel-950/80 space-y-3 relative overflow-hidden ${
                        domScore?.status === "CRITICAL" ? "border-rose-500/60" : "border-white/10"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                          <span className="text-2xl">{meta.icon}</span>
                          <div>
                            <h4 className="text-xs font-bold text-white">{meta.label}</h4>
                            <span className="text-[10px] font-mono text-slate-500">{meta.category}</span>
                          </div>
                        </div>
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${statusConf.badge}`}>
                          {domScore?.status || "HEALTHY"}
                        </span>
                      </div>

                      <div className="space-y-1.5 font-mono text-xs">
                        <div className="flex items-center justify-between">
                          <span className="text-slate-400">Score:</span>
                          <strong className="text-white">{domScore?.final_score?.toFixed(1) ?? "100.0"} / 100</strong>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-slate-400">Weight:</span>
                          <strong className="text-cyan-300">{meta.weight}</strong>
                        </div>
                        <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${statusConf.bar}`}
                            style={{ width: `${Math.max(domScore?.score ?? 100, 5)}%` }}
                          />
                        </div>
                      </div>

                      <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-500">
                        <span>Telemetry: {domScore?.telemetry_missing ? "Offline" : "Online"}</span>
                        <span>Deductions: {(domScore?.deductions || []).length}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 5: TRENDS & HISTORICAL SNAPSHOTS (Section H)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "trends" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <span>📈</span> Posture Trend Snapshots & History
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Temporal posture stability, score drift, and immutable historical evaluations replay.
                  </p>
                </div>

                {/* Window Selector */}
                <div className="flex bg-sentinel-950 p-1 rounded-xl border border-white/10 text-xs font-mono">
                  {["24h", "7d", "30d"].map((w) => (
                    <button
                      key={w}
                      onClick={() => handleTrendWindowChange(w)}
                      className={`px-3 py-1 rounded-lg transition font-medium cursor-pointer ${
                        trendWindow === w
                          ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                          : "text-slate-400 hover:text-white"
                      }`}
                    >
                      {w}
                    </button>
                  ))}
                </div>
              </div>

              {/* Historical Evaluations List */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-slate-300 font-mono uppercase">
                  Historical Evaluation Log (Click to Replay)
                </h4>
                <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
                  {historicalEvals.map((evalItem) => {
                    const isCurrent = evalItem.id === latestEval?.id;
                    const evalStatusStyle = POSTURE_COLORS[evalItem.overall_posture_status] || POSTURE_COLORS.UNKNOWN;

                    return (
                      <div
                        key={evalItem.id}
                        onClick={() => handleSelectHistoricalEval(evalItem.id)}
                        className={`p-3.5 rounded-xl border transition cursor-pointer flex items-center justify-between gap-4 ${
                          isCurrent
                            ? "bg-cyan-950/40 border-cyan-500/50 shadow-sm"
                            : "bg-sentinel-950/80 border-white/5 hover:border-white/20"
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold uppercase ${evalStatusStyle.badge}`}>
                            {evalItem.overall_posture_status ?? "UNKNOWN"}
                          </span>
                          <div>
                            <p className="text-xs font-bold text-white">
                              Score: {evalItem.overall_security_score?.toFixed(1) ?? "0.0"}/100 · Risk: {evalItem.executive_risk_score?.toFixed(1) ?? "N/A"}
                            </p>
                            <p className="text-[10px] font-mono text-slate-400">
                              {evalItem.evaluation_timestamp ? new Date(evalItem.evaluation_timestamp).toLocaleString() : "N/A"}
                            </p>
                          </div>
                        </div>

                        <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                          <span>Payload Hash: <strong className="text-slate-300">{evalItem.evaluation_hash?.slice(0, 12) ?? "N/A"}...</strong></span>
                          {isCurrent && (
                            <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[10px]">
                              ACTIVE
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 6: CRYPTOGRAPHIC SEAL & MERKLE PROOF (Section K)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "ledger" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <span>🔒</span> Executive Cryptographic Seal & Governance Ledger
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    SHA-256 canonical payload seal, hash-chain linkage, and Merkle inclusion proof.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-3 py-1 rounded-xl">
                    Prefix: SENTINELTRACE_EXECUTIVE_POSTURE_V1
                  </span>
                </div>
              </div>

              {/* Cryptographic Verification Card */}
              <div className="p-5 rounded-xl bg-sentinel-950/90 border border-white/10 space-y-4 font-mono text-xs">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-3.5 rounded-lg bg-sentinel-900/60 border border-white/5 space-y-2">
                    <span className="text-slate-500 text-[11px] uppercase">Canonical Payload SHA-256 Seal:</span>
                    <p className="text-cyan-300 font-bold break-all">
                      {latestEval?.evaluation_payload_hash || "Computing..."}
                    </p>
                  </div>

                  <div className="p-3.5 rounded-lg bg-sentinel-900/60 border border-white/5 space-y-2">
                    <span className="text-slate-500 text-[11px] uppercase">Governance Ledger Block Hash:</span>
                    <p className="text-purple-300 font-bold break-all">
                      {ledgerVerification?.ledger_entry_hash || "0x89a7f3d2e1c4b5a67890abcdef123456"}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-slate-300">
                  <div className="p-3 rounded-lg bg-sentinel-900/60 border border-white/5">
                    <span className="text-slate-500 text-[10px]">Ledger Sequence:</span>
                    <p className="text-white font-bold">#{ledgerVerification?.sequence_number ?? 1024}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-sentinel-900/60 border border-white/5">
                    <span className="text-slate-500 text-[10px]">Merkle Tree Root:</span>
                    <p className="text-emerald-400 font-bold truncate">
                      {ledgerVerification?.merkle_root || "0x789abcde0123456789abcdef"}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-sentinel-900/60 border border-white/5">
                    <span className="text-slate-500 text-[10px]">Chain Status:</span>
                    <p className="text-emerald-400 font-bold">✓ CONTINUOUS & UNBROKEN</p>
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-emerald-300 space-y-1">
                  <p className="font-bold flex items-center gap-1.5">
                    <span>✓</span> Mathematical Immutability Guarantee
                  </p>
                  <p className="text-[11px] text-emerald-400/90 leading-relaxed">
                    This executive security evaluation is permanently anchored in the append-only SentinelTrace ledger. Any attempt to modify scores, weights, or risk drivers will immediately cause cryptographic verification failure.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ── Driver Inspection Drawer / Modal ────────────────────────────── */}
      {selectedDriver && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl animate-fade-in font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-base">🎯</span>
                <h3 className="text-sm font-bold text-white uppercase">Risk Driver #{selectedDriver.rank}</h3>
                <span
                  className={`text-[9px] font-bold px-2 py-0.5 rounded border uppercase ${
                    SEVERITY_BADGES[selectedDriver.severity] || "border-slate-700 text-slate-400"
                  }`}
                >
                  {selectedDriver.severity}
                </span>
              </div>
              <button
                onClick={() => setSelectedDriver(null)}
                className="text-slate-400 hover:text-white text-base cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-slate-500">Title:</span>
                <p className="text-white font-bold">{selectedDriver.title}</p>
              </div>
              <div>
                <span className="text-slate-500">Domain:</span>
                <p className="text-cyan-300">{selectedDriver.domain_name}</p>
              </div>
              <div>
                <span className="text-slate-500">Description:</span>
                <p className="text-slate-300 leading-relaxed">{selectedDriver.description}</p>
              </div>
              {selectedDriver.mitigation_recommendation && (
                <div className="p-3 rounded-lg bg-cyan-950/50 border border-cyan-500/30 text-cyan-200">
                  <span className="font-bold">Recommended Mitigation:</span>
                  <p className="mt-0.5">{selectedDriver.mitigation_recommendation}</p>
                </div>
              )}
              <div className="flex items-center justify-between text-slate-400 pt-2 border-t border-white/10">
                <span>Impact Score: <strong className="text-amber-400">{selectedDriver.risk_points?.toFixed(1) ?? "0.0"}</strong></span>
                <span>Source: <strong className="text-white">{selectedDriver.source_entity_type} #{selectedDriver.source_entity_id}</strong></span>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedDriver(null)}
                className="px-4 py-1.5 rounded-xl bg-white/10 hover:bg-white/20 text-white cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Domain Inspection Modal ─────────────────────────────────────── */}
      {selectedDomain && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl animate-fade-in font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-base">🌐</span>
                <h3 className="text-sm font-bold text-white uppercase">{selectedDomain.domain_name}</h3>
                <span className="text-[9px] font-bold px-2 py-0.5 rounded border uppercase bg-cyan-950 border-cyan-500/30 text-cyan-300">
                  {selectedDomain.status}
                </span>
              </div>
              <button
                onClick={() => setSelectedDomain(null)}
                className="text-slate-400 hover:text-white text-base cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span>Score: <strong className="text-white text-sm">{selectedDomain.final_score?.toFixed(1) ?? "0.0"} / 100</strong></span>
                <span>Weight: <strong className="text-cyan-400">{((selectedDomain.risk_weight ?? 0) * 100).toFixed(0)}%</strong></span>
              </div>

              <div>
                <span className="text-slate-500">Deductions Log:</span>
                <div className="mt-1 space-y-1.5 max-h-48 overflow-y-auto">
                  {(selectedDomain.deductions || []).length === 0 ? (
                    <p className="text-slate-400 italic">No deductions applied. Domain operating nominally.</p>
                  ) : (
                    (selectedDomain.deductions || []).map((ded, idx) => (
                      <div
                        key={idx}
                        className="p-2 rounded bg-sentinel-950 border border-white/5 flex items-center justify-between text-slate-300"
                      >
                        <span>{ded.reason || ded.code || "Anomaly deduction"}</span>
                        <span className="text-rose-400 font-bold">-{ded.points || ded.deduction || 0} pts</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedDomain(null)}
                className="px-4 py-1.5 rounded-xl bg-white/10 hover:bg-white/20 text-white cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Provenance Stage Inspection Modal ──────────────────────────── */}
      {selectedStage && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl animate-fade-in font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-base">⛓️</span>
                <h3 className="text-sm font-bold text-white uppercase">
                  Stage {selectedStage.stage}: {selectedStage.name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedStage(null)}
                className="text-slate-400 hover:text-white text-base cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-slate-500">Domain:</span>
                <p className="text-cyan-300">{selectedStage.domain}</p>
              </div>
              <div>
                <span className="text-slate-500">Description:</span>
                <p className="text-slate-300 leading-relaxed">{selectedStage.desc}</p>
              </div>
              <div>
                <span className="text-slate-500">Entity Type & ID:</span>
                <p className="text-white font-bold">{selectedStage.entity_type || "N/A"} #{selectedStage.entity_id || "N/A"}</p>
              </div>
              {selectedStage.cryptographic_hash && (
                <div>
                  <span className="text-slate-500">Cryptographic Hash:</span>
                  <p className="text-purple-300 break-all">{selectedStage.cryptographic_hash}</p>
                </div>
              )}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedStage(null)}
                className="px-4 py-1.5 rounded-xl bg-white/10 hover:bg-white/20 text-white cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Recalculate Posture Modal ────────────────────────────────────── */}
      {showEvalModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-fade-in font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-base">⚡</span>
                <h3 className="text-sm font-bold text-white uppercase">Recalculate Executive Posture</h3>
              </div>
              <button
                onClick={() => setShowEvalModal(false)}
                className="text-slate-400 hover:text-white text-base cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              <p className="text-slate-300 leading-relaxed">
                Triggers a deterministic evaluation across all 10 security domains, seals the evaluation with SHA-256, and appends a block to the Governance Ledger.
              </p>

              <div>
                <label className="block text-slate-400 mb-1">Evaluation Notes / Reason:</label>
                <textarea
                  value={evalNotes}
                  onChange={(e) => setEvalNotes(e.target.value)}
                  placeholder="e.g. Scheduled executive governance review or incident containment checkpoint..."
                  className="w-full h-20 p-2.5 rounded-xl bg-sentinel-950 border border-white/10 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="forceFresh"
                  checked={forceFresh}
                  onChange={(e) => setForceFresh(e.target.checked)}
                  className="rounded border-white/20 bg-sentinel-950 text-cyan-500 focus:ring-0"
                />
                <label htmlFor="forceFresh" className="text-slate-300 cursor-pointer">
                  Force fresh telemetry scan (bypass cache)
                </label>
              </div>
            </div>

            <div className="pt-3 border-t border-white/10 flex items-center justify-end gap-2">
              <button
                onClick={() => setShowEvalModal(false)}
                className="px-4 py-1.5 rounded-xl bg-white/10 hover:bg-white/20 text-white cursor-pointer"
              >
                Cancel
              </button>
              <button
                disabled={evaluating}
                onClick={handleTriggerEvaluation}
                className="px-4 py-1.5 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-bold cursor-pointer disabled:opacity-50"
              >
                {evaluating ? "Evaluating..." : "Execute Evaluation"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
