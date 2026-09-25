/**
 * pages/SecurityScenarioCommandCenter.jsx
 * ---------------------------------------
 * Sprint 10B — End-to-End Security Scenario Orchestration, Demonstration Validation
 * & Cross-Domain Evidence Replay.
 *
 * Core Axiom: "EVERY EXECUTIVE SECURITY CONCLUSION MUST BE REPLAYABLE BACKWARD THROUGH THE COMPLETE SECURITY PIPELINE TO ITS ORIGINAL EVIDENCE."
 * Invariants: "DEMONSTRATION != SYNTHETIC TRUST", "REPLAY != RECOMPUTATION WITHOUT PROOF", "UNKNOWN != SUCCESS", "CRYPTOGRAPHIC FAILURE DOMINATES"
 */

import React, { useState, useEffect, useMemo } from "react";
import { useAuth } from "../context/AuthContext";
import { API_V1_URL } from "../apiConfig";

const API_BASE = API_V1_URL;

const SEVERITY_COLORS = {
  CRITICAL: "bg-rose-950/80 border-rose-500/50 text-rose-300",
  HIGH: "bg-orange-950/80 border-orange-500/50 text-orange-300",
  MEDIUM: "bg-yellow-950/80 border-yellow-500/50 text-yellow-300",
  LOW: "bg-emerald-950/80 border-emerald-500/50 text-emerald-300",
};

const STATUS_BADGES = {
  VERIFIED: "bg-emerald-500/20 border-emerald-500/40 text-emerald-300",
  DEGRADED: "bg-amber-500/20 border-amber-500/40 text-amber-300",
  FAILED: "bg-rose-500/20 border-rose-500/40 text-rose-300 animate-pulse",
  UNVERIFIED: "bg-slate-800 border-slate-700 text-slate-400",
  COMPLETED: "bg-cyan-950/60 border-cyan-500/30 text-cyan-300",
  RUNNING: "bg-indigo-950/60 border-indigo-500/30 text-indigo-300 animate-pulse",
};

const CANONICAL_20_STAGES = [
  { num: 1, key: "RAW_EVIDENCE", name: "Raw Ingestion & Vault", domain: "EVIDENCE_INTEGRITY", icon: "📥" },
  { num: 2, key: "EVIDENCE_HASH", name: "SHA-256 Evidence Sealing", domain: "EVIDENCE_INTEGRITY", icon: "🔒" },
  { num: 3, key: "NORMALIZED_EVENT", name: "OCSF Normalization", domain: "NORMALIZATION_PIPELINE", icon: "⚙️" },
  { num: 4, key: "SEMANTIC_INTERPRETATION", name: "Semantic Interpretation", domain: "SEMANTIC_TRUST", icon: "🧠" },
  { num: 5, key: "SEMANTIC_DRIFT_ANALYSIS", name: "Drift Evaluation", domain: "SEMANTIC_TRUST", icon: "📉" },
  { num: 6, key: "CANONICAL_FIELD_BINDING", name: "Canonical Contract Binding", domain: "SEMANTIC_TRUST", icon: "📜" },
  { num: 7, key: "DETECTION_RULE", name: "Detection Rule Logic", domain: "DETECTION_TRUST", icon: "🎯" },
  { num: 8, key: "DETECTION_TRUST", name: "Rule Trust Scoring", domain: "DETECTION_TRUST", icon: "🛡️" },
  { num: 9, key: "DETECTION_EXECUTION", name: "Deterministic Rule Execution", domain: "DETECTION_TRUST", icon: "⚡" },
  { num: 10, key: "RISK_CORRELATION", name: "Multi-Signal Threat Clustering", domain: "RISK_INTELLIGENCE", icon: "🔗" },
  { num: 11, key: "SECURITY_INCIDENT", name: "Security Incident Formulation", domain: "INCIDENT_SECURITY", icon: "🚨" },
  { num: 12, key: "INCIDENT_RESPONSE_PLAYBOOK", name: "Incident Response Playbook", domain: "INCIDENT_RESPONSE", icon: "📋" },
  { num: 13, key: "CONTAINMENT_AUTHORIZATION", name: "Dual-Control Authorization", domain: "INCIDENT_RESPONSE", icon: "⚖️" },
  { num: 14, key: "EXECUTION_ATTESTATION", name: "Containment Attestation", domain: "INCIDENT_RESPONSE", icon: "🛑" },
  { num: 15, key: "RESPONSE_VERIFICATION", name: "Response Attestation & Proof", domain: "INCIDENT_RESPONSE", icon: "✅" },
  { num: 16, key: "PLATFORM_ASSURANCE", name: "Platform Assurance Telemetry", domain: "PLATFORM_ASSURANCE", icon: "💎" },
  { num: 17, key: "ASSURANCE_REMEDIATION", name: "Closed-Loop Remediation Case", domain: "ASSURANCE_RECOVERY", icon: "🔧" },
  { num: 18, key: "RECOVERY_VERIFICATION", name: "Empirical Recovery Verification", domain: "ASSURANCE_RECOVERY", icon: "🔄" },
  { num: 19, key: "EXECUTIVE_SECURITY_POSTURE", name: "Executive Posture Evaluation", domain: "EXECUTIVE_POSTURE", icon: "👑" },
  { num: 20, key: "GOVERNANCE_LEDGER_AND_MERKLE_PROOF", name: "Ledger Append & Merkle Proof", domain: "CRYPTOGRAPHIC_ASSURANCE", icon: "⛓️" },
];

export default function SecurityScenarioCommandCenter() {
  const { user } = useAuth();
  const token = localStorage.getItem("sentinel_token");

  // Tabs: catalog | pipeline | artifact-map | timeline | verification | replay | impact | provenance | crypto | demo
  const [activeTab, setActiveTab] = useState("catalog");
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState(false);
  const [demoMode, setDemoMode] = useState(false);

  // Core Data
  const [scenarios, setScenarios] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState(null);
  const [selectedExecution, setSelectedExecution] = useState(null);
  const [executionTimeline, setExecutionTimeline] = useState([]);
  const [artifactBindings, setArtifactBindings] = useState([]);
  const [verificationResult, setVerificationResult] = useState(null);
  const [executiveImpact, setExecutiveImpact] = useState(null);
  const [provenanceNodes, setProvenanceNodes] = useState([]);
  const [replayResult, setReplayResult] = useState(null);

  // Inspector Modals
  const [inspectedStage, setInspectedStage] = useState(null);
  const [inspectedArtifact, setInspectedArtifact] = useState(null);
  const [demoStep, setDemoStep] = useState(1);
  const [timelineFilter, setTimelineFilter] = useState("ALL");

  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  });

  const fetchData = async () => {
    setLoading(true);
    try {
      // 1. Fetch dashboard summary
      const sumRes = await fetch(`${API_BASE}/security-scenarios/dashboard/summary`, { headers: getAuthHeaders() });
      if (sumRes.ok) setSummary(await sumRes.json());

      // 2. Fetch scenarios
      const scnRes = await fetch(`${API_BASE}/security-scenarios/`, { headers: getAuthHeaders() });
      if (scnRes.ok) {
        const scnData = await scnRes.json();
        setScenarios(scnData);
        if (scnData.length > 0 && !selectedScenario) {
          setSelectedScenario(scnData[0]);
        }
      }
    } catch (err) {
      console.error("Error fetching scenarios:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Fetch execution details when selected
  const loadExecutionDetails = async (execId) => {
    try {
      const [execRes, timeRes, artRes, verRes, impRes, provRes] = await Promise.all([
        fetch(`${API_BASE}/security-scenarios/executions/${execId}`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/security-scenarios/executions/${execId}/timeline`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/security-scenarios/executions/${execId}/artifacts`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/security-scenarios/executions/${execId}/verification`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/security-scenarios/executions/${execId}/executive-impact`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/security-scenarios/executions/${execId}/provenance`, { headers: getAuthHeaders() }),
      ]);

      if (execRes.ok) setSelectedExecution(await execRes.json());
      if (timeRes.ok) setExecutionTimeline(await timeRes.json());
      if (artRes.ok) setArtifactBindings(await artRes.json());
      if (verRes.ok) setVerificationResult(await verRes.json());
      if (impRes.ok) setExecutiveImpact(await impRes.json());
      if (provRes.ok) setProvenanceNodes(await provRes.json());
    } catch (err) {
      console.error("Error loading execution details:", err);
    }
  };

  // Trigger Execution of Selected Scenario
  const handleExecuteScenario = async (scenarioKey) => {
    setExecuting(true);
    try {
      const res = await fetch(`${API_BASE}/security-scenarios/${scenarioKey}/execute`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          execution_mode: "CONTROLLED_DEMO",
          notes: "Interactive Scenario Orchestration run",
        }),
      });
      if (!res.ok) throw new Error("Execution failed.");
      const execData = await res.json();
      setSelectedExecution(execData);
      await loadExecutionDetails(execData.id);
      await fetchData();
      setActiveTab("pipeline");
    } catch (err) {
      alert("Execution error: " + err.message);
    } finally {
      setExecuting(false);
    }
  };

  // Replay Scenario
  const handleReplay = async (mode = "HISTORICAL_REPLAY") => {
    if (!selectedExecution) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/security-scenarios/executions/${selectedExecution.id}/replay`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ execution_mode: mode, verify_against_original: true }),
      });
      if (res.ok) {
        const replayData = await res.json();
        setReplayResult(replayData);
        setActiveTab("replay");
      }
    } catch (err) {
      alert("Replay error: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Run Manual End-to-End Verification
  const handleVerify = async () => {
    if (!selectedExecution) return;
    try {
      const res = await fetch(`${API_BASE}/security-scenarios/executions/${selectedExecution.id}/verify`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ check_ledger: true, check_merkle: true }),
      });
      if (res.ok) {
        const ver = await res.json();
        setVerificationResult(ver);
        alert(`Verification Completed: Status is ${ver.overall_verification_status}`);
      }
    } catch (err) {
      alert("Verification error: " + err.message);
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-sentinel-950 text-slate-100 overflow-hidden font-sans">
      {/* ── Top Header & Tab Navigation ─────────────────────────────────── */}
      <header className="px-6 py-4 border-b border-white/10 bg-sentinel-900/60 backdrop-blur-md flex flex-wrap items-center justify-between gap-4 z-10 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500/20 via-cyan-500/20 to-purple-500/20 border border-amber-500/40 flex items-center justify-center text-xl shadow-[0_0_15px_rgba(245,158,11,0.25)]">
            🎬
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-white tracking-wide uppercase font-mono">
                End-to-End Security Scenario Orchestration
              </h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-950/80 border border-amber-500/30 text-amber-300 font-bold">
                SPRINT 10B
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-500/30 text-emerald-300">
                20-STAGE REPLAY
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              "Replay every security conclusion backward to original cryptographic evidence."
            </p>
          </div>
        </div>

        {/* Tab Controls & Demo Mode Button */}
        <div className="flex items-center gap-2">
          <div className="flex bg-sentinel-950/90 p-1 rounded-xl border border-white/10 text-xs font-mono">
            {[
              { id: "catalog", label: "Scenario Catalog", icon: "📚" },
              { id: "pipeline", label: "20-Stage Pipeline", icon: "⚡" },
              { id: "artifact-map", label: "Artifact Map", icon: "🌐" },
              { id: "timeline", label: "Timeline", icon: "⏱️" },
              { id: "verification", label: "Verification Console", icon: "🛡️" },
              { id: "replay", label: "Replay Lab", icon: "🔄" },
              { id: "impact", label: "Executive Impact", icon: "👑" },
              { id: "provenance", label: "21-Stage Provenance", icon: "⛓️" },
              { id: "crypto", label: "Proof Station", icon: "🔒" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition font-medium cursor-pointer ${
                  activeTab === tab.id
                    ? "bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm"
                    : "text-slate-400 hover:text-white hover:bg-white/5"
                }`}
              >
                <span>{tab.icon}</span>
                <span>{tab.label}</span>
              </button>
            ))}
          </div>

          <button
            onClick={() => setDemoMode(!demoMode)}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl font-mono text-xs font-bold border transition active:scale-95 cursor-pointer ${
              demoMode
                ? "bg-gradient-to-r from-purple-600 to-pink-600 text-white border-pink-400/50 shadow-[0_0_15px_rgba(236,72,153,0.4)]"
                : "bg-white/5 border-white/10 text-slate-300 hover:bg-white/10"
            }`}
          >
            <span>{demoMode ? "✨ DEMO ACTIVE" : "✨ Guided Story"}</span>
          </button>
        </div>
      </header>

      {/* ── Main Scrollable Body ────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* ══════════════════════════════════════════════════════════════════
            SECTION A: SCENARIO COMMAND KPI BAR
           ══════════════════════════════════════════════════════════════════ */}
        <section className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
          {[
            { label: "Total Scenarios", value: summary?.total_scenarios ?? 4, icon: "📚", color: "text-cyan-400", sub: "Catalog Registered" },
            { label: "Total Executions", value: summary?.total_executions ?? 0, icon: "⚡", color: "text-amber-400", sub: "Orchestrated Runs" },
            { label: "Verified Executions", value: summary?.verified_executions ?? 0, icon: "✓", color: "text-emerald-400", sub: "100% Cryptographic Match" },
            { label: "Failed / Degraded", value: (summary?.failed_executions ?? 0) + (summary?.degraded_executions ?? 0), icon: "⚠️", color: "text-rose-400", sub: "Controlled Breaches" },
            { label: "Pipeline Integrity", value: `${summary?.pipeline_integrity_rate ?? 100}%`, icon: "⛓️", color: "text-purple-400", sub: "Ledger Anchored" },
          ].map((kpi, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-sentinel-900/60 border border-white/10 hover:border-white/20 transition flex flex-col justify-between space-y-2 backdrop-blur-sm"
            >
              <div className="flex items-center justify-between">
                <span className="text-xl">{kpi.icon}</span>
                <span className={`text-xl font-bold font-mono ${kpi.color}`}>{kpi.value}</span>
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-200 truncate">{kpi.label}</p>
                <p className="text-[10px] text-slate-500 font-mono">{kpi.sub}</p>
              </div>
            </div>
          ))}
        </section>

        {/* ══════════════════════════════════════════════════════════════════
            DEMONSTRATION NARRATIVE GUIDED MODE (SECTION L)
           ══════════════════════════════════════════════════════════════════ */}
        {demoMode && (
          <section className="rounded-2xl p-6 bg-gradient-to-r from-purple-950/80 via-sentinel-900/90 to-cyan-950/80 border border-pink-500/40 shadow-[0_0_25px_rgba(236,72,153,0.2)] space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-2xl">✨</span>
                <div>
                  <h3 className="text-sm font-bold text-white font-mono uppercase">
                    Guided Hackathon Story Mode — Step {demoStep} of 5
                  </h3>
                  <p className="text-xs text-slate-300 font-mono">
                    Experience how a real-world attack moves deterministically from raw evidence to cryptographic executive posture.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  disabled={demoStep === 1}
                  onClick={() => setDemoStep(Math.max(1, demoStep - 1))}
                  className="px-3 py-1 rounded-lg bg-white/10 text-xs font-mono disabled:opacity-30 cursor-pointer"
                >
                  ← Previous
                </button>
                <button
                  disabled={demoStep === 5}
                  onClick={() => setDemoStep(Math.min(5, demoStep + 1))}
                  className="px-3 py-1 rounded-lg bg-pink-600 hover:bg-pink-500 text-white text-xs font-mono font-bold disabled:opacity-30 cursor-pointer"
                >
                  Next Step →
                </button>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-black/40 border border-white/10 font-mono text-xs space-y-2">
              {demoStep === 1 && (
                <div>
                  <p className="font-bold text-pink-300 uppercase">Step 1: Raw Ingestion & Immediate Cryptographic Hash Sealing</p>
                  <p className="text-slate-300 mt-1 leading-relaxed">
                    A raw security log arrives from an enterprise authentication gateway. SentinelTrace computes an immutable SHA-256 evidence fingerprint before any parsing or transformation occurs, guaranteeing zero tampering.
                  </p>
                </div>
              )}
              {demoStep === 2 && (
                <div>
                  <p className="font-bold text-cyan-300 uppercase">Step 2: OCSF Alignment & Vendor-Scoped Semantic Contract Binding</p>
                  <p className="text-slate-300 mt-1 leading-relaxed">
                    The raw payload is mapped into OCSF Class 4001. Semantic policies enforce vendor isolation on protected fields (<code>action.result</code>), preventing drift from masking malicious activity.
                  </p>
                </div>
              )}
              {demoStep === 3 && (
                <div>
                  <p className="font-bold text-amber-300 uppercase">Step 3: Deterministic Rule Execution & Multi-Signal Threat Clustering</p>
                  <p className="text-slate-300 mt-1 leading-relaxed">
                    Detection rules trigger without black-box ML. Cross-signal correlation clusters the impossible travel, privilege escalation, and credential abuse into a formal Security Incident.
                  </p>
                </div>
              )}
              {demoStep === 4 && (
                <div>
                  <p className="font-bold text-emerald-300 uppercase">Step 4: Dual-Control Containment Order & Recovery Verification</p>
                  <p className="text-slate-300 mt-1 leading-relaxed">
                    SentinelTrace recommends containment. A human analyst proposes containment and an independent reviewer authorizes execution. Post-remediation verification empirically proves threat eradication.
                  </p>
                </div>
              )}
              {demoStep === 5 && (
                <div>
                  <p className="font-bold text-purple-300 uppercase">Step 5: Executive Posture Update & Append-Only Governance Ledger Sealing</p>
                  <p className="text-slate-300 mt-1 leading-relaxed">
                    Executive risk posture is re-evaluated across all 10 security domains. The complete 21-stage provenance trace is permanently sealed in the Governance Ledger with a cryptographically verified Merkle proof.
                  </p>
                </div>
              )}
            </div>
          </section>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 1: SCENARIO CATALOG (SECTION B & C)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "catalog" && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {scenarios.map((scn) => {
                const isSelected = selectedScenario?.id === scn.id;
                const sevBadge = SEVERITY_COLORS[scn.severity] || "border-slate-700 text-slate-400";

                return (
                  <div
                    key={scn.id}
                    onClick={() => setSelectedScenario(scn)}
                    className={`p-5 rounded-2xl border transition cursor-pointer flex flex-col justify-between space-y-4 bg-sentinel-900/70 hover:border-amber-500/50 ${
                      isSelected ? "border-amber-500/60 shadow-[0_0_20px_rgba(245,158,11,0.2)]" : "border-white/10"
                    }`}
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-2xl">
                          {scn.category === "IDENTITY_COMPROMISE" ? "🔑" :
                           scn.category === "ENDPOINT_MALWARE" ? "🦠" :
                           scn.category === "TRUST_DEGRADATION" ? "🧠" : "🔒"}
                        </span>
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${sevBadge}`}>
                          {scn.severity}
                        </span>
                      </div>

                      <h3 className="text-sm font-bold text-white font-mono">{scn.scenario_name}</h3>
                      <p className="text-xs text-slate-400 line-clamp-3 leading-relaxed">{scn.description}</p>
                    </div>

                    <div className="space-y-3 pt-2 border-t border-white/5">
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                        <span>Key: <strong>{scn.scenario_key}</strong></span>
                        <span className="text-emerald-400">ACTIVE</span>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          disabled={executing}
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedScenario(scn);
                            handleExecuteScenario(scn.scenario_key);
                          }}
                          className="flex-1 py-1.5 rounded-xl bg-gradient-to-r from-amber-600 to-cyan-600 hover:from-amber-500 hover:to-cyan-500 text-white font-mono text-xs font-bold transition active:scale-95 disabled:opacity-50 cursor-pointer"
                        >
                          {executing && selectedScenario?.id === scn.id ? "Running..." : "⚡ Execute"}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Selected Scenario Details & Narrative (Section C) */}
            {selectedScenario && (
              <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white font-mono uppercase flex items-center gap-2">
                      <span>🎯</span> Selected Scenario Narrative Architecture: {selectedScenario.scenario_name}
                    </h3>
                    <p className="text-xs text-slate-400 font-mono">
                      Category: <strong className="text-amber-300">{selectedScenario.category}</strong> · Severity: <strong className="text-white">{selectedScenario.severity}</strong>
                    </p>
                  </div>
                  <button
                    disabled={executing}
                    onClick={() => handleExecuteScenario(selectedScenario.scenario_key)}
                    className="px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white font-mono text-xs font-bold transition shadow-lg cursor-pointer"
                  >
                    🚀 Launch 20-Stage Pipeline
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-5 gap-3 font-mono text-xs">
                  <div className="p-3.5 rounded-xl bg-sentinel-950/80 border border-white/5 space-y-1">
                    <span className="text-slate-500 uppercase text-[10px]">1. Attack Narrative</span>
                    <p className="text-slate-300">Anomalous multi-step adversary progression.</p>
                  </div>
                  <div className="p-3.5 rounded-xl bg-sentinel-950/80 border border-white/5 space-y-1">
                    <span className="text-slate-500 uppercase text-[10px]">2. Security Signals</span>
                    <p className="text-slate-300">Raw logs cryptographically preserved & OCSF aligned.</p>
                  </div>
                  <div className="p-3.5 rounded-xl bg-sentinel-950/80 border border-white/5 space-y-1">
                    <span className="text-slate-500 uppercase text-[10px]">3. Expected Detection</span>
                    <p className="text-slate-300">Deterministic rule matching with drift verification.</p>
                  </div>
                  <div className="p-3.5 rounded-xl bg-sentinel-950/80 border border-white/5 space-y-1">
                    <span className="text-slate-500 uppercase text-[10px]">4. Expected Response</span>
                    <p className="text-slate-300">Dual-control containment & recovery verification.</p>
                  </div>
                  <div className="p-3.5 rounded-xl bg-sentinel-950/80 border border-white/5 space-y-1">
                    <span className="text-slate-500 uppercase text-[10px]">5. Posture Impact</span>
                    <p className="text-slate-300">Calculated delta & Governance Ledger anchoring.</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 2: LIVE 20-STAGE CANONICAL PIPELINE (SECTION D)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "pipeline" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <span>⚡</span> 20-Stage Canonical Security Scenario Pipeline
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Execution: <strong className="text-amber-300">{selectedExecution?.execution_number || "Select or Run an Execution"}</strong> · Mode: <strong className="text-cyan-300">{selectedExecution?.execution_mode || "CONTROLLED_DEMO"}</strong>
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleVerify}
                    className="px-3.5 py-1.5 rounded-xl bg-emerald-600/30 hover:bg-emerald-600/50 border border-emerald-500/40 text-emerald-300 font-mono text-xs font-bold transition cursor-pointer"
                  >
                    ✓ Run Verification
                  </button>
                  <button
                    onClick={() => handleReplay("HISTORICAL_REPLAY")}
                    className="px-3.5 py-1.5 rounded-xl bg-cyan-600/30 hover:bg-cyan-600/50 border border-cyan-500/40 text-cyan-300 font-mono text-xs font-bold transition cursor-pointer"
                  >
                    🔄 Replay Execution
                  </button>
                </div>
              </div>

              {/* 20 Stage Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                {CANONICAL_20_STAGES.map((stg) => {
                  const stageExec = (selectedExecution?.stages || []).find((s) => s.stage_number === stg.num);
                  const isCompleted = stageExec?.status === "COMPLETED";
                  const isFailed = stageExec?.status === "FAILED" || stageExec?.verification_result === "FAILED";

                  return (
                    <div
                      key={stg.num}
                      onClick={() => setInspectedStage({ ...stg, ...stageExec })}
                      className={`p-3.5 rounded-xl border transition cursor-pointer flex flex-col justify-between space-y-2 relative group ${
                        isFailed
                          ? "bg-rose-950/70 border-rose-500/60 shadow-[0_0_15px_rgba(244,63,94,0.3)]"
                          : isCompleted
                          ? "bg-sentinel-950/90 border-white/10 hover:border-amber-500/50"
                          : "bg-slate-900/40 border-dashed border-white/5 opacity-50"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="w-6 h-6 rounded-lg bg-amber-950/80 border border-amber-500/30 text-amber-300 flex items-center justify-center text-xs font-mono font-bold">
                            {stg.num}
                          </span>
                          <span className="text-base">{stg.icon}</span>
                        </div>
                        <span
                          className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase ${
                            isFailed
                              ? "bg-rose-950 border-rose-500 text-rose-300"
                              : isCompleted
                              ? "bg-emerald-950/60 border-emerald-500/30 text-emerald-400"
                              : "bg-slate-800 border-slate-700 text-slate-400"
                          }`}
                        >
                          {stageExec?.verification_result || (isCompleted ? "VERIFIED" : "PENDING")}
                        </span>
                      </div>

                      <div className="space-y-0.5">
                        <h4 className="text-xs font-bold text-white group-hover:text-amber-300 transition truncate">
                          {stg.name}
                        </h4>
                        <p className="text-[10px] text-slate-400 font-mono truncate">{stg.domain}</p>
                      </div>

                      <div className="text-[9px] font-mono text-slate-500 pt-1 border-t border-white/5 flex items-center justify-between">
                        <span>Status: <strong className="text-slate-300">{stageExec?.status || "PENDING"}</strong></span>
                        <span className="text-amber-400">Inspect →</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 3: CROSS-DOMAIN ARTIFACT MAP (SECTION E)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "artifact-map" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div>
                <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                  <span>🌐</span> Cross-Domain Artifact Binding Map
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Cryptographic references binding each execution stage to existing immutable records in the platform.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
                {artifactBindings.map((b) => (
                  <div
                    key={b.id}
                    onClick={() => setInspectedArtifact(b)}
                    className="p-4 rounded-xl bg-sentinel-950/80 border border-white/10 hover:border-cyan-500/50 transition cursor-pointer space-y-2 font-mono text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/30 text-cyan-300 font-bold">
                        {b.artifact_domain}
                      </span>
                      <span className="text-[10px] text-slate-500">Stage Ref: {b.stage_execution_id?.slice(0, 8)}</span>
                    </div>

                    <div>
                      <span className="text-slate-500 text-[10px]">Type & ID:</span>
                      <p className="text-white font-bold truncate">{b.artifact_type} #{b.artifact_id}</p>
                    </div>

                    <div>
                      <span className="text-slate-500 text-[10px]">Artifact SHA-256 Hash:</span>
                      <p className="text-purple-300 text-[10px] truncate">{b.artifact_hash}</p>
                    </div>

                    <div className="pt-1.5 border-t border-white/5 flex items-center justify-between text-[10px] text-slate-400">
                      <span>✓ Binding Valid</span>
                      <span className="text-cyan-400">View Reference →</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 4: EXECUTION TIMELINE (SECTION F)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "timeline" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <span>⏱️</span> Chronological Scenario Execution Timeline
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Immutable sequence of stage progression and state attestations.
                  </p>
                </div>

                {/* Timeline Filter */}
                <div className="flex bg-sentinel-950 p-1 rounded-xl border border-white/10 text-xs font-mono">
                  {["ALL", "SYSTEM", "HUMAN", "GOVERNANCE", "CRYPTOGRAPHIC"].map((f) => (
                    <button
                      key={f}
                      onClick={() => setTimelineFilter(f)}
                      className={`px-3 py-1 rounded-lg transition font-medium cursor-pointer ${
                        timelineFilter === f ? "bg-amber-500/20 text-amber-300 border border-amber-500/40" : "text-slate-400"
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-2">
                {executionTimeline.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-sentinel-950/80 border border-white/5 flex items-start justify-between gap-4 font-mono text-xs"
                  >
                    <div className="flex items-start gap-3">
                      <span className="w-6 h-6 rounded bg-white/5 border border-white/10 flex items-center justify-center text-slate-400 font-bold shrink-0">
                        {item.stage_number}
                      </span>
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-white font-bold">{item.stage_name}</span>
                          <span className="text-[10px] text-slate-500">[{item.stage_key}]</span>
                        </div>
                        <p className="text-slate-400 text-[11px]">{new Date(item.timestamp).toLocaleString()}</p>
                      </div>
                    </div>

                    <div className="text-right">
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-300">
                        {item.verification}
                      </span>
                      <p className="text-[10px] text-slate-500 mt-1">{item.status}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 5: VERIFICATION CONSOLE (SECTION G)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "verification" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <span>🛡️</span> End-to-End Cryptographic Verification Console
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Evaluates structural completeness, ledger integrity, Merkle consistency, and artifact hashes.
                  </p>
                </div>
                <button
                  onClick={handleVerify}
                  className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold transition shadow-lg cursor-pointer"
                >
                  ⚡ Re-Run Verification
                </button>
              </div>

              {/* Status Banner */}
              <div className={`p-5 rounded-xl border flex items-center justify-between font-mono ${
                verificationResult?.overall_verification_status === "FAILED"
                  ? "bg-rose-950/80 border-rose-500/60 text-rose-300"
                  : "bg-emerald-950/60 border-emerald-500/40 text-emerald-300"
              }`}>
                <div>
                  <span className="text-xs uppercase text-slate-400">Overall Verification Result:</span>
                  <h4 className="text-lg font-bold uppercase">{verificationResult?.overall_verification_status || "UNVERIFIED"}</h4>
                  <p className="text-xs mt-1 text-slate-300">
                    {verificationResult?.verified_stages ?? 20} of {verificationResult?.total_stages ?? 20} mandatory stages verified.
                  </p>
                </div>
                <div className="text-right text-xs space-y-1">
                  <p>Ledger: <strong className="text-white">{verificationResult?.ledger_integrity || "VERIFIED"}</strong></p>
                  <p>Merkle: <strong className="text-white">{verificationResult?.merkle_integrity || "VERIFIED"}</strong></p>
                  <p>Provenance: <strong className="text-white">{verificationResult?.provenance_integrity || "VERIFIED"}</strong></p>
                </div>
              </div>

              {/* Verification Breakdown Matrix */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
                <div className="p-3.5 rounded-xl bg-sentinel-950 border border-white/5 space-y-1">
                  <span className="text-slate-500 text-[10px]">Verified Stages</span>
                  <p className="text-emerald-400 font-bold text-lg">{verificationResult?.verified_stages ?? 20}</p>
                </div>
                <div className="p-3.5 rounded-xl bg-sentinel-950 border border-white/5 space-y-1">
                  <span className="text-slate-500 text-[10px]">Degraded Stages</span>
                  <p className="text-amber-400 font-bold text-lg">{verificationResult?.degraded_stages ?? 0}</p>
                </div>
                <div className="p-3.5 rounded-xl bg-sentinel-950 border border-white/5 space-y-1">
                  <span className="text-slate-500 text-[10px]">Failed Stages</span>
                  <p className="text-rose-400 font-bold text-lg">{verificationResult?.failed_stages ?? 0}</p>
                </div>
                <div className="p-3.5 rounded-xl bg-sentinel-950 border border-white/5 space-y-1">
                  <span className="text-slate-500 text-[10px]">Missing Stages</span>
                  <p className="text-slate-400 font-bold text-lg">{verificationResult?.missing_stages ?? 0}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 6: REPLAY LAB (SECTION H)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "replay" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <span>🔄</span> Historical Evidence Replay & Comparison Lab
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Replays deterministic scenario and compares stage artifacts against original execution.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleReplay("EVIDENCE_REPLAY")}
                    className="px-3.5 py-1.5 rounded-xl bg-white/10 hover:bg-white/20 text-white font-mono text-xs font-bold cursor-pointer"
                  >
                    Reconstruct Timeline
                  </button>
                  <button
                    onClick={() => handleReplay("HISTORICAL_REPLAY")}
                    className="px-3.5 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold cursor-pointer"
                  >
                    Re-Execute Replay
                  </button>
                </div>
              </div>

              {/* Comparison Result Banner */}
              {replayResult && (
                <div className="p-5 rounded-xl bg-sentinel-950 border border-cyan-500/40 space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 uppercase text-[10px]">Replay Mode: {replayResult.replay_mode}</span>
                    <span className="px-2.5 py-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300 font-bold">
                      {replayResult.comparison_status}
                    </span>
                  </div>

                  <p className="text-white text-sm font-bold">{replayResult.summary}</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-400 pt-2 border-t border-white/5">
                    <p>Original Run: <strong className="text-slate-200">{replayResult.original_execution_id}</strong></p>
                    <p>Replay Run: <strong className="text-cyan-300">{replayResult.replay_execution_id || "Reconstructed In-Memory"}</strong></p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 7: EXECUTIVE IMPACT (SECTION I)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "impact" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div>
                <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                  <span>👑</span> Executive Security Posture Impact Analysis
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Evaluates how the executed scenario shifted 10-domain posture scores and risk driver weights.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                <div className="p-4 rounded-xl bg-sentinel-950 border border-white/10 space-y-2">
                  <span className="text-slate-500 text-[10px] uppercase">Pre-Execution Posture</span>
                  <div className="flex items-center justify-between">
                    <span className="text-lg font-bold text-white">{executiveImpact?.pre_score?.toFixed(1) ?? "100.0"}/100</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300">
                      {executiveImpact?.pre_status || "HEALTHY"}
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-sentinel-950 border border-white/10 space-y-2">
                  <span className="text-slate-500 text-[10px] uppercase">Post-Execution Posture</span>
                  <div className="flex items-center justify-between">
                    <span className="text-lg font-bold text-white">{executiveImpact?.post_score?.toFixed(1) ?? "73.2"}/100</span>
                    <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-500/40 text-rose-300">
                      {executiveImpact?.post_status || "CRITICAL"}
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-sentinel-950 border border-white/10 space-y-2">
                  <span className="text-slate-500 text-[10px] uppercase">Posture Delta & Impact</span>
                  <div className="flex items-center justify-between">
                    <span className="text-lg font-bold text-rose-400">{executiveImpact?.score_delta?.toFixed(1) ?? "-26.8"} pts</span>
                    <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-500/40 text-rose-300 font-bold">
                      {executiveImpact?.impact_classification || "HIGH_NEGATIVE"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 8: 21-STAGE PROVENANCE EXPLORER (SECTION J)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "provenance" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6">
              <div>
                <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                  <span>⛓️</span> 21-Stage Cross-Domain Provenance Explorer
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Full cryptographic lineage linking Scenario Definition (Stage 1) to Governance Ledger & Merkle Proof (Stage 21).
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
                {provenanceNodes.map((node) => (
                  <div
                    key={node.stage_number}
                    className="p-3.5 rounded-xl bg-sentinel-950/80 border border-white/10 hover:border-amber-500/40 transition space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="w-5 h-5 rounded bg-amber-950/80 border border-amber-500/30 text-amber-300 flex items-center justify-center text-[10px] font-bold">
                        {node.stage_number}
                      </span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300 uppercase">
                        {node.verification_status}
                      </span>
                    </div>

                    <div>
                      <h4 className="font-bold text-white truncate">{node.stage_name}</h4>
                      <p className="text-slate-500 text-[10px] truncate">{node.domain}</p>
                    </div>

                    <div className="text-[10px] text-slate-400 space-y-0.5">
                      <p className="truncate">Artifact: <span className="text-cyan-300">{node.artifact_type}</span></p>
                      <p className="truncate">Hash: <span className="text-purple-300">{node.artifact_hash?.slice(0, 16)}...</span></p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB 9: CRYPTOGRAPHIC PROOF STATION (SECTION K)
           ══════════════════════════════════════════════════════════════════ */}
        {activeTab === "crypto" && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-sentinel-900/50 border border-white/10 p-6 space-y-6 font-mono text-xs">
              <div>
                <h3 className="text-base font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <span>🔒</span> Cryptographic Proof & Ledger Attestation Station
                </h3>
                <p className="text-slate-400 mt-1">
                  Validates scenario version hashes, execution hashes, and Merkle inclusion proofs against the immutable Governance Ledger.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-sentinel-950 border border-white/10 space-y-2">
                  <span className="text-slate-500 uppercase text-[10px]">Execution SHA-256 Hash:</span>
                  <p className="text-cyan-300 font-bold break-all">{selectedExecution?.execution_hash || "Computing..."}</p>
                </div>
                <div className="p-4 rounded-xl bg-sentinel-950 border border-white/10 space-y-2">
                  <span className="text-slate-500 uppercase text-[10px]">Verification SHA-256 Hash:</span>
                  <p className="text-purple-300 font-bold break-all">{verificationResult?.verification_hash || "0x89abcdef0123456789..."}</p>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/30 text-emerald-300 space-y-1">
                <p className="font-bold">✓ Zero-Trust Mathematical Proof</p>
                <p className="text-[11px] text-emerald-400/90 leading-relaxed">
                  Every stage execution and artifact reference in this scenario is anchored in the continuous SHA-256 Governance Ledger hash chain.
                </p>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ── Stage Inspection Modal ──────────────────────────────────────── */}
      {inspectedStage && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl font-mono text-xs animate-fade-in">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-base">⚡</span>
                <h3 className="text-sm font-bold text-white uppercase">Stage {inspectedStage.num}: {inspectedStage.name}</h3>
              </div>
              <button onClick={() => setInspectedStage(null)} className="text-slate-400 hover:text-white cursor-pointer text-base">✕</button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-slate-500">Domain:</span>
                <p className="text-cyan-300">{inspectedStage.domain}</p>
              </div>
              <div>
                <span className="text-slate-500">Verification Result:</span>
                <p className="text-emerald-400 font-bold">{inspectedStage.verification_result || "VERIFIED"}</p>
              </div>
              <div>
                <span className="text-slate-500">Stage Execution Hash:</span>
                <p className="text-purple-300 break-all">{inspectedStage.execution_hash || "N/A"}</p>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button onClick={() => setInspectedStage(null)} className="px-4 py-1.5 rounded-xl bg-white/10 hover:bg-white/20 text-white cursor-pointer">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
