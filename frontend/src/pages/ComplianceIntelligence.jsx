/**
 * ComplianceIntelligence.jsx
 * --------------------------
 * Cyber SOC Compliance Intelligence, Security Control Governance & Evidence-Backed Assurance Command Center.
 *
 * Sprint 11A — Compliance Intelligence, Security Control Governance & Evidence-Backed Compliance Assurance.
 * Core Invariant: "COMPLIANCE MUST BE EVIDENCE-BACKED, EXPLAINABLE, HUMAN-GOVERNED, AND CRYPTOGRAPHICALLY VERIFIABLE."
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";

const API_BASE = "/api/v1/compliance";

export default function ComplianceIntelligence() {
  const { user, token } = useAuth();
  const [activeTab, setActiveTab] = useState("frameworks"); // frameworks, controls, gaps, governance, provenance
  const [loading, setLoading] = useState(false);
  const [metrics, setMetrics] = useState(null);
  const [frameworks, setFrameworks] = useState([]);
  const [selectedFramework, setSelectedFramework] = useState(null);
  const [frameworkRequirements, setFrameworkRequirements] = useState([]);
  const [latestPosture, setLatestPosture] = useState(null);
  const [controls, setControls] = useState([]);
  const [selectedControl, setSelectedControl] = useState(null);
  const [controlEvaluations, setControlEvaluations] = useState([]);
  const [controlBindings, setControlBindings] = useState([]);
  const [gaps, setGaps] = useState([]);
  const [findings, setFindings] = useState([]);
  const [reviews, setReviews] = useState([]);
  const [provenance, setProvenance] = useState(null);
  const [statusMessage, setStatusMessage] = useState(null);

  // Modals state
  const [showEvaluateModal, setShowEvaluateModal] = useState(false);
  const [showResolveGapModal, setShowResolveGapModal] = useState(null);
  const [gapResolutionSummary, setGapResolutionSummary] = useState("");
  const [showCreateFindingModal, setShowCreateFindingModal] = useState(false);
  const [newFindingData, setNewFindingData] = useState({
    framework_requirement_id: "",
    security_control_id: "",
    title: "",
    description: "",
    severity: "HIGH",
    finding_type: "NON_CONFORMANCE",
    remediation_plan: "",
  });
  const [showReviewModal, setShowReviewModal] = useState(null);
  const [reviewNotes, setReviewNotes] = useState("");
  const [forceCryptoFailureToggle, setForceCryptoFailureToggle] = useState(false);

  // Headers helper
  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  });

  // Fetch initial dashboard metrics
  const fetchMetrics = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/command-center`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch (err) {
      console.error("Failed to load metrics", err);
    } finally {
      setLoading(false);
    }
  };

  // Fetch frameworks
  const fetchFrameworks = async () => {
    try {
      const res = await fetch(`${API_BASE}/frameworks`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setFrameworks(data);
        if (data.length > 0 && !selectedFramework) {
          selectFramework(data[0]);
        }
      }
    } catch (err) {
      console.error("Failed to load frameworks", err);
    }
  };

  // Select framework & load posture + requirements
  const selectFramework = async (fw) => {
    setSelectedFramework(fw);
    try {
      const reqRes = await fetch(`${API_BASE}/frameworks/${fw.id}/requirements`, { headers: getAuthHeaders() });
      if (reqRes.ok) {
        const reqData = await reqRes.json();
        setFrameworkRequirements(reqData);
      }
      const posRes = await fetch(`${API_BASE}/posture/${fw.id}/latest`, { headers: getAuthHeaders() });
      if (posRes.ok) {
        const posData = await posRes.json();
        setLatestPosture(posData);
      }
    } catch (err) {
      console.error("Failed to load framework details", err);
    }
  };

  // Fetch controls
  const fetchControls = async () => {
    try {
      const res = await fetch(`${API_BASE}/controls`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setControls(data);
        if (data.length > 0 && !selectedControl) {
          selectControl(data[0]);
        }
      }
    } catch (err) {
      console.error("Failed to load controls", err);
    }
  };

  // Select control & load details
  const selectControl = async (ctrl) => {
    setSelectedControl(ctrl);
    try {
      const evalRes = await fetch(`${API_BASE}/controls/${ctrl.id}/evaluations`, { headers: getAuthHeaders() });
      if (evalRes.ok) {
        const evalData = await evalRes.json();
        setControlEvaluations(evalData);
      }
      const bindRes = await fetch(`${API_BASE}/controls/${ctrl.id}/evidence-bindings`, { headers: getAuthHeaders() });
      if (bindRes.ok) {
        const bindData = await bindRes.json();
        setControlBindings(bindData);
      }
    } catch (err) {
      console.error("Failed to load control info", err);
    }
  };

  // Fetch gaps
  const fetchGaps = async () => {
    try {
      const res = await fetch(`${API_BASE}/gaps`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setGaps(data);
      }
    } catch (err) {
      console.error("Failed to load gaps", err);
    }
  };

  // Fetch findings & reviews
  const fetchGovernance = async () => {
    try {
      const fRes = await fetch(`${API_BASE}/findings`, { headers: getAuthHeaders() });
      if (fRes.ok) {
        const fData = await fRes.json();
        setFindings(fData);
      }
      const rRes = await fetch(`${API_BASE}/reviews`, { headers: getAuthHeaders() });
      if (rRes.ok) {
        const rData = await rRes.json();
        setReviews(rData);
      }
    } catch (err) {
      console.error("Failed to load governance data", err);
    }
  };

  // Fetch Provenance
  const fetchProvenance = async (entityType, entityId) => {
    try {
      const res = await fetch(`${API_BASE}/provenance/${entityType}/${entityId}`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setProvenance(data);
      }
    } catch (err) {
      console.error("Failed to load provenance", err);
    }
  };

  useEffect(() => {
    fetchMetrics();
    fetchFrameworks();
    fetchControls();
    fetchGaps();
    fetchGovernance();
  }, []);

  // Action: Seed Defaults
  const handleSeedDefaults = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/seed-defaults`, {
        method: "POST",
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        setStatusMessage({ type: "success", text: "Default Compliance Baseline seeded successfully (3 Frameworks, 30+ Requirements, 12 Controls)." });
        fetchMetrics();
        fetchFrameworks();
        fetchControls();
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: "Failed to seed default baseline." });
    } finally {
      setLoading(false);
    }
  };

  // Action: Evaluate Framework Posture
  const handleEvaluateFrameworkPosture = async (frameworkId) => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/posture/${frameworkId}/evaluate?trigger_source=MANUAL_SOC_TRIGGER`, {
        method: "POST",
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setLatestPosture(data);
        setStatusMessage({ type: "success", text: `Evaluated ${selectedFramework?.framework_code} Posture: ${data.posture_status} (${data.overall_posture_score?.toFixed(1) ?? "--"}/100.0)` });
        fetchMetrics();
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: "Posture evaluation failed." });
    } finally {
      setLoading(false);
    }
  };

  // Action: Evaluate Control
  const handleEvaluateControl = async () => {
    if (!selectedControl) return;
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/controls/${selectedControl.id}/evaluate`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          trigger_source: "SOC_MANUAL_EVALUATION",
          force_crypto_failure: forceCryptoFailureToggle,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMessage({
          type: data.cryptographic_integrity_status === "FAILED" ? "warning" : "success",
          text: `Control ${selectedControl.control_code} evaluated: ${data.effectiveness_status} (${data.effectiveness_score?.toFixed(1) ?? "--"}/100.0). Crypto: ${data.cryptographic_integrity_status}`,
        });
        selectControl(selectedControl);
        fetchControls();
        fetchMetrics();
        setShowEvaluateModal(false);
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: "Control evaluation failed." });
    } finally {
      setLoading(false);
    }
  };

  // Action: Scan Gaps
  const handleScanGaps = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/gaps/scan`, {
        method: "POST",
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setGaps(data);
        setStatusMessage({ type: "success", text: `Compliance gap scan completed. Found ${data.length} active gaps.` });
        fetchMetrics();
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: "Gap scan failed." });
    } finally {
      setLoading(false);
    }
  };

  // Action: Resolve Gap
  const handleResolveGap = async () => {
    if (!showResolveGapModal) return;
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/gaps/${showResolveGapModal.id}/resolve`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          resolution_summary: gapResolutionSummary || "Remediated operational controls and attached verified evidence.",
        }),
      });
      if (res.ok) {
        setStatusMessage({ type: "success", text: `Gap ${showResolveGapModal.id} marked as RESOLVED.` });
        setShowResolveGapModal(null);
        setGapResolutionSummary("");
        fetchGaps();
        fetchMetrics();
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: "Failed to resolve gap." });
    } finally {
      setLoading(false);
    }
  };

  // Action: Submit Maker-Checker Review
  const handleSubmitReview = async (decision) => {
    if (!showReviewModal) return;
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/reviews`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          review_type: showReviewModal.review_type || "COMPLIANCE_FINDING",
          target_entity_id: showReviewModal.id,
          review_decision: decision,
          review_notes: reviewNotes || `Dual governance ${decision} by ${user?.username}.`,
          initiator_user_id: showReviewModal.creator_user_id || showReviewModal.evaluator_id,
          initiator_username: showReviewModal.creator_username || showReviewModal.evaluator_username,
        }),
      });

      if (res.status === 409) {
        const errData = await res.json();
        setStatusMessage({
          type: "error",
          text: `Maker-Checker Violation: ${errData.detail || "Self-approval is strictly forbidden."}`,
        });
        return;
      }

      if (res.ok) {
        setStatusMessage({ type: "success", text: `Governance review submitted: ${decision}.` });
        setShowReviewModal(null);
        setReviewNotes("");
        fetchGovernance();
        fetchMetrics();
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: "Governance review submission failed." });
    } finally {
      setLoading(false);
    }
  };

  // Helper colors
  const getScoreColor = (score) => {
    if (score >= 90) return "text-emerald-400 border-emerald-500/30 bg-emerald-950/20";
    if (score >= 75) return "text-cyan-400 border-cyan-500/30 bg-cyan-950/20";
    if (score >= 50) return "text-amber-400 border-amber-500/30 bg-amber-950/20";
    return "text-rose-400 border-rose-500/30 bg-rose-950/20";
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-rose-950/60 text-rose-300 border-rose-500/50";
      case "HIGH":
        return "bg-amber-950/60 text-amber-300 border-amber-500/50";
      case "MEDIUM":
        return "bg-blue-950/60 text-blue-300 border-blue-500/50";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  return (
    <main className="flex-1 overflow-y-auto bg-sentinel-950 text-slate-100 p-6 space-y-6">
      {/* 1. Header & Command Center Overview */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 border-b border-sentinel-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-3xl">⚖️</span>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-mono flex items-center gap-3">
                Cyber SOC Compliance Command Center
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-950 border border-cyan-500/40 text-cyan-300 font-mono">
                  Sprint 11A Live
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Deterministic Security Control Governance, Evidence-Backed Assurance & 22-Stage Provenance.
              </p>
            </div>
          </div>
        </div>

        {/* Global Action Bar */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleSeedDefaults}
            disabled={loading}
            className="px-3.5 py-2 rounded-lg bg-sentinel-800 hover:bg-sentinel-700 text-slate-300 text-xs font-mono border border-sentinel-700 transition"
          >
            🌱 Seed Baseline
          </button>
          <button
            onClick={handleScanGaps}
            disabled={loading}
            className="px-3.5 py-2 rounded-lg bg-accent-cyan/10 hover:bg-accent-cyan/20 text-accent-cyan text-xs font-mono border border-accent-cyan/30 transition"
          >
            🔍 Scan Framework Gaps
          </button>
          {selectedFramework && (
            <button
              onClick={() => handleEvaluateFrameworkPosture(selectedFramework.id)}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-gradient-to-r from-accent-cyan to-accent-emerald hover:opacity-90 text-sentinel-950 font-semibold text-xs font-mono shadow-md transition"
            >
              ⚡ Evaluate Framework Posture
            </button>
          )}
        </div>
      </div>

      {/* Status Alert Banner */}
      {statusMessage && (
        <div
          className={`p-3.5 rounded-lg border text-xs font-mono flex items-center justify-between ${
            statusMessage.type === "success"
              ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-300"
              : statusMessage.type === "warning"
              ? "bg-amber-950/40 border-amber-500/40 text-amber-300"
              : "bg-rose-950/40 border-rose-500/40 text-rose-300"
          }`}
        >
          <span>{statusMessage.text}</span>
          <button onClick={() => setStatusMessage(null)} className="text-slate-400 hover:text-slate-200">
            ✕
          </button>
        </div>
      )}

      {/* 2. Top-Level KPI Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Global Compliance Index */}
        <div className="bg-sentinel-900/60 border border-sentinel-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>GLOBAL COMPLIANCE INDEX</span>
            <span>🌐</span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className={`text-3xl font-extrabold font-mono ${metrics?.global_compliance_index >= 90 ? 'text-emerald-400' : metrics?.global_compliance_index >= 75 ? 'text-cyan-400' : 'text-amber-400'}`}>
              {metrics?.global_compliance_index != null ? metrics.global_compliance_index.toFixed(1) : "--"}
            </span>
            <span className="text-xs text-slate-500">/ 100.0</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            {metrics?.total_frameworks || 3} Registered Frameworks
          </div>
        </div>

        {/* Security Controls */}
        <div className="bg-sentinel-900/60 border border-sentinel-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>SECURITY CONTROLS</span>
            <span>🛡️</span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-cyan-300">
              {metrics ? metrics.total_controls : "--"}
            </span>
            <span className="text-xs text-emerald-400 font-mono">
              ({metrics ? metrics.effective_controls : 0} Effective)
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            {metrics?.partially_effective_controls || 0} Partial | {metrics?.ineffective_controls || 0} Ineffective
          </div>
        </div>

        {/* Active Compliance Gaps */}
        <div className="bg-sentinel-900/60 border border-sentinel-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>ACTIVE GAPS</span>
            <span>⚠️</span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className={`text-3xl font-extrabold font-mono ${metrics?.critical_gaps_count > 0 ? 'text-rose-400' : 'text-amber-400'}`}>
              {metrics ? metrics.active_gaps_count : "--"}
            </span>
            <span className="text-xs text-rose-400 font-mono">
              ({metrics ? metrics.critical_gaps_count : 0} Critical)
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            {metrics?.high_gaps_count || 0} High Severity Gaps
          </div>
        </div>

        {/* Formal Findings */}
        <div className="bg-sentinel-900/60 border border-sentinel-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>OPEN FINDINGS</span>
            <span>📑</span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-purple-300">
              {metrics ? metrics.open_findings_count : "--"}
            </span>
            <span className="text-xs text-slate-500 font-mono">Formal Records</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            Requires Dual Human Sign-off
          </div>
        </div>

        {/* Maker-Checker Queue */}
        <div className="bg-sentinel-900/60 border border-sentinel-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>MAKER-CHECKER QUEUE</span>
            <span>👥</span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-emerald-400">
              {metrics ? metrics.pending_reviews_count : "--"}
            </span>
            <span className="text-xs text-slate-500 font-mono">Pending Review</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            Self-Approval Forbidden (HTTP 409)
          </div>
        </div>
      </div>

      {/* 3. Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-sentinel-800 text-xs font-mono">
        <button
          onClick={() => setActiveTab("frameworks")}
          className={`px-4 py-2.5 border-b-2 font-medium transition ${
            activeTab === "frameworks"
              ? "border-accent-cyan text-accent-cyan bg-accent-cyan/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          🏛️ Framework Posture & Requirements
        </button>
        <button
          onClick={() => setActiveTab("controls")}
          className={`px-4 py-2.5 border-b-2 font-medium transition ${
            activeTab === "controls"
              ? "border-accent-cyan text-accent-cyan bg-accent-cyan/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          🛡️ Security Controls & Deductions ({controls.length})
        </button>
        <button
          onClick={() => setActiveTab("gaps")}
          className={`px-4 py-2.5 border-b-2 font-medium transition ${
            activeTab === "gaps"
              ? "border-accent-cyan text-accent-cyan bg-accent-cyan/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          ⚠️ Gap Fingerprints & Remediation ({gaps.length})
        </button>
        <button
          onClick={() => setActiveTab("governance")}
          className={`px-4 py-2.5 border-b-2 font-medium transition ${
            activeTab === "governance"
              ? "border-accent-cyan text-accent-cyan bg-accent-cyan/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          ⚖️ Maker-Checker Human Governance
        </button>
        <button
          onClick={() => {
            setActiveTab("provenance");
            if (latestPosture) {
              fetchProvenance("COMPLIANCE_POSTURE", latestPosture.id);
            } else if (selectedControl) {
              fetchProvenance("SECURITY_CONTROL", selectedControl.id);
            }
          }}
          className={`px-4 py-2.5 border-b-2 font-medium transition ${
            activeTab === "provenance"
              ? "border-accent-cyan text-accent-cyan bg-accent-cyan/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          🌲 22-Stage Compliance Lineage
        </button>
      </div>

      {/* 4. Tab 1: Framework Posture & Requirements */}
      {activeTab === "frameworks" && (
        <div className="space-y-6 animate-fade-in">
          {/* Framework Selector Pills */}
          <div className="flex flex-wrap items-center gap-3">
            {frameworks.map((fw) => (
              <button
                key={fw.id}
                onClick={() => selectFramework(fw)}
                className={`px-4 py-2 rounded-xl text-xs font-mono border transition ${
                  selectedFramework?.id === fw.id
                    ? "bg-accent-cyan/15 border-accent-cyan text-accent-cyan shadow-sm"
                    : "bg-sentinel-900 border-sentinel-800 text-slate-400 hover:bg-sentinel-800"
                }`}
              >
                <span className="font-semibold">{fw.framework_code}</span> — {fw.framework_name}
              </button>
            ))}
          </div>

          {selectedFramework && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Framework Posture Card */}
              <div className="bg-sentinel-900/70 border border-sentinel-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {selectedFramework.framework_category}
                  </span>
                  <span className="text-xs font-mono text-slate-500">v{selectedFramework.framework_version}</span>
                </div>
                <div>
                  <h3 className="text-lg font-bold font-mono text-slate-100">{selectedFramework.framework_name}</h3>
                  <p className="text-xs text-slate-400 mt-1">{selectedFramework.description}</p>
                </div>

                {latestPosture ? (
                  <div className="border-t border-sentinel-800 pt-4 space-y-3 font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-slate-400">POSTURE SCORE</span>
                      <span className={`text-xl font-bold px-2 py-0.5 rounded border ${getScoreColor(latestPosture.overall_posture_score)}`}>
                        {latestPosture.overall_posture_score?.toFixed(1) ?? "--"} / 100.0
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400">STATUS</span>
                      <span className="font-bold text-slate-200">{latestPosture.posture_status}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400">REQUIREMENTS</span>
                      <span className="text-slate-300">
                        {latestPosture.compliant_requirements_count} / {latestPosture.total_requirements_count} Compliant
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400">ACTIVE GAPS</span>
                      <span className="text-amber-400">{latestPosture.total_gaps_count} Gaps</span>
                    </div>
                    <div className="text-[11px] text-slate-400 bg-sentinel-950 p-2.5 rounded border border-sentinel-850 leading-relaxed">
                      {latestPosture.posture_summary}
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-6 text-slate-500 text-xs font-mono">
                    Posture has not been evaluated yet.
                  </div>
                )}
              </div>

              {/* Requirements & Mapped Controls Matrix */}
              <div className="lg:col-span-2 bg-sentinel-900/70 border border-sentinel-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-sentinel-800 pb-3">
                  <h4 className="text-sm font-bold font-mono text-slate-200">
                    Framework Requirements & Control Bindings ({frameworkRequirements.length})
                  </h4>
                  <span className="text-xs text-slate-500 font-mono">Zero Trust Axiom: UNKNOWN != COMPLIANT</span>
                </div>

                <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
                  {frameworkRequirements.map((req) => (
                    <div
                      key={req.id}
                      className="p-3.5 rounded-lg bg-sentinel-950 border border-sentinel-800/80 hover:border-accent-cyan/40 transition font-mono space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-accent-cyan">{req.requirement_code}</span>
                          <span className="text-xs text-slate-200 font-semibold">{req.title}</span>
                        </div>
                        <div className="flex items-center gap-2 text-[11px]">
                          {req.is_mandatory && (
                            <span className="px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-500/40">
                              MANDATORY
                            </span>
                          )}
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                            Weight: {req.weight}
                          </span>
                        </div>
                      </div>
                      <p className="text-xs text-slate-400">{req.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 5. Tab 2: Security Controls & Deductions */}
      {activeTab === "controls" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in">
          {/* Controls List */}
          <div className="bg-sentinel-900/70 border border-sentinel-800 rounded-xl p-5 space-y-3">
            <h4 className="text-sm font-bold font-mono text-slate-200 border-b border-sentinel-800 pb-2">
              Registered Security Controls ({controls.length})
            </h4>
            <div className="space-y-2 max-h-[550px] overflow-y-auto pr-1">
              {controls.map((ctrl) => (
                <div
                  key={ctrl.id}
                  onClick={() => selectControl(ctrl)}
                  className={`p-3 rounded-lg border cursor-pointer transition font-mono ${
                    selectedControl?.id === ctrl.id
                      ? "bg-accent-cyan/10 border-accent-cyan text-slate-100 shadow-sm"
                      : "bg-sentinel-950 border-sentinel-800 text-slate-400 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-accent-cyan">{ctrl.control_code}</span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded border ${
                        ctrl.current_effectiveness_status === "EFFECTIVE"
                          ? "bg-emerald-950 text-emerald-300 border-emerald-500/40"
                          : ctrl.current_effectiveness_status === "PARTIALLY_EFFECTIVE"
                          ? "bg-amber-950 text-amber-300 border-amber-500/40"
                          : "bg-rose-950 text-rose-300 border-rose-500/40"
                      }`}
                    >
                      {ctrl.current_effectiveness_status || "PENDING"}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-slate-200 mt-1 truncate">{ctrl.control_name}</div>
                  <div className="flex items-center justify-between text-[11px] text-slate-500 mt-2">
                    <span>Domain: {ctrl.domain}</span>
                    <span>Score: {ctrl.current_effectiveness_score?.toFixed(1) || "--"}/100</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Control Detail & Deductions Inspector */}
          {selectedControl && (
            <div className="lg:col-span-2 bg-sentinel-900/70 border border-sentinel-800 rounded-xl p-5 space-y-5">
              <div className="flex items-start justify-between border-b border-sentinel-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-accent-cyan font-mono">{selectedControl.control_code}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      {selectedControl.criticality} CRITICALITY
                    </span>
                  </div>
                  <h3 className="text-base font-bold font-mono text-slate-100 mt-1">{selectedControl.control_name}</h3>
                  <p className="text-xs text-slate-400 mt-1">{selectedControl.description}</p>
                </div>

                <button
                  onClick={() => setShowEvaluateModal(true)}
                  className="px-3.5 py-1.5 rounded-lg bg-accent-cyan text-sentinel-950 font-bold text-xs font-mono hover:opacity-90 transition"
                >
                  ⚡ Evaluate Control
                </button>
              </div>

              {/* Latest Evaluation Breakdown */}
              {controlEvaluations.length > 0 ? (
                <div className="space-y-4 font-mono">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="bg-sentinel-950 p-3 rounded-lg border border-sentinel-800">
                      <div className="text-[10px] text-slate-500">SCORE & STATUS</div>
                      <div className="text-lg font-bold text-accent-cyan mt-1">
                        {controlEvaluations[0].effectiveness_score?.toFixed(1) ?? "--"} / 100
                      </div>
                      <div className="text-[11px] text-slate-400">{controlEvaluations[0].effectiveness_status}</div>
                    </div>
                    <div className="bg-sentinel-950 p-3 rounded-lg border border-sentinel-800">
                      <div className="text-[10px] text-slate-500">OPERATIONAL STATE</div>
                      <div className="text-lg font-bold text-emerald-400 mt-1">
                        {controlEvaluations[0].operational_state}
                      </div>
                      <div className="text-[11px] text-slate-400">Healthy Telemetry</div>
                    </div>
                    <div className="bg-sentinel-950 p-3 rounded-lg border border-sentinel-800">
                      <div className="text-[10px] text-slate-500">CRYPTO INTEGRITY</div>
                      <div className={`text-lg font-bold mt-1 ${controlEvaluations[0].cryptographic_integrity_status === 'FAILED' ? 'text-rose-400' : 'text-cyan-400'}`}>
                        {controlEvaluations[0].cryptographic_integrity_status}
                      </div>
                      <div className="text-[11px] text-slate-400">Zero Dominance</div>
                    </div>
                    <div className="bg-sentinel-950 p-3 rounded-lg border border-sentinel-800">
                      <div className="text-[10px] text-slate-500">EVIDENCE COUNT</div>
                      <div className="text-lg font-bold text-slate-200 mt-1">
                        {controlEvaluations[0].verified_evidence_count} / {controlEvaluations[0].total_evidence_count}
                      </div>
                      <div className="text-[11px] text-slate-400">{controlEvaluations[0].stale_evidence_count} Stale</div>
                    </div>
                  </div>

                  {/* Explainable Deductions List */}
                  <div>
                    <h5 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                      Explainable Deductions ({controlEvaluations[0].deductions_json?.length || 0})
                    </h5>
                    {controlEvaluations[0].deductions_json?.length > 0 ? (
                      <div className="space-y-2">
                        {controlEvaluations[0].deductions_json.map((d, i) => (
                          <div key={i} className="p-2.5 rounded bg-rose-950/30 border border-rose-500/30 text-xs flex items-start justify-between">
                            <div>
                              <div className="font-bold text-rose-300">{d.rule}</div>
                              <div className="text-slate-400 mt-0.5">{d.reason}</div>
                            </div>
                            <span className="font-bold text-rose-400 shrink-0 ml-3">-{d.deduction} pts</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-3 rounded bg-emerald-950/20 border border-emerald-500/20 text-xs text-emerald-300">
                        ✓ No deductions triggered. Control satisfies 100% of baseline criteria.
                      </div>
                    )}
                  </div>

                  {/* Upstream Evidence Bindings */}
                  <div>
                    <h5 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                      Bound Upstream Evidence ({controlBindings.length})
                    </h5>
                    <div className="space-y-1.5 max-h-36 overflow-y-auto">
                      {controlBindings.map((b) => (
                        <div key={b.id} className="p-2 rounded bg-sentinel-950 border border-sentinel-800 text-[11px] flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-slate-400 font-bold">{b.evidence_type}</span>
                            <span className="text-slate-500">Stage: {b.source_stage}</span>
                          </div>
                          <span className="text-accent-cyan font-mono">{b.evidence_hash.substring(0, 12)}...</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-10 text-slate-500 text-xs font-mono">
                  No evaluation history. Click "Evaluate Control" to trigger scoring.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 6. Tab 3: Compliance Gaps & Deduplicated Remediation */}
      {activeTab === "gaps" && (
        <div className="space-y-4 animate-fade-in font-mono">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200">
              Deduplicated Compliance Gaps ({gaps.length})
            </h3>
            <span className="text-xs text-slate-500">
              SHA-256 Fingerprint Deduplication Active
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {gaps.map((gap) => (
              <div
                key={gap.id}
                className="bg-sentinel-900/80 border border-sentinel-800 rounded-xl p-4 space-y-3 hover:border-slate-700 transition"
              >
                <div className="flex items-center justify-between">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadge(gap.severity)}`}>
                    {gap.severity}
                  </span>
                  <span className="text-[10px] text-slate-500">Status: {gap.status}</span>
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-200">{gap.gap_title}</h4>
                  <p className="text-[11px] text-slate-400 mt-1">{gap.description}</p>
                </div>
                <div className="p-2 rounded bg-sentinel-950 border border-sentinel-850 text-[10px] space-y-1">
                  <div>
                    <span className="text-slate-500">Fingerprint: </span>
                    <span className="text-accent-cyan">{gap.gap_fingerprint.substring(0, 16)}...</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Root Cause: </span>
                    <span className="text-slate-300">{gap.root_cause_rule}</span>
                  </div>
                </div>
                {gap.status !== "RESOLVED" && (
                  <button
                    onClick={() => setShowResolveGapModal(gap)}
                    className="w-full py-1.5 rounded-lg bg-accent-cyan/15 hover:bg-accent-cyan/25 text-accent-cyan text-xs font-bold border border-accent-cyan/30 transition"
                  >
                    Resolve Gap with Evidence
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 7. Tab 4: Maker-Checker Governance & Findings */}
      {activeTab === "governance" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fade-in font-mono">
          {/* Findings List */}
          <div className="bg-sentinel-900/70 border border-sentinel-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-sentinel-800 pb-3">
              <h4 className="text-sm font-bold text-slate-200">Formal Compliance Findings ({findings.length})</h4>
              <button
                onClick={() => setShowCreateFindingModal(true)}
                className="px-3 py-1 rounded bg-accent-cyan text-sentinel-950 font-bold text-xs"
              >
                + Create Finding
              </button>
            </div>

            <div className="space-y-3 max-h-[500px] overflow-y-auto">
              {findings.map((f) => (
                <div key={f.id} className="p-3.5 rounded-lg bg-sentinel-950 border border-sentinel-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200">{f.title}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded border ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{f.description}</p>
                  <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1 border-t border-sentinel-850">
                    <span>Author: {f.creator_username}</span>
                    <span>Status: {f.status}</span>
                  </div>
                  {f.status === "OPEN" && (
                    <button
                      onClick={() => setShowReviewModal(f)}
                      className="w-full mt-2 py-1 rounded bg-purple-950/60 hover:bg-purple-900 text-purple-300 text-xs border border-purple-500/40"
                    >
                      Dual-Control Review
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Maker-Checker Completed Reviews */}
          <div className="bg-sentinel-900/70 border border-sentinel-800 rounded-xl p-5 space-y-4">
            <h4 className="text-sm font-bold text-slate-200 border-b border-sentinel-800 pb-3">
              Governance Audit Ledger Reviews ({reviews.length})
            </h4>
            <div className="space-y-3 max-h-[500px] overflow-y-auto">
              {reviews.map((r) => (
                <div key={r.id} className="p-3 rounded-lg bg-sentinel-950 border border-sentinel-800 space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-300">{r.review_type}</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-[10px]">
                      {r.review_decision}
                    </span>
                  </div>
                  <div className="text-slate-400">{r.review_notes}</div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                    <span>Reviewer: {r.reviewer_username}</span>
                    <span>Hash: {r.review_hash.substring(0, 12)}...</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 8. Tab 5: 22-Stage Compliance Lineage */}
      {activeTab === "provenance" && (
        <div className="bg-sentinel-900/70 border border-sentinel-800 rounded-xl p-5 space-y-5 animate-fade-in font-mono">
          <div className="flex items-center justify-between border-b border-sentinel-800 pb-3">
            <div>
              <h3 className="text-base font-bold text-slate-100">
                22-Stage Unbroken Cryptographic Compliance Provenance
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Full cryptographic trace from Stage 1 (Raw Ingest) to Stage 22 (Merkle Batch Ledger Proof).
              </p>
            </div>
            {provenance && (
              <span className="text-xs px-3 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40">
                STATUS: {provenance.verification_status}
              </span>
            )}
          </div>

          {provenance ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {provenance.lineage_stages_json?.map((st) => (
                <div key={st.stage_number} className="p-3 rounded-lg bg-sentinel-950 border border-sentinel-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-accent-cyan">Stage {st.stage_number}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-emerald-300">
                      {st.verification_status}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-slate-200">{st.stage_name}</div>
                  <p className="text-[10px] text-slate-400">{st.description}</p>
                  <div className="text-[9px] text-slate-500 pt-1 font-mono truncate">
                    Hash: {st.stage_hash}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-slate-500 text-xs">
              Loading 22-stage lineage records...
            </div>
          )}
        </div>
      )}

      {/* Evaluate Control Modal */}
      {showEvaluateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-sentinel-800 rounded-xl max-w-md w-full p-6 space-y-4 font-mono">
            <h3 className="text-base font-bold text-slate-100">Evaluate Control Effectiveness</h3>
            <p className="text-xs text-slate-400">
              Trigger deterministic evaluation for {selectedControl?.control_code}.
            </p>

            <div className="p-3 rounded bg-sentinel-950 border border-sentinel-800 space-y-2">
              <label className="flex items-center gap-2 text-xs text-rose-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={forceCryptoFailureToggle}
                  onChange={(e) => setForceCryptoFailureToggle(e.target.checked)}
                  className="rounded bg-sentinel-900 border-sentinel-700 text-rose-500"
                />
                Simulate Cryptographic Verification Failure
              </label>
              <p className="text-[10px] text-slate-500 leading-relaxed">
                Axiom Test: Cryptographic failure strictly forces control score to 0.0 and status to INEFFECTIVE.
              </p>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setShowEvaluateModal(false)}
                className="px-4 py-2 rounded bg-sentinel-800 text-slate-300 text-xs hover:bg-sentinel-700"
              >
                Cancel
              </button>
              <button
                onClick={handleEvaluateControl}
                className="px-4 py-2 rounded bg-accent-cyan text-sentinel-950 font-bold text-xs hover:opacity-90"
              >
                Execute Evaluation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Resolve Gap Modal */}
      {showResolveGapModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-sentinel-800 rounded-xl max-w-md w-full p-6 space-y-4 font-mono">
            <h3 className="text-base font-bold text-slate-100">Resolve Compliance Gap</h3>
            <p className="text-xs text-slate-400">{showResolveGapModal.gap_title}</p>
            <textarea
              value={gapResolutionSummary}
              onChange={(e) => setGapResolutionSummary(e.target.value)}
              placeholder="Enter resolution notes and evidence verification details..."
              className="w-full h-24 p-3 rounded bg-sentinel-950 border border-sentinel-800 text-xs text-slate-200 focus:outline-none focus:border-accent-cyan"
            />
            <div className="flex items-center justify-end gap-3">
              <button
                onClick={() => setShowResolveGapModal(null)}
                className="px-4 py-2 rounded bg-sentinel-800 text-slate-300 text-xs hover:bg-sentinel-700"
              >
                Cancel
              </button>
              <button
                onClick={handleResolveGap}
                className="px-4 py-2 rounded bg-accent-cyan text-sentinel-950 font-bold text-xs hover:opacity-90"
              >
                Mark Resolved
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Maker-Checker Review Modal */}
      {showReviewModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-sentinel-800 rounded-xl max-w-md w-full p-6 space-y-4 font-mono">
            <h3 className="text-base font-bold text-slate-100">Maker-Checker Dual Governance</h3>
            <div className="p-3 rounded bg-amber-950/30 border border-amber-500/30 text-xs text-amber-300">
              ⚠️ Invariant: Submitting user ({showReviewModal.creator_username || showReviewModal.evaluator_username}) cannot approve their own record.
            </div>
            <textarea
              value={reviewNotes}
              onChange={(e) => setReviewNotes(e.target.value)}
              placeholder="Enter formal governance review justification..."
              className="w-full h-24 p-3 rounded bg-sentinel-950 border border-sentinel-800 text-xs text-slate-200 focus:outline-none focus:border-accent-cyan"
            />
            <div className="flex items-center justify-end gap-2">
              <button
                onClick={() => setShowReviewModal(null)}
                className="px-3 py-1.5 rounded bg-sentinel-800 text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                onClick={() => handleSubmitReview("REJECTED")}
                className="px-3 py-1.5 rounded bg-rose-950 text-rose-300 border border-rose-500/40 text-xs"
              >
                Reject
              </button>
              <button
                onClick={() => handleSubmitReview("APPROVED")}
                className="px-4 py-1.5 rounded bg-emerald-600 text-white font-bold text-xs hover:bg-emerald-500"
              >
                Approve
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
