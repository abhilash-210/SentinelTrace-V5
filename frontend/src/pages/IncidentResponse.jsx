/**
 * pages/IncidentResponse.jsx
 * --------------------------
 * Sprint 8B — Incident Response Governance, Containment Decision Engine & Human Authorization
 *
 * Core Principle: "SENTINELTRACE RECOMMENDS. HUMANS AUTHORIZE."
 * Deterministic playbook recommendations, Maker-Checker dual-control review,
 * execution attestation, response verification, and 17-stage cryptographic provenance.
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";

export default function IncidentResponse() {
  const { user } = useAuth();
  const token = localStorage.getItem("sentinel_token") || localStorage.getItem("token");

  const [activeTab, setActiveTab] = useState("workspace"); // workspace | review | execution | verification | provenance | playbooks
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState("");
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [playbooks, setPlaybooks] = useState([]);
  const [recommendations, setRecommendations] = useState([]);
  const [containmentRequests, setContainmentRequests] = useState([]);
  const [provenanceTrace, setProvenanceTrace] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Modal states
  const [proposeModalOpen, setProposeModalOpen] = useState(false);
  const [reviewModalOpen, setReviewModalOpen] = useState(false);
  const [executionModalOpen, setExecutionModalOpen] = useState(false);
  const [verificationModalOpen, setVerificationModalOpen] = useState(false);
  const [activeRequest, setActiveRequest] = useState(null);

  // Form states
  const [proposeForm, setProposeForm] = useState({
    action_type: "REVOKE_SESSION",
    action_description: "",
    impact_level: "HIGH_IMPACT",
    risk_justification: "",
    recommendation_id: "",
  });

  const [reviewForm, setReviewForm] = useState({
    decision: "APPROVE",
    reason: "",
  });

  const [executionForm, setExecutionForm] = useState({
    execution_status: "EXECUTION_ATTESTED",
    execution_reference: "",
    execution_notes: "",
  });

  const [verificationForm, setVerificationForm] = useState({
    verification_status: "VERIFIED",
    verification_method: "TELEMETRY_LOG_ANALYSIS",
    verification_evidence: "",
    verification_notes: "",
  });

  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  // ── Fetch Initial Data ───────────────────────────────────────────────────
  useEffect(() => {
    fetchIncidents();
    fetchPlaybooks();
    fetchContainmentRequests();
  }, []);

  useEffect(() => {
    if (selectedIncidentId) {
      const inc = incidents.find((i) => i.incident_id === selectedIncidentId);
      setSelectedIncident(inc || null);
      fetchRecommendations(selectedIncidentId);
      fetchProvenanceTrace(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/v1/incidents", { headers });
      if (res.ok) {
        const data = await res.json();
        setIncidents(data);
        if (data.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(data[0].incident_id);
          setSelectedIncident(data[0]);
        }
      }
    } catch (err) {
      console.error("Failed to load incidents", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchPlaybooks = async () => {
    try {
      const res = await fetch("/api/v1/incident-response/playbooks", { headers });
      if (res.ok) {
        const data = await res.json();
        setPlaybooks(data);
      }
    } catch (err) {
      console.error("Failed to load playbooks", err);
    }
  };

  const fetchRecommendations = async (incId) => {
    try {
      const res = await fetch(`/api/v1/incidents/${incId}/recommendations`, { headers });
      if (res.ok) {
        const data = await res.json();
        setRecommendations(data);
      }
    } catch (err) {
      console.error("Failed to load recommendations", err);
    }
  };

  const fetchContainmentRequests = async () => {
    try {
      const res = await fetch("/api/v1/containment-requests", { headers });
      if (res.ok) {
        const data = await res.json();
        setContainmentRequests(data);
      }
    } catch (err) {
      console.error("Failed to load containment requests", err);
    }
  };

  const fetchProvenanceTrace = async (incId) => {
    try {
      const res = await fetch(`/api/v1/incidents/${incId}/response-trace`, { headers });
      if (res.ok) {
        const data = await res.json();
        setProvenanceTrace(data);
      }
    } catch (err) {
      console.error("Failed to load provenance trace", err);
    }
  };

  const handleGenerateRecommendations = async () => {
    if (!selectedIncidentId) return;
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`/api/v1/incidents/${selectedIncidentId}/recommendations`, {
        method: "POST",
        headers,
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to generate recommendations");
      }
      const data = await res.json();
      setRecommendations(data);
      setSuccessMsg(`Generated ${data.length} deterministic containment recommendations.`);
      fetchProvenanceTrace(selectedIncidentId);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleProposeContainment = async (e) => {
    e.preventDefault();
    if (!selectedIncidentId) return;
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`/api/v1/incidents/${selectedIncidentId}/containment-requests`, {
        method: "POST",
        headers,
        body: JSON.stringify(proposeForm),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to propose containment request");
      }
      const newReq = await res.json();
      setSuccessMsg(`Containment request '${newReq.request_id}' created in PROPOSED state.`);
      setProposeModalOpen(false);
      setProposeForm({
        action_type: "REVOKE_SESSION",
        action_description: "",
        impact_level: "HIGH_IMPACT",
        risk_justification: "",
        recommendation_id: "",
      });
      fetchContainmentRequests();
      fetchProvenanceTrace(selectedIncidentId);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitForReview = async (requestId) => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`/api/v1/containment-requests/${requestId}/submit`, {
        method: "POST",
        headers,
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to submit request for review");
      }
      setSuccessMsg(`Containment request submitted for independent Maker-Checker review.`);
      fetchContainmentRequests();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReviewDecision = async (e) => {
    e.preventDefault();
    if (!activeRequest) return;
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`/api/v1/containment-requests/${activeRequest.request_id}/review`, {
        method: "POST",
        headers,
        body: JSON.stringify(reviewForm),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Review decision failed");
      }
      const updated = await res.json();
      setSuccessMsg(`Containment review completed: ${updated.status}.`);
      setReviewModalOpen(false);
      setActiveRequest(null);
      setReviewForm({ decision: "APPROVE", reason: "" });
      fetchContainmentRequests();
      if (selectedIncidentId) fetchProvenanceTrace(selectedIncidentId);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAttestExecution = async (e) => {
    e.preventDefault();
    if (!activeRequest) return;
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`/api/v1/containment-requests/${activeRequest.request_id}/attest-execution`, {
        method: "POST",
        headers,
        body: JSON.stringify(executionForm),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Execution attestation failed");
      }
      setSuccessMsg(`Human execution successfully attested in ledger.`);
      setExecutionModalOpen(false);
      setActiveRequest(null);
      setExecutionForm({
        execution_status: "EXECUTION_ATTESTED",
        execution_reference: "",
        execution_notes: "",
      });
      fetchContainmentRequests();
      if (selectedIncidentId) fetchProvenanceTrace(selectedIncidentId);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyResponse = async (e) => {
    e.preventDefault();
    if (!activeRequest) return;
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`/api/v1/containment-requests/${activeRequest.request_id}/verify`, {
        method: "POST",
        headers,
        body: JSON.stringify(verificationForm),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Response verification failed");
      }
      setSuccessMsg(`Response verification recorded. Incident state updated.`);
      setVerificationModalOpen(false);
      setActiveRequest(null);
      setVerificationForm({
        verification_status: "VERIFIED",
        verification_method: "TELEMETRY_LOG_ANALYSIS",
        verification_evidence: "",
        verification_notes: "",
      });
      fetchContainmentRequests();
      fetchIncidents();
      if (selectedIncidentId) fetchProvenanceTrace(selectedIncidentId);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Helper counts
  const pendingReviewCount = containmentRequests.filter((r) => r.status === "PENDING_REVIEW").length;
  const approvedCount = containmentRequests.filter((r) => r.status === "APPROVED").length;
  const executedCount = containmentRequests.filter((r) => r.status === "EXECUTION_ATTESTED").length;
  const verifiedCount = containmentRequests.filter((r) => r.status === "VERIFIED").length;

  return (
    <div className="flex-1 flex flex-col h-full bg-slate-950 text-slate-100 overflow-y-auto">
      {/* ── Top Hero Header ───────────────────────────────────────────────── */}
      <header className="px-8 py-6 bg-slate-900/60 border-b border-white/10 backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="text-2xl">🛑</span>
              <h1 className="text-2xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
                Incident Response Command Center
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  Sprint 8B Live
                </span>
              </h1>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Deterministic Playbook Recommendations • Maker-Checker Dual-Control Authorization • Cryptographic Attestation
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="px-3.5 py-1.5 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 text-xs font-mono font-medium flex items-center gap-2 shadow-sm">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              SENTINELTRACE RECOMMENDS. HUMANS AUTHORIZE.
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 text-xs font-mono">
              Role: <span className="text-cyan-400 font-semibold">{user?.role || "ANALYST"}</span>
            </div>
          </div>
        </div>

        {/* Global Notifications */}
        {error && (
          <div className="mt-4 p-3 rounded-lg bg-rose-950/60 border border-rose-500/50 text-rose-300 text-xs font-mono flex items-center justify-between animate-fade-in">
            <div className="flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
            <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">✕</button>
          </div>
        )}

        {successMsg && (
          <div className="mt-4 p-3 rounded-lg bg-emerald-950/60 border border-emerald-500/50 text-emerald-300 text-xs font-mono flex items-center justify-between animate-fade-in">
            <div className="flex items-center gap-2">
              <span>✓</span>
              <span>{successMsg}</span>
            </div>
            <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200">✕</button>
          </div>
        )}

        {/* ── 5 Executive KPI Cards ────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-6">
          <div className="p-3.5 rounded-xl bg-slate-800/60 border border-white/5 shadow-inner">
            <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Response Playbooks</div>
            <div className="text-xl font-bold font-mono text-cyan-400 mt-1">{playbooks.length} Active</div>
            <div className="text-[10px] text-slate-500 mt-0.5">100% Deterministic Matching</div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-800/60 border border-white/5 shadow-inner">
            <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Pending Dual-Control</div>
            <div className="text-xl font-bold font-mono text-amber-400 mt-1">{pendingReviewCount} Requests</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Independent Review Required</div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-800/60 border border-white/5 shadow-inner">
            <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Approved / In-Flight</div>
            <div className="text-xl font-bold font-mono text-indigo-400 mt-1">{approvedCount} Authorized</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Awaiting Human Execution</div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-800/60 border border-white/5 shadow-inner">
            <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Attested Executions</div>
            <div className="text-xl font-bold font-mono text-purple-400 mt-1">{executedCount} Executed</div>
            <div className="text-[10px] text-slate-500 mt-0.5">SHA-256 Sealed in Ledger</div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-800/60 border border-white/5 shadow-inner">
            <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Verified Contained</div>
            <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{verifiedCount} Verified</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Validated against Telemetry</div>
          </div>
        </div>

        {/* ── Tab Navigation ──────────────────────────────────────────────── */}
        <div className="flex items-center gap-2 mt-6 border-b border-white/5">
          <button
            onClick={() => setActiveTab("workspace")}
            className={`px-4 py-2.5 text-xs font-mono rounded-t-lg transition-all ${
              activeTab === "workspace"
                ? "bg-slate-800 text-cyan-300 border-t-2 border-cyan-400 font-semibold"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
            }`}
          >
            Incident Containment Workspace
          </button>

          <button
            onClick={() => setActiveTab("review")}
            className={`px-4 py-2.5 text-xs font-mono rounded-t-lg transition-all flex items-center gap-2 ${
              activeTab === "review"
                ? "bg-slate-800 text-amber-300 border-t-2 border-amber-400 font-semibold"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
            }`}
          >
            Dual-Control Review Queue
            {pendingReviewCount > 0 && (
              <span className="px-1.5 py-0.2 text-[10px] rounded-full bg-amber-500 text-slate-950 font-bold">
                {pendingReviewCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab("execution")}
            className={`px-4 py-2.5 text-xs font-mono rounded-t-lg transition-all ${
              activeTab === "execution"
                ? "bg-slate-800 text-purple-300 border-t-2 border-purple-400 font-semibold"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
            }`}
          >
            Execution Attestation
          </button>

          <button
            onClick={() => setActiveTab("verification")}
            className={`px-4 py-2.5 text-xs font-mono rounded-t-lg transition-all ${
              activeTab === "verification"
                ? "bg-slate-800 text-emerald-300 border-t-2 border-emerald-400 font-semibold"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
            }`}
          >
            Response Verification
          </button>

          <button
            onClick={() => setActiveTab("provenance")}
            className={`px-4 py-2.5 text-xs font-mono rounded-t-lg transition-all ${
              activeTab === "provenance"
                ? "bg-slate-800 text-cyan-300 border-t-2 border-cyan-400 font-semibold"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
            }`}
          >
            17-Stage Provenance Trace
          </button>

          <button
            onClick={() => setActiveTab("playbooks")}
            className={`px-4 py-2.5 text-xs font-mono rounded-t-lg transition-all ${
              activeTab === "playbooks"
                ? "bg-slate-800 text-slate-200 border-t-2 border-slate-400 font-semibold"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
            }`}
          >
            Playbook Catalog ({playbooks.length})
          </button>
        </div>
      </header>

      {/* ── Main Tab Content Area ─────────────────────────────────────────── */}
      <main className="p-8 flex-1">
        {/* ── TAB 1: INCIDENT CONTAINMENT WORKSPACE ───────────────────────── */}
        {activeTab === "workspace" && (
          <div className="space-y-6">
            {/* Top Selector Bar */}
            <div className="p-4 rounded-xl bg-slate-900 border border-white/10 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <span className="text-xs text-slate-400 font-mono">Active Investigation:</span>
                <select
                  value={selectedIncidentId}
                  onChange={(e) => setSelectedIncidentId(e.target.value)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs font-mono focus:outline-none focus:border-cyan-400"
                >
                  {incidents.map((inc) => (
                    <option key={inc.incident_id} value={inc.incident_id}>
                      {inc.incident_number} — {inc.title} ({inc.severity})
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleGenerateRecommendations}
                  disabled={loading || !selectedIncidentId}
                  className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition-all flex items-center gap-2 disabled:opacity-50"
                >
                  <span>⚡</span> Generate Deterministic Recommendations
                </button>
                <button
                  onClick={() => setProposeModalOpen(true)}
                  className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono transition-all flex items-center gap-2"
                >
                  <span>➕</span> Propose Containment Request
                </button>
              </div>
            </div>

            {/* Incident Summary Card */}
            {selectedIncident && (
              <div className="p-5 rounded-xl bg-slate-900/80 border border-white/10">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-white/10 pb-3">
                  <div>
                    <div className="text-xs font-mono text-cyan-400 font-semibold">{selectedIncident.incident_number}</div>
                    <h2 className="text-lg font-bold text-white mt-0.5">{selectedIncident.title}</h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-1 rounded bg-rose-950/80 border border-rose-500/50 text-rose-300 text-xs font-mono font-bold">
                      {selectedIncident.severity}
                    </span>
                    <span className="px-2.5 py-1 rounded bg-amber-950/80 border border-amber-500/50 text-amber-300 text-xs font-mono font-bold">
                      {selectedIncident.priority}
                    </span>
                    <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 text-xs font-mono">
                      Status: <strong className="text-cyan-400">{selectedIncident.status}</strong>
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 text-xs font-mono">
                  <div>
                    <span className="text-slate-400 block">Root Cause Summary:</span>
                    <span className="text-slate-200 mt-1 block">{selectedIncident.root_cause_summary || "Multi-signal synthesis"}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Contributing Signals:</span>
                    <span className="text-cyan-300 mt-1 block">{selectedIncident.affected_signal_count} Signals • {selectedIncident.affected_rule_count} Detection Rules</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Synthesis Confidence:</span>
                    <span className="text-emerald-400 mt-1 block">{Math.round((selectedIncident.confidence || 0.95) * 100)}% Deterministic</span>
                  </div>
                </div>
              </div>
            )}

            {/* Recommendations Grid */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold font-mono text-slate-200 flex items-center gap-2">
                  <span>📋</span> Deterministic Containment Recommendations ({recommendations.length})
                </h3>
                <span className="text-xs text-slate-400 font-mono">Governed by matched incident playbook</span>
              </div>

              {recommendations.length === 0 ? (
                <div className="p-8 rounded-xl bg-slate-900/40 border border-white/5 text-center text-slate-400 font-mono text-xs">
                  No recommendations generated yet for this incident. Click "Generate Deterministic Recommendations" above.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {recommendations.map((rec) => (
                    <div key={rec.recommendation_id} className="p-5 rounded-xl bg-slate-900 border border-white/10 hover:border-cyan-500/40 transition-all space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-500/30 text-cyan-300 text-[10px] font-mono font-bold">
                          {rec.action_type}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                            rec.impact_level === "CRITICAL_IMPACT"
                              ? "bg-rose-950 text-rose-300 border border-rose-500/40"
                              : rec.impact_level === "HIGH_IMPACT"
                              ? "bg-amber-950 text-amber-300 border border-amber-500/40"
                              : "bg-slate-800 text-slate-300"
                          }`}>
                            {rec.impact_level}
                          </span>
                          <span className="text-xs font-mono text-emerald-400 font-bold">
                            {Math.round((rec.confidence_score || 0.9) * 100)}% Conf
                          </span>
                        </div>
                      </div>

                      <div className="text-xs font-mono text-slate-300 leading-relaxed">
                        {rec.reasoning}
                      </div>

                      <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[11px] font-mono">
                        <div className="text-slate-400">
                          Dual-Control: <strong className={rec.risk_context?.requires_dual_control ? "text-amber-400" : "text-slate-300"}>
                            {rec.risk_context?.requires_dual_control ? "MANDATORY" : "OPTIONAL"}
                          </strong>
                        </div>
                        <button
                          onClick={() => {
                            setProposeForm({
                              action_type: rec.action_type,
                              action_description: `Executing recommended action ${rec.action_key}`,
                              impact_level: rec.impact_level,
                              risk_justification: rec.reasoning,
                              recommendation_id: rec.recommendation_id,
                            });
                            setProposeModalOpen(true);
                          }}
                          className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 text-xs font-mono"
                        >
                          Adopt & Propose →
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Existing Containment Requests for this incident */}
            <div className="space-y-3 mt-8">
              <h3 className="text-sm font-bold font-mono text-slate-200 flex items-center gap-2">
                <span>🛡️</span> Containment Requests ({containmentRequests.filter(r => r.incident_id === selectedIncidentId).length})
              </h3>

              <div className="rounded-xl border border-white/10 bg-slate-900 overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-800/80 text-slate-400 border-b border-white/10 uppercase text-[10px]">
                    <tr>
                      <th className="p-3">Request ID</th>
                      <th className="p-3">Action Type</th>
                      <th className="p-3">Impact</th>
                      <th className="p-3">Proposer (Maker)</th>
                      <th className="p-3">Status</th>
                      <th className="p-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {containmentRequests
                      .filter((r) => !selectedIncidentId || r.incident_id === selectedIncidentId)
                      .map((req) => (
                        <tr key={req.request_id} className="hover:bg-white/[0.02]">
                          <td className="p-3 font-bold text-cyan-400">{req.request_id}</td>
                          <td className="p-3 text-slate-200">{req.action_type}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] ${
                              req.impact_level === "CRITICAL_IMPACT" ? "bg-rose-950 text-rose-300" : "bg-slate-800 text-slate-300"
                            }`}>
                              {req.impact_level}
                            </span>
                          </td>
                          <td className="p-3 text-slate-400">{req.proposed_by_user_id}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              req.status === "APPROVED"
                                ? "bg-indigo-950 text-indigo-300 border border-indigo-500/40"
                                : req.status === "PENDING_REVIEW"
                                ? "bg-amber-950 text-amber-300 border border-amber-500/40"
                                : req.status === "VERIFIED"
                                ? "bg-emerald-950 text-emerald-300 border border-emerald-500/40"
                                : req.status === "EXECUTION_ATTESTED"
                                ? "bg-purple-950 text-purple-300 border border-purple-500/40"
                                : "bg-slate-800 text-slate-300"
                            }`}>
                              {req.status}
                            </span>
                          </td>
                          <td className="p-3 text-right space-x-2">
                            {req.status === "PROPOSED" && (
                              <button
                                onClick={() => handleSubmitForReview(req.request_id)}
                                className="px-2 py-1 rounded bg-amber-900/60 hover:bg-amber-800 text-amber-300 text-[11px]"
                              >
                                Submit for Review →
                              </button>
                            )}
                            {req.status === "PENDING_REVIEW" && (
                              <button
                                onClick={() => {
                                  setActiveRequest(req);
                                  setReviewModalOpen(true);
                                }}
                                className="px-2 py-1 rounded bg-indigo-900/60 hover:bg-indigo-800 text-indigo-300 text-[11px]"
                              >
                                Review Decision →
                              </button>
                            )}
                            {req.status === "APPROVED" && (
                              <button
                                onClick={() => {
                                  setActiveRequest(req);
                                  setExecutionModalOpen(true);
                                }}
                                className="px-2 py-1 rounded bg-purple-900/60 hover:bg-purple-800 text-purple-300 text-[11px]"
                              >
                                Attest Execution →
                              </button>
                            )}
                            {req.status === "EXECUTION_ATTESTED" && (
                              <button
                                onClick={() => {
                                  setActiveRequest(req);
                                  setVerificationModalOpen(true);
                                }}
                                className="px-2 py-1 rounded bg-emerald-900/60 hover:bg-emerald-800 text-emerald-300 text-[11px]"
                              >
                                Verify Telemetry →
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ── TAB 2: DUAL-CONTROL REVIEW QUEUE ────────────────────────────── */}
        {activeTab === "review" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold font-mono text-white flex items-center gap-2">
                  <span>⚖️</span> Maker-Checker Dual-Control Authorization Queue
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  High-impact containment actions require independent human approval. Proposers cannot self-approve.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4">
              {containmentRequests
                .filter((r) => r.status === "PENDING_REVIEW")
                .map((req) => (
                  <div key={req.request_id} className="p-5 rounded-xl bg-slate-900 border border-amber-500/30 space-y-4">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <span className="text-xl">⚠️</span>
                        <div>
                          <div className="text-xs font-mono text-amber-400 font-bold">{req.request_id}</div>
                          <h4 className="text-sm font-bold text-white">{req.action_type}: {req.action_description}</h4>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="px-2.5 py-1 rounded bg-amber-950 text-amber-300 border border-amber-500/50 text-xs font-mono font-bold">
                          PENDING DUAL-CONTROL
                        </span>
                        <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-300 border border-rose-500/50 text-xs font-mono font-bold">
                          {req.impact_level}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 rounded-lg bg-slate-950/60 text-xs font-mono">
                      <div>
                        <span className="text-slate-500">Incident Target:</span>
                        <span className="text-slate-300 block">{req.incident_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Proposed By (Maker):</span>
                        <span className="text-cyan-300 block font-semibold">{req.proposed_by_user_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Risk Justification:</span>
                        <span className="text-slate-300 block truncate">{req.risk_justification}</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between pt-2 border-t border-white/5">
                      <div className="text-[11px] font-mono text-slate-400">
                        Maker-Checker Guard: <span className="text-emerald-400 font-semibold">Enforced (HTTP 409 Block on Self-Approval)</span>
                      </div>
                      <button
                        onClick={() => {
                          setActiveRequest(req);
                          setReviewModalOpen(true);
                        }}
                        className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-mono transition-all font-semibold"
                      >
                        Perform Dual-Control Review →
                      </button>
                    </div>
                  </div>
                ))}

              {containmentRequests.filter((r) => r.status === "PENDING_REVIEW").length === 0 && (
                <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-white/5 text-slate-400 font-mono text-xs">
                  ✓ No containment requests pending dual-control review.
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── TAB 3: EXECUTION ATTESTATION ────────────────────────────────── */}
        {activeTab === "execution" && (
          <div className="space-y-6">
            <div>
              <h2 className="text-lg font-bold font-mono text-white flex items-center gap-2">
                <span>⚡</span> Human Execution Attestation Station
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Authorized containment actions executed in external firewalls/EDR/IAM must be cryptographically attested by the human operator.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4">
              {containmentRequests
                .filter((r) => r.status === "APPROVED")
                .map((req) => (
                  <div key={req.request_id} className="p-5 rounded-xl bg-slate-900 border border-indigo-500/40 space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-xs font-mono text-indigo-400 font-bold">{req.request_id} (AUTHORIZED)</div>
                        <h4 className="text-sm font-bold text-white">{req.action_type}: {req.action_description}</h4>
                      </div>
                      <span className="px-2.5 py-1 rounded bg-indigo-950 text-indigo-300 border border-indigo-500/50 text-xs font-mono font-bold">
                        AWAITING ATTESTATION
                      </span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/60 text-xs font-mono grid grid-cols-3 gap-2">
                      <div>
                        <span className="text-slate-500">Approved By (Checker):</span>
                        <span className="text-emerald-300 block">{req.approved_by_user_id || "SOC Reviewer"}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Target Incident:</span>
                        <span className="text-slate-300 block">{req.incident_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Approved At:</span>
                        <span className="text-slate-300 block">{req.approved_at || "Recent"}</span>
                      </div>
                    </div>

                    <div className="flex justify-end">
                      <button
                        onClick={() => {
                          setActiveRequest(req);
                          setExecutionModalOpen(true);
                        }}
                        className="px-4 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-mono font-semibold"
                      >
                        Record Execution Attestation →
                      </button>
                    </div>
                  </div>
                ))}

              {containmentRequests.filter((r) => r.status === "APPROVED").length === 0 && (
                <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-white/5 text-slate-400 font-mono text-xs">
                  ✓ No authorized actions currently awaiting human execution attestation.
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── TAB 4: RESPONSE VERIFICATION ────────────────────────────────── */}
        {activeTab === "verification" && (
          <div className="space-y-6">
            <div>
              <h2 className="text-lg font-bold font-mono text-white flex items-center gap-2">
                <span>🔍</span> Post-Response Telemetry Verification
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Validate that containment severed attacker communications and that telemetry confirms a clean state before closing the incident.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4">
              {containmentRequests
                .filter((r) => ["EXECUTION_ATTESTED", "VERIFIED", "VERIFICATION_PENDING"].includes(r.status))
                .map((req) => (
                  <div key={req.request_id} className="p-5 rounded-xl bg-slate-900 border border-white/10 space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="text-xs font-mono text-cyan-400 font-bold">{req.request_id}</span>
                        <h4 className="text-sm font-bold text-white">{req.action_type}</h4>
                      </div>
                      <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
                        req.status === "VERIFIED"
                          ? "bg-emerald-950 text-emerald-300 border border-emerald-500/50"
                          : "bg-purple-950 text-purple-300 border border-purple-500/50"
                      }`}>
                        {req.status}
                      </span>
                    </div>

                    <div className="text-xs font-mono text-slate-300">
                      {req.action_description}
                    </div>

                    <div className="flex justify-end pt-2 border-t border-white/5">
                      {req.status !== "VERIFIED" ? (
                        <button
                          onClick={() => {
                            setActiveRequest(req);
                            setVerificationModalOpen(true);
                          }}
                          className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-semibold"
                        >
                          Verify Telemetry Effectiveness →
                        </button>
                      ) : (
                        <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                          ✓ Response Cryptographically Verified & Sealed
                        </span>
                      )}
                    </div>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* ── TAB 5: 17-STAGE PROVENANCE TRACE ────────────────────────────── */}
        {activeTab === "provenance" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold font-mono text-white flex items-center gap-2">
                  <span>🌲</span> 17-Stage Cryptographic Provenance & Incident Audit Trail
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  End-to-end verifiable chain linking Raw Evidence through Semantic Trust, Incident Correlation, Playbook Matching, Maker-Checker Review, Execution, and Merkle Proof.
                </p>
              </div>

              {provenanceTrace && (
                <div className="px-3 py-1 rounded-lg bg-cyan-950 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-bold">
                  {provenanceTrace.total_stages}/17 Stages Complete
                </div>
              )}
            </div>

            {provenanceTrace && (
              <div className="space-y-3">
                {provenanceTrace.stages.map((stage) => (
                  <div
                    key={stage.stage_number}
                    className="p-4 rounded-xl bg-slate-900 border border-white/10 hover:border-cyan-500/30 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
                  >
                    <div className="flex items-start gap-3.5">
                      <div className="w-8 h-8 rounded-lg bg-slate-800 border border-white/10 text-cyan-400 flex items-center justify-center font-mono font-bold text-xs flex-shrink-0">
                        {stage.stage_number}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-bold text-white">{stage.stage_name}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                            {stage.entity_type}
                          </span>
                        </div>
                        <p className="text-xs font-mono text-slate-300 mt-1">{stage.summary}</p>
                      </div>
                    </div>

                    <div className="flex flex-col items-end text-right font-mono text-[11px] space-y-1 flex-shrink-0">
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                        stage.status === "VERIFIED_SEALED" || stage.status === "VERIFIED" || stage.status === "TRUSTED"
                          ? "bg-emerald-950 text-emerald-300 border border-emerald-500/30"
                          : stage.status === "NOT_AVAILABLE"
                          ? "bg-slate-800 text-slate-500"
                          : "bg-cyan-950 text-cyan-300 border border-cyan-500/30"
                      }`}>
                        {stage.status}
                      </span>
                      <span className="text-slate-500 text-[10px] truncate max-w-[200px]" title={stage.hash_reference}>
                        Hash: {stage.hash_reference ? stage.hash_reference.slice(0, 16) + "..." : "N/A"}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── TAB 6: PLAYBOOK CATALOG ─────────────────────────────────────── */}
        {activeTab === "playbooks" && (
          <div className="space-y-6">
            <div>
              <h2 className="text-lg font-bold font-mono text-white flex items-center gap-2">
                <span>📚</span> Deterministic Incident Response Playbooks
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Standardized containment playbooks with mandatory sequence ordering and dual-control impact classification.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {playbooks.map((pb) => (
                <div key={pb.playbook_id} className="p-6 rounded-xl bg-slate-900 border border-white/10 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="px-2.5 py-1 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-bold">
                      {pb.playbook_id}
                    </span>
                    <span className="text-xs font-mono text-slate-400">Min Severity: <strong>{pb.minimum_severity}</strong></span>
                  </div>

                  <div>
                    <h3 className="text-base font-bold text-white">{pb.name}</h3>
                    <p className="text-xs text-slate-400 mt-1">{pb.description}</p>
                  </div>

                  <div className="space-y-2 pt-2 border-t border-white/10">
                    <div className="text-xs font-mono text-slate-400 font-semibold">Playbook Actions ({pb.actions?.length || 0}):</div>
                    <div className="space-y-1.5">
                      {pb.actions?.map((act) => (
                        <div key={act.action_key} className="p-2.5 rounded-lg bg-slate-950/80 border border-white/5 flex items-center justify-between text-xs font-mono">
                          <div className="flex items-center gap-2">
                            <span className="text-slate-500 font-bold">#{act.sequence_number}</span>
                            <span className="text-slate-200">{act.action_name}</span>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] ${
                            act.requires_dual_control ? "bg-amber-950 text-amber-300 border border-amber-500/40" : "bg-slate-800 text-slate-400"
                          }`}>
                            {act.requires_dual_control ? "DUAL-CONTROL" : "AUTO/DIRECT"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* ── MODALS ────────────────────────────────────────────────────────── */}

      {/* 1. PROPOSE CONTAINMENT MODAL */}
      {proposeModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-white/10 p-6 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>➕</span> Propose Containment Request (Maker)
              </h3>
              <button onClick={() => setProposeModalOpen(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <form onSubmit={handleProposeContainment} className="space-y-4">
              <div>
                <label className="text-slate-400 block mb-1">Action Type</label>
                <select
                  value={proposeForm.action_type}
                  onChange={(e) => setProposeForm({ ...proposeForm, action_type: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="REVOKE_SESSION">REVOKE_SESSION (Identity / IAM)</option>
                  <option value="RESET_CREDENTIALS">RESET_CREDENTIALS (Password / API Key)</option>
                  <option value="ISOLATE_ENDPOINT">ISOLATE_ENDPOINT (Host / EDR Isolation)</option>
                  <option value="BLOCK_NETWORK">BLOCK_NETWORK (Perimeter Firewall Rule)</option>
                  <option value="SUSPEND_ACCOUNT">SUSPEND_ACCOUNT (Directory Lockdown)</option>
                  <option value="QUARANTINE_FILE">QUARANTINE_FILE (Malware Remediation)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Action Description</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Immediately revoke SSO tokens for compromised account."
                  value={proposeForm.action_description}
                  onChange={(e) => setProposeForm({ ...proposeForm, action_description: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Impact Level</label>
                <select
                  value={proposeForm.impact_level}
                  onChange={(e) => setProposeForm({ ...proposeForm, impact_level: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="LOW_IMPACT">LOW_IMPACT (Preservation / Analytical)</option>
                  <option value="MEDIUM_IMPACT">MEDIUM_IMPACT (Session termination)</option>
                  <option value="HIGH_IMPACT">HIGH_IMPACT (Perimeter Block / Credential Reset)</option>
                  <option value="CRITICAL_IMPACT">CRITICAL_IMPACT (Endpoint Isolation / Service Suspension)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Risk Justification & Supporting Evidence</label>
                <textarea
                  rows={3}
                  required
                  placeholder="Explain why this containment action is necessary based on telemetry..."
                  value={proposeForm.risk_justification}
                  onChange={(e) => setProposeForm({ ...proposeForm, risk_justification: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="pt-3 border-t border-white/10 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setProposeModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold"
                >
                  Propose Containment Request
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 2. DUAL-CONTROL REVIEW MODAL */}
      {reviewModalOpen && activeRequest && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-amber-500/40 p-6 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>⚖️</span> Dual-Control Maker-Checker Review
              </h3>
              <button onClick={() => setReviewModalOpen(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 text-slate-300 space-y-1">
              <div>Request: <strong className="text-cyan-400">{activeRequest.request_id}</strong></div>
              <div>Action: <strong>{activeRequest.action_type}</strong> ({activeRequest.impact_level})</div>
              <div>Proposed by: <strong className="text-amber-400">{activeRequest.proposed_by_user_id}</strong></div>
              <div className="text-[11px] text-slate-400 mt-1">{activeRequest.risk_justification}</div>
            </div>

            <form onSubmit={handleReviewDecision} className="space-y-4">
              <div>
                <label className="text-slate-400 block mb-1">Review Decision</label>
                <select
                  value={reviewForm.decision}
                  onChange={(e) => setReviewForm({ ...reviewForm, decision: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="APPROVE">APPROVE (Authorize Human Execution)</option>
                  <option value="REJECT">REJECT (Decline Containment Action)</option>
                  <option value="REQUEST_CHANGES">REQUEST_CHANGES (Return to Maker for Revision)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Review Reason & SOC Rationale</label>
                <textarea
                  rows={3}
                  required
                  placeholder="Provide independent verification rationale..."
                  value={reviewForm.reason}
                  onChange={(e) => setReviewForm({ ...reviewForm, reason: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="pt-3 border-t border-white/10 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setReviewModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold"
                >
                  Submit Dual-Control Decision
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 3. EXECUTION ATTESTATION MODAL */}
      {executionModalOpen && activeRequest && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-purple-500/40 p-6 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>⚡</span> Attest External Human Execution
              </h3>
              <button onClick={() => setExecutionModalOpen(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <form onSubmit={handleAttestExecution} className="space-y-4">
              <div>
                <label className="text-slate-400 block mb-1">Execution Status</label>
                <select
                  value={executionForm.execution_status}
                  onChange={(e) => setExecutionForm({ ...executionForm, execution_status: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="EXECUTION_ATTESTED">EXECUTION_ATTESTED (Action Applied Successfully)</option>
                  <option value="EXECUTION_FAILED">EXECUTION_FAILED (Infrastructure Error / Timeout)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">External Change Reference / Ticket ID</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. CHG-2026-00492 or EDR-TASK-8812"
                  value={executionForm.execution_reference}
                  onChange={(e) => setExecutionForm({ ...executionForm, execution_reference: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Execution Notes</label>
                <textarea
                  rows={3}
                  required
                  placeholder="Details of external firewall rule insertion or EDR isolation..."
                  value={executionForm.execution_notes}
                  onChange={(e) => setExecutionForm({ ...executionForm, execution_notes: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="pt-3 border-t border-white/10 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setExecutionModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold"
                >
                  Seal Attestation in Ledger
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 4. POST-RESPONSE VERIFICATION MODAL */}
      {verificationModalOpen && activeRequest && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-emerald-500/40 p-6 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>🔍</span> Telemetry Response Verification
              </h3>
              <button onClick={() => setVerificationModalOpen(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <form onSubmit={handleVerifyResponse} className="space-y-4">
              <div>
                <label className="text-slate-400 block mb-1">Verification Status</label>
                <select
                  value={verificationForm.verification_status}
                  onChange={(e) => setVerificationForm({ ...verificationForm, verification_status: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="VERIFIED">VERIFIED (Adversary Activity Ceased • Incident Contained)</option>
                  <option value="FAILED">FAILED (Threat Persists / Egress Observed)</option>
                  <option value="INCONCLUSIVE">INCONCLUSIVE (Awaiting Telemetry Batch)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Verification Method</label>
                <select
                  value={verificationForm.verification_method}
                  onChange={(e) => setVerificationForm({ ...verificationForm, verification_method: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="TELEMETRY_LOG_ANALYSIS">TELEMETRY_LOG_ANALYSIS (Fresh normalized event streams)</option>
                  <option value="EDR_POLLING">EDR_POLLING (Endpoint agent isolation heartbeat)</option>
                  <option value="FIREWALL_DROP_CONFIRMATION">FIREWALL_DROP_CONFIRMATION (Perimeter drop telemetry)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Verification Evidence & Log References</label>
                <textarea
                  rows={3}
                  required
                  placeholder="Specify verified log IDs or telemetry observations..."
                  value={verificationForm.verification_evidence}
                  onChange={(e) => setVerificationForm({ ...verificationForm, verification_evidence: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="pt-3 border-t border-white/10 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setVerificationModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold"
                >
                  Confirm & Update Incident Status
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
