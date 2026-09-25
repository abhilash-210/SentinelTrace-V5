/**
 * pages/DetectionRuleGovernance.jsx
 * ---------------------------------
 * Detection Rule Governance, Dual-Control Approval, Rule Versioning,
 * Version Impact Analysis, and Immutable Governance Auditability.
 *
 * Sprint 6C — Verifiable Detection Rule Lifecycle & Maker-Checker Governance.
 *
 * Core Cybersecurity Principle:
 * "Detection logic is a governed security asset. A detection rule must not become
 * operational merely because it was created."
 *
 * Sections:
 * - Section A: Governance Overview Hero & Verifiable Lifecycle Pipeline
 * - Section B: Governed Rule Version Registry (with filters, badges, and actions)
 * - Section C: Version Lineage Visualizer (parent-child trees and active version marker)
 * - Section D: Side-by-Side Version Comparison & Deterministic Impact Modal
 * - Section E: Pre-Approval Hypothetical Trust Simulation Panel
 * - Section F: Dual-Control Maker-Checker Approval Panel (Self-Approval Blocker)
 * - Section G: Governance Lifecycle Timeline
 * - Section H: Immutable Cryptographic Governance Audit Log
 * - Section I: 15-Stage Governance Provenance Trace Modal
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { API_V1_URL } from "../apiConfig";

const API_BASE = API_V1_URL;

const STATUS_CONFIG = {
  DRAFT: {
    label: "Draft",
    bg: "bg-slate-900/80 border-slate-700 text-slate-300",
    dot: "bg-slate-400",
    badge: "bg-slate-950/60 border-slate-700 text-slate-400",
  },
  PENDING_REVIEW: {
    label: "Pending Review",
    bg: "bg-amber-950/40 border-amber-500/40 text-amber-300",
    dot: "bg-amber-400 animate-pulse",
    badge: "bg-amber-950/80 border-amber-500/50 text-amber-300",
  },
  APPROVED: {
    label: "Approved",
    bg: "bg-indigo-950/40 border-indigo-500/40 text-indigo-300",
    dot: "bg-indigo-400",
    badge: "bg-indigo-950/80 border-indigo-500/50 text-indigo-300",
  },
  REJECTED: {
    label: "Rejected",
    bg: "bg-red-950/40 border-red-500/40 text-red-300",
    dot: "bg-red-400",
    badge: "bg-red-950/80 border-red-500/50 text-red-300",
  },
  ACTIVE: {
    label: "Active",
    bg: "bg-emerald-950/40 border-emerald-500/40 text-emerald-300",
    dot: "bg-emerald-400 shadow-[0_0_8px_#10b981]",
    badge: "bg-emerald-950/80 border-emerald-500/60 text-emerald-200",
  },
  SUPERSEDED: {
    label: "Superseded",
    bg: "bg-zinc-900/60 border-zinc-700/60 text-zinc-400",
    dot: "bg-zinc-500",
    badge: "bg-zinc-950/80 border-zinc-700/80 text-zinc-400",
  },
  DISABLED: {
    label: "Disabled",
    bg: "bg-rose-950/30 border-rose-800/40 text-rose-400",
    dot: "bg-rose-500",
    badge: "bg-rose-950/80 border-rose-800/60 text-rose-300",
  },
};

const IMPACT_COLORS = {
  NONE: "bg-slate-900/60 border-slate-700 text-slate-300",
  LOW: "bg-blue-950/60 border-blue-600/40 text-blue-300",
  MEDIUM: "bg-yellow-950/60 border-yellow-500/40 text-yellow-300",
  HIGH: "bg-orange-950/60 border-orange-500/50 text-orange-300",
  CRITICAL: "bg-red-950/80 border-red-500/70 text-red-200 shadow-[0_0_10px_rgba(239,68,68,0.2)]",
};

export default function DetectionRuleGovernance() {
  const { token, user, hasPermission } = useAuth();

  // Data states
  const [versions, setVersions] = useState([]);
  const [rules, setRules] = useState([]);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Filter states
  const [selectedRuleFilter, setSelectedRuleFilter] = useState("ALL");
  const [selectedStatusFilter, setSelectedStatusFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  // Modals & inspect states
  const [selectedVersion, setSelectedVersion] = useState(null);
  const [compareModalOpen, setCompareModalOpen] = useState(false);
  const [compareTargetVersionId, setCompareTargetVersionId] = useState("");
  const [comparisonResult, setComparisonResult] = useState(null);
  const [comparisonLoading, setComparisonLoading] = useState(false);

  const [simulationModalOpen, setSimulationModalOpen] = useState(false);
  const [simulationResult, setSimulationResult] = useState(null);
  const [simulationLoading, setSimulationLoading] = useState(false);

  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [createFormData, setCreateFormData] = useState({
    rule_id: "",
    rule_name: "",
    vendor_name: "CISCO_ASA",
    description: "",
    query_signature: "",
    severity: "HIGH",
    mitre_techniques: ["T1110.001"],
    dependencies: ["authentication.outcome", "target_user"],
  });

  const [reviewModalOpen, setReviewModalOpen] = useState(false);
  const [reviewForm, setReviewForm] = useState({
    decision: "APPROVE",
    comment: "",
    risk_acknowledged: false,
    risk_acknowledgement_comment: "",
  });

  const [traceModalOpen, setTraceModalOpen] = useState(false);
  const [governanceTrace, setGovernanceTrace] = useState(null);
  const [traceLoading, setTraceLoading] = useState(false);

  const authHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };

  // Fetch initial data
  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [versionsRes, rulesRes, eventsRes] = await Promise.all([
        fetch(`${API_BASE}/detection-rule-versions`, { headers: authHeaders }),
        fetch(`${API_BASE}/detection-rules`, { headers: authHeaders }),
        fetch(`${API_BASE}/detection-rule-governance/events`, { headers: authHeaders }),
      ]);

      if (!versionsRes.ok || !rulesRes.ok) {
        throw new Error("Failed to load governance registry data.");
      }

      const versionsData = await versionsRes.json();
      const rulesData = await rulesRes.json();
      const eventsData = eventsRes.ok ? await eventsRes.json() : [];

      setVersions(versionsData);
      setRules(rulesData);
      setEvents(eventsData);

      if (versionsData.length > 0 && !selectedVersion) {
        setSelectedVersion(versionsData[0]);
      }
    } catch (err) {
      console.error(err);
      setError(err.message || "Error fetching detection governance data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [token]);

  // Flash notification helper
  const notifySuccess = (msg) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 5000);
  };

  // Handle Create Version
  const handleCreateVersion = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/detection-rules/${createFormData.rule_id}/versions`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          rule_name: createFormData.rule_name,
          vendor_name: createFormData.vendor_name,
          description: createFormData.description,
          query_signature: createFormData.query_signature,
          severity: createFormData.severity,
          mitre_techniques: createFormData.mitre_techniques,
          dependencies: createFormData.dependencies.map((f) => ({
            canonical_field: f,
            dependency_type: "REQUIRED",
          })),
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Failed to create detection rule version.");
      }

      const newVer = await res.json();
      notifySuccess(`Rule version ${newVer.version_id} (v${newVer.version_number}) created successfully.`);
      setCreateModalOpen(false);
      fetchData();
    } catch (err) {
      setError(err.message);
    }
  };

  // Handle Submit for Review
  const handleSubmitForReview = async (versionId) => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/detection-rule-versions/${versionId}/submit`, {
        method: "POST",
        headers: authHeaders,
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Failed to submit version for review.");
      }

      const updated = await res.json();
      notifySuccess(`Version ${updated.version_id} submitted for dual-control review.`);
      fetchData();
      if (selectedVersion?.version_id === versionId) {
        setSelectedVersion(updated);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  // Handle Review (Maker-Checker Approval / Rejection)
  const handleReviewSubmit = async (e) => {
    e.preventDefault();
    if (!selectedVersion) return;
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/detection-rule-versions/${selectedVersion.version_id}/review`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify(reviewForm),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Governance review failed.");
      }

      const updated = await res.json();
      notifySuccess(`Governance decision recorded: ${updated.approval_decision} for ${updated.version_id}`);
      setReviewModalOpen(false);
      fetchData();
      setSelectedVersion(updated);
    } catch (err) {
      setError(err.message);
    }
  };

  // Handle Activate Version (Atomic supersession)
  const handleActivateVersion = async (versionId) => {
    if (!window.confirm("Activate this approved detection rule version? The previous ACTIVE version will be automatically superseded.")) {
      return;
    }
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/detection-rule-versions/${versionId}/activate`, {
        method: "POST",
        headers: authHeaders,
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Activation failed.");
      }

      const updated = await res.json();
      notifySuccess(`Version ${updated.version_id} is now ACTIVE. Prior active version superseded.`);
      fetchData();
      if (selectedVersion?.version_id === versionId) {
        setSelectedVersion(updated);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  // Handle Disable Version
  const handleDisableVersion = async (versionId) => {
    const reason = window.prompt("Enter reason for disabling this detection rule version:", "Emergency deprecation / semantic policy drift risk");
    if (!reason) return;
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/detection-rule-versions/${versionId}/disable`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({ reason }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Disable failed.");
      }

      const updated = await res.json();
      notifySuccess(`Version ${updated.version_id} DISABLED.`);
      fetchData();
      if (selectedVersion?.version_id === versionId) {
        setSelectedVersion(updated);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  // Fetch Version Comparison
  const handleCompareVersions = async (targetVerId) => {
    if (!selectedVersion || !targetVerId) return;
    setComparisonLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/detection-rule-versions/${selectedVersion.version_id}/compare/${targetVerId}`, {
        headers: authHeaders,
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Comparison failed.");
      }
      const data = await res.json();
      setComparisonResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setComparisonLoading(false);
    }
  };

  // Fetch Hypothetical Pre-Approval Trust Simulation
  const handleLoadSimulation = async (versionId) => {
    setSimulationLoading(true);
    setSimulationModalOpen(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/detection-rule-versions/${versionId}/trust-simulation`, {
        headers: authHeaders,
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Simulation failed.");
      }
      const data = await res.json();
      setSimulationResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setSimulationLoading(false);
    }
  };

  // Fetch 15-Stage Governance Provenance Trace
  const handleLoadTrace = async (versionId) => {
    setTraceLoading(true);
    setTraceModalOpen(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/detection-rule-versions/${versionId}/governance-trace`, {
        headers: authHeaders,
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Failed to load governance trace.");
      }
      const data = await res.json();
      setGovernanceTrace(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setTraceLoading(false);
    }
  };

  // Filter versions
  const filteredVersions = versions.filter((v) => {
    if (selectedRuleFilter !== "ALL" && v.rule_id !== selectedRuleFilter) return false;
    if (selectedStatusFilter !== "ALL" && v.status !== selectedStatusFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        v.rule_name.toLowerCase().includes(q) ||
        v.version_id.toLowerCase().includes(q) ||
        v.rule_id.toLowerCase().includes(q) ||
        v.vendor_name.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Calculate lineage for selected rule
  const currentRuleVersions = selectedVersion
    ? versions.filter((v) => v.rule_id === selectedVersion.rule_id).sort((a, b) => a.version_number - b.version_number)
    : [];

  const isCreatorOfSelected = selectedVersion && user && selectedVersion.created_by_user_id === user.id;

  return (
    <div className="flex-1 flex flex-col h-full bg-sentinel-950 text-slate-100 overflow-hidden font-sans">
      {/* ── Top Alert Banner for Success / Error ────────────────── */}
      {error && (
        <div className="bg-red-950/90 border-b border-red-500/50 px-6 py-2.5 flex items-center justify-between text-xs text-red-200 z-30 animate-fade-in font-mono">
          <div className="flex items-center gap-2">
            <span className="text-base">⛔</span>
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-white">✕</button>
        </div>
      )}

      {successMsg && (
        <div className="bg-emerald-950/90 border-b border-emerald-500/50 px-6 py-2.5 flex items-center justify-between text-xs text-emerald-200 z-30 animate-fade-in font-mono">
          <div className="flex items-center gap-2">
            <span className="text-base">✓</span>
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-white">✕</button>
        </div>
      )}

      {/* ── Main Scrollable Container ─────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-6 py-6 space-y-6">

        {/* ── SECTION A: GOVERNANCE OVERVIEW HERO ──────────────── */}
        <section className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-sentinel-900/90 via-sentinel-900/60 to-purple-950/30 border border-white/10 p-6 backdrop-blur-xl shadow-2xl">
          <div className="absolute -top-24 -right-24 w-96 h-96 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute -bottom-24 -left-24 w-96 h-96 bg-accent-cyan/10 rounded-full blur-3xl pointer-events-none" />

          <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div className="space-y-2 max-w-3xl">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-950/60 border border-purple-500/30 text-purple-300 text-xs font-mono">
                <span>🏛️</span>
                <span className="tracking-wider uppercase font-bold">Sprint 6C · Detection Rule Governance</span>
              </div>
              <h1 className="text-2xl lg:text-3xl font-bold tracking-tight text-white font-mono flex items-center gap-3">
                <span>Detection Rule Governance & Dual-Control Lifecycle</span>
              </h1>
              <p className="text-slate-400 text-xs sm:text-sm leading-relaxed">
                <span className="text-purple-300 font-semibold font-mono">"Detection logic is a governed security asset."</span> Every detection rule version undergoes deterministic hashing, semantic dependency impact analysis, hypothetical trust simulation, mandatory maker-checker separation, and cryptographic auditability.
              </p>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <button
                onClick={() => setCreateModalOpen(true)}
                className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-mono text-xs font-bold shadow-lg shadow-purple-900/30 transition flex items-center gap-2 border border-purple-400/30 cursor-pointer"
              >
                <span>➕</span>
                <span>Create Candidate Version</span>
              </button>
            </div>
          </div>

          {/* Verifiable Lifecycle Pipeline Pipeline Bar */}
          <div className="mt-6 pt-5 border-t border-white/10 grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-2 text-center text-[10px] font-mono">
            {[
              { step: "01", label: "Rule Definition", icon: "📝" },
              { step: "02", label: "Version Hash", icon: "🔒" },
              { step: "03", label: "Impact Analysis", icon: "📊" },
              { step: "04", label: "Trust Simulation", icon: "🛡️" },
              { step: "05", label: "Dual Review", icon: "👥" },
              { step: "06", label: "Independent Approval", icon: "✅" },
              { step: "07", label: "Atomic Activation", icon: "⚡" },
              { step: "08", label: "Ledger Audit", icon: "⛓️" },
            ].map((st, i) => (
              <div key={i} className="p-2 rounded-lg bg-white/[0.02] border border-white/5 flex flex-col items-center justify-center gap-1 group hover:border-purple-500/40 transition">
                <span className="text-slate-500 text-[8px]">{st.step}</span>
                <span className="text-sm">{st.icon}</span>
                <span className="text-slate-300 font-medium group-hover:text-purple-300">{st.label}</span>
              </div>
            ))}
          </div>
        </section>

        {/* ── SECTION B: RULE VERSION REGISTRY ────────────────── */}
        <section className="space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="text-lg">📜</span>
              <h2 className="text-base font-bold text-white font-mono tracking-wide uppercase">
                Governed Rule Version Registry
              </h2>
              <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-white/5 text-slate-400 border border-white/10">
                {filteredVersions.length} versions
              </span>
            </div>

            {/* Filters */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <input
                type="text"
                placeholder="Search rule / version / vendor..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
              />

              <select
                value={selectedRuleFilter}
                onChange={(e) => setSelectedRuleFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 focus:outline-none focus:border-purple-500"
              >
                <option value="ALL">All Detection Rules</option>
                {rules.map((r) => (
                  <option key={r.rule_id} value={r.rule_id}>
                    {r.rule_name} ({r.rule_id})
                  </option>
                ))}
              </select>

              <select
                value={selectedStatusFilter}
                onChange={(e) => setSelectedStatusFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 focus:outline-none focus:border-purple-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="DRAFT">DRAFT</option>
                <option value="PENDING_REVIEW">PENDING_REVIEW</option>
                <option value="APPROVED">APPROVED</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="SUPERSEDED">SUPERSEDED</option>
                <option value="REJECTED">REJECTED</option>
                <option value="DISABLED">DISABLED</option>
              </select>
            </div>
          </div>

          {/* Versions Table */}
          <div className="rounded-xl border border-white/10 bg-sentinel-900/60 overflow-hidden backdrop-blur-md">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-white/10 bg-white/[0.02] text-slate-400 uppercase text-[10px] tracking-wider">
                    <th className="px-4 py-3">Rule & Version</th>
                    <th className="px-4 py-3">Vendor / Severity</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Creator / Reviewer</th>
                    <th className="px-4 py-3">Version Hash</th>
                    <th className="px-4 py-3 text-right">Governance Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-slate-300">
                  {loading ? (
                    <tr>
                      <td colSpan="6" className="px-4 py-8 text-center text-slate-500">
                        <div className="w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                        Loading governed rule versions...
                      </td>
                    </tr>
                  ) : filteredVersions.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="px-4 py-8 text-center text-slate-500">
                        No rule versions found matching filters.
                      </td>
                    </tr>
                  ) : (
                    filteredVersions.map((v) => {
                      const st = STATUS_CONFIG[v.status] || STATUS_CONFIG.DRAFT;
                      const isSelected = selectedVersion?.version_id === v.version_id;

                      return (
                        <tr
                          key={v.version_id}
                          onClick={() => setSelectedVersion(v)}
                          className={`hover:bg-white/[0.03] transition cursor-pointer ${
                            isSelected ? "bg-purple-950/20 border-l-2 border-purple-400" : ""
                          }`}
                        >
                          <td className="px-4 py-3">
                            <div className="font-bold text-white flex items-center gap-2">
                              <span>{v.rule_name}</span>
                              <span className="px-1.5 py-0.2 rounded bg-purple-950/80 border border-purple-500/40 text-purple-300 text-[10px]">
                                v{v.version_number}
                              </span>
                            </div>
                            <div className="text-[10px] text-slate-500 mt-0.5 truncate max-w-xs">
                              ID: {v.version_id}
                            </div>
                          </td>

                          <td className="px-4 py-3">
                            <div className="text-slate-300 font-bold">{v.vendor_name}</div>
                            <div className="text-[10px] text-slate-400">
                              Sev: <span className="text-amber-400">{v.severity}</span>
                            </div>
                          </td>

                          <td className="px-4 py-3">
                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-bold ${st.badge}`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                              {st.label}
                            </span>
                          </td>

                          <td className="px-4 py-3 text-[10px]">
                            <div className="text-slate-300 truncate">
                              <span className="text-slate-500">By:</span> @{v.created_by_user_id?.slice(0, 8)}...
                            </div>
                            <div className="text-slate-400 truncate">
                              <span className="text-slate-500">Rev:</span>{" "}
                              {v.reviewed_by_user_id ? `@${v.reviewed_by_user_id.slice(0, 8)}...` : "—"}
                            </div>
                          </td>

                          <td className="px-4 py-3">
                            <span
                              className="font-mono text-[10px] text-purple-300/80 bg-purple-950/40 px-2 py-0.5 rounded border border-purple-500/20 truncate block max-w-[140px]"
                              title={v.version_hash}
                            >
                              {v.version_hash ? `${v.version_hash.slice(0, 12)}...` : "PENDING"}
                            </span>
                          </td>

                          <td className="px-4 py-3 text-right space-x-1.5">
                            {/* Actions per state */}
                            {v.status === "DRAFT" && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleSubmitForReview(v.version_id);
                                }}
                                className="px-2 py-1 rounded bg-amber-950/60 hover:bg-amber-900/80 border border-amber-500/40 text-amber-300 text-[10px] transition cursor-pointer"
                                title="Submit for independent dual-control review"
                              >
                                Submit Review
                              </button>
                            )}

                            {v.status === "PENDING_REVIEW" && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedVersion(v);
                                  setReviewModalOpen(true);
                                }}
                                className="px-2 py-1 rounded bg-indigo-950/60 hover:bg-indigo-900/80 border border-indigo-500/40 text-indigo-300 text-[10px] transition cursor-pointer"
                                title="Review candidate version (Maker-checker enforced)"
                              >
                                Review & Decide
                              </button>
                            )}

                            {v.status === "APPROVED" && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleActivateVersion(v.version_id);
                                }}
                                className="px-2 py-1 rounded bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-500/40 text-emerald-300 text-[10px] transition cursor-pointer"
                                title="Activate approved version and supersede prior active"
                              >
                                Activate
                              </button>
                            )}

                            {v.status === "ACTIVE" && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleDisableVersion(v.version_id);
                                }}
                                className="px-2 py-1 rounded bg-rose-950/60 hover:bg-rose-900/80 border border-rose-500/40 text-rose-300 text-[10px] transition cursor-pointer"
                                title="Disable active version"
                              >
                                Disable
                              </button>
                            )}

                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleLoadSimulation(v.version_id);
                              }}
                              className="px-2 py-1 rounded bg-cyan-950/60 hover:bg-cyan-900/80 border border-cyan-500/40 text-cyan-300 text-[10px] transition cursor-pointer"
                              title="Run hypothetical pre-approval trust simulation"
                            >
                              Simulate
                            </button>

                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleLoadTrace(v.version_id);
                              }}
                              className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 text-[10px] transition cursor-pointer"
                              title="View complete 15-stage governance provenance trace"
                            >
                              Trace
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* ── SPLIT VIEW: SECTION C (LINEAGE) & SECTION F (DUAL CONTROL) ── */}
        {selectedVersion && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* ── SECTION C: VERSION LINEAGE VISUALIZER ────────────── */}
            <section className="rounded-xl border border-white/10 bg-sentinel-900/60 p-5 space-y-4 backdrop-blur-md">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-base">🧬</span>
                  <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
                    Version Lineage: {selectedVersion.rule_name}
                  </h3>
                </div>
                <button
                  onClick={() => {
                    setCompareModalOpen(true);
                    if (currentRuleVersions.length > 1) {
                      const other = currentRuleVersions.find((x) => x.version_id !== selectedVersion.version_id);
                      if (other) {
                        setCompareTargetVersionId(other.version_id);
                        handleCompareVersions(other.version_id);
                      }
                    }
                  }}
                  className="px-2.5 py-1 rounded-lg bg-purple-950/60 hover:bg-purple-900/80 border border-purple-500/40 text-purple-300 text-xs font-mono transition cursor-pointer"
                >
                  ⚖️ Compare Versions
                </button>
              </div>

              {/* Lineage Tree */}
              <div className="space-y-3 pt-2">
                {currentRuleVersions.map((ver, idx) => {
                  const isCurrent = ver.version_id === selectedVersion.version_id;
                  const st = STATUS_CONFIG[ver.status] || STATUS_CONFIG.DRAFT;

                  return (
                    <div key={ver.version_id} className="relative pl-6 pb-2">
                      {idx < currentRuleVersions.length - 1 && (
                        <div className="absolute left-2.5 top-6 bottom-0 w-0.5 bg-purple-500/30" />
                      )}
                      <div className="absolute left-1 top-1.5 w-3.5 h-3.5 rounded-full border-2 border-purple-400 bg-sentinel-950 flex items-center justify-center">
                        <div className={`w-1.5 h-1.5 rounded-full ${ver.status === "ACTIVE" ? "bg-emerald-400" : "bg-purple-400"}`} />
                      </div>

                      <div
                        onClick={() => setSelectedVersion(ver)}
                        className={`p-3 rounded-xl border transition cursor-pointer ${
                          isCurrent
                            ? "bg-purple-950/30 border-purple-500/60 shadow-lg shadow-purple-950/40"
                            : "bg-white/[0.02] border-white/5 hover:border-white/20"
                        }`}
                      >
                        <div className="flex items-center justify-between text-xs font-mono">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-white">v{ver.version_number}</span>
                            <span className={`px-2 py-0.5 rounded-full border text-[9px] font-bold ${st.badge}`}>
                              {st.label}
                            </span>
                            {ver.parent_version_id && (
                              <span className="text-[10px] text-slate-500">
                                (parent: {ver.parent_version_id.slice(0, 8)}...)
                              </span>
                            )}
                          </div>
                          <span className="text-[10px] text-slate-500">
                            {new Date(ver.created_at).toLocaleDateString()}
                          </span>
                        </div>

                        <div className="text-[11px] text-slate-400 mt-2 font-mono">
                          Query: <code className="text-slate-300 bg-black/30 px-1 py-0.5 rounded">{ver.query_signature}</code>
                        </div>

                        <div className="mt-2 flex flex-wrap gap-1">
                          {ver.dependencies?.map((d, di) => (
                            <span
                              key={di}
                              className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                                d.is_protected_field
                                  ? "bg-red-950/40 border-red-500/30 text-red-300"
                                  : "bg-white/5 border-white/10 text-slate-300"
                              }`}
                            >
                              {d.canonical_field} {d.is_protected_field ? "⚠️" : ""}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>

            {/* ── SECTION F: DUAL-CONTROL MAKER-CHECKER PANEL ─────── */}
            <section className="rounded-xl border border-white/10 bg-sentinel-900/60 p-5 space-y-4 backdrop-blur-md flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-base">🛡️</span>
                    <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
                      Dual-Control Approval Panel
                    </h3>
                  </div>
                  <span className="text-xs font-mono text-purple-300 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-500/30">
                    Version: {selectedVersion.version_id}
                  </span>
                </div>

                <div className="mt-4 space-y-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-2">
                    <div className="flex justify-between text-slate-400">
                      <span>Creator Identity:</span>
                      <span className="text-white font-bold">@{selectedVersion.created_by_user_id?.slice(0, 12)}...</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Submitted By:</span>
                      <span className="text-white font-bold">
                        {selectedVersion.submitted_by_user_id ? `@${selectedVersion.submitted_by_user_id.slice(0, 12)}...` : "Not submitted yet"}
                      </span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Reviewer Identity:</span>
                      <span className="text-white font-bold">
                        {selectedVersion.reviewed_by_user_id ? `@${selectedVersion.reviewed_by_user_id.slice(0, 12)}...` : "Pending independent review"}
                      </span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Approval Decision:</span>
                      <span className="font-bold text-amber-300">{selectedVersion.approval_decision || "NONE"}</span>
                    </div>
                    {selectedVersion.approval_comment && (
                      <div className="text-[11px] text-slate-300 pt-1 border-t border-white/5">
                        <span className="text-slate-500">Comment:</span> {selectedVersion.approval_comment}
                      </div>
                    )}
                  </div>

                  {/* Maker-Checker Invariant Warning */}
                  {isCreatorOfSelected && (
                    <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs flex items-start gap-2.5">
                      <span className="text-base shrink-0">⚠️</span>
                      <div>
                        <div className="font-bold">Dual-Control Maker-Checker Enforced</div>
                        <div className="text-[11px] text-amber-300/80 mt-0.5">
                          You created this detection rule version. To prevent unilateral detection alterations, self-approval is cryptographically and logically forbidden. Another authorized reviewer must review this version.
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-4 border-t border-white/10 flex flex-wrap items-center gap-2">
                {selectedVersion.status === "PENDING_REVIEW" && (
                  <button
                    disabled={isCreatorOfSelected}
                    onClick={() => setReviewModalOpen(true)}
                    className={`flex-1 py-2 px-3 rounded-lg font-mono text-xs font-bold transition flex items-center justify-center gap-2 ${
                      isCreatorOfSelected
                        ? "bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed"
                        : "bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white border border-indigo-400/30 cursor-pointer"
                    }`}
                  >
                    <span>⚖️</span>
                    <span>{isCreatorOfSelected ? "Self-Approval Forbidden" : "Perform Independent Review"}</span>
                  </button>
                )}

                {selectedVersion.status === "APPROVED" && (
                  <button
                    onClick={() => handleActivateVersion(selectedVersion.version_id)}
                    className="flex-1 py-2 px-3 rounded-lg font-mono text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white transition flex items-center justify-center gap-2 cursor-pointer shadow-lg shadow-emerald-950/40"
                  >
                    <span>⚡</span>
                    <span>Activate Version & Supersede Prior</span>
                  </button>
                )}

                <button
                  onClick={() => handleLoadSimulation(selectedVersion.version_id)}
                  className="py-2 px-3 rounded-lg font-mono text-xs bg-cyan-950/60 hover:bg-cyan-900/80 border border-cyan-500/40 text-cyan-300 transition flex items-center gap-1.5 cursor-pointer"
                >
                  <span>🛡️</span>
                  <span>Trust Simulation</span>
                </button>

                <button
                  onClick={() => handleLoadTrace(selectedVersion.version_id)}
                  className="py-2 px-3 rounded-lg font-mono text-xs bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 transition flex items-center gap-1.5 cursor-pointer"
                >
                  <span>🔍</span>
                  <span>Full Trace</span>
                </button>
              </div>
            </section>
          </div>
        )}

        {/* ── SECTION H: IMMUTABLE GOVERNANCE AUDIT LOG ───────── */}
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-lg">⛓️</span>
              <h2 className="text-base font-bold text-white font-mono tracking-wide uppercase">
                Immutable Governance Audit Log
              </h2>
              <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-purple-950/60 text-purple-300 border border-purple-500/30">
                Deterministic SHA-256 Event Chaining
              </span>
            </div>
            <button
              onClick={fetchData}
              className="px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 text-xs font-mono"
            >
              🔄 Refresh Events
            </button>
          </div>

          <div className="rounded-xl border border-white/10 bg-sentinel-900/60 overflow-hidden backdrop-blur-md">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-white/10 bg-white/[0.02] text-slate-400 uppercase text-[10px] tracking-wider">
                    <th className="px-4 py-3">Event Type</th>
                    <th className="px-4 py-3">Rule / Version</th>
                    <th className="px-4 py-3">Actor / Role</th>
                    <th className="px-4 py-3">State Transition</th>
                    <th className="px-4 py-3">Event Hash</th>
                    <th className="px-4 py-3 text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-slate-300">
                  {events.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="px-4 py-8 text-center text-slate-500">
                        No governance events recorded yet.
                      </td>
                    </tr>
                  ) : (
                    events.slice(0, 15).map((ev) => (
                      <tr key={ev.event_id} className="hover:bg-white/[0.02]">
                        <td className="px-4 py-3 font-bold text-purple-300 flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                          {ev.event_type}
                        </td>
                        <td className="px-4 py-3 text-[10px] text-slate-400">
                          <div>Rule: {ev.rule_id}</div>
                          {ev.version_id && <div>Ver: {ev.version_id.slice(0, 10)}...</div>}
                        </td>
                        <td className="px-4 py-3 text-[10px]">
                          <div className="text-slate-300">@{ev.actor_user_id?.slice(0, 8)}...</div>
                          <div className="text-slate-500 font-bold">{ev.actor_role}</div>
                        </td>
                        <td className="px-4 py-3 text-[10px]">
                          <span className="text-slate-400">{ev.previous_status || "—"}</span>
                          <span className="text-purple-400 mx-1">→</span>
                          <span className="text-white font-bold">{ev.new_status || "—"}</span>
                        </td>
                        <td className="px-4 py-3 font-mono text-[10px] text-slate-400">
                          <span className="bg-black/40 px-2 py-0.5 rounded border border-white/5 block max-w-[130px] truncate" title={ev.event_hash}>
                            {ev.event_hash ? `${ev.event_hash.slice(0, 12)}...` : "—"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right text-[10px] text-slate-500">
                          {new Date(ev.created_at).toLocaleString()}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>

      </div>

      {/* ── SECTION D: VERSION COMPARISON MODAL ───────────────── */}
      {compareModalOpen && selectedVersion && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col overflow-hidden shadow-2xl animate-fade-in font-mono">
            {/* Header */}
            <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between bg-white/[0.02]">
              <div className="flex items-center gap-2">
                <span className="text-lg">⚖️</span>
                <h3 className="text-base font-bold text-white">
                  Deterministic Version Impact Comparison
                </h3>
              </div>
              <button
                onClick={() => setCompareModalOpen(false)}
                className="text-slate-400 hover:text-white text-lg"
              >
                ✕
              </button>
            </div>

            {/* Content */}
            <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
              <div className="flex items-center gap-4">
                <div className="flex-1">
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Source Version (A)</label>
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 text-white font-bold">
                    v{selectedVersion.version_number} ({selectedVersion.version_id})
                  </div>
                </div>

                <div className="text-xl text-purple-400">⇄</div>

                <div className="flex-1">
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Target Version (B)</label>
                  <select
                    value={compareTargetVersionId}
                    onChange={(e) => {
                      setCompareTargetVersionId(e.target.value);
                      handleCompareVersions(e.target.value);
                    }}
                    className="w-full p-2.5 rounded-lg bg-black/40 border border-white/10 text-white font-bold focus:outline-none focus:border-purple-500"
                  >
                    <option value="">Select target version...</option>
                    {currentRuleVersions
                      .filter((x) => x.version_id !== selectedVersion.version_id)
                      .map((v) => (
                        <option key={v.version_id} value={v.version_id}>
                          v{v.version_number} ({v.version_id}) · {v.status}
                        </option>
                      ))}
                  </select>
                </div>
              </div>

              {comparisonLoading && (
                <div className="text-center py-8 text-slate-400">
                  <div className="w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                  Analyzing semantic differences and calculating blast radius...
                </div>
              )}

              {comparisonResult && (
                <div className="space-y-4">
                  {/* Overall Impact Banner */}
                  <div className={`p-4 rounded-xl border flex items-center justify-between ${IMPACT_COLORS[comparisonResult.overall_impact]}`}>
                    <div>
                      <div className="text-[10px] uppercase tracking-wider font-bold">Deterministic Impact Level</div>
                      <div className="text-xl font-bold mt-0.5">{comparisonResult.overall_impact} IMPACT</div>
                    </div>
                    <div className="text-right text-[11px] text-slate-300">
                      <div>Protected Field Impact: <span className="font-bold">{comparisonResult.protected_field_impact}</span></div>
                    </div>
                  </div>

                  {/* Changes Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 rounded-xl bg-black/30 border border-white/5 space-y-2">
                      <div className="text-[11px] font-bold text-slate-300">Query Signature Difference</div>
                      <div className="text-[10px]">
                        Changed: <span className={comparisonResult.changes?.query_signature?.changed ? "text-amber-400 font-bold" : "text-slate-500"}>
                          {comparisonResult.changes?.query_signature?.changed ? "YES (HIGH IMPACT)" : "NO"}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400">
                        Severity Change: {comparisonResult.changes?.severity?.from || "—"} → {comparisonResult.changes?.severity?.to || "—"}
                      </div>
                    </div>

                    <div className="p-4 rounded-xl bg-black/30 border border-white/5 space-y-2">
                      <div className="text-[11px] font-bold text-slate-300">Canonical Dependencies Delta</div>
                      <div className="text-[10px] text-emerald-400">
                        + Added: {comparisonResult.changes?.dependencies?.added?.length > 0 ? comparisonResult.changes.dependencies.added.join(", ") : "None"}
                      </div>
                      <div className="text-[10px] text-red-400">
                        - Removed: {comparisonResult.changes?.dependencies?.removed?.length > 0 ? comparisonResult.changes.dependencies.removed.join(", ") : "None"}
                      </div>
                      <div className="text-[10px] text-amber-400">
                        ⚠️ Protected Fields Added: {comparisonResult.changes?.dependencies?.protected_fields_added?.length > 0 ? comparisonResult.changes.dependencies.protected_fields_added.join(", ") : "None"}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="px-6 py-3 border-t border-white/10 bg-white/[0.02] flex justify-end">
              <button
                onClick={() => setCompareModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white font-mono text-xs"
              >
                Close Comparison
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── SECTION E: PRE-APPROVAL TRUST SIMULATION MODAL ────── */}
      {simulationModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col overflow-hidden shadow-2xl animate-fade-in font-mono">
            <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between bg-white/[0.02]">
              <div className="flex items-center gap-2">
                <span className="text-lg">🛡️</span>
                <h3 className="text-base font-bold text-white">
                  Pre-Approval Trust Simulation
                </h3>
              </div>
              <button
                onClick={() => setSimulationModalOpen(false)}
                className="text-slate-400 hover:text-white text-lg"
              >
                ✕
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 flex-1 text-xs">
              <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-500/30 text-cyan-200 text-[11px] leading-relaxed">
                <span className="font-bold">⚠️ HYPOTHETICAL GOVERNANCE SIMULATION:</span> This calculates what the trust score of this candidate detection rule version WOULD be if deployed, inspecting protected field dependencies and active drift. It does NOT mutate runtime trust evaluation tables.
              </div>

              {simulationLoading ? (
                <div className="text-center py-8 text-slate-400">
                  <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                  Running pre-approval trust calculation...
                </div>
              ) : simulationResult ? (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between">
                    <div>
                      <div className="text-[10px] text-slate-400 uppercase font-bold">Simulated Trust Score</div>
                      <div className="text-3xl font-bold text-white mt-1">
                        {(simulationResult.simulated_score * 100).toFixed(1)}%
                      </div>
                    </div>
                    <div className="text-right">
                      <span className="px-3 py-1 rounded-full border text-xs font-bold bg-cyan-950/80 border-cyan-500/60 text-cyan-300">
                        {simulationResult.simulated_state}
                      </span>
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-black/30 border border-white/5 space-y-2">
                    <div className="text-[11px] font-bold text-slate-300">Deduction & Dominance Reasons:</div>
                    <ul className="space-y-1.5 text-[10px] text-slate-400">
                      {simulationResult.reasons?.map((r, ri) => (
                        <li key={ri} className="flex items-start gap-2">
                          <span className="text-cyan-400 mt-0.5">•</span>
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : null}
            </div>

            <div className="px-6 py-3 border-t border-white/10 bg-white/[0.02] flex justify-end">
              <button
                onClick={() => setSimulationModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white font-mono text-xs"
              >
                Close Simulation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── CREATE CANDIDATE VERSION MODAL ────────────────────── */}
      {createModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col overflow-hidden shadow-2xl animate-fade-in font-mono">
            <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between bg-white/[0.02]">
              <div className="flex items-center gap-2">
                <span className="text-lg">➕</span>
                <h3 className="text-base font-bold text-white">
                  Create Governed Detection Rule Candidate Version
                </h3>
              </div>
              <button
                onClick={() => setCreateModalOpen(false)}
                className="text-slate-400 hover:text-white text-lg"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateVersion} className="p-6 overflow-y-auto space-y-4 flex-1 text-xs">
              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Target Logical Rule</label>
                <select
                  required
                  value={createFormData.rule_id}
                  onChange={(e) => {
                    const selected = rules.find((r) => r.rule_id === e.target.value);
                    setCreateFormData({
                      ...createFormData,
                      rule_id: e.target.value,
                      rule_name: selected ? selected.rule_name : "",
                      vendor_name: selected ? selected.vendor_name : "CISCO_ASA",
                      query_signature: selected ? selected.query_signature : "",
                      severity: selected ? selected.severity : "HIGH",
                      description: selected ? selected.description : "",
                    });
                  }}
                  className="w-full p-2.5 rounded-lg bg-black/40 border border-white/10 text-white focus:outline-none focus:border-purple-500"
                >
                  <option value="">Select logical detection rule...</option>
                  {rules.map((r) => (
                    <option key={r.rule_id} value={r.rule_id}>
                      {r.rule_name} ({r.rule_id})
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Rule Name</label>
                  <input
                    type="text"
                    required
                    value={createFormData.rule_name}
                    onChange={(e) => setCreateFormData({ ...createFormData, rule_name: e.target.value })}
                    className="w-full p-2.5 rounded-lg bg-black/40 border border-white/10 text-white focus:outline-none focus:border-purple-500"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Vendor Scope</label>
                  <input
                    type="text"
                    required
                    value={createFormData.vendor_name}
                    onChange={(e) => setCreateFormData({ ...createFormData, vendor_name: e.target.value })}
                    className="w-full p-2.5 rounded-lg bg-black/40 border border-white/10 text-white focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Query Signature Logic</label>
                <textarea
                  required
                  rows="3"
                  value={createFormData.query_signature}
                  onChange={(e) => setCreateFormData({ ...createFormData, query_signature: e.target.value })}
                  className="w-full p-2.5 rounded-lg bg-black/40 border border-white/10 text-white focus:outline-none focus:border-purple-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Severity</label>
                  <select
                    value={createFormData.severity}
                    onChange={(e) => setCreateFormData({ ...createFormData, severity: e.target.value })}
                    className="w-full p-2.5 rounded-lg bg-black/40 border border-white/10 text-white focus:outline-none focus:border-purple-500"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">MITRE Technique</label>
                  <input
                    type="text"
                    value={createFormData.mitre_techniques[0] || ""}
                    onChange={(e) => setCreateFormData({ ...createFormData, mitre_techniques: [e.target.value] })}
                    className="w-full p-2.5 rounded-lg bg-black/40 border border-white/10 text-white focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Description & Rationalization</label>
                <textarea
                  rows="2"
                  value={createFormData.description}
                  onChange={(e) => setCreateFormData({ ...createFormData, description: e.target.value })}
                  className="w-full p-2.5 rounded-lg bg-black/40 border border-white/10 text-white focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="px-6 py-3 border-t border-white/10 bg-white/[0.02] -mx-6 -mb-6 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white font-mono text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 text-white font-mono text-xs font-bold"
                >
                  Create Version Snapshot
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── REVIEW MODAL (MAKER-CHECKER DECISION) ─────────────── */}
      {reviewModalOpen && selectedVersion && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-xl w-full max-h-[90vh] flex flex-col overflow-hidden shadow-2xl animate-fade-in font-mono">
            <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between bg-white/[0.02]">
              <div className="flex items-center gap-2">
                <span className="text-lg">⚖️</span>
                <h3 className="text-base font-bold text-white">
                  Independent Dual-Control Review Decision
                </h3>
              </div>
              <button
                onClick={() => setReviewModalOpen(false)}
                className="text-slate-400 hover:text-white text-lg"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleReviewSubmit} className="p-6 overflow-y-auto space-y-4 flex-1 text-xs">
              <div className="p-3 rounded-lg bg-black/40 border border-white/10 space-y-1 text-[11px]">
                <div>Version: <span className="text-white font-bold">{selectedVersion.version_id} (v{selectedVersion.version_number})</span></div>
                <div>Rule: <span className="text-white">{selectedVersion.rule_name}</span></div>
                <div>Author: <span className="text-purple-300">@{selectedVersion.created_by_user_id?.slice(0, 12)}...</span></div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Governance Decision</label>
                <div className="grid grid-cols-2 gap-3">
                  <label
                    className={`p-3 rounded-lg border flex items-center gap-2 cursor-pointer transition ${
                      reviewForm.decision === "APPROVE"
                        ? "bg-emerald-950/60 border-emerald-500/80 text-emerald-300 font-bold"
                        : "bg-black/30 border-white/10 text-slate-400"
                    }`}
                  >
                    <input
                      type="radio"
                      name="decision"
                      value="APPROVE"
                      checked={reviewForm.decision === "APPROVE"}
                      onChange={() => setReviewForm({ ...reviewForm, decision: "APPROVE" })}
                      className="hidden"
                    />
                    <span>✅</span>
                    <span>APPROVE VERSION</span>
                  </label>

                  <label
                    className={`p-3 rounded-lg border flex items-center gap-2 cursor-pointer transition ${
                      reviewForm.decision === "REJECT"
                        ? "bg-red-950/60 border-red-500/80 text-red-300 font-bold"
                        : "bg-black/30 border-white/10 text-slate-400"
                    }`}
                  >
                    <input
                      type="radio"
                      name="decision"
                      value="REJECT"
                      checked={reviewForm.decision === "REJECT"}
                      onChange={() => setReviewForm({ ...reviewForm, decision: "REJECT" })}
                      className="hidden"
                    />
                    <span>❌</span>
                    <span>REJECT VERSION</span>
                  </label>
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Reviewer Comment / Rationale</label>
                <textarea
                  required
                  rows="3"
                  value={reviewForm.comment}
                  onChange={(e) => setReviewForm({ ...reviewForm, comment: e.target.value })}
                  placeholder="State review findings and justification..."
                  className="w-full p-2.5 rounded-lg bg-black/40 border border-white/10 text-white focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30 space-y-2">
                <label className="flex items-center gap-2 cursor-pointer text-[11px] text-amber-200">
                  <input
                    type="checkbox"
                    checked={reviewForm.risk_acknowledged}
                    onChange={(e) => setReviewForm({ ...reviewForm, risk_acknowledged: e.target.checked })}
                    className="rounded border-amber-500 text-amber-500"
                  />
                  <span>Explicitly acknowledge semantic drift risk & blast radius</span>
                </label>

                {reviewForm.risk_acknowledged && (
                  <input
                    type="text"
                    placeholder="Risk mitigation justification (e.g. compensating SIEM controls)..."
                    value={reviewForm.risk_acknowledgement_comment}
                    onChange={(e) => setReviewForm({ ...reviewForm, risk_acknowledgement_comment: e.target.value })}
                    className="w-full p-2 rounded bg-black/50 border border-amber-500/40 text-amber-100 text-[10px] focus:outline-none"
                  />
                )}
              </div>

              <div className="px-6 py-3 border-t border-white/10 bg-white/[0.02] -mx-6 -mb-6 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setReviewModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white font-mono text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-mono text-xs font-bold"
                >
                  Commit Governance Decision
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── SECTION I: 15-STAGE GOVERNANCE TRACE MODAL ───────── */}
      {traceModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/15 rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col overflow-hidden shadow-2xl animate-fade-in font-mono">
            <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between bg-white/[0.02]">
              <div className="flex items-center gap-2">
                <span className="text-lg">📜</span>
                <h3 className="text-base font-bold text-white">
                  15-Stage Cryptographic Governance Trace
                </h3>
              </div>
              <button
                onClick={() => setTraceModalOpen(false)}
                className="text-slate-400 hover:text-white text-lg"
              >
                ✕
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-3 flex-1 text-xs">
              {traceLoading ? (
                <div className="text-center py-8 text-slate-400">
                  <div className="w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                  Tracing cryptographic provenance and ledger chain...
                </div>
              ) : governanceTrace ? (
                <div className="space-y-2">
                  {governanceTrace.trace_stages?.map((st) => (
                    <div
                      key={st.stage_number}
                      className="p-3 rounded-lg bg-black/30 border border-white/5 flex items-start gap-3 hover:border-purple-500/30 transition"
                    >
                      <span className="px-2 py-0.5 rounded bg-purple-950/80 border border-purple-500/40 text-purple-300 font-bold text-[10px] shrink-0">
                        Stage {String(st.stage_number).padStart(2, "0")}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="text-white font-bold">{st.stage_name}</div>
                        <div className="text-[10px] text-slate-400 mt-0.5">{st.summary}</div>
                        {st.hash && (
                          <div className="text-[9px] text-purple-300/80 font-mono mt-1 truncate">
                            SHA-256: {st.hash}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>

            <div className="px-6 py-3 border-t border-white/10 bg-white/[0.02] flex justify-end">
              <button
                onClick={() => setTraceModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white font-mono text-xs"
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
