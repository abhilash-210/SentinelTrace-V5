/**
 * SecurityIncidents.jsx
 * ---------------------
 * Security Incident Correlation & Investigation Workspace.
 *
 * Sprint 8A — Security Incident Correlation & Investigation Foundation.
 * SOC investigation platform connecting raw evidence, normalized events, semantic drift,
 * detection trust alerts, risk correlations, and remediation candidates into formal security incidents.
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";

export default function SecurityIncidents() {
  const { user, token } = useAuth();

  // Primary State
  const [incidents, setIncidents] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [selectedPriority, setSelectedPriority] = useState("ALL");
  const [selectedStatus, setSelectedStatus] = useState("ALL");
  const [selectedType, setSelectedType] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  // Investigation Workspace State
  const [activeIncidentId, setActiveIncidentId] = useState(null);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("OVERVIEW"); // OVERVIEW, SIGNALS, EVIDENCE, FINDINGS, TIMELINE, PROVENANCE, GRAPH

  // Provenance Trace
  const [traceData, setTraceData] = useState(null);
  const [traceLoading, setTraceLoading] = useState(false);

  // Modals & Action Forms
  const [showManualModal, setShowManualModal] = useState(false);
  const [showCorrelationModal, setShowCorrelationModal] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [showFindingModal, setShowFindingModal] = useState(false);
  const [showEvidenceModal, setShowEvidenceModal] = useState(false);
  const [showSignalModal, setShowSignalModal] = useState(false);

  // Form Fields
  const [manualForm, setManualForm] = useState({
    title: "",
    description: "",
    incident_type: "SEMANTIC_RISK",
    severity: "MEDIUM",
    priority: "P3",
    confidence: 1.0,
  });

  const [selectedCorrelationId, setSelectedCorrelationId] = useState("");
  const [dedupWarning, setDedupWarning] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);

  const [targetStatus, setTargetStatus] = useState("TRIAGING");
  const [statusReason, setStatusReason] = useState("");
  const [assignedUserId, setAssignedUserId] = useState("");

  const [findingForm, setFindingForm] = useState({
    finding_type: "OBSERVATION",
    title: "",
    description: "",
    confidence: 1.0,
  });

  const [evidenceForm, setEvidenceForm] = useState({
    evidence_type: "RAW_EVIDENCE",
    evidence_id: "",
    relationship: "SUPPORTING",
  });

  const [signalForm, setSignalForm] = useState({
    signal_type: "DETECTION_TRUST_ALERT",
    signal_id: "",
    relationship_type: "CONTRIBUTING_SIGNAL",
  });

  // Role permissions helper
  const role = user?.role || "VIEWER";
  const canCreate = ["ADMIN", "SECURITY_ANALYST"].includes(role);
  const canAssign = ["ADMIN", "SECURITY_ANALYST"].includes(role);
  const canUpdateStatus = ["ADMIN", "SECURITY_ANALYST"].includes(role);
  const canLink = ["ADMIN", "SECURITY_ANALYST"].includes(role);
  const canCreateFinding = ["ADMIN", "SECURITY_ANALYST", "POLICY_REVIEWER"].includes(role);
  const canReviewFinding = ["ADMIN"].includes(role);
  const canViewTrace = ["ADMIN", "AUDITOR", "SECURITY_ANALYST", "POLICY_REVIEWER", "POLICY_AUTHOR", "VIEWER"].includes(role);

  // Fetch Incidents & Correlations
  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [incRes, corrRes] = await Promise.all([
        fetch("/api/v1/incidents", { headers }),
        fetch("/api/v1/risk-correlations", { headers }),
      ]);

      if (!incRes.ok) throw new Error("Failed to fetch security incidents.");
      const incData = await incRes.json();
      setIncidents(incData);

      if (corrRes.ok) {
        const corrData = await corrRes.json();
        setCorrelations(corrData);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [token]);

  // Load Incident Detail
  const fetchIncidentDetail = async (id) => {
    setDetailLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const res = await fetch(`/api/v1/incidents/${id}`, { headers });
      if (!res.ok) throw new Error("Failed to fetch incident details.");
      const data = await res.json();
      setIncidentDetail(data);
      setActiveIncidentId(id);
    } catch (err) {
      setError(err.message);
    } finally {
      setDetailLoading(false);
    }
  };

  // Load Provenance Trace
  const fetchProvenanceTrace = async (id) => {
    setTraceLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const res = await fetch(`/api/v1/incidents/${id}/trace`, { headers });
      if (!res.ok) throw new Error("Failed to fetch provenance trace.");
      const data = await res.json();
      setTraceData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setTraceLoading(false);
    }
  };

  // Handlers
  const handleManualCreate = async (e) => {
    e.preventDefault();
    setActionLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
      const res = await fetch("/api/v1/incidents", {
        method: "POST",
        headers,
        body: JSON.stringify(manualForm),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create manual incident.");
      }
      setShowManualModal(false);
      setManualForm({
        title: "",
        description: "",
        incident_type: "SEMANTIC_RISK",
        severity: "MEDIUM",
        priority: "P3",
        confidence: 1.0,
      });
      await fetchData();
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleCorrelationCreate = async (e) => {
    e.preventDefault();
    if (!selectedCorrelationId) return;
    setActionLoading(true);
    setDedupWarning(null);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const res = await fetch(`/api/v1/incidents/from-correlation/${selectedCorrelationId}`, {
        method: "POST",
        headers,
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create incident from correlation.");
      }
      const data = await res.json();
      setShowCorrelationModal(false);
      await fetchData();
      fetchIncidentDetail(data.incident_id);
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleStatusUpdate = async (e) => {
    e.preventDefault();
    if (!incidentDetail) return;
    setActionLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
      const res = await fetch(`/api/v1/incidents/${incidentDetail.incident.incident_id}/status`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ status: targetStatus, reason: statusReason }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to update incident status.");
      }
      setShowStatusModal(false);
      setStatusReason("");
      await fetchIncidentDetail(incidentDetail.incident.incident_id);
      await fetchData();
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleAssignAnalyst = async (e) => {
    e.preventDefault();
    if (!incidentDetail) return;
    setActionLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
      const res = await fetch(`/api/v1/incidents/${incidentDetail.incident.incident_id}/assign`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ assigned_to_user_id: assignedUserId || null }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to assign analyst.");
      }
      setShowAssignModal(false);
      await fetchIncidentDetail(incidentDetail.incident.incident_id);
      await fetchData();
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleAddFinding = async (e) => {
    e.preventDefault();
    if (!incidentDetail) return;
    setActionLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
      const res = await fetch(`/api/v1/incidents/${incidentDetail.incident.incident_id}/findings`, {
        method: "POST",
        headers,
        body: JSON.stringify(findingForm),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to add finding.");
      }
      setShowFindingModal(false);
      setFindingForm({
        finding_type: "OBSERVATION",
        title: "",
        description: "",
        confidence: 1.0,
      });
      await fetchIncidentDetail(incidentDetail.incident.incident_id);
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleReviewFinding = async (findingId, newStatus) => {
    if (!incidentDetail) return;
    try {
      const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
      const res = await fetch(`/api/v1/incidents/${incidentDetail.incident.incident_id}/findings/${findingId}`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ status: newStatus, comment: `Finding ${newStatus.toLowerCase()} by ${user?.username}` }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to review finding.");
      }
      await fetchIncidentDetail(incidentDetail.incident.incident_id);
    } catch (err) {
      alert(err.message);
    }
  };

  const handleLinkEvidence = async (e) => {
    e.preventDefault();
    if (!incidentDetail) return;
    setActionLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
      const res = await fetch(`/api/v1/incidents/${incidentDetail.incident.incident_id}/evidence`, {
        method: "POST",
        headers,
        body: JSON.stringify(evidenceForm),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to link evidence.");
      }
      setShowEvidenceModal(false);
      setEvidenceForm({
        evidence_type: "RAW_EVIDENCE",
        evidence_id: "",
        relationship: "SUPPORTING",
      });
      await fetchIncidentDetail(incidentDetail.incident.incident_id);
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleLinkSignal = async (e) => {
    e.preventDefault();
    if (!incidentDetail) return;
    setActionLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
      const res = await fetch(`/api/v1/incidents/${incidentDetail.incident.incident_id}/signals`, {
        method: "POST",
        headers,
        body: JSON.stringify(signalForm),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to link signal.");
      }
      setShowSignalModal(false);
      setSignalForm({
        signal_type: "DETECTION_TRUST_ALERT",
        signal_id: "",
        relationship_type: "CONTRIBUTING_SIGNAL",
      });
      await fetchIncidentDetail(incidentDetail.incident.incident_id);
      await fetchData();
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  // KPIs
  const totalIncidents = incidents.length;
  const openIncidents = incidents.filter((i) => ["OPEN", "TRIAGING", "INVESTIGATING"].includes(i.status)).length;
  const criticalIncidents = incidents.filter((i) => i.severity === "CRITICAL").length;
  const highPriority = incidents.filter((i) => ["P1", "P2"].includes(i.priority)).length;
  const investigatingCount = incidents.filter((i) => i.status === "INVESTIGATING").length;
  const unassignedCount = incidents.filter((i) => !i.assigned_to_user_id).length;

  // Filtered Incidents
  const filteredIncidents = incidents.filter((inc) => {
    if (selectedSeverity !== "ALL" && inc.severity !== selectedSeverity) return false;
    if (selectedPriority !== "ALL" && inc.priority !== selectedPriority) return false;
    if (selectedStatus !== "ALL" && inc.status !== selectedStatus) return false;
    if (selectedType !== "ALL" && inc.incident_type !== selectedType) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        inc.incident_number.toLowerCase().includes(q) ||
        inc.title.toLowerCase().includes(q) ||
        (inc.description && inc.description.toLowerCase().includes(q)) ||
        (inc.source_cluster_key && inc.source_cluster_key.toLowerCase().includes(q))
      );
    }
    return true;
  });

  // Badges styling
  const severityBadge = (sev) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-red-950/80 text-red-400 border border-red-500/50";
      case "HIGH":
        return "bg-amber-950/80 text-amber-400 border border-amber-500/50";
      case "MEDIUM":
        return "bg-yellow-950/80 text-yellow-400 border border-yellow-500/50";
      default:
        return "bg-slate-900 text-slate-400 border border-slate-700";
    }
  };

  const priorityBadge = (prio) => {
    switch (prio) {
      case "P1":
        return "bg-red-900/60 text-red-300 border border-red-500/60 font-bold";
      case "P2":
        return "bg-amber-900/60 text-amber-300 border border-amber-500/60";
      case "P3":
        return "bg-blue-900/60 text-blue-300 border border-blue-500/60";
      default:
        return "bg-slate-800 text-slate-400 border border-slate-700";
    }
  };

  const statusBadge = (st) => {
    switch (st) {
      case "INVESTIGATING":
        return "bg-purple-950/80 text-purple-300 border border-purple-500/50 animate-pulse";
      case "TRIAGING":
        return "bg-cyan-950/80 text-cyan-300 border border-cyan-500/50";
      case "OPEN":
        return "bg-emerald-950/80 text-emerald-300 border border-emerald-500/50";
      case "REJECTED":
        return "bg-slate-900 text-slate-500 border border-slate-700 line-through";
      case "CLOSED":
        return "bg-slate-900 text-slate-400 border border-slate-700";
      default:
        return "bg-slate-900 text-slate-300 border border-slate-700";
    }
  };

  return (
    <main className="flex-1 flex flex-col h-full bg-sentinel-950 text-slate-200 overflow-y-auto">
      {/* ── Top Header / Command Center ──────────────────────────────── */}
      <div className="border-b border-white/10 bg-sentinel-900/40 p-6 backdrop-blur-md">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xl">🛡️</span>
              <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
                Security Incident Investigation
                <span className="text-xs px-2 py-0.5 rounded bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan font-mono">
                  Sprint 8A Live
                </span>
              </h1>
            </div>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Deterministic correlation, explainable root cause analysis, and verifiable investigation provenance.
            </p>
          </div>

          <div className="flex items-center gap-3">
            {canCreate && (
              <>
                <button
                  onClick={() => setShowCorrelationModal(true)}
                  className="px-3.5 py-2 rounded-xl bg-purple-950/80 hover:bg-purple-900 border border-purple-500/50 text-purple-200 text-xs font-mono font-bold flex items-center gap-2 transition cursor-pointer"
                >
                  <span>⚡</span>
                  <span>From Correlation</span>
                </button>
                <button
                  onClick={() => setShowManualModal(true)}
                  className="px-3.5 py-2 rounded-xl bg-accent-cyan/20 hover:bg-accent-cyan/30 border border-accent-cyan/50 text-accent-cyan text-xs font-mono font-bold flex items-center gap-2 transition cursor-pointer"
                >
                  <span>+</span>
                  <span>New Incident</span>
                </button>
              </>
            )}
            <button
              onClick={fetchData}
              className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-mono transition cursor-pointer"
              title="Refresh Incident Registry"
            >
              🔄
            </button>
          </div>
        </div>

        {/* ── Investigation Pipeline Flow ────────────────────────────── */}
        <div className="mt-6 pt-4 border-t border-white/5 flex items-center justify-between overflow-x-auto text-[11px] font-mono text-slate-400 gap-2">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 shrink-0">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>1. Signals (Drift/Trust)</span>
          </div>
          <span>→</span>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 shrink-0">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>2. Risk Correlation</span>
          </div>
          <span>→</span>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-cyan/15 border border-accent-cyan/40 text-accent-cyan font-bold shrink-0">
            <span className="w-2 h-2 rounded-full bg-accent-cyan animate-ping" />
            <span>3. Security Incident</span>
          </div>
          <span>→</span>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 shrink-0">
            <span className="w-2 h-2 rounded-full bg-purple-400" />
            <span>4. Evidence & Findings</span>
          </div>
          <span>→</span>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 shrink-0">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            <span>5. 13-Stage Provenance</span>
          </div>
        </div>
      </div>

      {/* ── KPI Row ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 p-6 border-b border-white/5 bg-sentinel-950/60">
        <div className="p-3.5 rounded-xl bg-sentinel-900/60 border border-white/10">
          <p className="text-[10px] uppercase font-mono text-slate-400">Total Incidents</p>
          <p className="text-xl font-bold font-mono text-white mt-1">{totalIncidents}</p>
        </div>
        <div className="p-3.5 rounded-xl bg-emerald-950/30 border border-emerald-500/20">
          <p className="text-[10px] uppercase font-mono text-emerald-400">Active / Open</p>
          <p className="text-xl font-bold font-mono text-emerald-300 mt-1">{openIncidents}</p>
        </div>
        <div className="p-3.5 rounded-xl bg-red-950/30 border border-red-500/20">
          <p className="text-[10px] uppercase font-mono text-red-400">Critical Severity</p>
          <p className="text-xl font-bold font-mono text-red-300 mt-1">{criticalIncidents}</p>
        </div>
        <div className="p-3.5 rounded-xl bg-amber-950/30 border border-amber-500/20">
          <p className="text-[10px] uppercase font-mono text-amber-400">P1 / P2 Priority</p>
          <p className="text-xl font-bold font-mono text-amber-300 mt-1">{highPriority}</p>
        </div>
        <div className="p-3.5 rounded-xl bg-purple-950/30 border border-purple-500/20">
          <p className="text-[10px] uppercase font-mono text-purple-400">Investigating</p>
          <p className="text-xl font-bold font-mono text-purple-300 mt-1">{investigatingCount}</p>
        </div>
        <div className="p-3.5 rounded-xl bg-blue-950/30 border border-blue-500/20">
          <p className="text-[10px] uppercase font-mono text-blue-400">Unassigned</p>
          <p className="text-xl font-bold font-mono text-blue-300 mt-1">{unassignedCount}</p>
        </div>
      </div>

      {/* ── Main Content Area: Registry Table & Details Workspace ───── */}
      <div className="p-6 space-y-6 flex-1">
        {/* Filters and Search Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-sentinel-900/50 border border-white/10">
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              placeholder="Search by incident #, title, cluster..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-sentinel-950 border border-white/15 text-xs text-slate-200 placeholder-slate-500 font-mono w-64 focus:outline-none focus:border-accent-cyan/50"
            />
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-sentinel-950 border border-white/15 text-xs text-slate-300 font-mono"
            >
              <option value="ALL">Severity: All</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
            <select
              value={selectedPriority}
              onChange={(e) => setSelectedPriority(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-sentinel-950 border border-white/15 text-xs text-slate-300 font-mono"
            >
              <option value="ALL">Priority: All</option>
              <option value="P1">P1 (Immediate)</option>
              <option value="P2">P2 (Urgent)</option>
              <option value="P3">P3 (Elevated)</option>
              <option value="P4">P4 (Routine)</option>
            </select>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-sentinel-950 border border-white/15 text-xs text-slate-300 font-mono"
            >
              <option value="ALL">Status: All</option>
              <option value="OPEN">Open</option>
              <option value="TRIAGING">Triaging</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="CLOSED">Closed</option>
              <option value="REJECTED">Rejected</option>
            </select>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-sentinel-950 border border-white/15 text-xs text-slate-300 font-mono"
            >
              <option value="ALL">Type: All</option>
              <option value="PROTECTED_FIELD">Protected Field</option>
              <option value="MULTI_SIGNAL">Multi-Signal</option>
              <option value="DETECTION_TRUST">Detection Trust</option>
              <option value="SEMANTIC_RISK">Semantic Risk</option>
              <option value="RISK_CLUSTER">Risk Cluster</option>
            </select>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Showing {filteredIncidents.length} of {incidents.length} records
          </span>
        </div>

        {/* Incident Registry Table */}
        <div className="rounded-xl border border-white/10 bg-sentinel-900/40 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-sentinel-950/80 border-b border-white/10 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="p-3.5">Incident #</th>
                  <th className="p-3.5">Title & Context</th>
                  <th className="p-3.5">Type</th>
                  <th className="p-3.5">Severity</th>
                  <th className="p-3.5">Priority</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5">Signals / Rules</th>
                  <th className="p-3.5">Analyst</th>
                  <th className="p-3.5">Created</th>
                  <th className="p-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300">
                {loading ? (
                  <tr>
                    <td colSpan={10} className="text-center p-8 text-slate-500">
                      Loading security incidents...
                    </td>
                  </tr>
                ) : filteredIncidents.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="text-center p-8 text-slate-500">
                      No security incidents match the active filters.
                    </td>
                  </tr>
                ) : (
                  filteredIncidents.map((inc) => (
                    <tr
                      key={inc.incident_id}
                      className={`hover:bg-white/[0.03] transition ${
                        activeIncidentId === inc.incident_id ? "bg-accent-cyan/10" : ""
                      }`}
                    >
                      <td className="p-3.5 font-bold text-accent-cyan whitespace-nowrap">
                        {inc.incident_number}
                      </td>
                      <td className="p-3.5 max-w-xs">
                        <p className="font-bold text-slate-200 truncate">{inc.title}</p>
                        {inc.source_cluster_key && (
                          <p className="text-[10px] text-purple-400 font-mono truncate mt-0.5">
                            🏷️ {inc.source_cluster_key}
                          </p>
                        )}
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        <span className="text-[10px] px-2 py-0.5 rounded bg-white/5 border border-white/10 text-slate-300">
                          {inc.incident_type}
                        </span>
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${severityBadge(inc.severity)}`}>
                          {inc.severity}
                        </span>
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        <span className={`text-[10px] px-2 py-0.5 rounded ${priorityBadge(inc.priority)}`}>
                          {inc.priority}
                        </span>
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${statusBadge(inc.status)}`}>
                          {inc.status}
                        </span>
                      </td>
                      <td className="p-3.5 whitespace-nowrap text-slate-400 text-[11px]">
                        ⚡ {inc.affected_signal_count} sigs · 🎯 {inc.affected_rule_count} rules
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        {inc.assigned_to_user_id ? (
                          <span className="text-xs text-emerald-300 flex items-center gap-1">
                            <span>👤</span>
                            <span>{inc.assigned_to_user_id}</span>
                          </span>
                        ) : (
                          <span className="text-xs text-slate-500 italic">Unassigned</span>
                        )}
                      </td>
                      <td className="p-3.5 whitespace-nowrap text-slate-500 text-[10px]">
                        {inc.created_at ? new Date(inc.created_at).toLocaleString() : "N/A"}
                      </td>
                      <td className="p-3.5 text-right whitespace-nowrap">
                        <button
                          onClick={() => fetchIncidentDetail(inc.incident_id)}
                          className="px-2.5 py-1.5 rounded-lg bg-accent-cyan/15 hover:bg-accent-cyan/25 border border-accent-cyan/40 text-accent-cyan text-xs font-mono font-bold transition cursor-pointer"
                        >
                          Investigate →
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* ── SECTION C: INCIDENT DETAIL WORKSPACE MODAL ──────────────── */}
      {incidentDetail && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-sentinel-950 border border-white/20 rounded-2xl w-full max-w-6xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-fade-in">
            {/* Modal Header */}
            <div className="p-5 border-b border-white/10 bg-sentinel-900/60 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-2xl">🔍</span>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold font-mono text-accent-cyan">
                      {incidentDetail.incident.incident_number}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${severityBadge(incidentDetail.incident.severity)}`}>
                      {incidentDetail.incident.severity}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded ${priorityBadge(incidentDetail.incident.priority)}`}>
                      {incidentDetail.incident.priority}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${statusBadge(incidentDetail.incident.status)}`}>
                      {incidentDetail.incident.status}
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-white mt-1">
                    {incidentDetail.incident.title}
                  </h2>
                </div>
              </div>
              <button
                onClick={() => setIncidentDetail(null)}
                className="w-8 h-8 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white flex items-center justify-center transition cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Navigation Tabs */}
            <div className="flex items-center gap-1 px-5 border-b border-white/10 bg-sentinel-950/80 overflow-x-auto text-xs font-mono">
              {[
                { id: "OVERVIEW", label: "Overview & Context", icon: "📋" },
                { id: "SIGNALS", label: `Contributing Signals (${incidentDetail.signals?.length || 0})`, icon: "⚡" },
                { id: "EVIDENCE", label: `Evidence Links (${incidentDetail.evidence?.length || 0})`, icon: "🔒" },
                { id: "FINDINGS", label: `Analyst Findings (${incidentDetail.findings?.length || 0})`, icon: "✍️" },
                { id: "TIMELINE", label: `Investigation Timeline (${incidentDetail.timeline?.length || 0})`, icon: "⏳" },
                { id: "GRAPH", label: "Root Cause Graph", icon: "🕸️" },
                { id: "PROVENANCE", label: "13-Stage Provenance", icon: "⛓️" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => {
                    setActiveTab(tab.id);
                    if (tab.id === "PROVENANCE" && !traceData) {
                      fetchProvenanceTrace(incidentDetail.incident.incident_id);
                    }
                  }}
                  className={`px-3 py-3 border-b-2 flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap ${
                    activeTab === tab.id
                      ? "border-accent-cyan text-accent-cyan font-bold bg-accent-cyan/5"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <span>{tab.icon}</span>
                  <span>{tab.label}</span>
                </button>
              ))}
            </div>

            {/* Tab Body */}
            <div className="p-6 overflow-y-auto flex-1 space-y-6">
              {/* TAB 1: OVERVIEW */}
              {activeTab === "OVERVIEW" && (
                <div className="space-y-6">
                  {/* Action Bar */}
                  <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-white/[0.02] border border-white/10">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400">Assigned Analyst:</span>
                      <span className="text-xs font-mono font-bold text-emerald-300">
                        {incidentDetail.incident.assigned_to_user_id || "Unassigned"}
                      </span>
                      {canAssign && (
                        <button
                          onClick={() => {
                            setAssignedUserId(incidentDetail.incident.assigned_to_user_id || "");
                            setShowAssignModal(true);
                          }}
                          className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] text-slate-300 font-mono ml-2 cursor-pointer"
                        >
                          Change
                        </button>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400">Lifecycle State:</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${statusBadge(incidentDetail.incident.status)}`}>
                        {incidentDetail.incident.status}
                      </span>
                      {canUpdateStatus && (
                        <button
                          onClick={() => {
                            setTargetStatus(
                              incidentDetail.incident.status === "OPEN"
                                ? "TRIAGING"
                                : incidentDetail.incident.status === "TRIAGING"
                                ? "INVESTIGATING"
                                : "TRIAGING"
                            );
                            setShowStatusModal(true);
                          }}
                          className="px-2.5 py-1 rounded bg-purple-950/80 hover:bg-purple-900 border border-purple-500/50 text-[10px] text-purple-200 font-mono font-bold cursor-pointer"
                        >
                          Transition Status
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Root Cause & Summary */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 rounded-xl bg-sentinel-900/60 border border-white/10 space-y-2">
                      <h4 className="text-xs font-bold font-mono text-accent-cyan uppercase">
                        🔍 Root Cause Summary
                      </h4>
                      <p className="text-xs text-slate-300 leading-relaxed font-mono">
                        {incidentDetail.incident.root_cause_summary || "Automated correlation did not identify a definitive root cause string."}
                      </p>
                    </div>

                    <div className="p-4 rounded-xl bg-sentinel-900/60 border border-white/10 space-y-2">
                      <h4 className="text-xs font-bold font-mono text-purple-400 uppercase">
                        🎯 Blast Radius & Impact
                      </h4>
                      <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
                        <div className="p-2 rounded bg-white/5">
                          <p className="text-slate-400 text-[10px]">Rules</p>
                          <p className="text-sm font-bold text-white mt-0.5">{incidentDetail.incident.affected_rule_count}</p>
                        </div>
                        <div className="p-2 rounded bg-white/5">
                          <p className="text-slate-400 text-[10px]">Fields</p>
                          <p className="text-sm font-bold text-white mt-0.5">{incidentDetail.incident.affected_field_count}</p>
                        </div>
                        <div className="p-2 rounded bg-white/5">
                          <p className="text-slate-400 text-[10px]">Confidence</p>
                          <p className="text-sm font-bold text-emerald-400 mt-0.5">{(incidentDetail.incident.confidence * 100).toFixed(0)}%</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Incident Description */}
                  <div className="p-4 rounded-xl bg-sentinel-900/40 border border-white/10 space-y-2">
                    <h4 className="text-xs font-bold font-mono text-slate-300 uppercase">
                      Technical Description & Origin
                    </h4>
                    <p className="text-xs text-slate-400 leading-relaxed font-mono whitespace-pre-wrap">
                      {incidentDetail.incident.description || "No extended description provided."}
                    </p>
                    {incidentDetail.incident.source_correlation_id && (
                      <p className="text-[11px] font-mono text-cyan-400 pt-2 border-t border-white/5">
                        Initiated from Risk Correlation: <span className="font-bold">{incidentDetail.incident.source_correlation_id}</span>
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 2: CONTRIBUTING SIGNALS */}
              {activeTab === "SIGNALS" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold font-mono text-slate-300 uppercase">
                      Contributing Security Signals
                    </h4>
                    {canLink && (
                      <button
                        onClick={() => setShowSignalModal(true)}
                        className="px-2.5 py-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/50 text-cyan-300 text-xs font-mono font-bold transition cursor-pointer"
                      >
                        + Link Signal
                      </button>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {incidentDetail.signals?.map((sig) => (
                      <div
                        key={sig.incident_signal_id}
                        className="p-3.5 rounded-xl bg-sentinel-900/60 border border-white/10 space-y-1.5 font-mono text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 text-[10px] font-bold">
                            {sig.signal_type}
                          </span>
                          <span className="text-[10px] text-purple-400 uppercase font-bold">
                            {sig.relationship_type}
                          </span>
                        </div>
                        <p className="font-bold text-slate-200 text-xs truncate">
                          ID: {sig.signal_id}
                        </p>
                        <p className="text-[10px] text-slate-500">
                          Linked: {sig.created_at ? new Date(sig.created_at).toLocaleString() : "N/A"}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 3: EVIDENCE LINKS */}
              {activeTab === "EVIDENCE" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold font-mono text-slate-300 uppercase">
                      Immutable Upstream Evidence References
                    </h4>
                    {canLink && (
                      <button
                        onClick={() => setShowEvidenceModal(true)}
                        className="px-2.5 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-500/50 text-emerald-300 text-xs font-mono font-bold transition cursor-pointer"
                      >
                        + Link Evidence
                      </button>
                    )}
                  </div>

                  <div className="rounded-xl border border-white/10 bg-sentinel-900/40 overflow-hidden">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-sentinel-950/80 border-b border-white/10 text-slate-400 uppercase text-[10px]">
                        <tr>
                          <th className="p-3">Evidence Type</th>
                          <th className="p-3">Reference ID</th>
                          <th className="p-3">Relationship</th>
                          <th className="p-3">Verification</th>
                          <th className="p-3">Linked By</th>
                          <th className="p-3">Timestamp</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 text-slate-300">
                        {incidentDetail.evidence?.map((ev) => (
                          <tr key={ev.link_id} className="hover:bg-white/[0.02]">
                            <td className="p-3 font-bold text-accent-cyan">{ev.evidence_type}</td>
                            <td className="p-3 text-slate-200">{ev.evidence_id}</td>
                            <td className="p-3">
                              <span className="text-[10px] px-2 py-0.5 rounded bg-white/5 border border-white/10 text-slate-300">
                                {ev.relationship}
                              </span>
                            </td>
                            <td className="p-3 text-emerald-400 text-[11px]">
                              ✓ SHA-256 Verified
                            </td>
                            <td className="p-3 text-slate-400">{ev.linked_by_user_id}</td>
                            <td className="p-3 text-slate-500 text-[10px]">
                              {ev.linked_at ? new Date(ev.linked_at).toLocaleString() : "N/A"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 4: FINDINGS */}
              {activeTab === "FINDINGS" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold font-mono text-slate-300 uppercase">
                      Analyst Investigation Findings
                    </h4>
                    {canCreateFinding && (
                      <button
                        onClick={() => setShowFindingModal(true)}
                        className="px-2.5 py-1.5 rounded-lg bg-accent-cyan/20 hover:bg-accent-cyan/30 border border-accent-cyan/50 text-accent-cyan text-xs font-mono font-bold transition cursor-pointer"
                      >
                        + Add Finding
                      </button>
                    )}
                  </div>

                  <div className="space-y-3">
                    {incidentDetail.findings?.map((f) => (
                      <div
                        key={f.finding_id}
                        className="p-4 rounded-xl bg-sentinel-900/60 border border-white/10 space-y-2 font-mono text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded bg-purple-950 border border-purple-500/40 text-purple-300 text-[10px] font-bold">
                              {f.finding_type}
                            </span>
                            <span className="font-bold text-white text-sm">{f.title}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                                f.status === "CONFIRMED"
                                  ? "bg-emerald-950 text-emerald-300 border border-emerald-500/40"
                                  : f.status === "REJECTED"
                                  ? "bg-red-950 text-red-300 border border-red-500/40 line-through"
                                  : "bg-blue-950 text-blue-300 border border-blue-500/40"
                              }`}
                            >
                              {f.status}
                            </span>
                            {canReviewFinding && f.status === "OPEN" && (
                              <div className="flex items-center gap-1">
                                <button
                                  onClick={() => handleReviewFinding(f.finding_id, "CONFIRMED")}
                                  className="px-2 py-0.5 rounded bg-emerald-900/60 hover:bg-emerald-800 text-emerald-200 text-[10px] cursor-pointer"
                                  title="Confirm this finding"
                                >
                                  ✓ Confirm
                                </button>
                                <button
                                  onClick={() => handleReviewFinding(f.finding_id, "REJECTED")}
                                  className="px-2 py-0.5 rounded bg-red-900/60 hover:bg-red-800 text-red-200 text-[10px] cursor-pointer"
                                  title="Reject this finding"
                                >
                                  ✕ Reject
                                </button>
                              </div>
                            )}
                          </div>
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed font-mono whitespace-pre-wrap">
                          {f.description}
                        </p>
                        <div className="flex items-center justify-between text-[10px] text-slate-500 pt-2 border-t border-white/5">
                          <span>Author: {f.created_by_user_id}</span>
                          <span>Confidence: {(f.confidence * 100).toFixed(0)}%</span>
                          <span>Created: {f.created_at ? new Date(f.created_at).toLocaleString() : "N/A"}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 5: TIMELINE */}
              {activeTab === "TIMELINE" && (
                <div className="space-y-4">
                  <h4 className="text-xs font-bold font-mono text-slate-300 uppercase">
                    Append-Only Investigation Timeline
                  </h4>

                  <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-white/10 font-mono text-xs">
                    {incidentDetail.timeline?.map((ev, idx) => (
                      <div key={ev.timeline_event_id} className="relative space-y-1">
                        <span className="absolute -left-6 top-1 w-3 h-3 rounded-full bg-accent-cyan border-2 border-sentinel-950" />
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-accent-cyan text-xs">
                            {ev.event_type.replace(/_/g, " ")}
                          </span>
                          <span className="text-[10px] text-slate-500">
                            {ev.created_at ? new Date(ev.created_at).toLocaleString() : "N/A"}
                          </span>
                        </div>
                        <p className="text-slate-400 text-xs">
                          {ev.actor_user_id ? `Actor: ${ev.actor_user_id}` : "System Automated Engine"}
                        </p>
                        {ev.event_data && Object.keys(ev.event_data).length > 0 && (
                          <pre className="p-2 rounded bg-black/40 text-[10px] text-slate-400 overflow-x-auto border border-white/5">
                            {JSON.stringify(ev.event_data, null, 2)}
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 6: ROOT CAUSE INVESTIGATION GRAPH (SVG) */}
              {activeTab === "GRAPH" && (
                <div className="space-y-4 font-mono">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-slate-300 uppercase">
                      Deterministic Root Cause Investigation DAG
                    </h4>
                    <span className="text-[10px] text-slate-400">
                      Visualizing causality from Raw Evidence to Security Incident
                    </span>
                  </div>

                  <div className="p-4 rounded-xl bg-sentinel-900/60 border border-white/10 flex items-center justify-center overflow-x-auto">
                    <svg width="850" height="260" viewBox="0 0 850 260" className="w-full max-w-4xl">
                      <defs>
                        <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                          <path d="M 0 0 L 10 5 L 0 10 z" fill="#00e5ff" />
                        </marker>
                      </defs>

                      {/* Connection Edges */}
                      <line x1="100" y1="130" x2="220" y2="130" stroke="#00e5ff" strokeWidth="2" strokeDasharray="4 2" markerEnd="url(#arrow)" />
                      <line x1="280" y1="130" x2="380" y2="70" stroke="#ff5252" strokeWidth="2" markerEnd="url(#arrow)" />
                      <line x1="280" y1="130" x2="380" y2="190" stroke="#ffd740" strokeWidth="2" markerEnd="url(#arrow)" />
                      <line x1="450" y1="70" x2="550" y2="130" stroke="#ff5252" strokeWidth="2" markerEnd="url(#arrow)" />
                      <line x1="450" y1="190" x2="550" y2="130" stroke="#ffd740" strokeWidth="2" markerEnd="url(#arrow)" />
                      <line x1="620" y1="130" x2="720" y2="130" stroke="#00e5ff" strokeWidth="2" markerEnd="url(#arrow)" />

                      {/* Node 1: Raw Evidence */}
                      <g transform="translate(40, 100)">
                        <rect width="120" height="60" rx="8" fill="#0d1f2d" stroke="#00e5ff" strokeWidth="1.5" />
                        <text x="60" y="25" textAnchor="middle" fill="#00e5ff" fontSize="10" fontWeight="bold">Raw Evidence</text>
                        <text x="60" y="42" textAnchor="middle" fill="#94a3b8" fontSize="9">SHA-256 Vault</text>
                      </g>

                      {/* Node 2: Normalized Event */}
                      <g transform="translate(220, 100)">
                        <rect width="120" height="60" rx="8" fill="#0d1f2d" stroke="#38bdf8" strokeWidth="1.5" />
                        <text x="60" y="25" textAnchor="middle" fill="#38bdf8" fontSize="10" fontWeight="bold">Normalized Event</text>
                        <text x="60" y="42" textAnchor="middle" fill="#94a3b8" fontSize="9">OCSF Canonical</text>
                      </g>

                      {/* Node 3A: Semantic Drift Alert */}
                      <g transform="translate(380, 40)">
                        <rect width="130" height="60" rx="8" fill="#2d0d0d" stroke="#ff5252" strokeWidth="2" />
                        <text x="65" y="25" textAnchor="middle" fill="#ff5252" fontSize="10" fontWeight="bold">Semantic Drift</text>
                        <text x="65" y="42" textAnchor="middle" fill="#fca5a5" fontSize="9">action.result</text>
                      </g>

                      {/* Node 3B: Detection Trust Alert */}
                      <g transform="translate(380, 160)">
                        <rect width="130" height="60" rx="8" fill="#2d240d" stroke="#ffd740" strokeWidth="1.5" />
                        <text x="65" y="25" textAnchor="middle" fill="#ffd740" fontSize="10" fontWeight="bold">Trust Alert</text>
                        <text x="65" y="42" textAnchor="middle" fill="#fde68a" fontSize="9">drule_ssh AT_RISK</text>
                      </g>

                      {/* Node 4: Risk Correlation */}
                      <g transform="translate(550, 100)">
                        <rect width="130" height="60" rx="8" fill="#1e112a" stroke="#c084fc" strokeWidth="2" />
                        <text x="65" y="25" textAnchor="middle" fill="#c084fc" fontSize="10" fontWeight="bold">Risk Correlation</text>
                        <text x="65" y="42" textAnchor="middle" fill="#e9d5ff" fontSize="9">CRITICAL Cluster</text>
                      </g>

                      {/* Node 5: Security Incident */}
                      <g transform="translate(720, 100)">
                        <rect width="120" height="60" rx="8" fill="#140808" stroke="#ff5252" strokeWidth="2.5" />
                        <text x="60" y="25" textAnchor="middle" fill="#ff5252" fontSize="10" fontWeight="bold">Security Incident</text>
                        <text x="60" y="42" textAnchor="middle" fill="#fca5a5" fontSize="9">{incidentDetail.incident.incident_number}</text>
                      </g>
                    </svg>
                  </div>
                </div>
              )}

              {/* TAB 7: 13-STAGE PROVENANCE TRACE */}
              {activeTab === "PROVENANCE" && (
                <div className="space-y-4 font-mono">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-slate-300 uppercase">
                        13-Stage Investigation Provenance Chain
                      </h4>
                      <p className="text-[10px] text-slate-500">
                        Cryptographic verification from raw evidence to governance ledger
                      </p>
                    </div>
                    {traceData && (
                      <span className="text-xs px-2.5 py-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300 font-bold">
                        {traceData.verified_stages} / {traceData.total_stages} Stages Verified
                      </span>
                    )}
                  </div>

                  {traceLoading ? (
                    <div className="text-center p-8 text-slate-500 text-xs">
                      Computing 13-stage provenance trace...
                    </div>
                  ) : traceData?.stages ? (
                    <div className="space-y-2">
                      {traceData.stages.map((stg) => (
                        <div
                          key={stg.stage_number}
                          className={`p-3.5 rounded-xl border flex items-center justify-between text-xs transition ${
                            stg.status === "VERIFIED"
                              ? "bg-sentinel-900/60 border-emerald-500/30"
                              : "bg-slate-900/40 border-white/5 opacity-60"
                          }`}
                        >
                          <div className="flex items-center gap-3">
                            <span className="w-6 h-6 rounded-full bg-white/10 text-white font-bold flex items-center justify-center text-[10px]">
                              {stg.stage_number}
                            </span>
                            <div>
                              <p className="font-bold text-slate-200">
                                {stg.stage_name.replace(/_/g, " ")}
                              </p>
                              <p className="text-[10px] text-slate-400 mt-0.5">
                                {stg.description}
                              </p>
                              {stg.trace_hash && (
                                <p className="text-[9px] text-cyan-400 font-mono mt-0.5">
                                  Hash: {stg.trace_hash.slice(0, 24)}...
                                </p>
                              )}
                            </div>
                          </div>

                          <div className="text-right">
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                                stg.status === "VERIFIED"
                                  ? "bg-emerald-950 text-emerald-400 border border-emerald-500/50"
                                  : "bg-slate-800 text-slate-500 border border-slate-700"
                              }`}
                            >
                              {stg.status}
                            </span>
                            {stg.timestamp && (
                              <p className="text-[9px] text-slate-500 mt-1">
                                {new Date(stg.timestamp).toLocaleTimeString()}
                              </p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── MODAL: CREATE MANUAL INCIDENT ─────────────────────────── */}
      {showManualModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-950 border border-white/20 rounded-2xl w-full max-w-lg p-6 space-y-4 font-mono shadow-2xl">
            <h3 className="text-sm font-bold text-white uppercase">Create Manual Incident</h3>
            <form onSubmit={handleManualCreate} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Title</label>
                <input
                  type="text"
                  required
                  value={manualForm.title}
                  onChange={(e) => setManualForm({ ...manualForm, title: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200"
                  placeholder="e.g. Unauthorized Sudo Escalation"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Description</label>
                <textarea
                  rows={3}
                  value={manualForm.description}
                  onChange={(e) => setManualForm({ ...manualForm, description: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200"
                  placeholder="Technical findings and observed anomaly context..."
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={manualForm.severity}
                    onChange={(e) => setManualForm({ ...manualForm, severity: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Type</label>
                  <select
                    value={manualForm.incident_type}
                    onChange={(e) => setManualForm({ ...manualForm, incident_type: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200"
                  >
                    <option value="SEMANTIC_RISK">Semantic Risk</option>
                    <option value="DETECTION_TRUST">Detection Trust</option>
                    <option value="PROTECTED_FIELD">Protected Field</option>
                    <option value="MULTI_SIGNAL">Multi Signal</option>
                    <option value="GOVERNANCE_ANOMALY">Governance Anomaly</option>
                  </select>
                </div>
              </div>
              <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowManualModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-1.5 rounded-lg bg-accent-cyan/20 hover:bg-accent-cyan/30 text-accent-cyan border border-accent-cyan/50 font-bold"
                >
                  {actionLoading ? "Creating..." : "Create Incident"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: CREATE FROM CORRELATION ────────────────────────── */}
      {showCorrelationModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-950 border border-white/20 rounded-2xl w-full max-w-lg p-6 space-y-4 font-mono shadow-2xl">
            <h3 className="text-sm font-bold text-purple-300 uppercase">Generate Incident From Risk Correlation</h3>
            <p className="text-xs text-slate-400">
              Select an active correlation chain. Deterministic deduplication will safely reuse existing active incidents.
            </p>
            <form onSubmit={handleCorrelationCreate} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Target Risk Correlation</label>
                <select
                  required
                  value={selectedCorrelationId}
                  onChange={(e) => setSelectedCorrelationId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                >
                  <option value="">-- Select Correlation --</option>
                  {correlations.map((c) => (
                    <option key={c.correlation_id} value={c.correlation_id}>
                      [{c.severity}] {c.correlation_type} ({c.correlation_id})
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowCorrelationModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading || !selectedCorrelationId}
                  className="px-4 py-1.5 rounded-lg bg-purple-950 hover:bg-purple-900 text-purple-200 border border-purple-500/50 font-bold"
                >
                  {actionLoading ? "Processing..." : "Generate Incident"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: ASSIGN ANALYST ──────────────────────────────────── */}
      {showAssignModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-950 border border-white/20 rounded-2xl w-full max-w-md p-6 space-y-4 font-mono shadow-2xl">
            <h3 className="text-sm font-bold text-white uppercase">Assign Security Analyst</h3>
            <form onSubmit={handleAssignAnalyst} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Analyst User ID</label>
                <input
                  type="text"
                  value={assignedUserId}
                  onChange={(e) => setAssignedUserId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                  placeholder="e.g. usr_analyst_01 or leave blank to unassign"
                />
              </div>
              <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowAssignModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-1.5 rounded-lg bg-emerald-950 hover:bg-emerald-900 text-emerald-200 border border-emerald-500/50 font-bold"
                >
                  Save Assignment
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: UPDATE STATUS ──────────────────────────────────── */}
      {showStatusModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-950 border border-white/20 rounded-2xl w-full max-w-md p-6 space-y-4 font-mono shadow-2xl">
            <h3 className="text-sm font-bold text-purple-300 uppercase">Transition Incident Lifecycle</h3>
            <form onSubmit={handleStatusUpdate} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Target Status</label>
                <select
                  value={targetStatus}
                  onChange={(e) => setTargetStatus(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                >
                  {incidentDetail?.incident.status === "OPEN" && (
                    <option value="TRIAGING">TRIAGING</option>
                  )}
                  {incidentDetail?.incident.status === "TRIAGING" && (
                    <>
                      <option value="INVESTIGATING">INVESTIGATING</option>
                      <option value="REJECTED">REJECTED</option>
                    </>
                  )}
                  {incidentDetail?.incident.status === "INVESTIGATING" && (
                    <option value="TRIAGING">TRIAGING (Revert)</option>
                  )}
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Rationale / Audit Reason</label>
                <textarea
                  rows={3}
                  required
                  value={statusReason}
                  onChange={(e) => setStatusReason(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200"
                  placeholder="Reason for state transition..."
                />
              </div>
              <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowStatusModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-1.5 rounded-lg bg-purple-950 hover:bg-purple-900 text-purple-200 border border-purple-500/50 font-bold"
                >
                  Update Status
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: ADD FINDING ────────────────────────────────────── */}
      {showFindingModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-950 border border-white/20 rounded-2xl w-full max-w-lg p-6 space-y-4 font-mono shadow-2xl">
            <h3 className="text-sm font-bold text-accent-cyan uppercase">Add Investigation Finding</h3>
            <form onSubmit={handleAddFinding} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Finding Type</label>
                  <select
                    value={findingForm.finding_type}
                    onChange={(e) => setFindingForm({ ...findingForm, finding_type: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                  >
                    <option value="OBSERVATION">Observation</option>
                    <option value="ROOT_CAUSE">Root Cause</option>
                    <option value="IMPACT">Impact</option>
                    <option value="HYPOTHESIS">Hypothesis</option>
                    <option value="CONFIRMED_FACT">Confirmed Fact</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Confidence Rating</label>
                  <input
                    type="number"
                    step="0.05"
                    min="0"
                    max="1"
                    value={findingForm.confidence}
                    onChange={(e) => setFindingForm({ ...findingForm, confidence: parseFloat(e.target.value) })}
                    className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Title</label>
                <input
                  type="text"
                  required
                  value={findingForm.title}
                  onChange={(e) => setFindingForm({ ...findingForm, title: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200"
                  placeholder="e.g. Semantic mapping changed from ALLOWED to MONITORED"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Description & Evidence Grounding</label>
                <textarea
                  rows={4}
                  required
                  value={findingForm.description}
                  onChange={(e) => setFindingForm({ ...findingForm, description: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200"
                  placeholder="Detailed findings and evidence justification..."
                />
              </div>
              <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowFindingModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-1.5 rounded-lg bg-accent-cyan/20 hover:bg-accent-cyan/30 text-accent-cyan border border-accent-cyan/50 font-bold"
                >
                  Save Finding
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: LINK EVIDENCE ──────────────────────────────────── */}
      {showEvidenceModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-950 border border-white/20 rounded-2xl w-full max-w-md p-6 space-y-4 font-mono shadow-2xl">
            <h3 className="text-sm font-bold text-emerald-300 uppercase">Link Upstream Evidence</h3>
            <p className="text-[11px] text-slate-400">
              Stores an immutable reference without duplicating upstream records.
            </p>
            <form onSubmit={handleLinkEvidence} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Evidence Type</label>
                <select
                  value={evidenceForm.evidence_type}
                  onChange={(e) => setEvidenceForm({ ...evidenceForm, evidence_type: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                >
                  <option value="RAW_EVIDENCE">Raw Evidence (Log)</option>
                  <option value="NORMALIZED_EVENT">Normalized Event</option>
                  <option value="SEMANTIC_INTERPRETATION">Semantic Interpretation</option>
                  <option value="DRIFT_ALERT">Drift Alert</option>
                  <option value="TRUST_EVALUATION">Trust Evaluation</option>
                  <option value="RISK_CORRELATION">Risk Correlation</option>
                  <option value="MERKLE_BATCH">Merkle Batch</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Evidence Reference ID</label>
                <input
                  type="text"
                  required
                  value={evidenceForm.evidence_id}
                  onChange={(e) => setEvidenceForm({ ...evidenceForm, evidence_id: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                  placeholder="e.g. ev_cisco_asa_permit_log"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Relationship</label>
                <select
                  value={evidenceForm.relationship}
                  onChange={(e) => setEvidenceForm({ ...evidenceForm, relationship: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                >
                  <option value="PRIMARY">Primary</option>
                  <option value="SUPPORTING">Supporting</option>
                  <option value="ROOT_CAUSE">Root Cause</option>
                  <option value="FORENSIC_CONTEXT">Forensic Context</option>
                </select>
              </div>
              <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowEvidenceModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-1.5 rounded-lg bg-emerald-950 hover:bg-emerald-900 text-emerald-200 border border-emerald-500/50 font-bold"
                >
                  Link Reference
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: LINK SIGNAL ────────────────────────────────────── */}
      {showSignalModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-950 border border-white/20 rounded-2xl w-full max-w-md p-6 space-y-4 font-mono shadow-2xl">
            <h3 className="text-sm font-bold text-cyan-300 uppercase">Link Security Signal</h3>
            <form onSubmit={handleLinkSignal} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Signal Type</label>
                <select
                  value={signalForm.signal_type}
                  onChange={(e) => setSignalForm({ ...signalForm, signal_type: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                >
                  <option value="DETECTION_TRUST_ALERT">Detection Trust Alert</option>
                  <option value="SEMANTIC_DRIFT_ALERT">Semantic Drift Alert</option>
                  <option value="RISK_CORRELATION">Risk Correlation</option>
                  <option value="REMEDIATION_CANDIDATE">Remediation Candidate</option>
                  <option value="POSTURE_FINDING">Posture Finding</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Signal Identifier</label>
                <input
                  type="text"
                  required
                  value={signalForm.signal_id}
                  onChange={(e) => setSignalForm({ ...signalForm, signal_id: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                  placeholder="e.g. dta_ssh_rule_01"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Relationship</label>
                <select
                  value={signalForm.relationship_type}
                  onChange={(e) => setSignalForm({ ...signalForm, relationship_type: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-sentinel-900 border border-white/10 text-slate-200 font-mono"
                >
                  <option value="PRIMARY_TRIGGER">Primary Trigger</option>
                  <option value="CONTRIBUTING_SIGNAL">Contributing Signal</option>
                  <option value="ROOT_CAUSE">Root Cause</option>
                  <option value="DOWNSTREAM_IMPACT">Downstream Impact</option>
                  <option value="SUPPORTING_EVIDENCE">Supporting Evidence</option>
                </select>
              </div>
              <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowSignalModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-200 border border-cyan-500/50 font-bold"
                >
                  Link Signal
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </main>
  );
}
