/**
 * pages/PolicyApprovals.jsx
 * -------------------------
 * Dual-Control Approval & Policy Governance Workflow Interface.
 *
 * Sprint 4B — Maker-Checker Separation of Duties & Immutable Governance Audit Trail.
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import AccessRestricted from "../components/AccessRestricted";

const STATUS_COLORS = {
  DRAFT: "bg-slate-900/80 border-slate-700 text-slate-300",
  PENDING: "bg-amber-950/70 border-amber-500/60 text-amber-300 animate-pulse",
  PENDING_REVIEW: "bg-amber-950/70 border-amber-500/60 text-amber-300",
  APPROVED: "bg-emerald-950/70 border-emerald-500/60 text-emerald-300",
  REJECTED: "bg-rose-950/70 border-rose-500/60 text-rose-300",
  ACTIVE: "bg-cyan-950/70 border-cyan-500/60 text-cyan-300 shadow-sm shadow-cyan-500/20",
  SUPERSEDED: "bg-purple-950/70 border-purple-500/60 text-purple-300 line-through",
};

const ACTION_BADGES = {
  POLICY_CREATED: "bg-slate-800 text-slate-300 border-slate-700",
  POLICY_UPDATED: "bg-slate-800 text-slate-300 border-slate-700",
  POLICY_SUBMITTED: "bg-blue-950 text-blue-300 border-blue-500/50",
  POLICY_REVIEW_STARTED: "bg-indigo-950 text-indigo-300 border-indigo-500/50",
  POLICY_APPROVED: "bg-emerald-950 text-emerald-300 border-emerald-500/50",
  POLICY_REJECTED: "bg-rose-950 text-rose-300 border-rose-500/50",
  POLICY_ACTIVATED: "bg-cyan-950 text-cyan-300 border-cyan-500/50",
  POLICY_SUPERSEDED: "bg-purple-950 text-purple-300 border-purple-500/50",
};

export default function PolicyApprovals() {
  const { user, hasPermission, authFetch } = useAuth();

  // Primary state
  const [approvals, setApprovals] = useState([]);
  const [metrics, setMetrics] = useState({
    pending_count: 0,
    approved_count: 0,
    rejected_count: 0,
    active_count: 0,
    total: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  // Review Modal State
  const [selectedApproval, setSelectedApproval] = useState(null);
  const [approvalDetails, setApprovalDetails] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [reviewComment, setReviewComment] = useState("");
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [actionSuccess, setActionSuccess] = useState(null);

  // Security Alert Modal for Maker-Checker violation
  const [securityViolation, setSecurityViolation] = useState(null);

  // Governance Timeline Modal State
  const [timelinePolicyId, setTimelinePolicyId] = useState(null);
  const [timelineData, setTimelineData] = useState([]);
  const [loadingTimeline, setLoadingTimeline] = useState(false);

  // Fetch approvals queue and active count
  const fetchApprovals = async () => {
    setLoading(true);
    setError(null);
    try {
      const url = statusFilter === "ALL" 
        ? "/api/v1/policy-approvals" 
        : `/api/v1/policy-approvals?status=${statusFilter}`;
      
      const res = await authFetch(url);
      if (!res.ok) {
        if (res.status === 403) {
          setError("ACCESS_DENIED");
          setLoading(false);
          return;
        }
        throw new Error(`Failed to load approval requests: HTTP ${res.status}`);
      }
      const data = await res.json();
      setApprovals(data.items || []);
      
      // Also fetch policies to count ACTIVE
      const polRes = await authFetch("/api/v1/semantic-policies");
      let activeCount = 0;
      if (polRes.ok) {
        const polData = await polRes.json();
        activeCount = (polData.items || []).filter(p => p.status === "ACTIVE").length;
      }

      setMetrics({
        pending_count: data.pending_count || 0,
        approved_count: data.approved_count || 0,
        rejected_count: data.rejected_count || 0,
        active_count: activeCount,
        total: data.total || 0,
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApprovals();
  }, [statusFilter]);

  // Open review modal and fetch full details
  const openReviewModal = async (approval) => {
    setSelectedApproval(approval);
    setReviewComment("");
    setActionError(null);
    setActionSuccess(null);
    setLoadingDetails(true);
    try {
      const res = await authFetch(`/api/v1/policy-approvals/${approval.approval_id}`);
      if (res.ok) {
        const data = await res.json();
        setApprovalDetails(data);
      } else {
        setActionError("Failed to fetch full approval details");
      }
    } catch (err) {
      setActionError(err.message);
    } finally {
      setLoadingDetails(false);
    }
  };

  // Approve action
  const handleApprove = async () => {
    if (!selectedApproval) return;
    setActionLoading(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const res = await authFetch(`/api/v1/policy-approvals/${selectedApproval.approval_id}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ review_comment: reviewComment || "Approved via Governance Console" }),
      });
      
      const data = await res.json();
      if (!res.ok) {
        if (res.status === 403 && data.detail && data.detail.includes("SELF_APPROVAL_FORBIDDEN")) {
          setSecurityViolation({
            title: "MAKER-CHECKER SECURITY VIOLATION",
            code: "SELF_APPROVAL_FORBIDDEN (HTTP 403)",
            message: "Policy authors are strictly prohibited from approving their own policies under Dual-Control governance rules.",
            details: `Requester: ${selectedApproval.requested_by_username} | Current Actor: ${user.username}`,
          });
          return;
        }
        throw new Error(data.detail || `Approval failed with HTTP ${res.status}`);
      }

      setActionSuccess(`Policy successfully APPROVED by ${user.username}.`);
      setTimeout(() => {
        setSelectedApproval(null);
        fetchApprovals();
      }, 1200);
    } catch (err) {
      setActionError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  // Reject action
  const handleReject = async () => {
    if (!selectedApproval) return;
    if (!reviewComment.trim()) {
      setActionError("A rejection reason/comment is required.");
      return;
    }
    setActionLoading(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const res = await authFetch(`/api/v1/policy-approvals/${selectedApproval.approval_id}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ review_comment: reviewComment }),
      });
      
      const data = await res.json();
      if (!res.ok) {
        if (res.status === 403 && data.detail && data.detail.includes("SELF_APPROVAL_FORBIDDEN")) {
          setSecurityViolation({
            title: "MAKER-CHECKER SECURITY VIOLATION",
            code: "SELF_APPROVAL_FORBIDDEN (HTTP 403)",
            message: "Policy authors cannot reject or review their own approval tickets.",
            details: `Requester: ${selectedApproval.requested_by_username} | Current Actor: ${user.username}`,
          });
          return;
        }
        throw new Error(data.detail || `Rejection failed with HTTP ${res.status}`);
      }

      setActionSuccess(`Policy successfully REJECTED.`);
      setTimeout(() => {
        setSelectedApproval(null);
        fetchApprovals();
      }, 1200);
    } catch (err) {
      setActionError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  // Activate policy action
  const handleActivate = async (policyId) => {
    setActionLoading(true);
    try {
      const res = await authFetch(`/api/v1/semantic-policies/${policyId}/activate`, {
        method: "POST",
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || `Activation failed with HTTP ${res.status}`);
      }
      alert(`Policy ${data.activated_policy_id} is now ACTIVE. ${data.superseded_policy_id ? `Superseded previous policy: ${data.superseded_policy_id}` : 'No previous version superseded.'}`);
      fetchApprovals();
    } catch (err) {
      alert(`Activation error: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  // Open Governance Timeline
  const openTimeline = async (policyId) => {
    setTimelinePolicyId(policyId);
    setLoadingTimeline(true);
    try {
      const res = await authFetch(`/api/v1/semantic-policies/${policyId}/governance-history`);
      if (res.ok) {
        const data = await res.json();
        setTimelineData(data.timeline || []);
      } else {
        setTimelineData([]);
      }
    } catch (err) {
      setTimelineData([]);
    } finally {
      setLoadingTimeline(false);
    }
  };

  // Trigger quick Maker-Checker demo test
  const triggerSelfApprovalDemo = async () => {
    try {
      // 1. Create temporary draft policy as current user
      const polRes = await authFetch("/api/v1/semantic-policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          policy_name: `Self-Approval Demo Policy ${Date.now().toString().slice(-4)}`,
          vendor_name: "Demo Vendor",
          source_profile_id: "sp_demo_vendor",
          status: "DRAFT",
          description: "Temporary draft policy created to demonstrate Maker-Checker security block.",
          rules: [{
            source_field: "action",
            source_value: "DEMO_TEST",
            canonical_field: "action.result",
            canonical_value: "MONITORED",
          }],
        }),
      });

      if (!polRes.ok) {
        alert("Could not create demo draft policy. Please ensure you have POLICY_AUTHOR or ADMIN role.");
        return;
      }
      const newPol = await polRes.json();

      // 2. Submit policy for review
      const subRes = await authFetch(`/api/v1/semantic-policies/${newPol.policy_id}/submit`, {
        method: "POST",
      });
      if (!subRes.ok) {
        alert("Submission failed during demo setup.");
        return;
      }
      const subData = await subRes.json();

      // 3. Current user attempts to self-approve
      const appRes = await authFetch(`/api/v1/policy-approvals/${subData.approval_id}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ review_comment: "Attempted self-approval demo" }),
      });

      if (appRes.status === 403) {
        const errData = await appRes.json();
        setSecurityViolation({
          title: "MAKER-CHECKER SECURITY BLOCK DEMONSTRATED",
          code: "HTTP 403 FORBIDDEN — SELF_APPROVAL_FORBIDDEN",
          message: `The server actively blocked ${user.username} from approving policy ${newPol.policy_id} because the creator and approver are the identical user.`,
          details: `Policy Author: ${user.username} | Attempted Approver: ${user.username} | Enforcement: Separation of Duties Strict Barrier`,
        });
      }
      fetchApprovals();
    } catch (err) {
      alert(`Demo error: ${err.message}`);
    }
  };

  if (error === "ACCESS_DENIED") {
    return (
      <AccessRestricted
        requiredRole="POLICY_REVIEWER, ADMIN, or AUDITOR"
        requiredPermission="POLICY_REVIEW or GOVERNANCE_AUDIT_READ"
      />
    );
  }

  const filteredApprovals = approvals.filter((a) => {
    const q = searchQuery.toLowerCase();
    return (
      a.approval_id.toLowerCase().includes(q) ||
      a.policy_id.toLowerCase().includes(q) ||
      (a.policy_name && a.policy_name.toLowerCase().includes(q)) ||
      (a.vendor_name && a.vendor_name.toLowerCase().includes(q)) ||
      (a.requested_by_username && a.requested_by_username.toLowerCase().includes(q))
    );
  });

  return (
    <main className="flex-1 flex flex-col bg-sentinel-950 overflow-hidden min-w-0">
      {/* Top Header */}
      <header className="px-6 py-4 border-b border-sentinel-800/80 bg-sentinel-900/50 backdrop-blur-sm flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-xl">⚖️</span>
            <h1 className="text-base font-semibold text-slate-100 font-mono tracking-tight">
              Policy Governance & Dual-Control Approvals
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-950/80 text-indigo-300 border border-indigo-500/40">
              Sprint 4B Frozen
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Maker-Checker Separation of Duties • Multi-State Lifecycle • Immutable Governance Audit Trail
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={triggerSelfApprovalDemo}
            className="px-3 py-1.5 rounded-lg bg-rose-950/50 hover:bg-rose-900/60 border border-rose-500/40 text-rose-300 text-xs font-mono font-medium flex items-center gap-2 transition-colors shadow-sm"
            title="Demonstrate active Maker-Checker block when an author attempts self-approval"
          >
            <span className="w-2 h-2 rounded-full bg-rose-400 animate-ping" />
            Maker-Checker Violation Demo
          </button>
          <button
            onClick={fetchApprovals}
            className="px-3 py-1.5 rounded-lg bg-sentinel-800 hover:bg-sentinel-700 border border-sentinel-700 text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            ↻ Refresh Queue
          </button>
        </div>
      </header>

      {/* Main Container */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* KPI Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-sentinel-900/60 border border-sentinel-800 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-amber-400 uppercase tracking-wider">Pending Reviews</span>
              <span className="text-amber-400 text-lg">⏳</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{metrics.pending_count}</div>
            <p className="text-[11px] text-slate-500 mt-1">Requires dual-control checker sign-off</p>
          </div>

          <div className="p-4 rounded-xl bg-sentinel-900/60 border border-sentinel-800 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-emerald-400 uppercase tracking-wider">Approved Policies</span>
              <span className="text-emerald-400 text-lg">✓</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{metrics.approved_count}</div>
            <p className="text-[11px] text-slate-500 mt-1">Ready for controlled activation</p>
          </div>

          <div className="p-4 rounded-xl bg-sentinel-900/60 border border-sentinel-800 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-rose-400 uppercase tracking-wider">Rejected Requests</span>
              <span className="text-rose-400 text-lg">✕</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{metrics.rejected_count}</div>
            <p className="text-[11px] text-slate-500 mt-1">Returned to author with audit reason</p>
          </div>

          <div className="p-4 rounded-xl bg-sentinel-900/60 border border-sentinel-800 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">Active Policies</span>
              <span className="text-cyan-400 text-lg">🛡️</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{metrics.active_count}</div>
            <p className="text-[11px] text-slate-500 mt-1">Enforcing runtime normalization</p>
          </div>
        </div>

        {/* Maker-Checker Architecture Banner */}
        <div className="p-4 rounded-xl bg-gradient-to-r from-indigo-950/40 via-sentinel-900/80 to-sentinel-900/40 border border-indigo-500/30 flex items-start gap-3">
          <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 text-xl flex-shrink-0">
            🛡️
          </div>
          <div className="space-y-1 text-xs">
            <h3 className="font-semibold text-slate-200 font-mono flex items-center gap-2">
              Maker-Checker Security Governance Active
              <span className="px-1.5 py-0.2 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-500/40">
                Separation of Duties Enforced
              </span>
            </h3>
            <p className="text-slate-400 leading-relaxed">
              In accordance with Zero Trust and cybersecurity governance standards, policy authors cannot approve their own policies.
              Direct transitions from <span className="text-slate-300 font-mono">DRAFT</span> to <span className="text-cyan-300 font-mono">ACTIVE</span> are strictly prohibited by the server state machine.
            </p>
          </div>
        </div>

        {/* Approval Queue Section */}
        <div className="rounded-xl bg-sentinel-900/60 border border-sentinel-800 overflow-hidden">
          {/* Controls Bar */}
          <div className="p-4 border-b border-sentinel-800 flex flex-wrap items-center justify-between gap-4">
            {/* Filter Tabs */}
            <div className="flex items-center gap-1.5 bg-sentinel-950/80 p-1 rounded-lg border border-sentinel-800">
              {["ALL", "PENDING", "APPROVED", "REJECTED"].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setStatusFilter(tab)}
                  className={`px-3 py-1 rounded text-xs font-mono font-medium transition-colors ${
                    statusFilter === tab
                      ? "bg-indigo-600 text-white shadow"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            {/* Search Input */}
            <div className="relative min-w-[260px]">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search ticket, policy, author..."
                className="w-full px-3 py-1.5 bg-sentinel-950 border border-sentinel-700 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          {/* Queue Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-sentinel-950/60 text-slate-400 font-mono uppercase tracking-wider border-b border-sentinel-800">
                <tr>
                  <th className="py-3 px-4">Approval ID</th>
                  <th className="py-3 px-4">Policy</th>
                  <th className="py-3 px-4">Vendor</th>
                  <th className="py-3 px-4">Version</th>
                  <th className="py-3 px-4">Requested By</th>
                  <th className="py-3 px-4">Requested At</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-800/60 text-slate-300">
                {loading ? (
                  <tr>
                    <td colSpan="8" className="py-8 text-center text-slate-500 font-mono">
                      Loading governance requests...
                    </td>
                  </tr>
                ) : filteredApprovals.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="py-8 text-center text-slate-500 font-mono">
                      No policy approval requests matching the selected filter.
                    </td>
                  </tr>
                ) : (
                  filteredApprovals.map((item) => (
                    <tr key={item.approval_id} className="hover:bg-sentinel-800/30 transition-colors">
                      <td className="py-3 px-4 font-mono font-medium text-slate-200">
                        {item.approval_id}
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-200">{item.policy_name || item.policy_id}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{item.policy_id}</div>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {item.vendor_name || "—"}
                      </td>
                      <td className="py-3 px-4 font-mono">
                        v{item.version || 1}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        <div className="flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                          <span>{item.requested_by_username || item.requested_by_user_id}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                        {item.requested_at ? new Date(item.requested_at).toLocaleString() : "—"}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${STATUS_COLORS[item.status] || STATUS_COLORS.DRAFT}`}>
                          {item.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          onClick={() => openReviewModal(item)}
                          className="px-2.5 py-1 rounded bg-indigo-950 hover:bg-indigo-900 border border-indigo-500/40 text-indigo-300 text-[11px] font-mono transition-colors"
                        >
                          Review & Diff
                        </button>
                        {item.status === "APPROVED" && (
                          <button
                            onClick={() => handleActivate(item.policy_id)}
                            className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 text-[11px] font-mono transition-colors"
                          >
                            Activate
                          </button>
                        )}
                        <button
                          onClick={() => openTimeline(item.policy_id)}
                          className="px-2.5 py-1 rounded bg-sentinel-800 hover:bg-sentinel-700 border border-sentinel-700 text-slate-300 text-[11px] font-mono transition-colors"
                        >
                          Timeline
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

      {/* Review & Dual-Control Decision Modal */}
      {selectedApproval && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-sentinel-700 rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-fade-in">
            {/* Modal Header */}
            <div className="p-5 border-b border-sentinel-800 flex items-center justify-between bg-sentinel-950/60">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-lg">📋</span>
                  <h2 className="text-sm font-bold font-mono text-slate-100">
                    Dual-Control Policy Review: {selectedApproval.approval_id}
                  </h2>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Target Policy: {selectedApproval.policy_id} (Version {selectedApproval.version || 1})
                </p>
              </div>
              <button
                onClick={() => setSelectedApproval(null)}
                className="p-1 rounded-lg hover:bg-sentinel-800 text-slate-400 hover:text-slate-200 font-mono text-sm"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-5 text-xs">
              {/* Maker-Checker Enforced Warning */}
              <div className="p-3.5 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-300 flex items-start gap-2.5">
                <span className="text-base">⚠️</span>
                <div className="space-y-0.5">
                  <span className="font-bold font-mono uppercase tracking-wide">
                    Maker-Checker Compliance Rule:
                  </span>
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    The policy author (<span className="text-amber-300 font-mono">{selectedApproval.requested_by_username || selectedApproval.requested_by_user_id}</span>)
                    cannot approve their own policy. Approval requires an independent authorized <span className="text-indigo-300 font-mono">POLICY_REVIEWER</span>.
                  </p>
                </div>
              </div>

              {loadingDetails ? (
                <div className="py-8 text-center text-slate-500 font-mono">Loading full policy specification...</div>
              ) : approvalDetails ? (
                <>
                  {/* Metadata Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-3 rounded-lg bg-sentinel-950 border border-sentinel-800">
                      <span className="text-slate-500 text-[10px] uppercase font-mono block">Vendor</span>
                      <span className="text-slate-200 font-mono font-medium">{approvalDetails.vendor_name}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-sentinel-950 border border-sentinel-800">
                      <span className="text-slate-500 text-[10px] uppercase font-mono block">Source Profile</span>
                      <span className="text-slate-200 font-mono">{approvalDetails.source_profile_id}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-sentinel-950 border border-sentinel-800">
                      <span className="text-slate-500 text-[10px] uppercase font-mono block">Requested By</span>
                      <span className="text-emerald-300 font-mono font-medium">{approvalDetails.requested_by_username}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-sentinel-950 border border-sentinel-800">
                      <span className="text-slate-500 text-[10px] uppercase font-mono block">Current State</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border inline-block mt-0.5 ${STATUS_COLORS[approvalDetails.status]}`}>
                        {approvalDetails.status}
                      </span>
                    </div>
                  </div>

                  {/* Semantic Rules Summary */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-semibold text-slate-300 uppercase tracking-wider text-[11px]">
                        Semantic Translation Rules ({approvalDetails.rules_count || 0})
                      </span>
                      {approvalDetails.supersedes_policy_id && (
                        <span className="text-purple-400 font-mono text-[10px]">
                          Supersedes: {approvalDetails.supersedes_policy_id}
                        </span>
                      )}
                    </div>
                    <div className="rounded-lg border border-sentinel-800 overflow-hidden">
                      <table className="w-full text-left text-[11px]">
                        <thead className="bg-sentinel-950 text-slate-400 font-mono uppercase">
                          <tr>
                            <th className="py-2 px-3">Rule ID</th>
                            <th className="py-2 px-3">Source Mapping</th>
                            <th className="py-2 px-3">Canonical Target</th>
                            <th className="py-2 px-3">Equivalence</th>
                            <th className="py-2 px-3">Risk</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-sentinel-800 font-mono text-slate-300">
                          {(approvalDetails.rules || []).map((rule) => (
                            <tr key={rule.rule_id} className="hover:bg-sentinel-800/40">
                              <td className="py-2 px-3 text-slate-400">{rule.rule_id}</td>
                              <td className="py-2 px-3 text-amber-300">{rule.source_field}={rule.source_value}</td>
                              <td className="py-2 px-3 text-cyan-300">{rule.canonical_field}={rule.canonical_value}</td>
                              <td className="py-2 px-3">{rule.equivalence_classification}</td>
                              <td className="py-2 px-3">
                                <span className={`px-1.5 py-0.5 rounded text-[9px] ${
                                  rule.risk_level === 'HIGH' ? 'bg-rose-950 text-rose-300 border border-rose-500/40' :
                                  rule.risk_level === 'MEDIUM' ? 'bg-amber-950 text-amber-300 border border-amber-500/40' :
                                  'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                                }`}>
                                  {rule.risk_level}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Review Comments & Decision Form */}
                  <div className="space-y-2 pt-2 border-t border-sentinel-800">
                    <label className="font-mono font-semibold text-slate-300 uppercase tracking-wider text-[11px] block">
                      Governance Reviewer Assessment & Remarks
                    </label>
                    <textarea
                      rows="3"
                      value={reviewComment}
                      onChange={(e) => setReviewComment(e.target.value)}
                      placeholder="State technical justification, verification results, or rejection rationale..."
                      className="w-full p-3 bg-sentinel-950 border border-sentinel-700 rounded-xl text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                    />
                  </div>

                  {actionError && (
                    <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-500/50 text-rose-300 font-mono text-xs">
                      {actionError}
                    </div>
                  )}

                  {actionSuccess && (
                    <div className="p-3 rounded-lg bg-emerald-950/50 border border-emerald-500/50 text-emerald-300 font-mono text-xs">
                      {actionSuccess}
                    </div>
                  )}
                </>
              ) : null}
            </div>

            {/* Modal Actions */}
            <div className="p-4 border-t border-sentinel-800 bg-sentinel-950/60 flex items-center justify-between">
              <div className="text-[11px] font-mono text-slate-400">
                Logged in as: <span className="text-indigo-300 font-semibold">{user?.username}</span> ({user?.role})
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => setSelectedApproval(null)}
                  className="px-3 py-1.5 rounded-lg bg-sentinel-800 hover:bg-sentinel-700 text-slate-300 text-xs font-mono transition-colors"
                >
                  Cancel
                </button>

                {selectedApproval.status === "PENDING" && (
                  <>
                    <button
                      onClick={handleReject}
                      disabled={actionLoading}
                      className="px-4 py-1.5 rounded-lg bg-rose-950 hover:bg-rose-900 border border-rose-500/50 text-rose-300 text-xs font-mono font-medium transition-colors"
                    >
                      Reject Policy
                    </button>
                    <button
                      onClick={handleApprove}
                      disabled={actionLoading}
                      className="px-4 py-1.5 rounded-lg bg-emerald-700 hover:bg-emerald-600 border border-emerald-500/60 text-white text-xs font-mono font-medium shadow-md transition-colors"
                    >
                      {actionLoading ? "Processing..." : "Approve Policy"}
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Security Violation Alert Modal */}
      {securityViolation && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border-2 border-rose-500/80 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl animate-fade-in">
            <div className="flex items-center gap-3 text-rose-400">
              <span className="text-3xl">🚫</span>
              <div>
                <h3 className="text-base font-bold font-mono tracking-tight text-rose-200">
                  {securityViolation.title}
                </h3>
                <span className="text-[11px] font-mono text-rose-400 font-semibold">
                  {securityViolation.code}
                </span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-sentinel-950 border border-rose-500/40 text-xs space-y-2">
              <p className="text-slate-200 font-medium leading-relaxed">
                {securityViolation.message}
              </p>
              <div className="p-2 rounded bg-rose-950/50 border border-rose-500/30 text-[11px] font-mono text-rose-300">
                {securityViolation.details}
              </div>
            </div>

            <p className="text-[11px] text-slate-400">
              Dual-control governance mandates that every semantic policy modification must receive an independent verification from a designated reviewer.
            </p>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSecurityViolation(null)}
                className="px-4 py-1.5 rounded-lg bg-rose-800 hover:bg-rose-700 text-white text-xs font-mono font-semibold transition-colors"
              >
                Acknowledge & Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Chronological Governance History Timeline Modal */}
      {timelinePolicyId && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-sentinel-700 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-fade-in">
            <div className="p-5 border-b border-sentinel-800 flex items-center justify-between bg-sentinel-950/60">
              <div>
                <h2 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
                  <span>📜</span> Governance Audit Timeline
                </h2>
                <p className="text-xs text-slate-400 font-mono mt-0.5">Policy ID: {timelinePolicyId}</p>
              </div>
              <button
                onClick={() => setTimelinePolicyId(null)}
                className="p-1 rounded-lg hover:bg-sentinel-800 text-slate-400 hover:text-slate-200 font-mono text-sm"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6">
              {loadingTimeline ? (
                <div className="py-8 text-center text-slate-500 font-mono">Retrieving immutable audit history...</div>
              ) : timelineData.length === 0 ? (
                <div className="py-8 text-center text-slate-500 font-mono">No governance audit events found for this policy.</div>
              ) : (
                <div className="relative border-l-2 border-sentinel-700 ml-4 space-y-6">
                  {timelineData.map((item, idx) => (
                    <div key={item.audit_id || idx} className="relative pl-6">
                      {/* Timeline Node Dot */}
                      <span className="absolute -left-[9px] top-1 w-4 h-4 rounded-full bg-sentinel-950 border-2 border-indigo-400" />
                      
                      <div className="p-3.5 rounded-xl bg-sentinel-950 border border-sentinel-800 space-y-1.5">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono border font-semibold ${ACTION_BADGES[item.action] || 'bg-slate-800 text-slate-300'}`}>
                            {item.action}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400">
                            {new Date(item.created_at).toLocaleString()}
                          </span>
                        </div>

                        <div className="text-xs text-slate-300 flex items-center gap-2">
                          <span className="font-semibold text-slate-200">{item.actor_username || "System"}</span>
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-sentinel-800 text-slate-400">
                            {item.actor_role || "SYSTEM"}
                          </span>
                        </div>

                        {(item.previous_state || item.new_state) && (
                          <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                            <span>Transition:</span>
                            <span className="text-amber-400">{item.previous_state || "NONE"}</span>
                            <span>→</span>
                            <span className="text-emerald-400">{item.new_state || "NONE"}</span>
                          </div>
                        )}

                        {item.reason && (
                          <p className="text-xs text-slate-400 italic bg-sentinel-900/50 p-2 rounded border border-sentinel-800/60">
                            "{item.reason}"
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="p-4 border-t border-sentinel-800 bg-sentinel-950/60 flex justify-end">
              <button
                onClick={() => setTimelinePolicyId(null)}
                className="px-4 py-1.5 rounded-lg bg-sentinel-800 hover:bg-sentinel-700 text-slate-300 text-xs font-mono transition-colors"
              >
                Close History
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
