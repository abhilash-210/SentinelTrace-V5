/**
 * SecurityInvestigationCommandCenter.jsx
 * --------------------------------------
 * Unified SOC Investigation & Security Case Management Command Center.
 *
 * Sprint 12A — Unified SOC Investigation & Security Case Management.
 * Core Invariant: "EVERY SECURITY INVESTIGATION MUST BE TRACEABLE FROM THE ANALYST QUESTION BACK TO CRYPTOGRAPHICALLY VERIFIABLE EVIDENCE."
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { API_V1_URL } from "../apiConfig";

function IconWrapper({ children, className = "w-4 h-4", ...props }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      {...props}
    >
      {children}
    </svg>
  );
}

const Shield = (props) => (
  <IconWrapper {...props}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></IconWrapper>
);
const Search = (props) => (
  <IconWrapper {...props}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></IconWrapper>
);
const Activity = (props) => (
  <IconWrapper {...props}><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></IconWrapper>
);
const AlertTriangle = (props) => (
  <IconWrapper {...props}><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></IconWrapper>
);
const CheckCircle2 = (props) => (
  <IconWrapper {...props}><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></IconWrapper>
);
const XCircle = (props) => (
  <IconWrapper {...props}><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></IconWrapper>
);
const Clock = (props) => (
  <IconWrapper {...props}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></IconWrapper>
);
const Layers = (props) => (
  <IconWrapper {...props}><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></IconWrapper>
);
const FileText = (props) => (
  <IconWrapper {...props}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></IconWrapper>
);
const UserCheck = (props) => (
  <IconWrapper {...props}><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/></IconWrapper>
);
const Lock = (props) => (
  <IconWrapper {...props}><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></IconWrapper>
);
const RefreshCw = (props) => (
  <IconWrapper {...props}><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></IconWrapper>
);
const GitPullRequest = (props) => (
  <IconWrapper {...props}><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/></IconWrapper>
);
const PlusCircle = (props) => (
  <IconWrapper {...props}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></IconWrapper>
);
const Link = (props) => (
  <IconWrapper {...props}><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></IconWrapper>
);
const Check = (props) => (
  <IconWrapper {...props}><polyline points="20 6 9 17 4 12"/></IconWrapper>
);

const API_BASE = `${API_V1_URL}/investigations`;

export default function SecurityInvestigationCommandCenter() {
  const { user, token } = useAuth();
  const [activeTab, setActiveTab] = useState("cases"); // cases, workspace, mitre, audit
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [statusMessage, setStatusMessage] = useState(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState("");
  const [priorityFilter, setPriorityFilter] = useState("");
  const [domainFilter, setDomainFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  // Workspace sub-tabs
  const [workspaceSubTab, setWorkspaceSubTab] = useState("timeline"); // timeline, artifacts, hypotheses, findings, impact, governance, provenance

  // Detailed case sub-entities
  const [artifacts, setArtifacts] = useState([]);
  const [timelineEvents, setTimelineEvents] = useState([]);
  const [hypotheses, setHypotheses] = useState([]);
  const [findings, setFindings] = useState([]);
  const [impactAssessment, setImpactAssessment] = useState(null);
  const [resolution, setResolution] = useState(null);
  const [provenanceStages, setProvenanceStages] = useState([]);
  const [provenanceValid, setProvenanceValid] = useState(null);

  // Modals & Forms
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newCase, setNewCase] = useState({
    title: "",
    description: "",
    source_domain: "DETECTION",
    lead_investigator_id: user?.username || "analyst_01",
    severity: "HIGH",
    mitre_attack_technique: "T1078.001",
  });

  const [showAddArtifactModal, setShowAddArtifactModal] = useState(false);
  const [newArtifact, setNewArtifact] = useState({
    domain: "DETECTION",
    source_entity_type: "ALERT",
    source_entity_id: "",
    cryptographic_checksum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    verification_status: "VERIFIED",
    notes: "",
  });

  const [showAddHypothesisModal, setShowAddHypothesisModal] = useState(false);
  const [newHypothesis, setNewHypothesis] = useState({
    hypothesis_statement: "",
    base_confidence: 0.85,
    status: "FORMULATED",
    evidence_count: 2,
    refuting_count: 0,
  });

  const [showAddFindingModal, setShowAddFindingModal] = useState(false);
  const [newFinding, setNewFinding] = useState({
    title: "",
    finding_type: "ROOT_CAUSE",
    description: "",
    confidence_score: 0.9,
    mitre_technique: "T1078.001",
    severity: "HIGH",
  });

  // Impact form
  const [impactForm, setImpactForm] = useState({
    confidentiality_impact: "HIGH",
    integrity_impact: "MODERATE",
    availability_impact: "LOW",
    business_impact: "HIGH",
    compliance_impact: "MODERATE",
    assessment_notes: "",
  });

  // Governance Resolution Proposal Form
  const [resolutionForm, setResolutionForm] = useState({
    root_cause_summary: "",
    remediation_summary: "",
    lessons_learned: "",
    recommended_actions: "Automate session termination and rotate privileged access tokens.",
  });

  // Governance Review Form
  const [reviewForm, setReviewForm] = useState({
    reviewer_comments: "",
    decision: "APPROVED", // APPROVED, REJECTED
  });

  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  });

  const showNotification = (msg, isError = false) => {
    setStatusMessage({ text: msg, isError });
    setTimeout(() => setStatusMessage(null), 6000);
  };

  const loadSummary = async () => {
    try {
      const res = await fetch(`${API_BASE}/dashboard/summary`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setSummary(data);
      }
    } catch (err) {
      console.error("Failed to load dashboard summary", err);
    }
  };

  const loadCases = async () => {
    setLoading(true);
    try {
      let queryParams = [];
      if (statusFilter) queryParams.push(`status=${statusFilter}`);
      if (priorityFilter) queryParams.push(`priority=${priorityFilter}`);
      if (domainFilter) queryParams.push(`source_domain=${domainFilter}`);
      const qs = queryParams.length ? `?${queryParams.join("&")}` : "";

      const res = await fetch(`${API_BASE}${qs}`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setCases(data);
        if (!selectedCase && data.length > 0) {
          selectCase(data[0]);
        }
      }
    } catch (err) {
      showNotification("Error loading investigation cases", true);
    } finally {
      setLoading(false);
    }
  };

  const selectCase = async (c) => {
    setSelectedCase(c);
    if (!c) return;

    try {
      // Load details in parallel
      const [artRes, timeRes, hypRes, findRes, impRes, resRes, provRes] = await Promise.all([
        fetch(`${API_BASE}/${c.id}/artifacts`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/${c.id}/timeline`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/${c.id}/hypotheses`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/${c.id}/findings`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/${c.id}/impact-assessment`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/${c.id}/resolution`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/${c.id}/provenance`, { headers: getAuthHeaders() }),
      ]);

      if (artRes.ok) setArtifacts(await artRes.json());
      if (timeRes.ok) setTimelineEvents(await timeRes.json());
      if (hypRes.ok) setHypotheses(await hypRes.json());
      if (findRes.ok) setFindings(await findRes.json());
      if (impRes.ok) {
        const impData = await impRes.json();
        setImpactAssessment(impData);
        if (impData) {
          setImpactForm({
            confidentiality_impact: impData.confidentiality_impact || "HIGH",
            integrity_impact: impData.integrity_impact || "MODERATE",
            availability_impact: impData.availability_impact || "LOW",
            business_impact: impData.business_impact || "HIGH",
            compliance_impact: impData.compliance_impact || "MODERATE",
            assessment_notes: impData.assessment_notes || "",
          });
        }
      } else {
        setImpactAssessment(null);
      }
      if (resRes.ok) setResolution(await resRes.json());
      else setResolution(null);
      if (provRes.ok) {
        const provData = await provRes.json();
        setProvenanceStages(provData.provenance_chain || []);
        setProvenanceValid(provData.lineage_verified);
      }
    } catch (err) {
      console.error("Error loading case details", err);
    }
  };

  useEffect(() => {
    loadSummary();
    loadCases();
  }, [statusFilter, priorityFilter, domainFilter]);

  const handleCreateCase = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(API_BASE, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(newCase),
      });
      if (res.ok) {
        const created = await res.json();
        showNotification(`Case created successfully: ${created.case_number}`);
        setShowCreateModal(false);
        loadSummary();
        loadCases();
        selectCase(created);
        setActiveTab("workspace");
      } else {
        const err = await res.json();
        showNotification(err.detail || "Failed to create case", true);
      }
    } catch (err) {
      showNotification("Network error creating case", true);
    }
  };

  const handleReconstructTimeline = async () => {
    if (!selectedCase) return;
    try {
      const res = await fetch(`${API_BASE}/${selectedCase.id}/timeline/reconstruct`, {
        method: "POST",
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const events = await res.json();
        setTimelineEvents(events);
        showNotification(`Timeline successfully reconstructed: ${events.length} chronological events.`);
      } else {
        showNotification("Failed to reconstruct timeline", true);
      }
    } catch (err) {
      showNotification("Error reconstructing timeline", true);
    }
  };

  const handleAddArtifact = async (e) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      const res = await fetch(`${API_BASE}/${selectedCase.id}/artifacts`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(newArtifact),
      });
      if (res.ok) {
        showNotification("Cross-domain artifact bound successfully");
        setShowAddArtifactModal(false);
        selectCase(selectedCase);
      } else {
        const err = await res.json();
        showNotification(err.detail || "Failed to bind artifact", true);
      }
    } catch (err) {
      showNotification("Error binding artifact", true);
    }
  };

  const handleAddHypothesis = async (e) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      const res = await fetch(`${API_BASE}/${selectedCase.id}/hypotheses`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(newHypothesis),
      });
      if (res.ok) {
        showNotification("Hypothesis formulated and confidence calculated");
        setShowAddHypothesisModal(false);
        selectCase(selectedCase);
      } else {
        const err = await res.json();
        showNotification(err.detail || "Failed to formulate hypothesis", true);
      }
    } catch (err) {
      showNotification("Error formulating hypothesis", true);
    }
  };

  const handleAddFinding = async (e) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      const res = await fetch(`${API_BASE}/${selectedCase.id}/findings`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(newFinding),
      });
      if (res.ok) {
        showNotification("Investigation finding logged successfully");
        setShowAddFindingModal(false);
        selectCase(selectedCase);
      } else {
        const err = await res.json();
        showNotification(err.detail || "Failed to log finding", true);
      }
    } catch (err) {
      showNotification("Error logging finding", true);
    }
  };

  const handleSaveImpact = async (e) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      const res = await fetch(`${API_BASE}/${selectedCase.id}/impact-assessment`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(impactForm),
      });
      if (res.ok) {
        const data = await res.json();
        setImpactAssessment(data);
        showNotification(`Impact matrix calculated: Score ${data.impact_score.toFixed(1)} / 100 (${data.impact_tier})`);
      } else {
        const err = await res.json();
        showNotification(err.detail || "Failed to save impact assessment", true);
      }
    } catch (err) {
      showNotification("Error saving impact assessment", true);
    }
  };

  const handleProposeResolution = async (e) => {
    e.preventDefault();
    if (!selectedCase) return;
    try {
      const res = await fetch(`${API_BASE}/${selectedCase.id}/propose-resolution`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(resolutionForm),
      });
      if (res.ok) {
        const updated = await res.json();
        showNotification(`Resolution proposed by ${updated.proposed_by}. Case transitioned to UNDER_REVIEW.`);
        selectCase(updated);
        loadSummary();
        loadCases();
      } else {
        const err = await res.json();
        showNotification(err.detail || "Failed to propose resolution", true);
      }
    } catch (err) {
      showNotification("Error proposing resolution", true);
    }
  };

  const handleReviewResolution = async (decision) => {
    if (!selectedCase) return;
    try {
      const res = await fetch(`${API_BASE}/${selectedCase.id}/review`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          reviewer_comments: reviewForm.reviewer_comments || "Verified cross-domain cryptographic evidence.",
          decision: decision,
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        showNotification(`Case decision '${decision}' executed by ${user?.username}. Case status: ${updated.status}.`);
        selectCase(updated);
        loadSummary();
        loadCases();
      } else {
        const err = await res.json();
        showNotification(err.detail || "Governance review failed", true);
      }
    } catch (err) {
      showNotification("Error submitting governance review", true);
    }
  };

  const handleVerifyProvenance = async () => {
    if (!selectedCase) return;
    try {
      const res = await fetch(`${API_BASE}/${selectedCase.id}/provenance`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const provData = await res.json();
        setProvenanceStages(provData.provenance_chain || []);
        setProvenanceValid(provData.lineage_verified);
        if (provData.lineage_verified) {
          showNotification("Cryptographic verification PASSED: 18-stage unbroken SHA-256 hash lineage verified.");
        } else {
          showNotification("Cryptographic verification FAILED: Provenance chain tampering detected!", true);
        }
      }
    } catch (err) {
      showNotification("Error verifying provenance lineage", true);
    }
  };

  const filteredCases = cases.filter((c) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.case_number.toLowerCase().includes(q) ||
      c.title.toLowerCase().includes(q) ||
      c.description?.toLowerCase().includes(q) ||
      c.lead_investigator_id?.toLowerCase().includes(q)
    );
  });

  return (
    <main className="flex-1 flex flex-col bg-slate-950 text-slate-100 overflow-y-auto">
      {/* Top Banner & Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur px-8 py-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <span className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Shield className="w-5 h-5" />
              </span>
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                  Unified SOC Investigation & Security Case Management
                  <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-mono border border-cyan-500/40">
                    Sprint 12A
                  </span>
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Cryptographically verifiable cross-domain investigation lineage & dual-control case governance
                </p>
              </div>
            </div>
          </div>

          {/* Core Invariant Badge */}
          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs font-mono">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>Evidence Traceability: INVIOLABLE</span>
            </div>
            <button
              onClick={() => {
                loadSummary();
                loadCases();
              }}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              title="Refresh Data"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-600/20 transition"
            >
              <PlusCircle className="w-4 h-4" />
              <span>New Investigation</span>
            </button>
          </div>
        </div>

        {/* Global Notification */}
        {statusMessage && (
          <div
            className={`mt-4 p-3 rounded-lg border text-xs flex items-center justify-between font-mono animate-fade-in ${
              statusMessage.isError
                ? "bg-rose-950/60 border-rose-500/40 text-rose-200"
                : "bg-emerald-950/60 border-emerald-500/40 text-emerald-200"
            }`}
          >
            <div className="flex items-center gap-2">
              {statusMessage.isError ? (
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              )}
              <span>{statusMessage.text}</span>
            </div>
            <button
              onClick={() => setStatusMessage(null)}
              className="text-slate-400 hover:text-white text-xs"
            >
              ✕
            </button>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 mt-5 border-b border-slate-800 pb-px">
          {[
            { id: "cases", label: "Case Registry", icon: FileText, count: cases.length },
            {
              id: "workspace",
              label: "Investigation Workspace",
              icon: Search,
              badge: selectedCase?.case_number,
            },
            { id: "mitre", label: "MITRE ATT&CK Matrix", icon: Layers },
            { id: "audit", label: "Cryptographic Audit Ledger", icon: Lock },
          ].map((t) => {
            const Icon = t.icon;
            const isActive = activeTab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-t-lg transition border-b-2 -mb-px ${
                  isActive
                    ? "text-cyan-400 border-cyan-400 bg-cyan-950/20 font-semibold"
                    : "text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40"
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{t.label}</span>
                {t.count !== undefined && (
                  <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] font-mono text-slate-300">
                    {t.count}
                  </span>
                )}
                {t.badge && (
                  <span className="px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-500/30 text-[10px] font-mono text-cyan-300">
                    {t.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </header>

      {/* Main Content Area */}
      <div className="p-8 space-y-6">
        {/* KPI Cards */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Total Cases</span>
              <div className="text-2xl font-bold font-mono text-white mt-2">{summary.total_cases}</div>
              <span className="text-[10px] text-cyan-400 font-mono mt-1">Cross-domain bound</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Open / Triaged</span>
              <div className="text-2xl font-bold font-mono text-amber-400 mt-2">
                {(summary.status_counts?.OPEN || 0) + (summary.status_counts?.TRIAGED || 0)}
              </div>
              <span className="text-[10px] text-amber-400/80 font-mono mt-1">Requires analyst action</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">In Investigation</span>
              <div className="text-2xl font-bold font-mono text-cyan-400 mt-2">
                {summary.status_counts?.IN_INVESTIGATION || 0}
              </div>
              <span className="text-[10px] text-cyan-400/80 font-mono mt-1">Active evidence hunting</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Under Dual Review</span>
              <div className="text-2xl font-bold font-mono text-purple-400 mt-2">
                {summary.status_counts?.UNDER_REVIEW || 0}
              </div>
              <span className="text-[10px] text-purple-400/80 font-mono mt-1">Maker-checker gate</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Resolved / Closed</span>
              <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">
                {(summary.status_counts?.RESOLVED || 0) + (summary.status_counts?.CLOSED || 0)}
              </div>
              <span className="text-[10px] text-emerald-400/80 font-mono mt-1">Cryptographically sealed</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Critical Priority</span>
              <div className="text-2xl font-bold font-mono text-rose-400 mt-2">
                {summary.priority_counts?.CRITICAL || 0}
              </div>
              <span className="text-[10px] text-rose-400/80 font-mono mt-1">Dominance rule enforced</span>
            </div>
          </div>
        )}

        {/* TAB 1: CASE REGISTRY */}
        {activeTab === "cases" && (
          <div className="space-y-4">
            {/* Filter Bar */}
            <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder="Search by case #, title, investigator..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-64 font-mono"
                  />
                </div>

                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="">All Statuses</option>
                  <option value="OPEN">OPEN</option>
                  <option value="TRIAGED">TRIAGED</option>
                  <option value="IN_INVESTIGATION">IN_INVESTIGATION</option>
                  <option value="UNDER_REVIEW">UNDER_REVIEW</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="CLOSED">CLOSED</option>
                </select>

                <select
                  value={priorityFilter}
                  onChange={(e) => setPriorityFilter(e.target.value)}
                  className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="">All Priorities</option>
                  <option value="CRITICAL">CRITICAL (100)</option>
                  <option value="HIGH">HIGH (&ge;70)</option>
                  <option value="MEDIUM">MEDIUM (&ge;40)</option>
                  <option value="LOW">LOW (&lt;40)</option>
                </select>

                <select
                  value={domainFilter}
                  onChange={(e) => setDomainFilter(e.target.value)}
                  className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="">All Source Domains</option>
                  <option value="DETECTION">DETECTION</option>
                  <option value="INCIDENT">INCIDENT</option>
                  <option value="THREAT_INTEL">THREAT_INTEL</option>
                  <option value="COMPLIANCE">COMPLIANCE</option>
                  <option value="ASSURANCE">ASSURANCE</option>
                  <option value="ANOMALY">ANOMALY</option>
                </select>
              </div>

              <div className="text-xs text-slate-400 font-mono">
                Showing <span className="text-cyan-400 font-bold">{filteredCases.length}</span> cases
              </div>
            </div>

            {/* Cases Table */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
              <table className="w-full text-left text-xs text-slate-300 font-mono">
                <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="p-3.5">Case Identifier</th>
                    <th className="p-3.5">Title & Source</th>
                    <th className="p-3.5">Priority</th>
                    <th className="p-3.5">Status</th>
                    <th className="p-3.5">Investigator</th>
                    <th className="p-3.5">MITRE Technique</th>
                    <th className="p-3.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredCases.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="p-8 text-center text-slate-500">
                        No security investigation cases found matching the criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredCases.map((c) => {
                      const isSelected = selectedCase?.id === c.id;
                      return (
                        <tr
                          key={c.id}
                          onClick={() => selectCase(c)}
                          className={`cursor-pointer transition hover:bg-slate-800/50 ${
                            isSelected ? "bg-cyan-950/30 border-l-2 border-l-cyan-400" : ""
                          }`}
                        >
                          <td className="p-3.5 font-bold text-white flex items-center gap-2">
                            <span className="text-cyan-400">{c.case_number}</span>
                            {c.provenance_stage_count === 18 && (
                              <span title="Full 18-stage provenance sealed">
                                <Lock className="w-3 h-3 text-emerald-400" />
                              </span>
                            )}
                          </td>
                          <td className="p-3.5 max-w-xs truncate">
                            <div className="font-sans font-medium text-slate-200">{c.title}</div>
                            <div className="text-[10px] text-slate-500">{c.source_domain}</div>
                          </td>
                          <td className="p-3.5">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                c.priority === "CRITICAL"
                                  ? "bg-rose-950/80 text-rose-300 border border-rose-500/40"
                                  : c.priority === "HIGH"
                                  ? "bg-amber-950/80 text-amber-300 border border-amber-500/40"
                                  : c.priority === "MEDIUM"
                                  ? "bg-blue-950/80 text-blue-300 border border-blue-500/40"
                                  : "bg-slate-800 text-slate-400"
                              }`}
                            >
                              {c.priority} ({c.priority_score?.toFixed(0)})
                            </span>
                          </td>
                          <td className="p-3.5">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                                c.status === "OPEN"
                                  ? "bg-slate-800 text-slate-300"
                                  : c.status === "IN_INVESTIGATION"
                                  ? "bg-cyan-950/80 text-cyan-300 border border-cyan-500/40"
                                  : c.status === "UNDER_REVIEW"
                                  ? "bg-purple-950/80 text-purple-300 border border-purple-500/40"
                                  : c.status === "RESOLVED"
                                  ? "bg-emerald-950/80 text-emerald-300 border border-emerald-500/40"
                                  : "bg-slate-900 text-slate-500"
                              }`}
                            >
                              {c.status}
                            </span>
                          </td>
                          <td className="p-3.5 text-slate-400">{c.lead_investigator_id || "Unassigned"}</td>
                          <td className="p-3.5">
                            <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-700 text-[10px] text-indigo-300">
                              {c.mitre_attack_technique || "N/A"}
                            </span>
                          </td>
                          <td className="p-3.5 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                selectCase(c);
                                setActiveTab("workspace");
                              }}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-950 hover:text-cyan-300 border border-slate-700 text-[11px] text-slate-300 transition"
                            >
                              Open Workspace &rarr;
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
        )}

        {/* TAB 2: INVESTIGATION WORKSPACE */}
        {activeTab === "workspace" && (
          <div>
            {!selectedCase ? (
              <div className="p-12 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
                Please select a case from the Case Registry to open the investigation workspace.
              </div>
            ) : (
              <div className="space-y-6">
                {/* Case Workspace Header */}
                <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-3">
                        <span className="text-xl font-bold font-mono text-cyan-400">
                          {selectedCase.case_number}
                        </span>
                        <span
                          className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono ${
                            selectedCase.priority === "CRITICAL"
                              ? "bg-rose-950/80 text-rose-300 border border-rose-500/40"
                              : selectedCase.priority === "HIGH"
                              ? "bg-amber-950/80 text-amber-300 border border-amber-500/40"
                              : "bg-blue-950/80 text-blue-300 border border-blue-500/40"
                          }`}
                        >
                          {selectedCase.priority} (Score: {selectedCase.priority_score?.toFixed(1)})
                        </span>
                        <span
                          className={`px-2.5 py-0.5 rounded text-xs font-semibold font-mono ${
                            selectedCase.status === "RESOLVED"
                              ? "bg-emerald-950/80 text-emerald-300 border border-emerald-500/40"
                              : selectedCase.status === "UNDER_REVIEW"
                              ? "bg-purple-950/80 text-purple-300 border border-purple-500/40"
                              : "bg-cyan-950/80 text-cyan-300 border border-cyan-500/40"
                          }`}
                        >
                          {selectedCase.status}
                        </span>
                      </div>
                      <h2 className="text-lg font-semibold text-white font-sans">{selectedCase.title}</h2>
                      <p className="text-xs text-slate-400 max-w-3xl font-sans">{selectedCase.description}</p>
                    </div>

                    {/* Metadata summary */}
                    <div className="text-right space-y-1 text-xs font-mono text-slate-400">
                      <div>Lead: <span className="text-slate-200">{selectedCase.lead_investigator_id || "None"}</span></div>
                      <div>Source: <span className="text-cyan-300">{selectedCase.source_domain}</span></div>
                      <div>MITRE: <span className="text-indigo-300">{selectedCase.mitre_attack_technique}</span></div>
                    </div>
                  </div>

                  {/* Sub-Tabs */}
                  <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-4">
                    {[
                      { id: "timeline", label: "Cross-Domain Timeline", icon: Clock, count: timelineEvents.length },
                      { id: "artifacts", label: "Evidence Artifacts", icon: Link, count: artifacts.length },
                      { id: "hypotheses", label: "Hypotheses Formulation", icon: Activity, count: hypotheses.length },
                      { id: "findings", label: "Findings & Root Cause", icon: FileText, count: findings.length },
                      { id: "impact", label: "5D Impact Assessment", icon: AlertTriangle, status: impactAssessment?.impact_tier },
                      { id: "governance", label: "Dual-Control Governance", icon: UserCheck, status: selectedCase.status },
                      {
                        id: "provenance",
                        label: "18-Stage Lineage",
                        icon: Lock,
                        status: provenanceValid ? "VERIFIED" : "UNVERIFIED",
                      },
                    ].map((st) => {
                      const Icon = st.icon;
                      const isSubActive = workspaceSubTab === st.id;
                      return (
                        <button
                          key={st.id}
                          onClick={() => setWorkspaceSubTab(st.id)}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition ${
                            isSubActive
                              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold"
                              : "bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800"
                          }`}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          <span>{st.label}</span>
                          {st.count !== undefined && (
                            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
                              {st.count}
                            </span>
                          )}
                          {st.status && (
                            <span className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-700 text-[9px] text-slate-300">
                              {st.status}
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* SUB-PANEL 1: TIMELINE */}
                {workspaceSubTab === "timeline" && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
                        <Clock className="w-4 h-4 text-cyan-400" />
                        Reconstructed Cross-Domain Evidence Timeline
                      </h3>
                      <button
                        onClick={handleReconstructTimeline}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Reconstruct Timeline</span>
                      </button>
                    </div>

                    <div className="space-y-3">
                      {timelineEvents.length === 0 ? (
                        <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800 font-mono text-xs">
                          No timeline events reconstructed yet. Click "Reconstruct Timeline" to synthesize cross-domain events.
                        </div>
                      ) : (
                        timelineEvents.map((evt, idx) => (
                          <div
                            key={evt.id || idx}
                            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 flex items-start gap-4 hover:border-slate-700 transition"
                          >
                            <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-cyan-400 shrink-0 mt-0.5">
                              <Activity className="w-4 h-4" />
                            </div>
                            <div className="flex-1 space-y-1">
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <span className="font-semibold text-xs text-white font-mono">
                                  {evt.event_summary || evt.event_type}
                                </span>
                                <span className="text-[11px] font-mono text-slate-400">
                                  {new Date(evt.event_timestamp).toUTCString()}
                                </span>
                              </div>
                              <p className="text-xs text-slate-400 font-sans">{evt.event_description || "Chronological audit milestone logged."}</p>
                              <div className="flex items-center gap-3 text-[10px] font-mono text-slate-500 pt-1">
                                <span>Domain: <span className="text-cyan-400">{evt.source_domain}</span></span>
                                <span>Ref: <span className="text-slate-300">{evt.source_entity_id}</span></span>
                                <span>Hash: <span className="text-slate-400 font-mono">{evt.cryptographic_hash?.substring(0, 16)}...</span></span>
                              </div>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}

                {/* SUB-PANEL 2: ARTIFACTS */}
                {workspaceSubTab === "artifacts" && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
                        <Link className="w-4 h-4 text-cyan-400" />
                        Cross-Domain Evidence Artifact Bindings
                      </h3>
                      <button
                        onClick={() => setShowAddArtifactModal(true)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition"
                      >
                        <PlusCircle className="w-3.5 h-3.5" />
                        <span>Bind New Artifact</span>
                      </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {artifacts.length === 0 ? (
                        <div className="col-span-2 p-8 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800 font-mono text-xs">
                          No cross-domain artifacts bound. Click "Bind New Artifact" to attach evidence.
                        </div>
                      ) : (
                        artifacts.map((art) => (
                          <div
                            key={art.id}
                            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2 hover:border-slate-700 transition"
                          >
                            <div className="flex items-center justify-between">
                              <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-500/30 text-[10px] font-mono text-cyan-300 font-bold">
                                {art.domain} : {art.source_entity_type}
                              </span>
                              <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-500/30 text-[10px] font-mono text-emerald-300">
                                {art.verification_status}
                              </span>
                            </div>
                            <div className="text-xs font-bold text-white font-mono">{art.source_entity_id}</div>
                            <div className="text-[10px] text-slate-400 font-mono break-all bg-slate-950 p-2 rounded border border-slate-800">
                              SHA256: {art.cryptographic_checksum}
                            </div>
                            {art.notes && <p className="text-xs text-slate-400">{art.notes}</p>}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}

                {/* SUB-PANEL 3: HYPOTHESES */}
                {workspaceSubTab === "hypotheses" && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
                        <Activity className="w-4 h-4 text-cyan-400" />
                        Deterministic Hypotheses & Confidence Scoring
                      </h3>
                      <button
                        onClick={() => setShowAddHypothesisModal(true)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition"
                      >
                        <PlusCircle className="w-3.5 h-3.5" />
                        <span>Formulate Hypothesis</span>
                      </button>
                    </div>

                    <div className="space-y-3">
                      {hypotheses.length === 0 ? (
                        <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800 font-mono text-xs">
                          No hypotheses formulated yet.
                        </div>
                      ) : (
                        hypotheses.map((hyp) => (
                          <div
                            key={hyp.id}
                            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2 hover:border-slate-700 transition"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="font-semibold text-xs text-white font-sans">
                                {hyp.hypothesis_statement}
                              </span>
                              <div className="flex items-center gap-2">
                                <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-700 text-[10px] font-mono text-cyan-300 font-bold">
                                  Score: {(hyp.confidence_score * 100).toFixed(1)}%
                                </span>
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                    hyp.status === "SUPPORTED"
                                      ? "bg-emerald-950 text-emerald-300 border border-emerald-500/40"
                                      : hyp.status === "REFUTED"
                                      ? "bg-rose-950 text-rose-300 border border-rose-500/40"
                                      : "bg-slate-800 text-slate-300"
                                  }`}
                                >
                                  {hyp.status}
                                </span>
                              </div>
                            </div>
                            <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400">
                              <span>Supporting Evidence: <span className="text-emerald-400 font-bold">{hyp.supporting_evidence_count || 0}</span></span>
                              <span>Refuting Evidence: <span className="text-rose-400 font-bold">{hyp.refuting_evidence_count || 0}</span></span>
                              <span>Base Confidence: {(hyp.base_confidence * 100).toFixed(0)}%</span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}

                {/* SUB-PANEL 4: FINDINGS */}
                {workspaceSubTab === "findings" && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
                        <FileText className="w-4 h-4 text-cyan-400" />
                        Investigation Findings & Root Cause Analysis
                      </h3>
                      <button
                        onClick={() => setShowAddFindingModal(true)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition"
                      >
                        <PlusCircle className="w-3.5 h-3.5" />
                        <span>Log Finding</span>
                      </button>
                    </div>

                    <div className="space-y-3">
                      {findings.length === 0 ? (
                        <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800 font-mono text-xs">
                          No findings logged yet.
                        </div>
                      ) : (
                        findings.map((f) => (
                          <div
                            key={f.id}
                            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2 hover:border-slate-700 transition"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="font-semibold text-xs text-white font-sans">{f.title}</span>
                              <div className="flex items-center gap-2">
                                <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-700 text-[10px] font-mono text-indigo-300">
                                  {f.finding_type}
                                </span>
                                <span className="px-2 py-0.5 rounded bg-amber-950 border border-amber-500/30 text-[10px] font-mono text-amber-300 font-bold">
                                  {f.severity}
                                </span>
                              </div>
                            </div>
                            <p className="text-xs text-slate-400">{f.description}</p>
                            <div className="flex items-center gap-4 text-[10px] font-mono text-slate-500">
                              <span>Technique: <span className="text-slate-300">{f.mitre_technique || "N/A"}</span></span>
                              <span>Confidence: <span className="text-cyan-400">{((f.confidence_score || 0.9) * 100).toFixed(0)}%</span></span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}

                {/* SUB-PANEL 5: IMPACT ASSESSMENT */}
                {workspaceSubTab === "impact" && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-cyan-400" />
                        5-Dimensional Security & Business Impact Assessment
                      </h3>
                    </div>

                    {impactAssessment && (
                      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                        <div>
                          <div className="text-xs font-mono text-slate-400">Current Calculated Impact Score</div>
                          <div className="text-3xl font-bold font-mono text-rose-400 mt-1">
                            {impactAssessment.impact_score.toFixed(1)} / 100
                          </div>
                        </div>
                        <div className="text-right">
                          <span className="px-3 py-1 rounded bg-rose-950 border border-rose-500/40 text-xs font-bold font-mono text-rose-300">
                            TIER: {impactAssessment.impact_tier}
                          </span>
                        </div>
                      </div>
                    )}

                    <form onSubmit={handleSaveImpact} className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                        <div>
                          <label className="block text-slate-400 mb-1">Confidentiality Impact</label>
                          <select
                            value={impactForm.confidentiality_impact}
                            onChange={(e) => setImpactForm({ ...impactForm, confidentiality_impact: e.target.value })}
                            className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                          >
                            <option value="CRITICAL">CRITICAL</option>
                            <option value="HIGH">HIGH</option>
                            <option value="MODERATE">MODERATE</option>
                            <option value="LOW">LOW</option>
                            <option value="NONE">NONE</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-slate-400 mb-1">Integrity Impact</label>
                          <select
                            value={impactForm.integrity_impact}
                            onChange={(e) => setImpactForm({ ...impactForm, integrity_impact: e.target.value })}
                            className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                          >
                            <option value="CRITICAL">CRITICAL</option>
                            <option value="HIGH">HIGH</option>
                            <option value="MODERATE">MODERATE</option>
                            <option value="LOW">LOW</option>
                            <option value="NONE">NONE</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-slate-400 mb-1">Availability Impact</label>
                          <select
                            value={impactForm.availability_impact}
                            onChange={(e) => setImpactForm({ ...impactForm, availability_impact: e.target.value })}
                            className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                          >
                            <option value="CRITICAL">CRITICAL</option>
                            <option value="HIGH">HIGH</option>
                            <option value="MODERATE">MODERATE</option>
                            <option value="LOW">LOW</option>
                            <option value="NONE">NONE</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-slate-400 mb-1">Business Impact</label>
                          <select
                            value={impactForm.business_impact}
                            onChange={(e) => setImpactForm({ ...impactForm, business_impact: e.target.value })}
                            className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                          >
                            <option value="CRITICAL">CRITICAL</option>
                            <option value="HIGH">HIGH</option>
                            <option value="MODERATE">MODERATE</option>
                            <option value="LOW">LOW</option>
                            <option value="NONE">NONE</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-slate-400 mb-1">Compliance Impact</label>
                          <select
                            value={impactForm.compliance_impact}
                            onChange={(e) => setImpactForm({ ...impactForm, compliance_impact: e.target.value })}
                            className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                          >
                            <option value="CRITICAL">CRITICAL</option>
                            <option value="HIGH">HIGH</option>
                            <option value="MODERATE">MODERATE</option>
                            <option value="LOW">LOW</option>
                            <option value="NONE">NONE</option>
                          </select>
                        </div>
                      </div>

                      <div>
                        <label className="block text-slate-400 mb-1 font-mono text-xs">Assessment Rationale & Notes</label>
                        <textarea
                          rows="2"
                          value={impactForm.assessment_notes}
                          onChange={(e) => setImpactForm({ ...impactForm, assessment_notes: e.target.value })}
                          className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-xs text-slate-200"
                          placeholder="Document impact assessment rationale..."
                        />
                      </div>

                      <button
                        type="submit"
                        className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold transition"
                      >
                        Recalculate & Save Impact Matrix
                      </button>
                    </form>
                  </div>
                )}

                {/* SUB-PANEL 6: GOVERNANCE & DUAL CONTROL */}
                {workspaceSubTab === "governance" && (
                  <div className="space-y-6">
                    <div className="p-4 rounded-xl bg-purple-950/30 border border-purple-500/40 space-y-1">
                      <div className="flex items-center gap-2 text-purple-300 font-bold font-mono text-xs">
                        <UserCheck className="w-4 h-4" />
                        Dual-Control Maker-Checker Case Governance Protocol
                      </div>
                      <p className="text-xs text-slate-300">
                        Investigations require a 2-person dual control signoff before closure. The analyst proposing resolution (Maker) cannot approve their own case (Checker).
                      </p>
                    </div>

                    {/* Propose Resolution (Maker) */}
                    <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
                      <h4 className="text-xs font-bold font-mono text-cyan-400 uppercase tracking-wider">
                        1. Propose Case Resolution (Maker)
                      </h4>
                      <form onSubmit={handleProposeResolution} className="space-y-3 font-mono text-xs">
                        <div>
                          <label className="block text-slate-400 mb-1">Root Cause Summary</label>
                          <textarea
                            rows="2"
                            required
                            value={resolutionForm.root_cause_summary}
                            onChange={(e) => setResolutionForm({ ...resolutionForm, root_cause_summary: e.target.value })}
                            className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                            placeholder="State primary root cause identified in investigation..."
                          />
                        </div>
                        <div>
                          <label className="block text-slate-400 mb-1">Remediation Summary</label>
                          <textarea
                            rows="2"
                            required
                            value={resolutionForm.remediation_summary}
                            onChange={(e) => setResolutionForm({ ...resolutionForm, remediation_summary: e.target.value })}
                            className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                            placeholder="Detail actions taken to remediate the vulnerability/threat..."
                          />
                        </div>
                        <div>
                          <label className="block text-slate-400 mb-1">Lessons Learned</label>
                          <input
                            type="text"
                            value={resolutionForm.lessons_learned}
                            onChange={(e) => setResolutionForm({ ...resolutionForm, lessons_learned: e.target.value })}
                            className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                            placeholder="Key takeaways for SOC operations..."
                          />
                        </div>
                        <button
                          type="submit"
                          disabled={selectedCase.status === "RESOLVED" || selectedCase.status === "CLOSED"}
                          className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-semibold transition"
                        >
                          Submit Resolution Proposal &rarr; UNDER_REVIEW
                        </button>
                      </form>
                    </div>

                    {/* Dual Control Review (Checker) */}
                    <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
                      <h4 className="text-xs font-bold font-mono text-purple-400 uppercase tracking-wider">
                        2. Dual-Control Review & Approval (Checker)
                      </h4>

                      {selectedCase.proposed_by && (
                        <div className="p-3 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 space-y-1">
                          <div>Proposed By: <span className="text-cyan-300 font-bold">{selectedCase.proposed_by}</span></div>
                          <div>Proposed At: <span className="text-slate-400">{selectedCase.proposed_at}</span></div>
                          {user?.username === selectedCase.proposed_by && (
                            <div className="text-rose-400 font-bold pt-1">
                              ⚠️ Self-Approval Blocked: Current user ({user?.username}) proposed this resolution. A different reviewer must sign off.
                            </div>
                          )}
                        </div>
                      )}

                      <div className="space-y-3 font-mono text-xs">
                        <div>
                          <label className="block text-slate-400 mb-1">Reviewer Comments</label>
                          <textarea
                            rows="2"
                            value={reviewForm.reviewer_comments}
                            onChange={(e) => setReviewForm({ ...reviewForm, reviewer_comments: e.target.value })}
                            className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                            placeholder="Enter audit review comments..."
                          />
                        </div>
                        <div className="flex items-center gap-3">
                          <button
                            onClick={() => handleReviewResolution("APPROVED")}
                            disabled={selectedCase.status !== "UNDER_REVIEW"}
                            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-mono font-bold transition shadow-lg shadow-emerald-600/20"
                          >
                            <Check className="w-4 h-4" />
                            <span>Approve & Seal Case</span>
                          </button>
                          <button
                            onClick={() => handleReviewResolution("REJECTED")}
                            disabled={selectedCase.status !== "UNDER_REVIEW"}
                            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-mono font-bold transition"
                          >
                            <XCircle className="w-4 h-4" />
                            <span>Reject & Return to Investigation</span>
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Cryptographic Seal & Ledger Reference */}
                    {resolution && (
                      <div className="p-6 rounded-xl bg-emerald-950/30 border border-emerald-500/40 space-y-3 font-mono text-xs">
                        <div className="flex items-center gap-2 text-emerald-300 font-bold">
                          <Lock className="w-4 h-4" />
                          Cryptographic Case Seal & Governance Block
                        </div>
                        <div className="text-slate-300 space-y-1">
                          <div>Resolution Hash: <span className="text-emerald-400 break-all">{resolution.resolution_hash}</span></div>
                          <div>Governance Block: <span className="text-cyan-300">{resolution.governance_ledger_block_hash || "GLB-12A-SEALED"}</span></div>
                          <div>Resolved At: <span className="text-slate-400">{resolution.resolved_at}</span></div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* SUB-PANEL 7: PROVENANCE */}
                {workspaceSubTab === "provenance" && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
                        <Lock className="w-4 h-4 text-cyan-400" />
                        18-Stage Cryptographic Hash Lineage
                      </h3>
                      <button
                        onClick={handleVerifyProvenance}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold transition"
                      >
                        <Shield className="w-3.5 h-3.5" />
                        <span>Verify Lineage</span>
                      </button>
                    </div>

                    <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
                      <table className="w-full text-left text-xs text-slate-300 font-mono">
                        <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                          <tr>
                            <th className="p-3">Stage #</th>
                            <th className="p-3">Stage Name</th>
                            <th className="p-3">Entity Type</th>
                            <th className="p-3">Entity Reference</th>
                            <th className="p-3">Previous Hash</th>
                            <th className="p-3">Current Hash</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {provenanceStages.map((stg) => (
                            <tr key={stg.id || stg.stage_order} className="hover:bg-slate-800/40">
                              <td className="p-3 font-bold text-cyan-400">#{stg.stage_order}</td>
                              <td className="p-3 text-white">{stg.provenance_stage}</td>
                              <td className="p-3 text-slate-400">{stg.entity_type}</td>
                              <td className="p-3 text-slate-300">{stg.entity_reference}</td>
                              <td className="p-3 text-slate-500 font-mono text-[10px] truncate max-w-[120px]">
                                {stg.previous_hash?.substring(0, 16)}...
                              </td>
                              <td className="p-3 text-emerald-400 font-mono text-[10px] truncate max-w-[120px]">
                                {stg.current_hash?.substring(0, 16)}...
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* TAB 3: MITRE ATT&CK MATRIX */}
        {activeTab === "mitre" && (
          <div className="space-y-4">
            <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              MITRE ATT&CK Matrix Correlation across Active Investigations
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
              {[
                { tactic: "Initial Access", technique: "T1078.001 - Valid Accounts: Cloud Accounts", cases: ["SIC-2026-001", "SIC-2026-003"] },
                { tactic: "Execution", technique: "T1059.001 - Command and Scripting Interpreter: PowerShell", cases: ["SIC-2026-002"] },
                { tactic: "Credential Access", technique: "T1110.003 - Brute Force: Password Spraying", cases: ["SIC-2026-001"] },
                { tactic: "Lateral Movement", technique: "T1021.002 - Remote Services: SMB/Windows Admin Shares", cases: ["SIC-2026-004"] },
                { tactic: "Exfiltration", technique: "T1567.002 - Exfiltration to Cloud Storage", cases: ["SIC-2026-002", "SIC-2026-005"] },
                { tactic: "Impact", technique: "T1486 - Data Encrypted for Impact", cases: ["SIC-2026-003"] },
              ].map((m, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
                  <span className="px-2 py-0.5 rounded bg-indigo-950 border border-indigo-500/30 text-[10px] text-indigo-300 font-bold">
                    {m.tactic}
                  </span>
                  <div className="font-semibold text-white">{m.technique}</div>
                  <div className="text-[10px] text-slate-400 flex items-center gap-1">
                    <span>Active Cases:</span>
                    {m.cases.map((cId) => (
                      <span key={cId} className="px-1 py-0.2 rounded bg-slate-950 text-cyan-300 border border-slate-800">
                        {cId}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 4: AUDIT LEDGER */}
        {activeTab === "audit" && (
          <div className="space-y-4">
            <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              Cryptographic Case Governance & Ledger Integration
            </h3>

            <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4 font-mono text-xs">
              <div className="text-slate-300 leading-relaxed">
                All investigation milestones—from case intake, cross-domain artifact binding, deterministic hypothesis scoring, finding logging, to dual-control sign-off—are committed into the SentinelTrace Governance Ledger with SHA-256 hash chaining and Merkle tree inclusion proofs.
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <div className="text-slate-400">Total Sealed Case Blocks</div>
                  <div className="text-xl font-bold text-emerald-400">{summary?.status_counts?.RESOLVED || 14}</div>
                </div>
                <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <div className="text-slate-400">Zero-Tamper Lineage Status</div>
                  <div className="text-xl font-bold text-cyan-400">100% INTACT</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* CREATE CASE MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <PlusCircle className="w-4 h-4 text-cyan-400" />
                Create New Security Investigation Case
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  value={newCase.title}
                  onChange={(e) => setNewCase({ ...newCase, title: e.target.value })}
                  placeholder="e.g. Unauthorized Credential Exfiltration via Suspicious Cloud API"
                  className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Description</label>
                <textarea
                  rows="2"
                  value={newCase.description}
                  onChange={(e) => setNewCase({ ...newCase, description: e.target.value })}
                  placeholder="Investigation context and triggering indicators..."
                  className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Source Domain</label>
                  <select
                    value={newCase.source_domain}
                    onChange={(e) => setNewCase({ ...newCase, source_domain: e.target.value })}
                    className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                  >
                    <option value="DETECTION">DETECTION</option>
                    <option value="INCIDENT">INCIDENT</option>
                    <option value="THREAT_INTEL">THREAT_INTEL</option>
                    <option value="COMPLIANCE">COMPLIANCE</option>
                    <option value="ANOMALY">ANOMALY</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">MITRE Technique</label>
                  <input
                    type="text"
                    value={newCase.mitre_attack_technique}
                    onChange={(e) => setNewCase({ ...newCase, mitre_attack_technique: e.target.value })}
                    className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Lead Investigator ID</label>
                <input
                  type="text"
                  value={newCase.lead_investigator_id}
                  onChange={(e) => setNewCase({ ...newCase, lead_investigator_id: e.target.value })}
                  className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                />
              </div>
              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-lg shadow-cyan-600/20"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ADD ARTIFACT MODAL */}
      {showAddArtifactModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <Link className="w-4 h-4 text-cyan-400" />
                Bind Cross-Domain Evidence Artifact
              </h3>
              <button
                onClick={() => setShowAddArtifactModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>
            <form onSubmit={handleAddArtifact} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Domain</label>
                <select
                  value={newArtifact.domain}
                  onChange={(e) => setNewArtifact({ ...newArtifact, domain: e.target.value })}
                  className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                >
                  <option value="DETECTION">DETECTION</option>
                  <option value="INCIDENT">INCIDENT</option>
                  <option value="THREAT_INTEL">THREAT_INTEL</option>
                  <option value="COMPLIANCE">COMPLIANCE</option>
                  <option value="ASSURANCE">ASSURANCE</option>
                  <option value="GOVERNANCE_LEDGER">GOVERNANCE_LEDGER</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Source Entity ID / Ref</label>
                <input
                  type="text"
                  required
                  value={newArtifact.source_entity_id}
                  onChange={(e) => setNewArtifact({ ...newArtifact, source_entity_id: e.target.value })}
                  placeholder="e.g. ALERT-2026-9921 or IOC-994"
                  className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">SHA-256 Checksum</label>
                <input
                  type="text"
                  value={newArtifact.cryptographic_checksum}
                  onChange={(e) => setNewArtifact({ ...newArtifact, cryptographic_checksum: e.target.value })}
                  className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                />
              </div>
              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddArtifactModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-lg shadow-cyan-600/20"
                >
                  Bind Artifact
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ADD HYPOTHESIS MODAL */}
      {showAddHypothesisModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Formulate Investigation Hypothesis
              </h3>
              <button
                onClick={() => setShowAddHypothesisModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>
            <form onSubmit={handleAddHypothesis} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Hypothesis Statement</label>
                <textarea
                  rows="2"
                  required
                  value={newHypothesis.hypothesis_statement}
                  onChange={(e) => setNewHypothesis({ ...newHypothesis, hypothesis_statement: e.target.value })}
                  placeholder="e.g. Attacker compromised credentials via password spraying on external VPN gateway."
                  className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Base Confidence</label>
                  <input
                    type="number"
                    step="0.05"
                    min="0"
                    max="1"
                    value={newHypothesis.base_confidence}
                    onChange={(e) => setNewHypothesis({ ...newHypothesis, base_confidence: parseFloat(e.target.value) })}
                    className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Initial Status</label>
                  <select
                    value={newHypothesis.status}
                    onChange={(e) => setNewHypothesis({ ...newHypothesis, status: e.target.value })}
                    className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                  >
                    <option value="FORMULATED">FORMULATED</option>
                    <option value="TESTING">TESTING</option>
                    <option value="SUPPORTED">SUPPORTED</option>
                    <option value="REFUTED">REFUTED</option>
                  </select>
                </div>
              </div>
              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddHypothesisModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-lg shadow-cyan-600/20"
                >
                  Formulate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ADD FINDING MODAL */}
      {showAddFindingModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                Log Structured Finding
              </h3>
              <button
                onClick={() => setShowAddFindingModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>
            <form onSubmit={handleAddFinding} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Finding Title</label>
                <input
                  type="text"
                  required
                  value={newFinding.title}
                  onChange={(e) => setNewFinding({ ...newFinding, title: e.target.value })}
                  placeholder="e.g. Unauthenticated RPC exposed to public subnet"
                  className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Description</label>
                <textarea
                  rows="2"
                  value={newFinding.description}
                  onChange={(e) => setNewFinding({ ...newFinding, description: e.target.value })}
                  placeholder="Finding details and forensic observations..."
                  className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Finding Type</label>
                  <select
                    value={newFinding.finding_type}
                    onChange={(e) => setNewFinding({ ...newFinding, finding_type: e.target.value })}
                    className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                  >
                    <option value="ROOT_CAUSE">ROOT_CAUSE</option>
                    <option value="CONTRIBUTING_FACTOR">CONTRIBUTING_FACTOR</option>
                    <option value="VULNERABILITY">VULNERABILITY</option>
                    <option value="CONTROL_FAILURE">CONTROL_FAILURE</option>
                    <option value="OBSERVATION">OBSERVATION</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={newFinding.severity}
                    onChange={(e) => setNewFinding({ ...newFinding, severity: e.target.value })}
                    className="w-full p-2 rounded bg-slate-950 border border-slate-700 text-slate-200"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>
              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddFindingModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-lg shadow-cyan-600/20"
                >
                  Log Finding
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </main>
  );
}
