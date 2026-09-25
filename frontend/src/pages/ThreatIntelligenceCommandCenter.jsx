/**
 * ThreatIntelligenceCommandCenter.jsx
 * -----------------------------------
 * Cyber SOC Threat Intelligence, Adversary Context & Observable Correlation Command Center.
 *
 * Sprint 11B — Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation.
 * Core Invariant: "THREAT INTELLIGENCE MUST BE PROVEN, CONTEXTUALIZED, TRACEABLE, AND NEVER BLINDLY TRUSTED."
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
const Activity = (props) => (
  <IconWrapper {...props}><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></IconWrapper>
);
const AlertTriangle = (props) => (
  <IconWrapper {...props}><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></IconWrapper>
);
const Radio = (props) => (
  <IconWrapper {...props}><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></IconWrapper>
);
const Search = (props) => (
  <IconWrapper {...props}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></IconWrapper>
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
const Cpu = (props) => (
  <IconWrapper {...props}><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></IconWrapper>
);
const Lock = (props) => (
  <IconWrapper {...props}><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></IconWrapper>
);
const ArrowRight = (props) => (
  <IconWrapper {...props}><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></IconWrapper>
);
const ExternalLink = (props) => (
  <IconWrapper {...props}><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></IconWrapper>
);
const ChevronRight = (props) => (
  <IconWrapper {...props}><polyline points="9 18 15 12 9 6"/></IconWrapper>
);
const RefreshCw = (props) => (
  <IconWrapper {...props}><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></IconWrapper>
);
const Zap = (props) => (
  <IconWrapper {...props}><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></IconWrapper>
);
const Target = (props) => (
  <IconWrapper {...props}><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></IconWrapper>
);
const Globe = (props) => (
  <IconWrapper {...props}><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></IconWrapper>
);
const Database = (props) => (
  <IconWrapper {...props}><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></IconWrapper>
);
const Crosshair = (props) => (
  <IconWrapper {...props}><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></IconWrapper>
);
const Server = (props) => (
  <IconWrapper {...props}><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></IconWrapper>
);
const Hash = (props) => (
  <IconWrapper {...props}><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></IconWrapper>
);
const Compass = (props) => (
  <IconWrapper {...props}><circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/></IconWrapper>
);

const API_BASE = `${API_V1_URL}/threat-intelligence`;

export default function ThreatIntelligenceCommandCenter() {
  const { user, token } = useAuth();
  const [activeTab, setActiveTab] = useState("landscape"); // landscape, sources, iocs, actors_campaigns, mitre, correlations, provenance
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const [landscape, setLandscape] = useState(null);
  const [sources, setSources] = useState([]);
  const [indicators, setIndicators] = useState([]);
  const [artifacts, setArtifacts] = useState([]);
  const [actors, setActors] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [mitreMappings, setMitreMappings] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [selectedArtifact, setSelectedArtifact] = useState(null);
  const [artifactTrustHistory, setArtifactTrustHistory] = useState([]);
  const [provenanceLineage, setProvenanceLineage] = useState([]);
  const [statusMessage, setStatusMessage] = useState(null);

  // Search & Filter States
  const [iocSearch, setIocSearch] = useState("");
  const [iocTypeFilter, setIocTypeFilter] = useState("");
  const [iocSeverityFilter, setIocSeverityFilter] = useState("");

  // Correlation Console Form
  const [corrEventRef, setCorrEventRef] = useState("EVT-CONSOLE-TEST-001");
  const [corrObservable, setCorrObservable] = useState("198.51.100.42");
  const [corrType, setCorrType] = useState("IP_ADDRESS");
  const [corrResult, setCorrResult] = useState(null);

  // Modals
  const [showAddSourceModal, setShowAddSourceModal] = useState(false);
  const [newSource, setNewSource] = useState({
    source_name: "",
    source_type: "INTERNAL",
    provider: "",
    trust_level: "TRUSTED",
    description: "",
  });

  const [showAddIocModal, setShowAddIocModal] = useState(false);
  const [newIoc, setNewIoc] = useState({
    indicator_value: "",
    indicator_type: "IP_ADDRESS",
    severity: "HIGH",
    confidence_score: 90.0,
  });

  const [forceCryptoFailureToggle, setForceCryptoFailureToggle] = useState(false);

  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  });

  // Fetch Dashboard Summary
  const fetchSummary = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/dashboard/summary`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setSummary(data);
      }
    } catch (e) {
      console.error("Error fetching threat intel summary:", e);
    } finally {
      setLoading(false);
    }
  };

  // Fetch Threat Landscape
  const fetchLandscape = async () => {
    try {
      const res = await fetch(`${API_BASE}/dashboard/threat-landscape`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setLandscape(data);
      }
    } catch (e) {
      console.error("Error fetching threat landscape:", e);
    }
  };

  // Fetch Sources
  const fetchSources = async () => {
    try {
      const res = await fetch(`${API_BASE}/sources`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setSources(data);
      }
    } catch (e) {
      console.error("Error fetching sources:", e);
    }
  };

  // Fetch Indicators
  const fetchIndicators = async () => {
    try {
      let url = `${API_BASE}/indicators`;
      const params = [];
      if (iocTypeFilter) params.push(`indicator_type=${iocTypeFilter}`);
      if (iocSeverityFilter) params.push(`severity=${iocSeverityFilter}`);
      if (params.length > 0) url += `?${params.join("&")}`;

      const res = await fetch(url, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setIndicators(data);
      }
    } catch (e) {
      console.error("Error fetching indicators:", e);
    }
  };

  // Fetch Artifacts
  const fetchArtifacts = async () => {
    try {
      const res = await fetch(`${API_BASE}/artifacts`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setArtifacts(data);
        if (data.length > 0 && !selectedArtifact) {
          setSelectedArtifact(data[0]);
        }
      }
    } catch (e) {
      console.error("Error fetching artifacts:", e);
    }
  };

  // Fetch Actors & Campaigns
  const fetchActorsAndCampaigns = async () => {
    try {
      const [resAct, resCmp] = await Promise.all([
        fetch(`${API_BASE}/actors`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE}/campaigns`, { headers: getAuthHeaders() }),
      ]);
      if (resAct.ok) setActors(await resAct.json());
      if (resCmp.ok) setCampaigns(await resCmp.json());
    } catch (e) {
      console.error("Error fetching actors/campaigns:", e);
    }
  };

  // Fetch MITRE Mappings
  const fetchMitreMappings = async () => {
    try {
      const res = await fetch(`${API_BASE}/mitre-mappings`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setMitreMappings(data);
      }
    } catch (e) {
      console.error("Error fetching MITRE mappings:", e);
    }
  };

  // Fetch Correlations
  const fetchCorrelations = async () => {
    try {
      const res = await fetch(`${API_BASE}/correlations`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setCorrelations(data);
      }
    } catch (e) {
      console.error("Error fetching correlations:", e);
    }
  };

  // Fetch Provenance Lineage for an Artifact
  const fetchProvenance = async (artifactId) => {
    if (!artifactId) return;
    try {
      const res = await fetch(`${API_BASE}/artifacts/${artifactId}/provenance`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setProvenanceLineage(data);
      }
    } catch (e) {
      console.error("Error fetching provenance:", e);
    }
  };

  // Fetch Trust History for an Artifact
  const fetchTrustHistory = async (artifactId) => {
    if (!artifactId) return;
    try {
      const res = await fetch(`${API_BASE}/artifacts/${artifactId}/trust`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setArtifactTrustHistory(data);
      }
    } catch (e) {
      console.error("Error fetching trust history:", e);
    }
  };

  useEffect(() => {
    fetchSummary();
    fetchLandscape();
    fetchSources();
    fetchIndicators();
    fetchArtifacts();
    fetchActorsAndCampaigns();
    fetchMitreMappings();
    fetchCorrelations();
  }, [token]);

  useEffect(() => {
    if (selectedArtifact) {
      fetchTrustHistory(selectedArtifact.id);
      fetchProvenance(selectedArtifact.id);
    }
  }, [selectedArtifact]);

  // Execute Observable Correlation
  const handleExecuteCorrelation = async (e) => {
    e.preventDefault();
    try {
      setStatusMessage({ type: "info", text: "Evaluating deterministic IOC observable correlation..." });
      const res = await fetch(`${API_BASE}/correlations/execute`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          event_reference: corrEventRef,
          observable_value: corrObservable,
          observable_type: corrType || undefined,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setCorrResult(data);
        setStatusMessage({ type: "success", text: `Observable matched! Match Type: ${data.correlation_type} | Confidence: ${data.correlation_confidence}` });
        fetchCorrelations();
        fetchSummary();
      } else {
        const err = await res.json();
        setCorrResult(null);
        setStatusMessage({ type: "warning", text: err.detail || "No matching IOC found in registry." });
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: "Correlation execution failed: " + err.message });
    }
  };

  // Evaluate Trust with Optional Crypto Override
  const handleEvaluateTrust = async () => {
    if (!selectedArtifact) return;
    try {
      setStatusMessage({ type: "info", text: `Evaluating trust for ${selectedArtifact.artifact_reference}...` });
      const res = await fetch(
        `${API_BASE}/artifacts/${selectedArtifact.id}/evaluate-trust?force_crypto_failure=${forceCryptoFailureToggle}`,
        {
          method: "POST",
          headers: getAuthHeaders(),
        }
      );
      if (res.ok) {
        const data = await res.json();
        setStatusMessage({
          type: "success",
          text: `Trust evaluated: ${data.final_trust_score}/100 [${data.trust_status}]`,
        });
        fetchArtifacts();
        fetchTrustHistory(selectedArtifact.id);
        fetchSummary();
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: "Trust evaluation failed: " + err.message });
    }
  };

  // Register Source
  const handleCreateSource = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/sources`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(newSource),
      });
      if (res.ok) {
        setStatusMessage({ type: "success", text: `Source '${newSource.source_name}' registered successfully!` });
        setShowAddSourceModal(false);
        fetchSources();
        fetchSummary();
      } else {
        const err = await res.json();
        setStatusMessage({ type: "error", text: err.detail || "Failed to create source." });
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: err.message });
    }
  };

  // Register IOC
  const handleCreateIoc = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/indicators`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(newIoc),
      });
      if (res.ok) {
        setStatusMessage({ type: "success", text: `IOC '${newIoc.indicator_value}' registered and normalized.` });
        setShowAddIocModal(false);
        fetchIndicators();
        fetchSummary();
      } else {
        const err = await res.json();
        setStatusMessage({ type: "error", text: err.detail || "Failed to register IOC." });
      }
    } catch (err) {
      setStatusMessage({ type: "error", text: err.message });
    }
  };

  const filteredIndicators = indicators.filter((ioc) => {
    if (!iocSearch) return true;
    return (
      ioc.indicator_value.toLowerCase().includes(iocSearch.toLowerCase()) ||
      ioc.normalized_value.toLowerCase().includes(iocSearch.toLowerCase()) ||
      ioc.indicator_type.toLowerCase().includes(iocSearch.toLowerCase())
    );
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 space-y-6">
      {/* ── Top Header & Hero ── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400">
              <Crosshair className="w-7 h-7 animate-pulse" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Threat Intelligence & Adversary Context
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 font-mono">
                  SPRINT 11B FROZEN
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Deterministic IOC Extraction, Adversary Campaigns, MITRE ATT&CK Mapping & 15-Stage Cryptographic Lineage
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              fetchSummary();
              fetchLandscape();
              fetchIndicators();
              fetchArtifacts();
            }}
            className="flex items-center gap-2 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-300 transition shadow-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh Intelligence
          </button>
          <button
            onClick={() => setShowAddIocModal(true)}
            className="flex items-center gap-2 px-3 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold shadow-md transition"
          >
            <Target className="w-4 h-4" />
            + Register IOC
          </button>
          <button
            onClick={() => setShowAddSourceModal(true)}
            className="flex items-center gap-2 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow-md transition"
          >
            <Globe className="w-4 h-4" />
            + Add Source Feed
          </button>
        </div>
      </div>

      {/* ── Status Banner ── */}
      {statusMessage && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center justify-between transition ${
            statusMessage.type === "success"
              ? "bg-emerald-950/60 border-emerald-500/40 text-emerald-300"
              : statusMessage.type === "error"
              ? "bg-rose-950/60 border-rose-500/40 text-rose-300"
              : statusMessage.type === "warning"
              ? "bg-amber-950/60 border-amber-500/40 text-amber-300"
              : "bg-blue-950/60 border-blue-500/40 text-blue-300"
          }`}
        >
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 shrink-0" />
            <span>{statusMessage.text}</span>
          </div>
          <button onClick={() => setStatusMessage(null)} className="text-slate-400 hover:text-white text-xs">
            ✕
          </button>
        </div>
      )}

      {/* ── Section A: Threat Intelligence Hero KPIs ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
        {/* Global Threat Score Dial */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-2xl flex flex-col justify-between relative overflow-hidden shadow-lg">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Global Intel Trust</span>
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="my-2 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white tracking-tight">
              {summary ? summary.global_threat_intel_score : "--"}
            </span>
            <span className="text-xs text-slate-400 font-mono">/ 100.0</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs">
            <span
              className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                summary?.intelligence_integrity_status === "VALID"
                  ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                  : "bg-rose-500/20 text-rose-300 border border-rose-500/30"
              }`}
            >
              {summary ? summary.intelligence_integrity_status : "VALID"}
            </span>
            <span className="text-[11px] text-slate-400">Cryptographic Seal</span>
          </div>
        </div>

        {/* Active IOCs */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-2xl flex flex-col justify-between shadow-lg">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Active IOCs</span>
            <Target className="w-4 h-4 text-rose-400" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold text-white tracking-tight">
              {summary ? summary.active_ioc_count : "--"}
            </span>
          </div>
          <div className="text-[11px] text-slate-400">Canonical Normalized Registry</div>
        </div>

        {/* High Confidence Threats */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-2xl flex flex-col justify-between shadow-lg">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>High-Confidence Threats</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold text-amber-400 tracking-tight">
              {summary ? summary.high_confidence_threats : "--"}
            </span>
          </div>
          <div className="text-[11px] text-slate-400">Confidence Score ≥ 80%</div>
        </div>

        {/* Active Campaigns */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-2xl flex flex-col justify-between shadow-lg">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Active Campaigns</span>
            <Compass className="w-4 h-4 text-purple-400" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold text-white tracking-tight">
              {summary ? summary.active_campaigns_count : "--"}
            </span>
          </div>
          <div className="text-[11px] text-slate-400">Adversary Operations Tracked</div>
        </div>

        {/* Correlations */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-2xl flex flex-col justify-between shadow-lg">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Event Correlations</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold text-blue-400 tracking-tight">
              {summary ? summary.correlation_count : "--"}
            </span>
          </div>
          <div className="text-[11px] text-slate-400">Observed Matches in Logs</div>
        </div>

        {/* Feeds / Sources */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-2xl flex flex-col justify-between shadow-lg">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Feed Sources</span>
            <Radio className="w-4 h-4 text-teal-400" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold text-white tracking-tight">
              {summary ? summary.total_sources : "--"}
            </span>
          </div>
          <div className="text-[11px] text-slate-400">
            {summary ? summary.trusted_sources_count : "--"} Classified as TRUSTED
          </div>
        </div>
      </div>

      {/* ── Zero-Trust Axiom Banner ── */}
      <div className="p-3.5 bg-rose-950/30 border border-rose-500/30 rounded-xl text-xs text-rose-200 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-rose-400 shrink-0" />
          <span className="font-semibold uppercase tracking-wider text-rose-300">Zero-Trust Operational Axiom:</span>
          <span>UNKNOWN IOC ≠ MALICIOUS · UNKNOWN IOC ≠ SAFE · IOC MATCH ≠ CONFIRMED INCIDENT</span>
        </div>
        <span className="text-[11px] font-mono text-rose-400/80 bg-rose-900/40 px-2 py-0.5 rounded border border-rose-500/20">
          CRYPTOGRAPHIC INTEGRITY DOMINATES NUMERICAL SCORE
        </span>
      </div>

      {/* ── Navigation Tabs ── */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-2">
        {[
          { id: "landscape", label: "Threat Landscape", icon: Compass },
          { id: "sources", label: "Feed Sources", icon: Radio },
          { id: "iocs", label: "IOC Explorer", icon: Target },
          { id: "trust_matrix", label: "Threat Trust Matrix", icon: Shield },
          { id: "actors_campaigns", label: "Adversaries & Campaigns", icon: Globe },
          { id: "mitre", label: "MITRE ATT&CK Matrix", icon: Layers },
          { id: "correlations", label: "IOC Correlation Console", icon: Crosshair },
          { id: "provenance", label: "15-Stage Lineage", icon: Database },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition ${
                isActive
                  ? "bg-rose-600 text-white shadow-md shadow-rose-900/20"
                  : "bg-slate-900/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800"
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* ── TAB 1: THREAT LANDSCAPE ── */}
      {activeTab === "landscape" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Severity Distribution */}
            <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                IOC Severity Distribution
              </h3>
              <div className="space-y-3">
                {landscape?.severity_distribution &&
                  Object.entries(landscape.severity_distribution).map(([sev, cnt]) => {
                    const total = Object.values(landscape.severity_distribution).reduce((a, b) => a + b, 0) || 1;
                    const pct = Math.round((cnt / total) * 100);
                    return (
                      <div key={sev} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="font-semibold text-slate-300">{sev}</span>
                          <span className="text-slate-400">{cnt} IOCs ({pct}%)</span>
                        </div>
                        <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              sev === "CRITICAL"
                                ? "bg-rose-500"
                                : sev === "HIGH"
                                ? "bg-amber-500"
                                : sev === "MEDIUM"
                                ? "bg-blue-500"
                                : "bg-slate-500"
                            }`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>

            {/* Indicator Type Distribution */}
            <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Target className="w-4 h-4 text-rose-400" />
                Observable Categories
              </h3>
              <div className="grid grid-cols-2 gap-2">
                {landscape?.indicator_type_distribution &&
                  Object.entries(landscape.indicator_type_distribution).map(([type, cnt]) => (
                    <div key={type} className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl">
                      <div className="text-[11px] font-mono text-slate-400 truncate">{type}</div>
                      <div className="text-xl font-bold text-white mt-1">{cnt}</div>
                    </div>
                  ))}
              </div>
            </div>

            {/* Recent Deterministic Insights */}
            <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Zap className="w-4 h-4 text-emerald-400" />
                Executive Intelligence Insights
              </h3>
              <div className="space-y-2.5 max-h-[260px] overflow-y-auto pr-1">
                {landscape?.recent_insights && landscape.recent_insights.length > 0 ? (
                  landscape.recent_insights.map((ins) => (
                    <div
                      key={ins.id}
                      className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl space-y-1 hover:border-slate-700 transition"
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-rose-300">{ins.title}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 font-mono">
                          {ins.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400">{ins.description}</p>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 italic">No threat insights recorded yet.</p>
                )}
              </div>
            </div>
          </div>

          {/* Active Campaigns Deck */}
          <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Compass className="w-4 h-4 text-purple-400" />
              Active Adversary Campaigns
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {campaigns.map((cmp) => (
                <div key={cmp.id} className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="text-xs font-mono text-purple-400">{cmp.campaign_reference}</span>
                      <h4 className="text-sm font-bold text-white mt-0.5">{cmp.campaign_name}</h4>
                    </div>
                    <span className="px-2 py-0.5 text-xs rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                      {cmp.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{cmp.description}</p>
                  <div className="flex items-center justify-between text-[11px] text-slate-500 border-t border-slate-800/80 pt-2 font-mono">
                    <span>Hash: {cmp.campaign_hash.slice(0, 16)}...</span>
                    <span>Confidence: {cmp.confidence_score}%</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 2: SOURCES REGISTRY ── */}
      {activeTab === "sources" && (
        <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">Registered Threat Intelligence Feed Sources</h3>
              <p className="text-xs text-slate-400">
                Multi-feed intelligence origin management with verifiable trust levels and ingestion SLAs.
              </p>
            </div>
            <button
              onClick={() => setShowAddSourceModal(true)}
              className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow transition"
            >
              + Add Source
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/70 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="p-3">Source Name</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Provider</th>
                  <th className="p-3">Trust Level</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Last Ingestion</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {sources.map((src) => (
                  <tr key={src.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3 font-semibold text-white">{src.source_name}</td>
                    <td className="p-3 font-mono text-slate-400">{src.source_type}</td>
                    <td className="p-3 text-slate-300">{src.provider}</td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                          src.trust_level === "TRUSTED"
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                            : src.trust_level === "CONDITIONALLY_TRUSTED"
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                            : src.trust_level === "UNVERIFIED"
                            ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                            : "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                        }`}
                      >
                        {src.trust_level}
                      </span>
                    </td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] ${
                          src.is_active ? "bg-emerald-500/20 text-emerald-300" : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {src.is_active ? "ACTIVE" : "DISABLED"}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400 font-mono">
                      {src.last_ingested_at ? new Date(src.last_ingested_at).toLocaleString() : "Never"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── TAB 3: IOC EXPLORER ── */}
      {activeTab === "iocs" && (
        <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white">Canonical Threat Indicators (IOCs)</h3>
              <p className="text-xs text-slate-400">
                Canonical normalized observables (IPs, Domains, URLs, File Hashes, Emails, Hostnames).
              </p>
            </div>
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search IOCs..."
                  value={iocSearch}
                  onChange={(e) => setIocSearch(e.target.value)}
                  className="pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-rose-500"
                />
              </div>
              <select
                value={iocTypeFilter}
                onChange={(e) => {
                  setIocTypeFilter(e.target.value);
                  fetchIndicators();
                }}
                className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none"
              >
                <option value="">All Types</option>
                <option value="IP_ADDRESS">IP_ADDRESS</option>
                <option value="DOMAIN">DOMAIN</option>
                <option value="URL">URL</option>
                <option value="FILE_HASH">FILE_HASH</option>
                <option value="EMAIL_ADDRESS">EMAIL_ADDRESS</option>
                <option value="HOSTNAME">HOSTNAME</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/70 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="p-3">Indicator Value</th>
                  <th className="p-3">Normalized Value</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Confidence</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredIndicators.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3 font-semibold text-white truncate max-w-xs">{ioc.indicator_value}</td>
                    <td className="p-3 font-mono text-rose-300 truncate max-w-xs">{ioc.normalized_value}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                        {ioc.indicator_type}
                      </span>
                    </td>
                    <td className="p-3 font-mono font-bold text-emerald-400">{ioc.confidence_score}%</td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          ioc.severity === "CRITICAL"
                            ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                            : ioc.severity === "HIGH"
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                            : "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                        }`}
                      >
                        {ioc.severity}
                      </span>
                    </td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] ${
                          ioc.status === "ACTIVE"
                            ? "bg-emerald-500/20 text-emerald-300"
                            : "bg-rose-500/20 text-rose-300"
                        }`}
                      >
                        {ioc.status}
                      </span>
                    </td>
                    <td className="p-3 font-mono text-slate-500">{ioc.indicator_hash.slice(0, 12)}...</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── TAB 4: THREAT TRUST MATRIX & DEDUCTIONS ── */}
      {activeTab === "trust_matrix" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Artifact Selector */}
          <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-blue-400" />
              Intelligence Artifacts
            </h3>
            <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
              {artifacts.map((art) => (
                <div
                  key={art.id}
                  onClick={() => setSelectedArtifact(art)}
                  className={`p-3 rounded-xl border cursor-pointer transition ${
                    selectedArtifact?.id === art.id
                      ? "bg-rose-950/40 border-rose-500/50 text-white shadow"
                      : "bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-rose-300">{art.artifact_reference}</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] ${
                        art.trust_status === "HIGH_TRUST" || art.trust_status === "TRUSTED"
                          ? "bg-emerald-500/20 text-emerald-300"
                          : art.trust_status === "CONDITIONAL"
                          ? "bg-amber-500/20 text-amber-300"
                          : "bg-rose-500/20 text-rose-300"
                      }`}
                    >
                      {art.trust_status}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">Type: {art.artifact_type}</div>
                  <div className="text-[10px] font-mono text-slate-500 mt-1">Hash: {art.content_hash.slice(0, 16)}...</div>
                </div>
              ))}
            </div>

            {/* Evaluate Trigger Controls */}
            {selectedArtifact && (
              <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-3 pt-3">
                <div className="text-xs font-bold text-white">Trigger Deterministic Trust Evaluation</div>
                <label className="flex items-center gap-2 text-xs text-rose-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={forceCryptoFailureToggle}
                    onChange={(e) => setForceCryptoFailureToggle(e.target.checked)}
                    className="rounded bg-slate-900 border-slate-700 text-rose-500 focus:ring-rose-500"
                  />
                  <span>Simulate Cryptographic Integrity Failure (Force 0.0 Override)</span>
                </label>
                <button
                  onClick={handleEvaluateTrust}
                  className="w-full py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold shadow transition"
                >
                  Evaluate Trust Now
                </button>
              </div>
            )}
          </div>

          {/* Trust Scoring Dimensions & Deductions */}
          <div className="lg:col-span-2 p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-5">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  Deterministic Trust Scoring Breakdown
                </h3>
                <p className="text-xs text-slate-400">
                  Base 100 mathematical scoring across 5 dimensions with itemized explainable deductions.
                </p>
              </div>
              {selectedArtifact && (
                <div className="text-right">
                  <div className="text-2xl font-extrabold text-white">{selectedArtifact.confidence_score} / 100.0</div>
                  <span className="text-[11px] font-bold text-emerald-400">{selectedArtifact.trust_status}</span>
                </div>
              )}
            </div>

            {/* Trust Evaluation Latest Record */}
            {artifactTrustHistory.length > 0 ? (
              <div className="space-y-4">
                {/* 5 Dimension Gauges */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  {[
                    { label: "Source Trust", score: artifactTrustHistory[0].source_score },
                    { label: "Freshness", score: artifactTrustHistory[0].freshness_score },
                    { label: "Completeness", score: artifactTrustHistory[0].completeness_score },
                    { label: "Cross-Validation", score: artifactTrustHistory[0].cross_validation_score },
                    { label: "Integrity", score: artifactTrustHistory[0].integrity_score },
                  ].map((dim) => (
                    <div key={dim.label} className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl text-center">
                      <div className="text-[11px] text-slate-400">{dim.label}</div>
                      <div className="text-lg font-bold text-white mt-1">{dim.score}</div>
                    </div>
                  ))}
                </div>

                {/* Deductions Explainability List */}
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                    Itemized Deductions ({artifactTrustHistory[0].deductions_json.length})
                  </h4>
                  {artifactTrustHistory[0].deductions_json.length > 0 ? (
                    artifactTrustHistory[0].deductions_json.map((d, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-rose-950/20 border border-rose-500/30 rounded-xl flex items-center justify-between text-xs"
                      >
                        <div>
                          <span className="font-mono font-bold text-rose-300">{d.reason}</span>
                          <p className="text-[11px] text-slate-400 mt-0.5">{d.details}</p>
                        </div>
                        <span className="text-rose-400 font-bold font-mono">-{d.points} pts</span>
                      </div>
                    ))
                  ) : (
                    <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-xl text-xs text-emerald-300 flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>Zero deductions recorded. Full cryptographic and telemetry trust confirmed.</span>
                    </div>
                  )}
                </div>

                {/* Evaluation Hash */}
                <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-xs font-mono text-slate-400 flex items-center justify-between">
                  <span>Evaluation Hash:</span>
                  <span className="text-slate-200">{artifactTrustHistory[0].evaluation_hash}</span>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic">Select an artifact to inspect trust deductions.</p>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 5: ADVERSARIES & CAMPAIGNS ── */}
      {activeTab === "actors_campaigns" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Threat Actors */}
            <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Globe className="w-4 h-4 text-indigo-400" />
                Tracked Threat Actors (APTs)
              </h3>
              <div className="space-y-3">
                {actors.map((actor) => (
                  <div key={actor.id} className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-indigo-300">{actor.actor_name}</h4>
                      <span className="px-2 py-0.5 text-[10px] rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                        {actor.sophistication}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{actor.description}</p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {actor.aliases &&
                        actor.aliases.map((al) => (
                          <span key={al} className="px-1.5 py-0.5 bg-slate-800 text-[10px] font-mono text-slate-400 rounded">
                            {al}
                          </span>
                        ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Campaign Associations */}
            <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Compass className="w-4 h-4 text-purple-400" />
                Adversary Campaign Operations
              </h3>
              <div className="space-y-3">
                {campaigns.map((cmp) => (
                  <div key={cmp.id} className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs text-purple-300">{cmp.campaign_reference}</span>
                      <span className="px-2 py-0.5 text-[10px] rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-bold">
                        {cmp.severity}
                      </span>
                    </div>
                    <h4 className="text-sm font-bold text-white">{cmp.campaign_name}</h4>
                    <p className="text-xs text-slate-400">{cmp.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 6: MITRE ATT&CK MAPPINGS ── */}
      {activeTab === "mitre" && (
        <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-amber-400" />
              MITRE ATT&CK Enterprise Matrix Alignments
            </h3>
            <p className="text-xs text-slate-400">
              Deterministic adversary technique mappings grounded in verified threat evidence.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/70 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="p-3">Tactic ID</th>
                  <th className="p-3">Technique ID</th>
                  <th className="p-3">Subtechnique</th>
                  <th className="p-3">Mapping Confidence</th>
                  <th className="p-3">Source</th>
                  <th className="p-3">Created At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {mitreMappings.map((m) => (
                  <tr key={m.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3 font-mono font-bold text-amber-300">{m.tactic_id}</td>
                    <td className="p-3 font-mono text-purple-300">{m.technique_id}</td>
                    <td className="p-3 font-mono text-slate-400">{m.subtechnique_id || "--"}</td>
                    <td className="p-3 font-mono text-emerald-400 font-bold">{m.mapping_confidence}%</td>
                    <td className="p-3 text-slate-400">{m.mapping_source}</td>
                    <td className="p-3 text-slate-500 font-mono">{new Date(m.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── TAB 7: CORRELATION CONSOLE ── */}
      {activeTab === "correlations" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Correlation Execution Form */}
          <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-rose-400" />
              Test Observable Correlation
            </h3>
            <p className="text-xs text-slate-400">
              Evaluates Match Strength × IOC Trust Factor × Freshness Factor against live registry.
            </p>

            <form onSubmit={handleExecuteCorrelation} className="space-y-3">
              <div>
                <label className="text-[11px] font-mono text-slate-400">Event Reference</label>
                <input
                  type="text"
                  value={corrEventRef}
                  onChange={(e) => setCorrEventRef(e.target.value)}
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white"
                  required
                />
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-400">Observable Value</label>
                <input
                  type="text"
                  value={corrObservable}
                  onChange={(e) => setCorrObservable(e.target.value)}
                  placeholder="e.g. 198.51.100.42 or auth-sentinel-verify.evilcorp.com"
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white font-mono"
                  required
                />
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-400">Observable Type (Optional)</label>
                <select
                  value={corrType}
                  onChange={(e) => setCorrType(e.target.value)}
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white"
                >
                  <option value="IP_ADDRESS">IP_ADDRESS</option>
                  <option value="DOMAIN">DOMAIN</option>
                  <option value="URL">URL</option>
                  <option value="FILE_HASH">FILE_HASH</option>
                  <option value="EMAIL_ADDRESS">EMAIL_ADDRESS</option>
                  <option value="HOSTNAME">HOSTNAME</option>
                </select>
              </div>

              <button
                type="submit"
                className="w-full py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold shadow transition"
              >
                Execute IOC Correlation
              </button>
            </form>

            {/* Result Display */}
            {corrResult && (
              <div className="p-4 bg-slate-950/90 border border-emerald-500/40 rounded-xl space-y-2 text-xs">
                <div className="font-bold text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" />
                  Correlation Established
                </div>
                <div className="space-y-1 font-mono text-[11px]">
                  <div>Type: <span className="text-slate-200">{corrResult.correlation_type}</span></div>
                  <div>Confidence: <span className="text-emerald-400 font-bold">{corrResult.correlation_confidence}</span></div>
                  <div>Match Strength: <span className="text-slate-200">{corrResult.match_strength}</span></div>
                  <div>Status: <span className="text-blue-400 font-bold">{corrResult.status}</span></div>
                  <div className="text-[10px] text-slate-500">Hash: {corrResult.correlation_hash}</div>
                </div>
              </div>
            )}
          </div>

          {/* Historical Correlations Log */}
          <div className="lg:col-span-2 p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              Recorded Event Correlations
            </h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950/70 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                  <tr>
                    <th className="p-3">Event Ref</th>
                    <th className="p-3">Match Type</th>
                    <th className="p-3">Confidence</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Correlation Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {correlations.map((c) => (
                    <tr key={c.id} className="hover:bg-slate-800/40 transition">
                      <td className="p-3 font-mono font-bold text-white">{c.event_reference}</td>
                      <td className="p-3 font-mono text-purple-300">{c.correlation_type}</td>
                      <td className="p-3 font-mono font-bold text-emerald-400">{c.correlation_confidence}</td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded-full text-[10px] bg-blue-500/20 text-blue-300 border border-blue-500/30">
                          {c.status}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-slate-500">{c.correlation_hash.slice(0, 12)}...</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 8: 15-STAGE PROVENANCE LINEAGE ── */}
      {activeTab === "provenance" && (
        <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-5">
          <div className="flex items-start justify-between border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Database className="w-4 h-4 text-indigo-400" />
                15-Stage Cryptographic Threat Intelligence Provenance Lineage
              </h3>
              <p className="text-xs text-slate-400">
                Unbroken SHA-256 hash chaining from raw intelligence feed ingestion to Governance Ledger & Merkle proof.
              </p>
            </div>
            {selectedArtifact && (
              <span className="font-mono text-xs text-rose-300 bg-rose-950/40 px-3 py-1 rounded-lg border border-rose-500/30">
                Artifact: {selectedArtifact.artifact_reference}
              </span>
            )}
          </div>

          <div className="space-y-2">
            {provenanceLineage.map((stg) => (
              <div
                key={stg.id}
                className="p-3.5 bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3 hover:border-slate-700 transition"
              >
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded-full bg-rose-500/10 border border-rose-500/30 flex items-center justify-center font-mono font-bold text-xs text-rose-300 shrink-0">
                    {stg.stage_order}
                  </div>
                  <div>
                    <div className="font-bold text-xs text-white">{stg.provenance_stage}</div>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                      Entity: {stg.entity_type} ({stg.entity_reference})
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-[11px] font-mono">
                  <div className="text-slate-500">
                    Prev: <span className="text-slate-400">{stg.previous_hash.slice(0, 8)}...</span>
                  </div>
                  <div className="text-emerald-400 font-bold">
                    Hash: <span>{stg.current_hash.slice(0, 12)}...</span>
                  </div>
                  {stg.ledger_reference && (
                    <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-[10px]">
                      {stg.ledger_reference}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── MODAL: ADD SOURCE ── */}
      {showAddSourceModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white">Register Threat Intelligence Feed Source</h3>
            <form onSubmit={handleCreateSource} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400">Source Name</label>
                <input
                  type="text"
                  value={newSource.source_name}
                  onChange={(e) => setNewSource({ ...newSource, source_name: e.target.value })}
                  placeholder="e.g. US-CERT Advisory Feed"
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                  required
                />
              </div>
              <div>
                <label className="text-slate-400">Provider</label>
                <input
                  type="text"
                  value={newSource.provider}
                  onChange={(e) => setNewSource({ ...newSource, provider: e.target.value })}
                  placeholder="e.g. CISA / DHS"
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                  required
                />
              </div>
              <div>
                <label className="text-slate-400">Source Type</label>
                <select
                  value={newSource.source_type}
                  onChange={(e) => setNewSource({ ...newSource, source_type: e.target.value })}
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                >
                  <option value="INTERNAL">INTERNAL</option>
                  <option value="COMMERCIAL">COMMERCIAL</option>
                  <option value="OPEN_SOURCE">OPEN_SOURCE</option>
                  <option value="GOVERNMENT">GOVERNMENT</option>
                  <option value="SECURITY_RESEARCH">SECURITY_RESEARCH</option>
                </select>
              </div>
              <div>
                <label className="text-slate-400">Initial Trust Level</label>
                <select
                  value={newSource.trust_level}
                  onChange={(e) => setNewSource({ ...newSource, trust_level: e.target.value })}
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                >
                  <option value="TRUSTED">TRUSTED</option>
                  <option value="CONDITIONALLY_TRUSTED">CONDITIONALLY_TRUSTED</option>
                  <option value="UNVERIFIED">UNVERIFIED</option>
                  <option value="UNTRUSTED">UNTRUSTED</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddSourceModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-300"
                >
                  Cancel
                </button>
                <button type="submit" className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-white font-semibold">
                  Register Source
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: ADD IOC ── */}
      {showAddIocModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white">Register & Normalize IOC Indicator</h3>
            <form onSubmit={handleCreateIoc} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400">Indicator Observable Value</label>
                <input
                  type="text"
                  value={newIoc.indicator_value}
                  onChange={(e) => setNewIoc({ ...newIoc, indicator_value: e.target.value })}
                  placeholder="e.g. 198.51.100.42 or malware.exe"
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                  required
                />
              </div>
              <div>
                <label className="text-slate-400">Indicator Type</label>
                <select
                  value={newIoc.indicator_type}
                  onChange={(e) => setNewIoc({ ...newIoc, indicator_type: e.target.value })}
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                >
                  <option value="IP_ADDRESS">IP_ADDRESS</option>
                  <option value="DOMAIN">DOMAIN</option>
                  <option value="URL">URL</option>
                  <option value="FILE_HASH">FILE_HASH</option>
                  <option value="EMAIL_ADDRESS">EMAIL_ADDRESS</option>
                  <option value="HOSTNAME">HOSTNAME</option>
                </select>
              </div>
              <div>
                <label className="text-slate-400">Severity</label>
                <select
                  value={newIoc.severity}
                  onChange={(e) => setNewIoc({ ...newIoc, severity: e.target.value })}
                  className="w-full mt-1 p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                >
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddIocModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-300"
                >
                  Cancel
                </button>
                <button type="submit" className="px-4 py-2 bg-rose-600 hover:bg-rose-500 rounded-lg text-white font-semibold">
                  Normalize & Save IOC
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
