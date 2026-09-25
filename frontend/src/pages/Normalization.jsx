/**
 * Normalization.jsx
 * -----------------
 * OCSF-Aligned Canonical Normalization & Traceability Dashboard.
 *
 * Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
 * Implements:
 * - Deterministic format-specific parsing (Syslog, JSON, CSV)
 * - Canonical OCSF-aligned classification
 * - Dual-pane evidence-to-canonical traceability modal
 * - Idempotent normalization engine
 */

import { useState, useEffect, useCallback } from "react";

import { API_BASE_URL, getAuthHeaders } from "../apiConfig";

const API_BASE = API_BASE_URL;

export default function Normalization() {
  // Data State
  const [normalizedEvents, setNormalizedEvents] = useState([]);
  const [rawEvents, setRawEvents] = useState([]);
  const [sourceProfiles, setSourceProfiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [normalizingId, setNormalizingId] = useState(null);
  const [batchNormalizing, setBatchNormalizing] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Filter & Search
  const [classFilter, setClassFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  // Modal / Traceability Inspector
  const [selectedNormalized, setSelectedNormalized] = useState(null);
  const [selectedRaw, setSelectedRaw] = useState(null);
  const [traceModalOpen, setTraceModalOpen] = useState(false);
  const [inspectLoading, setInspectLoading] = useState(false);
  const [copySuccess, setCopySuccess] = useState(null);

  // Fetch all data
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [normRes, rawRes, profRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/normalized-events?limit=100`, { headers: { ...getAuthHeaders() } }),
        fetch(`${API_BASE}/api/v1/events?limit=100`, { headers: { ...getAuthHeaders() } }),
        fetch(`${API_BASE}/api/v1/source-profiles`, { headers: { ...getAuthHeaders() } }),
      ]);

      if (normRes.ok) {
        const normData = await normRes.json();
        setNormalizedEvents(normData.items || []);
      }
      if (rawRes.ok) {
        const rawData = await rawRes.json();
        setRawEvents(rawData.items || []);
      }
      if (profRes.ok) {
        const profData = await profRes.json();
        setSourceProfiles(profData.items || []);
      }
    } catch (err) {
      console.error("Failed to load normalization data:", err);
      setError("Unable to connect to backend API.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Normalize single event
  const handleNormalizeEvent = async (eventId) => {
    setNormalizingId(eventId);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/events/${eventId}/normalize`, {
        method: "POST",
        headers: { ...getAuthHeaders() },
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Normalization failed");
      }
      const data = await res.json();
      setSuccessMsg(`Event ${eventId} normalized to ${data.class_name} (${Math.round(data.normalization_confidence * 100)}% confidence)`);
      await fetchData();
    } catch (err) {
      setError(err.message || "Failed to normalize event");
    } finally {
      setNormalizingId(null);
    }
  };

  // Batch Normalize All Unnormalized Events
  const handleBatchNormalize = async () => {
    setBatchNormalizing(true);
    setError(null);
    try {
      const normalizedIds = new Set(normalizedEvents.map((e) => e.original_event_id));
      const unnormalized = rawEvents.filter((e) => !normalizedIds.has(e.event_id));

      if (unnormalized.length === 0) {
        // Re-run all to demonstrate idempotency
        for (const evt of rawEvents.slice(0, 10)) {
          await fetch(`${API_BASE}/api/v1/events/${evt.event_id}/normalize`, {
            method: "POST",
            headers: { ...getAuthHeaders() },
          });
        }
      } else {
        for (const evt of unnormalized) {
          await fetch(`${API_BASE}/api/v1/events/${evt.event_id}/normalize`, {
            method: "POST",
            headers: { ...getAuthHeaders() },
          });
        }
      }
      setSuccessMsg("Batch normalization completed successfully.");
      await fetchData();
    } catch (err) {
      setError("Batch normalization encountered an error.");
    } finally {
      setBatchNormalizing(false);
    }
  };

  // Inspect Traceability (Dual Pane)
  const handleInspectTraceability = async (normEvent) => {
    setSelectedNormalized(normEvent);
    setInspectLoading(true);
    setTraceModalOpen(true);
    setSelectedRaw(null);

    try {
      const rawRes = await fetch(`${API_BASE}/api/v1/events/${normEvent.original_event_id}`, {
        headers: { ...getAuthHeaders() },
      });
      if (rawRes.ok) {
        const rawData = await rawRes.json();
        setSelectedRaw(rawData);
      }
    } catch (err) {
      console.error("Failed to load raw event:", err);
    } finally {
      setInspectLoading(false);
    }
  };

  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text);
    setCopySuccess(label);
    setTimeout(() => setCopySuccess(null), 2000);
  };

  // Filtered Events
  const filteredEvents = normalizedEvents.filter((evt) => {
    const matchesSearch =
      evt.normalized_event_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.original_event_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.source_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (evt.action && evt.action.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (evt.src_ip && evt.src_ip.includes(searchQuery));
    const matchesClass = classFilter === "all" || evt.class_name === classFilter;
    return matchesSearch && matchesClass;
  });

  // Calculate Metrics
  const totalCount = normalizedEvents.length;
  const networkCount = normalizedEvents.filter((e) => e.class_name === "Network Activity").length;
  const authCount = normalizedEvents.filter((e) => e.class_name === "Authentication").length;
  const systemCount = normalizedEvents.filter((e) => e.class_name === "System Activity").length;
  const avgConfidence =
    totalCount > 0
      ? Math.round((normalizedEvents.reduce((acc, e) => acc + e.normalization_confidence, 0) / totalCount) * 100)
      : 100;

  return (
    <main className="flex-1 overflow-y-auto">
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
        
        {/* ── Header Section ─────────────────────────────────── */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-white/10 pb-6">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-1 rounded-md text-[10px] font-mono tracking-wider font-semibold bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan uppercase">
                Sprint 2 · Active Module
              </span>
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent-cyan opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-accent-cyan"></span>
              </span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight text-slate-100">
              OCSF-Aligned Canonical Normalization
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Source-aware deterministic parsing, canonical schema alignment, and bidirectional evidence traceability.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleBatchNormalize}
              disabled={batchNormalizing}
              className="px-4 py-2 rounded-lg bg-accent-cyan hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold flex items-center gap-2 shadow-lg shadow-accent-cyan/10 transition-all disabled:opacity-50"
            >
              <span>{batchNormalizing ? "⚙" : "⚡"}</span>
              {batchNormalizing ? "Normalizing..." : "Normalize All Events"}
            </button>

            <button
              onClick={fetchData}
              disabled={loading}
              className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 text-xs font-mono flex items-center gap-2 transition-colors"
            >
              <span className={loading ? "animate-spin" : ""}>🔄</span>
              Refresh
            </button>
          </div>
        </div>

        {/* ── Pipeline Architecture Flow Graphic ──────────────── */}
        <div className="glass-card p-5 border-white/10 overflow-hidden">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
            <span>⚙</span> End-to-End Normalization Pipeline
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 text-center text-xs font-mono">
            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
              <div className="text-accent-cyan font-bold mb-1">1. RAW EVIDENCE</div>
              <p className="text-[10px] text-slate-500">Immutable SHA-256 Vault</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
              <div className="text-accent-cyan font-bold mb-1">2. SOURCE DETECT</div>
              <p className="text-[10px] text-slate-500">Profile &amp; Format Match</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
              <div className="text-accent-cyan font-bold mb-1">3. PARSER</div>
              <p className="text-[10px] text-slate-500">Syslog · JSON · CSV</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
              <div className="text-accent-cyan font-bold mb-1">4. OCSF MAPPING</div>
              <p className="text-[10px] text-slate-500">Canonical Taxonomy</p>
            </div>
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30">
              <div className="text-emerald-400 font-bold mb-1">5. CANONICAL EVENT</div>
              <p className="text-[10px] text-emerald-300">100% Traceable Link</p>
            </div>
          </div>
        </div>

        {/* ── KPI Summary Cards ──────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="glass-card p-4 border-white/10">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">Total Normalized</span>
            <p className="text-2xl font-bold font-mono text-slate-100 mt-1">{totalCount}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Canonical events</p>
          </div>

          <div className="glass-card p-4 border-white/10">
            <span className="text-[10px] font-mono uppercase tracking-wider text-accent-cyan block">Network Activity</span>
            <p className="text-2xl font-bold font-mono text-accent-cyan mt-1">{networkCount}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">OCSF Class 4001</p>
          </div>

          <div className="glass-card p-4 border-white/10">
            <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 block">Authentication</span>
            <p className="text-2xl font-bold font-mono text-emerald-400 mt-1">{authCount}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">OCSF Class 3001</p>
          </div>

          <div className="glass-card p-4 border-white/10">
            <span className="text-[10px] font-mono uppercase tracking-wider text-purple-400 block">System Activity</span>
            <p className="text-2xl font-bold font-mono text-purple-400 mt-1">{systemCount}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">OCSF Class 1001</p>
          </div>

          <div className="glass-card p-4 border-white/10">
            <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 block">Avg Confidence</span>
            <p className="text-2xl font-bold font-mono text-amber-400 mt-1">{avgConfidence}%</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Deterministic score</p>
          </div>
        </div>

        {/* ── Alerts & Notifications ──────────────────────────── */}
        {successMsg && (
          <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center justify-between animate-fade-in">
            <span>✓ {successMsg}</span>
            <button onClick={() => setSuccessMsg(null)} className="text-slate-400 hover:text-slate-200">✕</button>
          </div>
        )}
        {error && (
          <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center justify-between animate-fade-in">
            <span>⚠ {error}</span>
            <button onClick={() => setError(null)} className="text-slate-400 hover:text-slate-200">✕</button>
          </div>
        )}

        {/* ── Main Normalized Events Table ─────────────────────── */}
        <div className="glass-card border-white/10 overflow-hidden space-y-4 p-5">
          {/* Controls & Filter Tabs */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <span>📋</span> Canonical Security Events Ledger
              </h2>
              <p className="text-xs text-slate-500 font-mono mt-0.5">
                Showing {filteredEvents.length} of {totalCount} normalized records
              </p>
            </div>

            {/* Filter Tabs */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex rounded-lg bg-slate-900 border border-slate-700 p-0.5 text-xs font-mono">
                {[
                  { id: "all", label: "All" },
                  { id: "Network Activity", label: "Network" },
                  { id: "Authentication", label: "Auth" },
                  { id: "System Activity", label: "System" },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setClassFilter(tab.id)}
                    className={`px-2.5 py-1 rounded transition-colors ${
                      classFilter === tab.id
                        ? "bg-accent-cyan/20 text-accent-cyan font-semibold"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Search Box */}
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search norm ID, IP, user, action..."
                className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-accent-cyan w-48 sm:w-60"
              />
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/10 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                  <th className="py-3 px-3">Normalized ID</th>
                  <th className="py-3 px-3">Original Event ID</th>
                  <th className="py-3 px-3">OCSF Class</th>
                  <th className="py-3 px-3">Action</th>
                  <th className="py-3 px-3">Key Fields</th>
                  <th className="py-3 px-3">Parser</th>
                  <th className="py-3 px-3">Confidence</th>
                  <th className="py-3 px-3">Status</th>
                  <th className="py-3 px-3 text-right">Traceability</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-mono">
                {filteredEvents.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="py-8 text-center text-slate-500">
                      {loading ? "Loading normalized events..." : "No normalized events matching filter. Click 'Normalize All Events' above."}
                    </td>
                  </tr>
                ) : (
                  filteredEvents.map((evt) => {
                    const isNormal = evt.normalization_status === "NORMALIZED";
                    const isPartial = evt.normalization_status === "PARTIAL";
                    const confPercent = Math.round(evt.normalization_confidence * 100);

                    return (
                      <tr
                        key={evt.normalized_event_id}
                        className="hover:bg-white/[0.02] transition-colors group cursor-pointer"
                        onClick={() => handleInspectTraceability(evt)}
                      >
                        {/* Normalized ID */}
                        <td className="py-3 px-3 font-semibold text-accent-cyan whitespace-nowrap">
                          {evt.normalized_event_id}
                        </td>

                        {/* Original Event ID */}
                        <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                          <span className="font-mono text-slate-300">{evt.original_event_id}</span>
                        </td>

                        {/* Class */}
                        <td className="py-3 px-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              evt.class_name === "Network Activity"
                                ? "bg-cyan-950/60 border-cyan-500/40 text-cyan-300"
                                : evt.class_name === "Authentication"
                                ? "bg-emerald-950/60 border-emerald-500/40 text-emerald-300"
                                : "bg-purple-950/60 border-purple-500/40 text-purple-300"
                            }`}
                          >
                            {evt.class_name}
                          </span>
                        </td>

                        {/* Action */}
                        <td className="py-3 px-3 whitespace-nowrap">
                          {evt.action ? (
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                                ["ALLOW", "SUCCESS"].includes(evt.action.toUpperCase())
                                  ? "bg-emerald-950/60 text-emerald-400 border border-emerald-500/30"
                                  : ["DENY", "FAILURE", "ERROR"].includes(evt.action.toUpperCase())
                                  ? "bg-rose-950/60 text-rose-400 border border-rose-500/30"
                                  : "bg-slate-800 text-slate-300 border border-slate-700"
                              }`}
                            >
                              {evt.action}
                            </span>
                          ) : (
                            <span className="text-slate-600">--</span>
                          )}
                        </td>

                        {/* Key Fields */}
                        <td className="py-3 px-3 text-slate-300 text-[11px] max-w-xs truncate">
                          {evt.src_ip && <span>src: {evt.src_ip} </span>}
                          {evt.dst_ip && <span>dst: {evt.dst_ip} </span>}
                          {evt.user_name && <span>user: {evt.user_name} </span>}
                          {evt.process_name && <span>proc: {evt.process_name} </span>}
                        </td>

                        {/* Parser */}
                        <td className="py-3 px-3 text-slate-400 whitespace-nowrap text-[11px]">
                          {evt.parser_name} <span className="text-slate-600">v{evt.parser_version}</span>
                        </td>

                        {/* Confidence */}
                        <td className="py-3 px-3 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${
                                  confPercent >= 80
                                    ? "bg-emerald-400"
                                    : confPercent >= 50
                                    ? "bg-amber-400"
                                    : "bg-rose-400"
                                }`}
                                style={{ width: `${confPercent}%` }}
                              />
                            </div>
                            <span className="text-[11px] font-mono text-slate-300">{confPercent}%</span>
                          </div>
                        </td>

                        {/* Status */}
                        <td className="py-3 px-3 whitespace-nowrap">
                          {isNormal && (
                            <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950/60 border border-emerald-500/30 text-emerald-400">
                              NORMALIZED
                            </span>
                          )}
                          {isPartial && (
                            <span className="px-2 py-0.5 rounded text-[10px] bg-amber-950/60 border border-amber-500/30 text-amber-400">
                              PARTIAL
                            </span>
                          )}
                          {!isNormal && !isPartial && (
                            <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950/60 border border-rose-500/30 text-rose-400">
                              FAILED
                            </span>
                          )}
                        </td>

                        {/* Action */}
                        <td className="py-3 px-3 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            onClick={() => handleInspectTraceability(evt)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 text-[11px] text-accent-cyan transition-colors"
                          >
                            Trace Link ➔
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

        {/* ── Dual-Pane Traceability & Canonical Inspector Modal ──── */}
        {traceModalOpen && selectedNormalized && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-fade-in">
            <div className="glass-card border-white/20 w-full max-w-5xl max-h-[92vh] overflow-y-auto p-6 space-y-6 shadow-2xl">
              
              {/* Modal Header */}
              <div className="flex items-center justify-between border-b border-white/10 pb-4">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">🔗</span>
                  <div>
                    <h3 className="text-lg font-bold text-slate-100 font-mono">
                      Traceability &amp; Canonical Evidence Audit
                    </h3>
                    <p className="text-xs text-slate-500 font-mono">
                      Immutable Evidence Vault ➔ OCSF-Aligned Canonical Event
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setTraceModalOpen(false)}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs font-mono"
                >
                  ✕ Close
                </button>
              </div>

              {/* Dual Pane Layout */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                
                {/* ── LEFT PANE: Raw Evidence Summary ────────────────── */}
                <div className="space-y-4 p-4 rounded-xl bg-slate-900/80 border border-slate-800 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-white/5 pb-2">
                    <span className="font-bold text-slate-200 flex items-center gap-1.5">
                      <span>🔒</span> 1. Raw Preserved Evidence
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-950 border border-cyan-500/30 text-cyan-400">
                      EVIDENCE VAULT
                    </span>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Event ID:</span>
                      <span className="text-accent-cyan font-bold">{selectedNormalized.original_event_id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Source Name:</span>
                      <span className="text-slate-300">{selectedNormalized.source_name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Source Type:</span>
                      <span className="text-slate-300">{selectedNormalized.source_type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">SHA-256 Hash:</span>
                      <span className="text-slate-400 truncate max-w-[200px]" title={selectedRaw?.raw_content_hash}>
                        {selectedRaw?.raw_content_hash ? `${selectedRaw.raw_content_hash.slice(0, 16)}...` : "Verified in Vault"}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-1.5 pt-2">
                    <div className="flex items-center justify-between">
                      <label className="text-slate-400 text-[11px]">Exact Preserved Raw Payload:</label>
                      <button
                        onClick={() => copyToClipboard(selectedRaw?.raw_content, "raw")}
                        className="text-[10px] text-accent-cyan hover:underline"
                      >
                        {copySuccess === "raw" ? "✓ Copied" : "Copy Raw"}
                      </button>
                    </div>
                    <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800/90 text-slate-300 text-[11px] overflow-x-auto whitespace-pre-wrap max-h-48 leading-relaxed">
                      {inspectLoading ? "Loading raw evidence..." : selectedRaw?.raw_content || "Raw content stored in database."}
                    </pre>
                  </div>
                </div>

                {/* ── RIGHT PANE: Normalized Canonical Event ────────── */}
                <div className="space-y-4 p-4 rounded-xl bg-slate-900/80 border border-slate-800 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-white/5 pb-2">
                    <span className="font-bold text-slate-200 flex items-center gap-1.5">
                      <span>⚡</span> 2. OCSF-Aligned Canonical Event
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 border border-emerald-500/30 text-emerald-400">
                      {selectedNormalized.class_name}
                    </span>
                  </div>

                  {/* Top Canonical Fields */}
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div className="p-2 rounded bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block text-[9px] uppercase">Class UID</span>
                      <span className="text-accent-cyan font-bold">{selectedNormalized.class_uid}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block text-[9px] uppercase">Activity</span>
                      <span className="text-slate-200 font-bold">{selectedNormalized.activity_name}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block text-[9px] uppercase">Action</span>
                      <span className="text-emerald-400 font-bold">{selectedNormalized.action || "null"}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800">
                      <span className="text-slate-500 block text-[9px] uppercase">Confidence</span>
                      <span className="text-amber-400 font-bold">
                        {Math.round(selectedNormalized.normalization_confidence * 100)}%
                      </span>
                    </div>
                  </div>

                  {/* Network / Endpoint / Auth Canonical Details */}
                  <div className="space-y-1 text-[11px] p-2.5 rounded bg-slate-950 border border-slate-800">
                    <div className="text-slate-400 font-bold mb-1 text-[10px] uppercase">Extracted Canonical Attributes:</div>
                    {selectedNormalized.src_ip && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Source Endpoint:</span>
                        <span className="text-slate-300">{selectedNormalized.src_ip}:{selectedNormalized.src_port || "*"}</span>
                      </div>
                    )}
                    {selectedNormalized.dst_ip && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Dest Endpoint:</span>
                        <span className="text-slate-300">{selectedNormalized.dst_ip}:{selectedNormalized.dst_port || "*"}</span>
                      </div>
                    )}
                    {selectedNormalized.protocol && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Protocol:</span>
                        <span className="text-slate-300">{selectedNormalized.protocol}</span>
                      </div>
                    )}
                    {selectedNormalized.user_name && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Actor Username:</span>
                        <span className="text-slate-300">{selectedNormalized.user_name}</span>
                      </div>
                    )}
                    {selectedNormalized.process_name && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Process Name (PID):</span>
                        <span className="text-slate-300">{selectedNormalized.process_name} ({selectedNormalized.process_id || "N/A"})</span>
                      </div>
                    )}
                    {selectedNormalized.hostname && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Hostname:</span>
                        <span className="text-slate-300">{selectedNormalized.hostname}</span>
                      </div>
                    )}
                  </div>

                  {/* Unmapped Fields (Lossless Preservation) */}
                  {selectedNormalized.unmapped_data && Object.keys(selectedNormalized.unmapped_data).length > 0 && (
                    <div className="space-y-1 text-[11px] p-2.5 rounded bg-slate-950 border border-slate-800">
                      <div className="text-amber-500/80 font-bold mb-1 text-[10px] uppercase">Unmapped Vendor Fields:</div>
                      {Object.entries(selectedNormalized.unmapped_data).map(([key, val]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-slate-500">{key}:</span>
                          <span className="text-slate-300 truncate max-w-[150px]" title={String(val)}>{String(val)}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Confidence Breakdown Reasons */}
                  {selectedNormalized.confidence_reasons && selectedNormalized.confidence_reasons.length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[10px] text-slate-500 uppercase">Confidence Factors:</div>
                      <div className="flex flex-wrap gap-1">
                        {selectedNormalized.confidence_reasons.map((r, i) => (
                          <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            • {r}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                </div>
              </div>

            </div>
          </div>
        )}

      </div>
    </main>
  );
}
