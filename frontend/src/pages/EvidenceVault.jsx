/**
 * EvidenceVault.jsx
 * -----------------
 * Event Ingestion & Cryptographic Integrity Verification Dashboard.
 *
 * Sprint 1 — Raw Event Preservation & Traceable Ingestion.
 * Implements:
 * - Raw log submission & immutable preservation
 * - Deterministic SHA-256 fingerprinting
 * - Real-time cryptographic integrity verification
 * - Raw payload inspection modal
 */

import { useState, useEffect, useCallback } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const SAMPLE_PRESETS = [
  {
    name: "Cisco ASA Firewall",
    source_name: "perimeter-fw-01",
    source_type: "firewall",
    file_format: "text",
    content: "<134>1 2026-09-06T12:00:01.120Z perimeter-fw-01 cisco-asa 4120 - - %ASA-6-302013: Built inbound TCP connection 982103 for outside:198.51.100.45/443 (198.51.100.45/443) to inside:10.0.10.14/52140 (10.0.10.14/52140) action=ALLOW",
    metadata: { environment: "production", zone: "perimeter-north" },
  },
  {
    name: "Auth Gateway (JSON)",
    source_name: "auth-gateway-node",
    source_type: "authentication",
    file_format: "json",
    content: JSON.stringify(
      {
        timestamp: "2026-09-06T12:05:30.450Z",
        service: "auth-gateway",
        event_type: "AUTHENTICATION_FAILURE",
        client_ip: "198.51.100.77",
        username: "svc_monitoring",
        auth_method: "mfa_push",
        error_code: "AUTH_INVALID_TOKEN",
        session_id: "sess_8f912c4b7d10e23a",
        metadata: { geo_country: "IN", datacenter: "asia-south1", attempts: 3 },
      },
      null,
      2
    ),
    metadata: { environment: "staging", collector: "fluentbit-02" },
  },
  {
    name: "Process Audit (CSV)",
    source_name: "srv-app-prod-01",
    source_type: "system",
    file_format: "csv",
    content: "timestamp,hostname,process_name,process_id,parent_process,user,action,status\n2026-09-06T12:10:00Z,srv-app-prod-01,sshd,4120,systemd,root,LOGIN_SUCCESS,0\n2026-09-06T12:10:15Z,srv-app-prod-01,sudo,4128,sshd,secops,COMMAND_EXEC,0\n2026-09-06T12:10:18Z,srv-app-prod-01,systemctl,4130,sudo,root,SERVICE_RESTART,0",
    metadata: { environment: "production", auditd_version: "3.1.2" },
  },
];

export default function EvidenceVault() {
  // Ingestion Form State
  const [sourceName, setSourceName] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [fileFormat, setFileFormat] = useState("text");
  const [rawContent, setRawContent] = useState("");
  const [metadataJson, setMetadataJson] = useState("");
  
  // App State
  const [events, setEvents] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [successBanner, setSuccessBanner] = useState(null);

  // Filter & Search
  const [searchQuery, setSearchQuery] = useState("");
  const [formatFilter, setFormatFilter] = useState("all");

  // Inspection Modal State
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [inspectModalOpen, setInspectModalOpen] = useState(false);
  const [verifyingId, setVerifyingId] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [copySuccess, setCopySuccess] = useState(null);

  // Fetch events list
  const fetchEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/events?limit=50&offset=0`);
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setEvents(data.items || []);
      setTotalCount(data.total || 0);
    } catch (err) {
      console.error("Failed to fetch events:", err);
      setError("Unable to connect to backend API. Please ensure FastAPI is running.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  // Load Preset
  const handleLoadPreset = (preset) => {
    setSourceName(preset.source_name);
    setSourceType(preset.source_type);
    setFileFormat(preset.file_format);
    setRawContent(preset.content);
    setMetadataJson(JSON.stringify(preset.metadata, null, 2));
    setSuccessBanner(null);
  };

  // Submit Ingestion
  const handlePreserveEvent = async (e) => {
    e.preventDefault();
    if (!rawContent.trim()) {
      setError("Raw event content cannot be empty.");
      return;
    }

    setSubmitting(true);
    setError(null);
    setSuccessBanner(null);

    let parsedMeta = {};
    try {
      if (metadataJson.trim()) {
        parsedMeta = JSON.parse(metadataJson);
      }
    } catch {
      setError("Invalid JSON format in Metadata field.");
      setSubmitting(false);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/v1/ingest`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_name: sourceName,
          source_type: sourceType,
          file_format: fileFormat,
          raw_content: rawContent,
          metadata: parsedMeta,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Ingestion failed (${res.status})`);
      }

      const data = await res.json();
      setSuccessBanner(data);
      await fetchEvents();
    } catch (err) {
      setError(err.message || "Failed to preserve event.");
    } finally {
      setSubmitting(false);
    }
  };

  // Live Integrity Verification
  const handleVerifyIntegrity = async (eventId, e) => {
    if (e) e.stopPropagation();
    setVerifyingId(eventId);
    setVerificationResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/v1/events/${eventId}/verify`);
      if (!res.ok) throw new Error("Verification request failed");
      const result = await res.json();
      
      // Update local event status in table
      setEvents((prev) =>
        prev.map((evt) =>
          evt.event_id === eventId
            ? { ...evt, processing_status: result.integrity_status }
            : evt
        )
      );

      if (selectedEvent && selectedEvent.event_id === eventId) {
        setSelectedEvent((prev) => ({
          ...prev,
          processing_status: result.integrity_status,
        }));
        setVerificationResult(result);
      }
    } catch (err) {
      console.error("Verification error:", err);
    } finally {
      setVerifyingId(null);
    }
  };

  // Inspect Event Details
  const handleInspect = async (eventId) => {
    setVerificationResult(null);
    setInspectModalOpen(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/events/${eventId}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedEvent(data);
      }
    } catch (err) {
      console.error("Failed to load details:", err);
    }
  };

  // Copy to clipboard helper
  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text);
    setCopySuccess(label);
    setTimeout(() => setCopySuccess(null), 2000);
  };

  // Filtered Events
  const filteredEvents = events.filter((evt) => {
    const matchesSearch =
      evt.event_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.source_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.source_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.raw_content_hash.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesFormat = formatFilter === "all" || evt.file_format === formatFilter;
    return matchesSearch && matchesFormat;
  });

  // Calculate Metrics
  const verifiedCount = events.filter((e) => e.processing_status === "VERIFIED").length;
  const mismatchCount = events.filter((e) => e.processing_status === "MISMATCH").length;
  const latestEvent = events[0];

  return (
    <main className="flex-1 overflow-y-auto">
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
        
        {/* ── Header Section ─────────────────────────────────── */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-white/10 pb-6">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-1 rounded-md text-[10px] font-mono tracking-wider font-semibold bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan uppercase">
                Phase 1 · Evidence Integrity Active
              </span>
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent-cyan opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-accent-cyan"></span>
              </span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight text-slate-100">
              Evidence Vault &amp; Ingestion Engine
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Multi-format log ingestion, deterministic SHA-256 fingerprinting &amp; immutable raw log preservation.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchEvents}
              disabled={loading}
              className="px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 text-xs font-mono flex items-center gap-2 transition-colors"
            >
              <span className={loading ? "animate-spin" : ""}>🔄</span>
              Refresh Vault
            </button>
          </div>
        </div>

        {/* ── Summary KPI Cards ──────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="glass-card p-5 border-white/10 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Total Preserved</span>
              <span className="text-lg">🔒</span>
            </div>
            <p className="text-3xl font-bold font-mono text-slate-100 mt-2">{totalCount}</p>
            <p className="text-[11px] text-slate-500 mt-1">Immutable raw events</p>
          </div>

          <div className="glass-card p-5 border-white/10 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400">Integrity Verified</span>
              <span className="text-lg text-emerald-400">✓</span>
            </div>
            <p className="text-3xl font-bold font-mono text-emerald-400 mt-2">{verifiedCount}</p>
            <p className="text-[11px] text-slate-500 mt-1">100% SHA-256 match</p>
          </div>

          <div className="glass-card p-5 border-white/10 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-rose-400">Tamper Alerts</span>
              <span className="text-lg text-rose-400">⚠</span>
            </div>
            <p className="text-3xl font-bold font-mono text-rose-400 mt-2">{mismatchCount}</p>
            <p className="text-[11px] text-slate-500 mt-1">Hash mismatch detected</p>
          </div>

          <div className="glass-card p-5 border-white/10 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-accent-cyan">Latest Ingest</span>
              <span className="text-lg">⏱</span>
            </div>
            <p className="text-sm font-bold font-mono text-slate-200 mt-2 truncate">
              {latestEvent ? latestEvent.source_name : "None"}
            </p>
            <p className="text-[11px] font-mono text-slate-500 mt-1 truncate">
              {latestEvent ? new Date(latestEvent.ingested_at).toLocaleTimeString() : "--:--:--"}
            </p>
          </div>
        </div>

        {/* ── Preservation Ingestion Form ─────────────────────── */}
        <div className="glass-card p-6 border-white/10 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-white/5 pb-4">
            <div className="flex items-center gap-2">
              <span className="text-lg">📥</span>
              <h2 className="text-base font-semibold text-slate-100">Preserve Security Event</h2>
            </div>
            {/* Quick Sample Fill Buttons */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[11px] text-slate-500 font-mono">Sample Presets:</span>
              {SAMPLE_PRESETS.map((p) => (
                <button
                  key={p.name}
                  type="button"
                  onClick={() => handleLoadPreset(p)}
                  className="px-2.5 py-1 rounded bg-slate-800/80 hover:bg-accent-cyan/10 hover:border-accent-cyan/40 border border-slate-700 text-[11px] font-mono text-slate-300 transition-colors"
                >
                  {p.name}
                </button>
              ))}
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handlePreserveEvent} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1.5">Source Name</label>
                <input
                  type="text"
                  value={sourceName}
                  onChange={(e) => setSourceName(e.target.value)}
                  placeholder="e.g., perimeter-fw-01"
                  required
                  className="w-full px-3 py-2 rounded-lg bg-slate-900/90 border border-slate-700 text-slate-200 text-sm font-mono focus:outline-none focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1.5">Source Type</label>
                <input
                  type="text"
                  value={sourceType}
                  onChange={(e) => setSourceType(e.target.value)}
                  placeholder="e.g., firewall, auth, endpoint"
                  required
                  className="w-full px-3 py-2 rounded-lg bg-slate-900/90 border border-slate-700 text-slate-200 text-sm font-mono focus:outline-none focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1.5">Payload Format</label>
                <select
                  value={fileFormat}
                  onChange={(e) => setFileFormat(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900/90 border border-slate-700 text-slate-200 text-sm font-mono focus:outline-none focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan"
                >
                  <option value="text">Plain Text / Syslog (text)</option>
                  <option value="json">Structured JSON (json)</option>
                  <option value="csv">CSV Event (csv)</option>
                  <option value="syslog">Syslog RFC-5424 (syslog)</option>
                </select>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-mono text-slate-400">Raw Event Payload (Preserved Unaltered)</label>
                <span className="text-[10px] font-mono text-slate-500">
                  {rawContent.length} chars · {new Blob([rawContent]).size} bytes
                </span>
              </div>
              <textarea
                rows={4}
                value={rawContent}
                onChange={(e) => setRawContent(e.target.value)}
                placeholder="Paste raw log event here..."
                required
                className="w-full px-3 py-2 rounded-lg bg-slate-900/90 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan leading-relaxed"
              />
            </div>

            <div className="flex items-center justify-between pt-2">
              <div className="text-[11px] text-slate-500 font-mono">
                🔒 Sealed into Evidence Vault before parsing or normalization.
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="px-5 py-2.5 rounded-lg bg-accent-cyan hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono flex items-center gap-2 shadow-lg shadow-accent-cyan/10 transition-all disabled:opacity-50"
              >
                {submitting ? (
                  <>
                    <span className="animate-spin">⚙</span> Preserving...
                  </>
                ) : (
                  <>
                    <span>🔒</span> Preserve Evidence
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Success Banner */}
          {successBanner && (
            <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-500/30 animate-fade-in space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono font-semibold">
                  <span>✓</span> Evidence Preserved &amp; Fingerprinted
                </div>
                <button
                  onClick={() => setSuccessBanner(null)}
                  className="text-slate-400 hover:text-slate-200 text-xs"
                >
                  ✕
                </button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                <div className="text-slate-300">
                  <span className="text-slate-500">Event ID: </span>
                  <span className="text-accent-cyan font-bold">{successBanner.event_id}</span>
                </div>
                <div className="text-slate-300 truncate">
                  <span className="text-slate-500">SHA-256: </span>
                  <span className="text-slate-200">{successBanner.raw_content_hash}</span>
                </div>
              </div>
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center justify-between">
              <span>⚠ {error}</span>
              <button onClick={() => setError(null)} className="text-slate-400 hover:text-slate-200">
                ✕
              </button>
            </div>
          )}
        </div>

        {/* ── Ingested Events Vault Table ─────────────────────── */}
        <div className="glass-card border-white/10 overflow-hidden space-y-4 p-5">
          {/* Table Header & Controls */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <span>📋</span> Preserved Evidence Ledger
              </h2>
              <p className="text-xs text-slate-500 font-mono mt-0.5">
                Showing {filteredEvents.length} of {totalCount} events
              </p>
            </div>

            {/* Filters */}
            <div className="flex items-center gap-3 flex-wrap">
              {/* Format Filter Tabs */}
              <div className="flex rounded-lg bg-slate-900 border border-slate-700 p-0.5 text-xs font-mono">
                {["all", "text", "json", "csv"].map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => setFormatFilter(fmt)}
                    className={`px-2.5 py-1 rounded capitalize transition-colors ${
                      formatFilter === fmt
                        ? "bg-accent-cyan/20 text-accent-cyan font-semibold"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {fmt}
                  </button>
                ))}
              </div>

              {/* Search Box */}
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search event ID, source, hash..."
                className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-accent-cyan w-48 sm:w-60"
              />
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/10 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                  <th className="py-3 px-3">Event ID</th>
                  <th className="py-3 px-3">Source</th>
                  <th className="py-3 px-3">Format</th>
                  <th className="py-3 px-3">SHA-256 Fingerprint</th>
                  <th className="py-3 px-3">Size</th>
                  <th className="py-3 px-3">Status</th>
                  <th className="py-3 px-3">Ingested (UTC)</th>
                  <th className="py-3 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-mono">
                {filteredEvents.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-500">
                      {loading ? "Loading preserved events..." : "No matching evidence events found in vault."}
                    </td>
                  </tr>
                ) : (
                  filteredEvents.map((evt) => {
                    const isVerified = evt.processing_status === "VERIFIED";
                    const isMismatch = evt.processing_status === "MISMATCH";
                    const isVerifying = verifyingId === evt.event_id;

                    return (
                      <tr
                        key={evt.event_id}
                        className="hover:bg-white/[0.02] transition-colors group cursor-pointer"
                        onClick={() => handleInspect(evt.event_id)}
                      >
                        {/* Event ID */}
                        <td className="py-3 px-3 font-semibold text-accent-cyan whitespace-nowrap">
                          {evt.event_id}
                        </td>

                        {/* Source */}
                        <td className="py-3 px-3 text-slate-200">
                          <div>{evt.source_name}</div>
                          <div className="text-[10px] text-slate-500">{evt.source_type}</div>
                        </td>

                        {/* Format */}
                        <td className="py-3 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 text-slate-300 uppercase">
                            {evt.file_format}
                          </span>
                        </td>

                        {/* Fingerprint */}
                        <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                          <span className="font-mono text-slate-300" title={evt.raw_content_hash}>
                            {evt.hash_prefix || evt.raw_content_hash?.slice(0, 12)}…
                          </span>
                        </td>

                        {/* Size */}
                        <td className="py-3 px-3 text-slate-400">
                          {evt.content_size} B
                        </td>

                        {/* Status */}
                        <td className="py-3 px-3 whitespace-nowrap">
                          {isVerified && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/60 border border-emerald-500/40 text-emerald-400">
                              ✓ VERIFIED
                            </span>
                          )}
                          {isMismatch && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950/60 border border-rose-500/50 text-rose-400 shadow-sm shadow-rose-500/20">
                              ⚠ MISMATCH
                            </span>
                          )}
                          {!isVerified && !isMismatch && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 text-slate-400">
                              PRESERVED
                            </span>
                          )}
                        </td>

                        {/* Timestamp */}
                        <td className="py-3 px-3 text-slate-500 whitespace-nowrap">
                          {new Date(evt.ingested_at).toLocaleString()}
                        </td>

                        {/* Actions */}
                        <td className="py-3 px-3 text-right whitespace-nowrap space-x-2" onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            onClick={() => handleInspect(evt.event_id)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 text-[11px] text-slate-200 transition-colors"
                          >
                            Inspect
                          </button>
                          <button
                            type="button"
                            disabled={isVerifying}
                            onClick={(e) => handleVerifyIntegrity(evt.event_id, e)}
                            className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-all border ${
                              isVerified
                                ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-400 hover:bg-emerald-900/50"
                                : isMismatch
                                ? "bg-rose-950/40 border-rose-500/50 text-rose-400 hover:bg-rose-900/50"
                                : "bg-accent-cyan/10 border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/20"
                            }`}
                          >
                            {isVerifying ? "Verifying..." : "Verify"}
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

        {/* ── Event Inspection & Verification Modal ───────────── */}
        {inspectModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
            <div className="glass-card border-white/20 w-full max-w-3xl max-h-[90vh] overflow-y-auto p-6 space-y-6 shadow-2xl">
              
              {/* Modal Header */}
              <div className="flex items-center justify-between border-b border-white/10 pb-4">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">🔍</span>
                  <div>
                    <h3 className="text-lg font-bold text-slate-100 font-mono">
                      {selectedEvent?.event_id || "Event Inspection"}
                    </h3>
                    <p className="text-xs text-slate-500 font-mono">
                      Preserved at {selectedEvent ? new Date(selectedEvent.ingested_at).toUTCString() : ""}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setInspectModalOpen(false)}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs font-mono"
                >
                  ✕ Close
                </button>
              </div>

              {/* Event Metadata Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Source</span>
                  <span className="text-slate-200 font-semibold">{selectedEvent?.source_name}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Type</span>
                  <span className="text-slate-200 font-semibold">{selectedEvent?.source_type}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Format</span>
                  <span className="text-accent-cyan font-semibold uppercase">{selectedEvent?.file_format}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Size</span>
                  <span className="text-slate-200 font-semibold">{selectedEvent?.content_size} bytes</span>
                </div>
              </div>

              {/* Cryptographic Hash Section */}
              <div className="space-y-2 font-mono">
                <div className="flex items-center justify-between">
                  <label className="text-xs text-slate-400">SHA-256 Cryptographic Fingerprint</label>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(selectedEvent?.raw_content_hash, "hash")}
                    className="text-[11px] text-accent-cyan hover:underline"
                  >
                    {copySuccess === "hash" ? "✓ Copied!" : "Copy Hash"}
                  </button>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-accent-cyan break-all select-all font-mono">
                  {selectedEvent?.raw_content_hash}
                </div>
              </div>

              {/* Live Integrity Verification Action & Result */}
              <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3 font-mono">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-sm">🛡</span>
                    <span className="text-xs font-semibold text-slate-200">Cryptographic Integrity Audit</span>
                  </div>
                  <button
                    type="button"
                    disabled={verifyingId === selectedEvent?.event_id}
                    onClick={() => handleVerifyIntegrity(selectedEvent?.event_id)}
                    className="px-3 py-1.5 rounded bg-accent-cyan text-slate-950 font-bold text-xs hover:bg-cyan-400 transition-colors disabled:opacity-50"
                  >
                    {verifyingId === selectedEvent?.event_id ? "Auditing Live Hash..." : "Run Live Verification"}
                  </button>
                </div>

                {/* Verification Result Breakdown */}
                {verificationResult && (
                  <div
                    className={`p-3 rounded-md text-xs space-y-2 border ${
                      verificationResult.integrity_status === "VERIFIED"
                        ? "bg-emerald-950/30 border-emerald-500/40 text-emerald-300"
                        : "bg-rose-950/40 border-rose-500/50 text-rose-300"
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold">
                      <span>Status: {verificationResult.integrity_status}</span>
                      <span>{verificationResult.integrity_status === "VERIFIED" ? "✓ 100% MATCH" : "⚠ INTEGRITY COMPROMISED"}</span>
                    </div>
                    <div className="space-y-1 text-[11px] text-slate-400 break-all">
                      <div>
                        <span className="text-slate-500">Stored Hash: </span>
                        {verificationResult.stored_hash}
                      </div>
                      <div>
                        <span className="text-slate-500">Recalculated: </span>
                        {verificationResult.calculated_hash}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Preserved Raw Payload */}
              <div className="space-y-2 font-mono">
                <div className="flex items-center justify-between">
                  <label className="text-xs text-slate-400">Preserved Raw Content (Exact String)</label>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(selectedEvent?.raw_content, "content")}
                    className="text-[11px] text-accent-cyan hover:underline"
                  >
                    {copySuccess === "content" ? "✓ Copied!" : "Copy Raw Content"}
                  </button>
                </div>
                <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-60">
                  {selectedEvent?.raw_content}
                </pre>
              </div>

              {/* Metadata Viewer if present */}
              {selectedEvent?.metadata && Object.keys(selectedEvent.metadata).length > 0 && (
                <div className="space-y-1 font-mono">
                  <label className="text-[11px] text-slate-500">Context Metadata</label>
                  <pre className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-[11px] text-slate-400 overflow-x-auto">
                    {JSON.stringify(selectedEvent.metadata, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

      </div>
    </main>
  );
}
