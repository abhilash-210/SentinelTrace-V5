/**
 * SemanticIntelligence.jsx
 * ------------------------
 * Comprehensive cybersecurity UI for Sprint 3B:
 * Semantic Interpretation Engine, Semantic Drift Detection, and Explainable Audit Trace.
 */

import { useEffect, useState } from "react";

const API_BASE = "http://localhost:8000/api/v1";

export default function SemanticIntelligence() {
  const [activeTab, setActiveTab] = useState("interpretations"); // 'interpretations' | 'alerts' | 'policies'
  const [interpretations, setInterpretations] = useState([]);
  const [driftAlerts, setDriftAlerts] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [protectedFields, setProtectedFields] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedTrace, setSelectedTrace] = useState(null);
  const [traceLoading, setTraceLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [vendorFilter, setVendorFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");

  const fetchData = async () => {
    setLoading(true);
    try {
      const [resInterp, resAlerts, resPols, resFields] = await Promise.all([
        fetch(`${API_BASE}/semantic-interpretations?limit=100`),
        fetch(`${API_BASE}/semantic-drift-alerts?limit=100`),
        fetch(`${API_BASE}/semantic-policies`),
        fetch(`${API_BASE}/protected-fields`),
      ]);

      if (resInterp.ok) {
        const data = await resInterp.json();
        setInterpretations(data.items || []);
      }
      if (resAlerts.ok) {
        const data = await resAlerts.json();
        setDriftAlerts(data.items || []);
      }
      if (resPols.ok) {
        const data = await resPols.json();
        setPolicies(data || []);
      }
      if (resFields.ok) {
        const data = await resFields.json();
        setProtectedFields(data || []);
      }
    } catch (err) {
      console.error("Failed to fetch semantic data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const openTraceModal = async (interpretationId) => {
    setTraceLoading(true);
    try {
      const res = await fetch(`${API_BASE}/semantic-interpretations/${interpretationId}/trace`);
      if (res.ok) {
        const data = await res.json();
        setSelectedTrace(data);
      }
    } catch (err) {
      console.error("Failed to load semantic trace:", err);
    } finally {
      setTraceLoading(false);
    }
  };

  const runDemoScenario = async (type) => {
    setActionMessage({ type: "info", text: `Triggering ${type} pipeline execution...` });
    try {
      let rawLog = "";
      let sourceName = "";
      let sourceType = "firewall";
      let fileFormat = "text";

      if (type === "cisco_permit") {
        sourceName = "Cisco ASA Edge Gateway";
        rawLog = "<134>1 2026-09-06T12:00:00Z edge-asa-01 %ASA-6-302013: Built inbound TCP connection for outside:198.51.100.22/443 to inside:10.0.1.50/51234 action=PERMIT";
      } else if (type === "demo_permit") {
        sourceName = "Demo Vendor Tap Appliance";
        fileFormat = "json";
        rawLog = JSON.stringify({
          timestamp: new Date().toISOString(),
          vendor: "Demo Vendor",
          action: "PERMIT",
          src_ip: "192.168.10.45",
          note: "Observation/Shadow mode monitor pass-through",
        });
      } else if (type === "unmapped_drift") {
        sourceName = "Cisco ASA Edge Gateway";
        rawLog = "<134>1 2026-09-06T12:00:00Z edge-asa-01 %ASA-6-302013: action=UNKNOWN_CUSTOM_OP src=192.168.1.1 dst=10.0.0.1";
      } else if (type === "conflict_demo") {
        sourceName = "Conflict Vendor Device";
        rawLog = "<134>1 2026-09-06T12:00:00Z conflict-01 %ASA: action=ALLOW";
      }

      // 1. Ingest
      const ingestRes = await fetch(`${API_BASE}/ingest`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_name: sourceName,
          source_type: sourceType,
          file_format: fileFormat,
          raw_content: rawLog,
        }),
      });
      const ingestData = await ingestRes.json();

      // 2. Normalize
      const normRes = await fetch(`${API_BASE}/events/${ingestData.event_id}/normalize`, {
        method: "POST",
      });
      const normData = await normRes.json();

      // 3. Interpret
      const interpRes = await fetch(`${API_BASE}/normalized-events/${normData.normalized_event_id}/interpret`, {
        method: "POST",
      });
      const interpData = await interpRes.json();

      setActionMessage({
        type: "success",
        text: `Pipeline completed: ${sourceName} -> ${interpData.interpreted_value || interpData.interpretation_status} (${interpData.confidence_score * 100}% confidence)`,
      });

      await fetchData();
      if (interpData.interpretation_id) {
        openTraceModal(interpData.interpretation_id);
      }
    } catch (err) {
      setActionMessage({ type: "error", text: `Pipeline failed: ${err.message}` });
    }
  };

  // Filtered interpretations
  const filteredInterpretations = interpretations.filter((item) => {
    if (statusFilter !== "ALL" && item.interpretation_status !== statusFilter) return false;
    if (vendorFilter !== "ALL" && item.vendor_name !== vendorFilter) return false;
    return true;
  });

  // Filtered drift alerts
  const filteredAlerts = driftAlerts.filter((alert) => {
    if (severityFilter !== "ALL" && alert.severity !== severityFilter) return false;
    return true;
  });

  const totalInterpretations = interpretations.length;
  const highRiskCount = interpretations.filter((i) => i.risk_level === "HIGH" || i.risk_level === "CRITICAL").length;
  const openAlertsCount = driftAlerts.filter((a) => a.status === "OPEN").length;
  const ambiguousCount = interpretations.filter((i) => i.equivalence_classification === "AMBIGUOUS").length;

  return (
    <main className="flex-1 overflow-y-auto bg-sentinel-950 p-6 space-y-6 animate-fade-in text-slate-100 font-sans">
      {/* ── Header ────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-2xl font-mono text-accent-cyan">📋</span>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
              Semantic Intelligence & Policy Engine
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                Sprint 3B Live
              </span>
            </h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Vendor-scoped semantic policy evaluation, defensive drift detection, and explainable audit trails.
          </p>
        </div>

        {/* Action button */}
        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="px-3.5 py-2 text-xs font-medium rounded-lg bg-sentinel-800 border border-white/10 hover:bg-sentinel-700 transition flex items-center gap-2"
          >
            <span className={loading ? "animate-spin" : ""}>🔄</span> Refresh Registry
          </button>
        </div>
      </div>

      {/* ── Action Notice ─────────────────────────────────────── */}
      {actionMessage && (
        <div
          className={`p-3.5 rounded-lg border text-xs flex items-center justify-between transition ${
            actionMessage.type === "success"
              ? "bg-emerald-950/60 border-emerald-500/40 text-emerald-300"
              : actionMessage.type === "error"
              ? "bg-red-950/60 border-red-500/40 text-red-300"
              : "bg-cyan-950/60 border-cyan-500/40 text-cyan-300"
          }`}
        >
          <span>{actionMessage.text}</span>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white ml-4">
            ✕
          </button>
        </div>
      )}

      {/* ── KPI Cards ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-sentinel-900/70 border border-white/10 rounded-xl p-4.5 backdrop-blur shadow-sm">
          <div className="flex justify-between items-start">
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Interpretations</p>
            <span className="text-accent-cyan text-sm">📊</span>
          </div>
          <p className="text-2xl font-bold font-mono text-white mt-2">{totalInterpretations}</p>
          <p className="text-[11px] text-slate-500 mt-1">Derived from normalized canonical events</p>
        </div>

        <div className="bg-sentinel-900/70 border border-white/10 rounded-xl p-4.5 backdrop-blur shadow-sm">
          <div className="flex justify-between items-start">
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">High Risk Decisions</p>
            <span className="text-amber-400 text-sm">⚠️</span>
          </div>
          <p className="text-2xl font-bold font-mono text-amber-400 mt-2">{highRiskCount}</p>
          <p className="text-[11px] text-slate-500 mt-1">Requiring elevated security oversight</p>
        </div>

        <div className="bg-sentinel-900/70 border border-white/10 rounded-xl p-4.5 backdrop-blur shadow-sm">
          <div className="flex justify-between items-start">
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Drift Alerts</p>
            <span className="text-red-400 text-sm">🚨</span>
          </div>
          <p className="text-2xl font-bold font-mono text-red-400 mt-2">{openAlertsCount}</p>
          <p className="text-[11px] text-slate-500 mt-1">Unmapped, ambiguous & protected-field risks</p>
        </div>

        <div className="bg-sentinel-900/70 border border-white/10 rounded-xl p-4.5 backdrop-blur shadow-sm">
          <div className="flex justify-between items-start">
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Ambiguous Mappings</p>
            <span className="text-purple-400 text-sm">🔀</span>
          </div>
          <p className="text-2xl font-bold font-mono text-purple-400 mt-2">{ambiguousCount}</p>
          <p className="text-[11px] text-slate-500 mt-1">Vendor-specific non-standard semantics</p>
        </div>
      </div>

      {/* ── Demo Pipeline Scenario Bar ────────────────────────── */}
      <div className="bg-sentinel-900/90 border border-cyan-500/20 rounded-xl p-4.5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <span className="text-accent-cyan">⚡</span> Interactive Semantic Isolation & Drift Scenarios
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Execute live end-to-end ingestion $\rightarrow$ normalization $\rightarrow$ vendor-scoped policy derivation.
            </p>
          </div>
          <div className="flex flex-wrap gap-2.5">
            <button
              onClick={() => runDemoScenario("cisco_permit")}
              className="px-3 py-1.5 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-900/60 text-xs font-medium transition flex items-center gap-1.5"
            >
              <span>🛡️</span> Cisco ASA (PERMIT $\rightarrow$ ALLOWED)
            </button>
            <button
              onClick={() => runDemoScenario("demo_permit")}
              className="px-3 py-1.5 rounded-lg bg-purple-950/60 border border-purple-500/40 text-purple-300 hover:bg-purple-900/60 text-xs font-medium transition flex items-center gap-1.5"
            >
              <span>🔀</span> Demo Vendor (PERMIT $\rightarrow$ MONITORED)
            </button>
            <button
              onClick={() => runDemoScenario("unmapped_drift")}
              className="px-3 py-1.5 rounded-lg bg-amber-950/60 border border-amber-500/40 text-amber-300 hover:bg-amber-900/60 text-xs font-medium transition flex items-center gap-1.5"
            >
              <span>⚠️</span> Unmapped Drift (UNKNOWN $\rightarrow$ UNMAPPED)
            </button>
            <button
              onClick={() => runDemoScenario("conflict_demo")}
              className="px-3 py-1.5 rounded-lg bg-red-950/60 border border-red-500/40 text-red-300 hover:bg-red-900/60 text-xs font-medium transition flex items-center gap-1.5"
            >
              <span>🚨</span> Conflict Test (Rule Conflict)
            </button>
          </div>
        </div>
      </div>

      {/* ── Tabs Navigation ───────────────────────────────────── */}
      <div className="flex border-b border-white/10 gap-6 text-sm font-medium">
        <button
          onClick={() => setActiveTab("interpretations")}
          className={`pb-3 transition flex items-center gap-2 ${
            activeTab === "interpretations"
              ? "border-b-2 border-accent-cyan text-accent-cyan font-bold"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <span>🔍</span> Semantic Interpretations ({interpretations.length})
        </button>
        <button
          onClick={() => setActiveTab("alerts")}
          className={`pb-3 transition flex items-center gap-2 ${
            activeTab === "alerts"
              ? "border-b-2 border-accent-cyan text-accent-cyan font-bold"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <span>🚨</span> Drift & Risk Alerts ({driftAlerts.length})
        </button>
        <button
          onClick={() => setActiveTab("policies")}
          className={`pb-3 transition flex items-center gap-2 ${
            activeTab === "policies"
              ? "border-b-2 border-accent-cyan text-accent-cyan font-bold"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <span>📜</span> Policies & Protected Fields ({policies.length})
        </button>
      </div>

      {/* ── Tab 1: Semantic Interpretations Table ───────────────── */}
      {activeTab === "interpretations" && (
        <div className="space-y-4">
          {/* Filter Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-sentinel-900/40 p-3 rounded-lg border border-white/5">
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-400">Filter Status:</span>
              {["ALL", "INTERPRETED", "AMBIGUOUS", "UNMAPPED", "CONFLICT"].map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition ${
                    statusFilter === st
                      ? "bg-accent-cyan/20 border border-accent-cyan text-accent-cyan font-bold"
                      : "bg-sentinel-800/80 text-slate-400 hover:text-white"
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-400">Vendor:</span>
              {["ALL", "Cisco ASA", "Demo Vendor"].map((vnd) => (
                <button
                  key={vnd}
                  onClick={() => setVendorFilter(vnd)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition ${
                    vendorFilter === vnd
                      ? "bg-accent-cyan/20 border border-accent-cyan text-accent-cyan font-bold"
                      : "bg-sentinel-800/80 text-slate-400 hover:text-white"
                  }`}
                >
                  {vnd}
                </button>
              ))}
            </div>
          </div>

          {/* Interpretations Table */}
          <div className="overflow-x-auto rounded-xl border border-white/10 bg-sentinel-900/50">
            <table className="w-full text-left text-xs">
              <thead className="bg-sentinel-800/60 text-slate-400 border-b border-white/10 font-mono">
                <tr>
                  <th className="py-3 px-4">Interpretation ID</th>
                  <th className="py-3 px-4">Vendor Context</th>
                  <th className="py-3 px-4">Source Value</th>
                  <th className="py-3 px-4">Canonical Mapping</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-sans">
                {filteredInterpretations.length === 0 ? (
                  <tr>
                    <td colSpan="9" className="py-8 text-center text-slate-500 font-mono">
                      No semantic interpretations found. Trigger a scenario above to evaluate logs.
                    </td>
                  </tr>
                ) : (
                  filteredInterpretations.map((item) => (
                    <tr key={item.interpretation_id} className="hover:bg-white/[0.02] transition">
                      <td className="py-3 px-4 font-mono text-cyan-400">{item.interpretation_id.slice(0, 16)}...</td>
                      <td className="py-3 px-4 font-semibold text-slate-200">{item.vendor_name}</td>
                      <td className="py-3 px-4">
                        <span className="font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {item.source_value}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {item.interpreted_value ? (
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-400 font-mono">{item.canonical_field} $\rightarrow$</span>
                            <span className="font-bold text-white font-mono bg-white/5 px-2 py-0.5 rounded border border-white/10">
                              {item.interpreted_value}
                            </span>
                          </div>
                        ) : (
                          <span className="text-slate-500 italic">Unmapped</span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono">
                        {item.equivalence_classification === "EQUIVALENT" && (
                          <span className="px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-500/30 text-emerald-300">
                            EQUIVALENT
                          </span>
                        )}
                        {item.equivalence_classification === "COMPATIBLE" && (
                          <span className="px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-500/30 text-cyan-300">
                            COMPATIBLE
                          </span>
                        )}
                        {item.equivalence_classification === "AMBIGUOUS" && (
                          <span className="px-2 py-0.5 rounded bg-purple-950/70 border border-purple-500/30 text-purple-300">
                            AMBIGUOUS
                          </span>
                        )}
                        {!item.equivalence_classification && (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400">NONE</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`font-mono px-2 py-0.5 rounded text-[10px] font-bold ${
                            item.risk_level === "CRITICAL"
                              ? "bg-red-950 text-red-400 border border-red-500/40"
                              : item.risk_level === "HIGH"
                              ? "bg-orange-950 text-orange-400 border border-orange-500/40"
                              : item.risk_level === "MEDIUM"
                              ? "bg-amber-950 text-amber-400 border border-amber-500/40"
                              : "bg-emerald-950 text-emerald-400 border border-emerald-500/30"
                          }`}
                        >
                          {item.risk_level}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${
                                item.confidence_score >= 0.85
                                  ? "bg-emerald-400"
                                  : item.confidence_score >= 0.6
                                  ? "bg-amber-400"
                                  : "bg-red-400"
                              }`}
                              style={{ width: `${Math.round(item.confidence_score * 100)}%` }}
                            />
                          </div>
                          <span className="font-mono text-slate-300 text-[11px]">
                            {Math.round(item.confidence_score * 100)}%
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            item.interpretation_status === "INTERPRETED"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                              : item.interpretation_status === "AMBIGUOUS"
                              ? "bg-purple-500/10 text-purple-400 border border-purple-500/30"
                              : item.interpretation_status === "CONFLICT"
                              ? "bg-red-500/10 text-red-400 border border-red-500/30"
                              : "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                          }`}
                        >
                          {item.interpretation_status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => openTraceModal(item.interpretation_id)}
                          className="px-2.5 py-1 text-xs rounded bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/20 transition font-mono"
                        >
                          Inspect Trace $\rightarrow$
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Tab 2: Drift & Risk Alerts Feed ────────────────────── */}
      {activeTab === "alerts" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between bg-sentinel-900/40 p-3 rounded-lg border border-white/5">
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-400">Severity:</span>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition ${
                    severityFilter === sev
                      ? "bg-accent-cyan/20 border border-accent-cyan text-accent-cyan font-bold"
                      : "bg-sentinel-800/80 text-slate-400 hover:text-white"
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
            <p className="text-xs text-slate-400 font-mono">Total Alerts: {filteredAlerts.length}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredAlerts.length === 0 ? (
              <div className="col-span-2 py-12 text-center text-slate-500 font-mono bg-sentinel-900/30 border border-white/5 rounded-xl">
                No semantic drift alerts detected. System is currently aligned with active vendor policies.
              </div>
            ) : (
              filteredAlerts.map((alert) => (
                <div
                  key={alert.alert_id}
                  className="bg-sentinel-900/70 border border-white/10 rounded-xl p-4.5 space-y-3 relative overflow-hidden"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-2.5 h-2.5 rounded-full ${
                          alert.severity === "CRITICAL" || alert.severity === "HIGH"
                            ? "bg-red-500 animate-ping"
                            : "bg-amber-400"
                        }`}
                      />
                      <span className="font-mono text-xs font-bold text-white">{alert.drift_type}</span>
                    </div>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        alert.severity === "HIGH" || alert.severity === "CRITICAL"
                          ? "bg-red-950 text-red-400 border border-red-500/40"
                          : "bg-amber-950 text-amber-400 border border-amber-500/40"
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{alert.description}</p>

                  <div className="bg-black/30 p-2.5 rounded-lg border border-white/5 text-[11px] font-mono space-y-1">
                    {alert.expected_value && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Expected:</span>
                        <span className="text-emerald-400">{alert.expected_value}</span>
                      </div>
                    )}
                    {alert.observed_value && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Observed:</span>
                        <span className="text-amber-400">{alert.observed_value}</span>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1">
                    <span>ID: {alert.alert_id.slice(0, 18)}...</span>
                    <span>{new Date(alert.detected_at).toLocaleString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* ── Tab 3: Policies & Protected Fields Catalog ─────────── */}
      {activeTab === "policies" && (
        <div className="space-y-6">
          {/* Protected Fields Card */}
          <div className="bg-sentinel-900/60 border border-white/10 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <span className="text-red-400">🛡️</span> Protected Security-Sensitive Semantic Fields
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Fields requiring elevated governance and strict auditability. Ambiguities trigger high-severity alerts.
                </p>
              </div>
              <span className="text-xs font-mono px-2.5 py-1 rounded bg-red-950/60 border border-red-500/30 text-red-300">
                {protectedFields.length} Protected Fields
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {protectedFields.map((field) => (
                <div key={field.id} className="bg-sentinel-950/80 border border-white/5 rounded-lg p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm font-bold text-accent-cyan">{field.field_name}</span>
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-500/40">
                      {field.criticality}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{field.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Active Vendor Policies */}
          <div className="space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <span className="text-accent-cyan">📜</span> Active Vendor Semantic Policies
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {policies.map((pol) => (
                <div key={pol.policy_id} className="bg-sentinel-900/60 border border-white/10 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-bold text-white text-sm">{pol.policy_name}</h4>
                      <p className="text-xs text-slate-400 font-mono mt-0.5">
                        Vendor: <span className="text-slate-200 font-semibold">{pol.vendor_name}</span> · ID: {pol.policy_id}
                      </p>
                    </div>
                    <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                      {pol.status} (v{pol.version})
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{pol.description}</p>

                  <div className="border-t border-white/5 pt-3">
                    <p className="text-[11px] font-mono text-slate-400 mb-2">Policy Rule Scope ({pol.rule_count} rules):</p>
                    <div className="space-y-1.5">
                      {pol.rules && pol.rules.map((rule) => (
                        <div
                          key={rule.rule_id}
                          className="flex items-center justify-between bg-black/30 px-3 py-1.5 rounded border border-white/5 text-xs font-mono"
                        >
                          <span className="text-slate-300">
                            {rule.source_field}:<strong className="text-cyan-300">{rule.source_value}</strong>
                          </span>
                          <span className="text-slate-500">$\rightarrow$</span>
                          <span className="text-white font-bold">{rule.canonical_value}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                            {rule.equivalence_classification}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Traceability & Explainability Modal ─────────────────── */}
      {selectedTrace && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-cyan-500/30 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-6 shadow-2xl animate-fade-in">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <span className="text-accent-cyan">⛓️</span> End-to-End Semantic Audit Trace
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Interpretation ID: {selectedTrace.interpretation_id}
                </p>
              </div>
              <button
                onClick={() => setSelectedTrace(null)}
                className="text-slate-400 hover:text-white text-lg px-2 py-1 rounded-lg hover:bg-white/5 transition"
              >
                ✕
              </button>
            </div>

            {/* Visual Trace Flow */}
            <div className="bg-black/40 border border-white/10 rounded-xl p-4">
              <p className="text-xs font-mono text-slate-400 mb-3">TRACE PIPELINE FLOW:</p>
              <div className="grid grid-cols-2 md:grid-cols-6 gap-2 text-center text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-slate-800/80 border border-slate-700">
                  <p className="text-slate-500 text-[10px]">1. Evidence</p>
                  <p className="text-cyan-400 font-bold truncate mt-1">{selectedTrace.raw_evidence?.event_id?.slice(0, 10)}</p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-800/80 border border-slate-700">
                  <p className="text-slate-500 text-[10px]">2. Normalized</p>
                  <p className="text-cyan-400 font-bold truncate mt-1">{selectedTrace.normalized_event?.normalized_event_id?.slice(0, 10)}</p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-800/80 border border-slate-700">
                  <p className="text-slate-500 text-[10px]">3. Vendor</p>
                  <p className="text-white font-bold truncate mt-1">{selectedTrace.vendor}</p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-800/80 border border-slate-700">
                  <p className="text-slate-500 text-[10px]">4. Policy</p>
                  <p className="text-purple-400 font-bold truncate mt-1">{selectedTrace.semantic_policy?.policy_id || "Unmapped"}</p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-800/80 border border-slate-700">
                  <p className="text-slate-500 text-[10px]">5. Decision</p>
                  <p className="text-emerald-400 font-bold truncate mt-1">{selectedTrace.semantic_decision?.interpreted_value || "None"}</p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-800/80 border border-slate-700">
                  <p className="text-slate-500 text-[10px]">6. Alerts</p>
                  <p className="text-red-400 font-bold mt-1">{selectedTrace.drift_alerts?.length || 0} Alerts</p>
                </div>
              </div>
            </div>

            {/* Explainable Reasoning Block */}
            <div className="bg-sentinel-950 border border-cyan-500/20 rounded-xl p-4.5 space-y-2">
              <h4 className="text-xs font-mono font-bold text-accent-cyan uppercase tracking-wider flex items-center gap-2">
                <span>🤖</span> Explainable Decision Audit Trail
              </h4>
              <p className="text-xs text-slate-200 leading-relaxed font-sans bg-black/30 p-3 rounded-lg border border-white/5">
                "{selectedTrace.semantic_decision?.explanation}"
              </p>
            </div>

            {/* Details Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              {/* Decision Box */}
              <div className="bg-sentinel-950/80 p-4 rounded-xl border border-white/5 space-y-2">
                <p className="text-slate-400 font-bold border-b border-white/5 pb-2">SEMANTIC DECISION</p>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">Canonical Target:</span>
                  <span className="text-white">{selectedTrace.semantic_decision?.canonical_field}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">Interpreted Value:</span>
                  <span className="text-emerald-400 font-bold">{selectedTrace.semantic_decision?.interpreted_value || "None"}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">Classification:</span>
                  <span className="text-cyan-300">{selectedTrace.semantic_decision?.equivalence_classification || "None"}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">Risk Level:</span>
                  <span className="text-amber-400">{selectedTrace.semantic_decision?.risk_level}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">Confidence Score:</span>
                  <span className="text-cyan-400 font-bold">{Math.round((selectedTrace.semantic_decision?.confidence_score || 0) * 100)}%</span>
                </div>
              </div>

              {/* Deductions Box */}
              <div className="bg-sentinel-950/80 p-4 rounded-xl border border-white/5 space-y-2">
                <p className="text-slate-400 font-bold border-b border-white/5 pb-2">CONFIDENCE FACTORS & DEDUCTIONS</p>
                {selectedTrace.semantic_decision?.confidence_reasons?.length === 0 ? (
                  <p className="text-emerald-400 text-xs py-2">No deductions applied. 100% direct policy equivalence.</p>
                ) : (
                  <div className="space-y-1.5 py-1">
                    {selectedTrace.semantic_decision?.confidence_reasons?.map((reason, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-amber-300 bg-amber-950/30 p-2 rounded border border-amber-500/20">
                        <span>⚠️</span>
                        <span>{reason}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Close Button */}
            <div className="flex justify-end pt-2 border-t border-white/10">
              <button
                onClick={() => setSelectedTrace(null)}
                className="px-5 py-2 text-xs font-medium rounded-lg bg-sentinel-800 hover:bg-sentinel-700 text-white transition font-sans"
              >
                Close Trace Inspection
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
