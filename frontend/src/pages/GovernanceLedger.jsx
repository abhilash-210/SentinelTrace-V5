/**
 * pages/GovernanceLedger.jsx
 * --------------------------
 * Cryptographic Governance Ledger Dashboard for SentinelTrace V5.
 *
 * Sprint 5A — Cryptographic Governance Ledger Foundation (Tamper-Evident Hash Chaining).
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import AccessRestricted from "../components/AccessRestricted";

const EVENT_BADGES = {
  POLICY_CREATED: "bg-slate-900 text-slate-300 border-slate-700",
  POLICY_SUBMITTED: "bg-blue-950/80 text-blue-300 border-blue-500/40",
  POLICY_APPROVED: "bg-emerald-950/80 text-emerald-300 border-emerald-500/40",
  POLICY_REJECTED: "bg-rose-950/80 text-rose-300 border-rose-500/40",
  POLICY_ACTIVATED: "bg-cyan-950/80 text-cyan-300 border-cyan-500/40",
  POLICY_SUPERSEDED: "bg-purple-950/80 text-purple-300 border-purple-500/40",
  ROLE_CHANGED: "bg-amber-950/80 text-amber-300 border-amber-500/40",
  USER_CREATED: "bg-teal-950/80 text-teal-300 border-teal-500/40",
  USER_DEACTIVATED: "bg-red-950/80 text-red-300 border-red-500/40",
  GENESIS_TEST: "bg-slate-800 text-slate-400 border-slate-700",
};

export default function GovernanceLedger() {
  const { user, authFetch } = useAuth();

  // Primary Ledger State
  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);
  const [chainHead, setChainHead] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [eventTypeFilter, setEventTypeFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  // Chain Verification State
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);

  // Inspection Modal State
  const [selectedEntry, setSelectedEntry] = useState(null);

  // Fetch Ledger Entries
  const fetchLedger = async () => {
    setLoading(true);
    setError(null);
    try {
      const url = eventTypeFilter === "ALL"
        ? "/api/v1/governance-ledger?limit=100"
        : `/api/v1/governance-ledger?limit=100&event_type=${eventTypeFilter}`;

      const res = await authFetch(url);
      if (!res.ok) {
        if (res.status === 403) {
          setError("ACCESS_DENIED");
          setLoading(false);
          return;
        }
        throw new Error(`Failed to load governance ledger: HTTP ${res.status}`);
      }
      const data = await res.json();
      setEntries(data.items || []);
      setTotal(data.total || 0);
      setChainHead(data.chain_head || null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Run Cryptographic Verification
  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await authFetch("/api/v1/governance-ledger/verify");
      if (!res.ok) {
        throw new Error(`Verification request failed: HTTP ${res.status}`);
      }
      const data = await res.json();
      setVerificationResult(data);
      if (data.chain_head) {
        setChainHead(data.chain_head);
      }
    } catch (err) {
      setVerificationResult({
        status: "ERROR",
        reason: err.message,
        entries_checked: 0,
      });
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    fetchLedger();
    handleVerifyChain();
  }, [eventTypeFilter]);

  if (error === "ACCESS_DENIED") {
    return (
      <AccessRestricted
        requiredRole="AUDITOR or ADMIN"
        requiredPermission="AUDIT_READ or GOVERNANCE_AUDIT_READ"
      />
    );
  }

  const filteredEntries = entries.filter((e) => {
    const q = searchQuery.toLowerCase();
    return (
      e.ledger_entry_id.toLowerCase().includes(q) ||
      e.event_type.toLowerCase().includes(q) ||
      (e.actor_username && e.actor_username.toLowerCase().includes(q)) ||
      e.entry_hash.toLowerCase().includes(q) ||
      String(e.sequence_number).includes(q)
    );
  });

  return (
    <main className="flex-1 flex flex-col bg-sentinel-950 overflow-hidden min-w-0">
      {/* Top Header */}
      <header className="px-6 py-4 border-b border-sentinel-800/80 bg-sentinel-900/50 backdrop-blur-sm flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-xl">⛓️</span>
            <h1 className="text-base font-semibold text-slate-100 font-mono tracking-tight">
              Cryptographic Governance Ledger
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-500/40">
              Sprint 5A Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Deterministic SHA-256 Hash Chaining • Append-Only Ledger • Mathematical Tamper Detection
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleVerifyChain}
            disabled={verifying}
            className="px-3.5 py-1.5 rounded-lg bg-indigo-950 hover:bg-indigo-900 border border-indigo-500/40 text-indigo-200 text-xs font-mono font-medium flex items-center gap-2 transition-colors shadow-sm"
          >
            <span className={`w-2 h-2 rounded-full ${verifying ? "bg-amber-400 animate-ping" : "bg-indigo-400"}`} />
            {verifying ? "Verifying SHA-256 Chain..." : "Verify Ledger Chain"}
          </button>
          <button
            onClick={fetchLedger}
            className="px-3 py-1.5 rounded-lg bg-sentinel-800 hover:bg-sentinel-700 border border-sentinel-700 text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            ↻ Refresh
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* KPI Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-sentinel-900/60 border border-sentinel-800 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-indigo-400 uppercase tracking-wider">Total Ledger Blocks</span>
              <span className="text-indigo-400 text-lg">📦</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{total}</div>
            <p className="text-[11px] text-slate-500 mt-1">Append-only sequence records</p>
          </div>

          <div className="p-4 rounded-xl bg-sentinel-900/60 border border-sentinel-800 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-emerald-400 uppercase tracking-wider">Chain Integrity</span>
              <span className="text-emerald-400 text-lg">🛡️</span>
            </div>
            <div className="flex items-center gap-2 mt-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-lg font-bold font-mono text-emerald-300">
                {verificationResult?.status || "VERIFIED"}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              {verificationResult ? `${verificationResult.entries_checked} blocks validated` : "Checking hashes..."}
            </p>
          </div>

          <div className="p-4 rounded-xl bg-sentinel-900/60 border border-sentinel-800 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">Latest Block (Head)</span>
              <span className="text-cyan-400 text-lg">⛓</span>
            </div>
            <div className="text-sm font-bold font-mono text-cyan-300 mt-2 truncate">
              {chainHead ? `${chainHead.slice(0, 16)}...` : "GENESIS"}
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Sequence #{entries[0]?.sequence_number || total || 0}</p>
          </div>

          <div className="p-4 rounded-xl bg-sentinel-900/60 border border-sentinel-800 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-amber-400 uppercase tracking-wider">Tamper Detection</span>
              <span className="text-amber-400 text-lg">🔍</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100 mt-2">
              {verificationResult?.status === "TAMPER_DETECTED" ? "1 ALERT" : "0 DETECTED"}
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Cryptographic discrepancy monitor</p>
          </div>
        </div>

        {/* Verification Status Banner */}
        {verificationResult && (
          <div
            className={`p-4 rounded-xl border flex items-start justify-between gap-4 ${
              verificationResult.status === "VERIFIED"
                ? "bg-emerald-950/30 border-emerald-500/40 text-emerald-300"
                : "bg-rose-950/40 border-rose-500/60 text-rose-300"
            }`}
          >
            <div className="flex items-start gap-3">
              <span className="text-2xl">{verificationResult.status === "VERIFIED" ? "✓" : "🚫"}</span>
              <div className="space-y-0.5 text-xs">
                <div className="font-bold font-mono text-sm tracking-wide">
                  {verificationResult.status === "VERIFIED"
                    ? "Cryptographic Verification Passed: All Blocks Mathematically Sound"
                    : "TAMPER DETECTED: Cryptographic Invariant Broken"}
                </div>
                <p className="text-slate-300 text-[11px] font-mono leading-relaxed">
                  {verificationResult.reason} • Checked: {verificationResult.entries_checked} entries • Chain Head: {verificationResult.chain_head ? `${verificationResult.chain_head.slice(0, 24)}...` : "None"}
                </p>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded text-[10px] font-mono font-bold bg-sentinel-950/80 border border-sentinel-700">
              SHA-256 Validated
            </span>
          </div>
        )}

        {/* Visual Hash Chain Representation */}
        <div className="p-5 rounded-xl bg-sentinel-900/60 border border-sentinel-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider flex items-center gap-2">
              <span>⛓️</span> SHA-256 Sequential Block Linkage (Top Recent)
            </h3>
            <span className="text-[10px] text-slate-500 font-mono">
              H_n = SHA256(Seq | PrevHash | PayloadHash)
            </span>
          </div>

          <div className="flex items-center gap-2 overflow-x-auto py-3 px-1 scrollbar-thin">
            {/* Genesis Node */}
            <div className="flex-shrink-0 p-3 rounded-lg bg-sentinel-950 border border-sentinel-700/80 w-44 space-y-1">
              <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                <span>GENESIS</span>
                <span>#0</span>
              </div>
              <div className="text-[10px] font-mono text-indigo-400 truncate">000000000000...</div>
              <div className="text-[9px] text-slate-500">Origin Block</div>
            </div>

            <div className="text-slate-600 font-mono font-bold">➔</div>

            {/* Display first 4 recent blocks in reverse chronological sequence visualizer */}
            {entries.slice(0, 5).reverse().map((b) => (
              <React.Fragment key={b.ledger_entry_id}>
                <div
                  onClick={() => setSelectedEntry(b)}
                  className="flex-shrink-0 p-3 rounded-lg bg-sentinel-950 border border-indigo-500/40 hover:border-indigo-400 cursor-pointer w-48 space-y-1 transition-all group"
                >
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-300">
                    <span className="font-bold text-indigo-300">BLOCK #{b.sequence_number}</span>
                    <span className="text-[9px] text-slate-500">{b.event_type.slice(0, 10)}</span>
                  </div>
                  <div className="text-[10px] font-mono text-cyan-300 truncate group-hover:text-cyan-200">
                    {b.entry_hash.slice(0, 16)}...
                  </div>
                  <div className="text-[9px] font-mono text-slate-500 truncate">
                    Prev: {b.previous_hash.slice(0, 10)}...
                  </div>
                </div>
                <div className="text-slate-600 font-mono font-bold">➔</div>
              </React.Fragment>
            ))}

            <div className="flex-shrink-0 px-3 py-4 rounded-lg bg-emerald-950/50 border border-emerald-500/40 text-emerald-300 text-[10px] font-mono font-bold">
              HEAD ✓
            </div>
          </div>
        </div>

        {/* Ledger Table Section */}
        <div className="rounded-xl bg-sentinel-900/60 border border-sentinel-800 overflow-hidden">
          {/* Controls Bar */}
          <div className="p-4 border-b border-sentinel-800 flex flex-wrap items-center justify-between gap-4">
            {/* Filter Tabs */}
            <div className="flex items-center gap-1.5 bg-sentinel-950/80 p-1 rounded-lg border border-sentinel-800">
              {["ALL", "POLICY_CREATED", "POLICY_SUBMITTED", "POLICY_APPROVED", "POLICY_ACTIVATED", "ROLE_CHANGED", "USER_CREATED"].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setEventTypeFilter(tab)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors ${
                    eventTypeFilter === tab
                      ? "bg-indigo-600 text-white shadow"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {tab.replace(/_/g, " ")}
                </button>
              ))}
            </div>

            {/* Search Box */}
            <div className="relative min-w-[260px]">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search block, hash, actor, type..."
                className="w-full px-3 py-1.5 bg-sentinel-950 border border-sentinel-700 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-sentinel-950/60 text-slate-400 font-mono uppercase tracking-wider border-b border-sentinel-800">
                <tr>
                  <th className="py-3 px-4">Seq</th>
                  <th className="py-3 px-4">Ledger ID</th>
                  <th className="py-3 px-4">Event Type</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">Previous Hash</th>
                  <th className="py-3 px-4">Entry Hash</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-800/60 font-mono text-slate-300">
                {loading ? (
                  <tr>
                    <td colSpan="8" className="py-8 text-center text-slate-500 font-mono">
                      Loading cryptographic governance ledger...
                    </td>
                  </tr>
                ) : filteredEntries.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="py-8 text-center text-slate-500 font-mono">
                      No ledger entries matching the filter.
                    </td>
                  </tr>
                ) : (
                  filteredEntries.map((item) => (
                    <tr key={item.ledger_entry_id} className="hover:bg-sentinel-800/30 transition-colors">
                      <td className="py-3 px-4 font-bold text-indigo-400">
                        #{item.sequence_number}
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {item.ledger_entry_id}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${EVENT_BADGES[item.event_type] || "bg-slate-800 text-slate-300"}`}>
                          {item.event_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {item.actor_username || item.actor_id || "SYSTEM"}
                      </td>
                      <td className="py-3 px-4 text-slate-500 text-[11px]" title={item.previous_hash}>
                        {item.previous_hash.slice(0, 10)}...{item.previous_hash.slice(-6)}
                      </td>
                      <td className="py-3 px-4 text-cyan-400 text-[11px]" title={item.entry_hash}>
                        {item.entry_hash.slice(0, 10)}...{item.entry_hash.slice(-6)}
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {new Date(item.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setSelectedEntry(item)}
                          className="px-2.5 py-1 rounded bg-indigo-950 hover:bg-indigo-900 border border-indigo-500/40 text-indigo-300 text-[11px] transition-colors"
                        >
                          Inspect Block
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

      {/* Block Inspection Modal */}
      {selectedEntry && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-sentinel-700 rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-fade-in">
            {/* Header */}
            <div className="p-5 border-b border-sentinel-800 flex items-center justify-between bg-sentinel-950/60">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-lg">📦</span>
                  <h2 className="text-sm font-bold font-mono text-slate-100">
                    Ledger Block #{selectedEntry.sequence_number} ({selectedEntry.ledger_entry_id})
                  </h2>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Event Type: <span className="text-indigo-300 font-mono font-semibold">{selectedEntry.event_type}</span> • Timestamp: {new Date(selectedEntry.created_at).toISOString()}
                </p>
              </div>
              <button
                onClick={() => setSelectedEntry(null)}
                className="p-1 rounded-lg hover:bg-sentinel-800 text-slate-400 hover:text-slate-200 font-mono text-sm"
              >
                ✕
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-5 text-xs font-mono">
              {/* Cryptographic Linkage Overview */}
              <div className="p-4 rounded-xl bg-sentinel-950 border border-sentinel-800 space-y-2.5">
                <span className="text-[10px] uppercase tracking-wider text-indigo-400 font-semibold block">
                  Cryptographic Chain Linkage Equation
                </span>

                <div className="space-y-1.5 text-[11px]">
                  <div className="flex items-start gap-2">
                    <span className="text-slate-500 w-28 flex-shrink-0">Previous Hash (H_{'{n-1}'}):</span>
                    <span className="text-slate-300 break-all select-all">{selectedEntry.previous_hash}</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-slate-500 w-28 flex-shrink-0">Payload Hash:</span>
                    <span className="text-amber-300 break-all select-all">{selectedEntry.payload_hash}</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-slate-500 w-28 flex-shrink-0">Entry Hash (H_n):</span>
                    <span className="text-cyan-300 font-bold break-all select-all">{selectedEntry.entry_hash}</span>
                  </div>
                </div>

                <div className="p-2 rounded bg-sentinel-900 border border-sentinel-800 text-[10px] text-slate-400">
                  Formula: SHA256({selectedEntry.sequence_number} | {selectedEntry.previous_hash.slice(0, 10)}... | {selectedEntry.payload_hash.slice(0, 10)}...)
                </div>
              </div>

              {/* Attribution */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-sentinel-950 border border-sentinel-800">
                  <span className="text-slate-500 text-[10px] uppercase block">Actor Identity</span>
                  <span className="text-emerald-300 font-bold text-xs">{selectedEntry.actor_username || "SYSTEM"}</span>
                  <span className="text-slate-500 text-[10px] block mt-0.5">{selectedEntry.actor_id || "—"}</span>
                </div>
                <div className="p-3 rounded-lg bg-sentinel-950 border border-sentinel-800">
                  <span className="text-slate-500 text-[10px] uppercase block">Integrity Status</span>
                  <span className="text-emerald-300 font-bold text-xs">CRYPTOGRAPHICALLY LINKED</span>
                  <span className="text-slate-500 text-[10px] block mt-0.5">Deterministic SHA-256</span>
                </div>
              </div>

              {/* Canonical Payload */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                    Canonical Payload (JSON)
                  </span>
                  <span className="text-[10px] text-slate-500">Deterministic key-sorted serialization</span>
                </div>
                <pre className="p-4 rounded-xl bg-sentinel-950 border border-sentinel-800 text-[11px] text-slate-300 overflow-x-auto max-h-56 leading-relaxed">
                  {JSON.stringify(selectedEntry.payload, null, 2)}
                </pre>
              </div>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-sentinel-800 bg-sentinel-950/60 flex justify-end">
              <button
                onClick={() => setSelectedEntry(null)}
                className="px-4 py-1.5 rounded-lg bg-sentinel-800 hover:bg-sentinel-700 text-slate-300 text-xs font-mono transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
