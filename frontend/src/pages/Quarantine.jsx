/**
 * Quarantine.jsx
 * --------------
 * Dead Letter Queue (DLQ) / Quarantine Dashboard
 */

import { useState, useEffect, useCallback } from "react";

import { API_BASE_URL, getAuthHeaders } from "../apiConfig";

const API_BASE = API_BASE_URL;

export default function Quarantine() {
  const [quarantinedEvents, setQuarantinedEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Modal State
  const [inspectModalOpen, setInspectModalOpen] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [replayHistory, setReplayHistory] = useState([]);
  const [replaying, setReplaying] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/quarantine?status=QUARANTINED&limit=100`, {
        headers: { ...getAuthHeaders() },
      });
      if (res.ok) {
        const data = await res.json();
        setQuarantinedEvents(data.items || []);
      }
    } catch (err) {
      setError("Failed to load quarantined events");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleInspect = async (evt) => {
    setSelectedEvent(evt);
    setReplayHistory([]);
    setInspectModalOpen(true);
    
    // Fetch history
    try {
      const res = await fetch(`${API_BASE}/api/v1/quarantine/${evt.quarantine_id}/history`, {
        headers: { ...getAuthHeaders() },
      });
      if (res.ok) {
        const data = await res.json();
        setReplayHistory(data || []);
      }
    } catch (err) {
      console.error("Failed to load replay history", err);
    }
  };

  const handleReplay = async () => {
    if (!selectedEvent) return;
    setReplaying(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/quarantine/${selectedEvent.quarantine_id}/replay`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders(),
        },
        body: JSON.stringify({})
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Replay failed");
      }
      setSuccessMsg("Event replayed successfully");
      setInspectModalOpen(false);
      fetchData();
    } catch (err) {
      setError(err.message);
    } finally {
      setReplaying(false);
    }
  };

  return (
    <main className="flex-1 overflow-y-auto">
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-white/10 pb-6">
          <div>
            <h1 className="text-3xl font-extrabold tracking-tight text-slate-100">
              Quarantine / Dead Letter Queue (DLQ)
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Inspect and replay raw logs that failed parsing or validation.
            </p>
          </div>
          <button
            onClick={fetchData}
            disabled={loading}
            className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 text-xs font-mono flex items-center gap-2"
          >
            <span className={loading ? "animate-spin" : ""}>🔄</span> Refresh
          </button>
        </div>

        {/* Notifications */}
        {successMsg && (
          <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex justify-between">
            <span>✓ {successMsg}</span>
            <button onClick={() => setSuccessMsg(null)}>✕</button>
          </div>
        )}
        {error && (
          <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs font-mono flex justify-between">
            <span>⚠ {error}</span>
            <button onClick={() => setError(null)}>✕</button>
          </div>
        )}

        {/* Table */}
        <div className="glass-card border-white/10 overflow-hidden space-y-4 p-5">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <th className="py-3 px-3">Quarantine ID</th>
                <th className="py-3 px-3">Source Name</th>
                <th className="py-3 px-3">Failure Reason</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 font-mono">
              {quarantinedEvents.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-8 text-center text-slate-500">
                    No quarantined events found.
                  </td>
                </tr>
              ) : (
                quarantinedEvents.map((evt) => (
                  <tr key={evt.quarantine_id} className="hover:bg-white/[0.02]">
                    <td className="py-3 px-3 text-rose-400 font-semibold">{evt.quarantine_id}</td>
                    <td className="py-3 px-3 text-slate-300">{evt.source_name}</td>
                    <td className="py-3 px-3 text-slate-400 max-w-xs truncate">{evt.failure_reason}</td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950/60 border border-rose-500/30 text-rose-400">
                        {evt.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => handleInspect(evt)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 text-[11px] text-accent-cyan"
                      >
                        Inspect & Replay ➔
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Modal */}
        {inspectModalOpen && selectedEvent && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-fade-in">
            <div className="glass-card border-white/20 w-full max-w-3xl max-h-[92vh] overflow-y-auto p-6 space-y-6">
              <div className="flex justify-between items-center border-b border-white/10 pb-4">
                <h3 className="text-lg font-bold text-slate-100">Inspect & Fix Quarantined Event</h3>
                <button onClick={() => setInspectModalOpen(false)} className="text-slate-400 hover:text-slate-200">✕ Close</button>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-slate-500 mb-1">Failure Reason</label>
                  <div className="p-3 bg-rose-950/40 border border-rose-500/30 text-rose-300 rounded text-sm font-mono">
                    {selectedEvent.failure_reason}
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-mono text-slate-500 mb-1">Raw Content (Read Only - Evidence Preservation)</label>
                  <div className="w-full h-48 overflow-y-auto bg-slate-900 border border-slate-700 rounded p-3 text-slate-300 text-sm font-mono">
                    {selectedEvent.raw_content}
                  </div>
                </div>

                {replayHistory.length > 0 && (
                  <div>
                    <label className="block text-xs font-mono text-slate-500 mb-1">Replay History</label>
                    <div className="space-y-2">
                      {replayHistory.map((op) => (
                        <div key={op.id} className="p-3 bg-slate-800/50 border border-slate-700/50 rounded flex justify-between text-xs font-mono">
                          <div>
                            <span className={op.result === 'SUCCESS' ? 'text-emerald-400' : 'text-rose-400'}>{op.result}</span>
                            <span className="text-slate-500 ml-2">({new Date(op.replayed_at).toLocaleString()})</span>
                            {op.failure_reason && <div className="text-rose-300 mt-1">{op.failure_reason}</div>}
                          </div>
                          {op.resulting_normalized_event_id && (
                            <span className="text-slate-400">→ {op.resulting_normalized_event_id}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <div className="flex justify-end gap-3 pt-4 border-t border-white/10">
                <button
                  onClick={() => setInspectModalOpen(false)}
                  className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono"
                >
                  Cancel
                </button>
                <button
                  onClick={handleReplay}
                  disabled={replaying}
                  className="px-4 py-2 rounded bg-accent-cyan hover:bg-cyan-400 text-slate-950 text-xs font-bold font-mono"
                >
                  {replaying ? "Replaying..." : "Replay Event"}
                </button>
              </div>
            </div>
          </div>
        )}

      </div>
    </main>
  );
}
