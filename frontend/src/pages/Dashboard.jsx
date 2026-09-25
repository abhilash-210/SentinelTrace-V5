import React, { useState, useEffect } from "react";
import StatusCard from "../components/StatusCard";

export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState({
    received: 0,
    parsed: 0,
    normalized: 0,
    quarantined: 0,
    replayed: 0,
    forwarded: 0,
    recent_events: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const token = localStorage.getItem("sentinel_token");
        const res = await fetch("http://localhost:8000/api/v1/events/pipeline-stats", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) {
          throw new Error("Failed to fetch pipeline stats");
        }
        const data = await res.json();
        setStats(data);
        setError(null);
      } catch (err) {
        console.error(err);
        setError("Backend unreachable or unauthorized.");
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 3000); // Auto-refresh every 3s
    return () => clearInterval(interval);
  }, []);

  return (
    <main className="flex-1 overflow-y-auto bg-slate-950 text-slate-200">
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-10 animate-fade-in">
        {/* ── Hero Section ─────────────────────────────────── */}
        <section className="text-center space-y-4 pt-6">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-accent-cyan/30 bg-accent-cyan/5 text-xs text-accent-cyan font-mono tracking-widest uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-pulse" />
            Production Engine · Live ULPF Dashboard
          </div>
          <h1 className="text-5xl font-extrabold tracking-tight">
            <span className="text-neon-cyan">SENTINEL</span>
            <span className="text-slate-300">-TRACE</span>
          </h1>
          <p className="text-slate-400 text-lg font-light leading-relaxed max-w-2xl mx-auto">
            Universal Log Pre-processing Framework (ULPF)
          </p>
        </section>

        {error && (
          <div className="p-4 bg-red-900/50 border border-red-500/50 rounded-lg text-red-200 text-sm">
            {error}
          </div>
        )}

        {/* ── LIVE ULPF PIPELINE STATS ───────────────────── */}
        <section>
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-4">
            LIVE ULPF PIPELINE
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <StatCard label="Received" value={stats.received} color="text-blue-400" />
            <StatCard label="Parsed" value={stats.parsed} color="text-indigo-400" />
            <StatCard label="Normalized" value={stats.normalized} color="text-green-400" />
            <StatCard label="Quarantined" value={stats.quarantined} color="text-red-400" />
            <StatCard label="Replayed" value={stats.replayed} color="text-yellow-400" />
            <StatCard label="Forwarded" value={stats.forwarded} color="text-accent-cyan" />
          </div>
        </section>

        {/* ── RECENT EVENTS TABLE ───────────────────────── */}
        <section>
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-4">
            RECENT EVENTS
          </h2>
          <div className="glass-card border-white/10 overflow-hidden">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-900/50 text-slate-400 border-b border-white/5">
                <tr>
                  <th className="px-6 py-3 font-semibold">Time</th>
                  <th className="px-6 py-3 font-semibold">Source</th>
                  <th className="px-6 py-3 font-semibold">Format</th>
                  <th className="px-6 py-3 font-semibold">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {stats.recent_events.length > 0 ? (
                  stats.recent_events.map((evt, idx) => (
                    <tr
                      key={idx}
                      className="hover:bg-slate-800/30 transition-colors cursor-pointer"
                      onClick={() => {
                        if (evt.status === "QUARANTINED" || evt.status === "FAILED") {
                          onNavigate("quarantine");
                        } else {
                          onNavigate("normalization");
                        }
                      }}
                    >
                      <td className="px-6 py-4 font-mono text-xs text-slate-300">{evt.time}</td>
                      <td className="px-6 py-4 text-slate-200">{evt.source}</td>
                      <td className="px-6 py-4 font-mono text-xs text-slate-400">{evt.format}</td>
                      <td className="px-6 py-4">
                        <StatusBadge status={evt.status} />
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="4" className="px-6 py-8 text-center text-slate-500">
                      {loading ? "Loading live telemetry..." : "No events processed yet."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <footer className="text-center pt-4 pb-8">
          <p className="text-xs text-slate-500 font-mono">
            SENTINEL-TRACE v1.0.0 · Auto-refresh active
          </p>
        </footer>
      </div>
    </main>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div className="glass-card p-4 border-white/10 hover:border-white/20 transition-all text-center flex flex-col justify-center items-center h-24 rounded-lg bg-slate-900/60 shadow-lg">
      <div className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-2">
        {label}
      </div>
      <div className={`text-3xl font-bold font-mono ${color}`}>
        {value.toLocaleString()}
      </div>
    </div>
  );
}

function StatusBadge({ status }) {
  let bg = "bg-slate-500/10 border-slate-500/20 text-slate-400";
  if (status === "NORMALIZED") bg = "bg-green-500/10 border-green-500/20 text-green-400";
  if (status === "QUARANTINED" || status === "FAILED") bg = "bg-red-500/10 border-red-500/20 text-red-400";
  if (status === "PARTIAL") bg = "bg-yellow-500/10 border-yellow-500/20 text-yellow-400";
  if (status === "FORWARDED") bg = "bg-blue-500/10 border-blue-500/20 text-blue-400";

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono border ${bg}`}>
      {status}
    </span>
  );
}
