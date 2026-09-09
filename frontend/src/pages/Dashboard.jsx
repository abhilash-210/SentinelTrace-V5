/**
 * Dashboard.jsx
 * -------------
 * Main dashboard page for SENTINEL-TRACE.
 *
 * Sprint 0: UI shell only — no backend calls.
 * Sprint 1+ will wire up live data from the API.
 */

import StatusCard from "../components/StatusCard";

const PILLARS = [
  {
    number: "01",
    title: "Evidence Integrity",
    description:
      "Every raw log is SHA-256 hashed and stored immutably before any transformation. The original evidence is never mutated.",
    icon: "🔒",
    color: "accent-cyan",
  },
  {
    number: "02",
    title: "Interpretation Governance",
    description:
      "Changes to how log fields are interpreted require versioned semantic policies with dual-control human approval workflows.",
    icon: "📋",
    color: "accent-purple",
  },
  {
    number: "03",
    title: "Semantic Trust Propagation",
    description:
      "When a semantic policy changes, the platform automatically identifies and flags all affected detection rules for re-validation.",
    icon: "🕸",
    color: "accent-green",
  },
];

const SYSTEM_CARDS = [
  {
    title: "Evidence Vault",
    description: "Immutable raw log store with SHA-256 integrity proofs.",
    icon: "🔒",
    status: "future",
    sprint: 1,
  },
  {
    title: "Semantic Policies",
    description: "Active field interpretation registry and versioning.",
    icon: "📋",
    status: "future",
    sprint: 3,
  },
  {
    title: "Active Interpretations",
    description: "Currently approved semantic mappings in effect.",
    icon: "⚡",
    status: "future",
    sprint: 3,
  },
  {
    title: "Detection Rules",
    description: "STIG-bound detection rules and impact analysis.",
    icon: "🛡",
    status: "future",
    sprint: 7,
  },
  {
    title: "System Status",
    description: "Backend API and database connectivity.",
    icon: "📊",
    status: "online",
    value: "Sprint 0",
  },
];

export default function Dashboard() {
  return (
    <main className="flex-1 overflow-y-auto">
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-10 animate-fade-in">

        {/* ── Hero Section ─────────────────────────────────── */}
        <section className="text-center space-y-4 pt-6">
          {/* Glowing badge */}
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full
                          border border-accent-cyan/30 bg-accent-cyan/5 text-xs
                          text-accent-cyan font-mono tracking-widest uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-pulse" />
            Sprint 0 · Project Foundation
          </div>

          {/* Title */}
          <h1 className="text-5xl font-extrabold tracking-tight">
            <span className="text-neon-cyan">SENTINEL</span>
            <span className="text-slate-300">-TRACE</span>
          </h1>

          {/* Subtitle */}
          <p className="text-slate-400 text-lg font-light leading-relaxed max-w-2xl mx-auto">
            Verifiable Security Log Normalization
            <br />
            &amp; Semantic Trust Governance Platform
          </p>

          {/* Divider */}
          <div className="flex items-center justify-center gap-3 pt-2">
            <div className="h-px w-20 bg-gradient-to-r from-transparent to-accent-cyan/40" />
            <span className="text-accent-cyan/60 text-xs font-mono">SIH 2026</span>
            <div className="h-px w-20 bg-gradient-to-l from-transparent to-accent-cyan/40" />
          </div>
        </section>

        {/* ── Architecture Pillars ─────────────────────────── */}
        <section>
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-4">
            Architecture Pillars
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {PILLARS.map((pillar) => (
              <div
                key={pillar.number}
                className="glass-card p-5 border-white/10 hover:border-accent-cyan/20
                           transition-all duration-300 hover:-translate-y-1
                           hover:shadow-lg hover:shadow-accent-cyan/5 group"
              >
                <div className="flex items-start gap-4">
                  <div className="text-2xl mt-0.5">{pillar.icon}</div>
                  <div>
                    <p className="text-[10px] font-mono text-accent-cyan/60 mb-1">
                      PILLAR {pillar.number}
                    </p>
                    <h3 className="text-sm font-semibold text-slate-100 mb-2">
                      {pillar.title}
                    </h3>
                    <p className="text-xs text-slate-500 leading-relaxed">
                      {pillar.description}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── System Status Cards ──────────────────────────── */}
        <section>
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-4">
            System Status
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
            {SYSTEM_CARDS.map((card) => (
              <StatusCard key={card.title} {...card} />
            ))}
          </div>
        </section>

        {/* ── Sprint Info Banner ───────────────────────────── */}
        <section>
          <div className="glass-card border-accent-amber/20 p-5">
            <div className="flex items-start gap-4">
              <span className="text-2xl">🚧</span>
              <div>
                <h3 className="text-sm font-semibold text-accent-amber mb-1">
                  Sprint 0 — Project Foundation
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  This sprint establishes the project structure, technology stack, and
                  infrastructure. Feature modules are planned for upcoming sprints.
                  All disabled navigation items are clearly marked with their target sprint number.
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {["Evidence Vault (S1)", "Log Ingestion (S1)", "OCSF Normalization (S2)",
                    "Semantic Policies (S3)", "Approvals (S4)", "Ledger (S5)",
                    "Auth (S6)", "STIG Propagation (S7)"].map((item) => (
                    <span
                      key={item}
                      className="text-[10px] font-mono px-2 py-0.5 rounded
                                 bg-slate-800 border border-slate-700 text-slate-500"
                    >
                      {item}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── Footer ───────────────────────────────────────── */}
        <footer className="text-center pt-4 pb-8">
          <p className="text-xs text-slate-700 font-mono">
            SENTINEL-TRACE v0.1.0 · Offline-First · Zero Trust · SIH 2026
          </p>
        </footer>

      </div>
    </main>
  );
}
