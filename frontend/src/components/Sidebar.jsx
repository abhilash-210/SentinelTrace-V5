/**
 * components/Sidebar.jsx
 * ----------------------
 * Role-aware primary navigation sidebar for SENTINEL-TRACE.
 *
 * Sprint 4A — Identity & Role-Based Access Control (RBAC).
 */

import React from "react";
import { useAuth } from "../context/AuthContext";

const NAV_GROUPS = [
  {
    group: "Overview",
    phaseNum: null,
    color: "slate",
    subtitle: "System overview",
    items: [
      {
        id: "dashboard",
        label: "Architecture Dashboard",
        icon: "⬡",
        description: "System overview & core pillars",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
    ],
  },
  {
    group: "Ingestion & Evidence",
    phaseNum: "1",
    color: "cyan",
    subtitle: "SHA-256 raw log vault",
    items: [
      {
        id: "evidence-vault",
        label: "Evidence Vault & Ingest",
        icon: "🔒",
        description: "Raw log multi-format ingestion, SHA-256 preservation & integrity verification",
        roles: ["ADMIN", "SECURITY_ANALYST", "AUDITOR"],
      },
      {
        id: "quarantine",
        label: "Quarantine (DLQ)",
        icon: "🏥",
        description: "Dead letter queue for malformed and unmapped events",
        roles: ["ADMIN", "SECURITY_ANALYST"],
      },
    ],
  },
  {
    group: "Normalization & Drift",
    phaseNum: "2",
    color: "violet",
    subtitle: "OCSF v1.1.0 alignment",
    items: [
      {
        id: "normalization",
        label: "OCSF Normalization",
        icon: "⚙",
        description: "OCSF canonical alignment & parsing",
        roles: ["ADMIN", "SECURITY_ANALYST", "AUDITOR"],
      },
      {
        id: "semantic-intelligence",
        label: "Semantic Drift Detection",
        icon: "🧠",
        description: "Interpretation & vendor drift detection",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_REVIEWER", "AUDITOR"],
      },
      {
        id: "semantic-policies",
        label: "Semantic Policies",
        icon: "📋",
        description: "Policy registry & versioning",
        roles: ["ADMIN", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR"],
      },
    ],
  },
  {
    group: "Zero-Trust Detection",
    phaseNum: "3",
    color: "amber",
    subtitle: "Telemetry trust scoring",
    items: [
      {
        id: "detection-trust",
        label: "Detection Trust Score",
        icon: "🛡️",
        description: "Rule trust evaluation & semantic drift binding",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
      {
        id: "detection-execution",
        label: "Rule Execution Engine",
        icon: "⚡",
        description: "Real-time deterministic rule execution engine",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
      {
        id: "detection-rules",
        label: "Detection Rule Catalog",
        icon: "🎯",
        description: "Detection rule registry & field dependencies",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
      {
        id: "risk-remediation",
        label: "Risk & Posture",
        icon: "📊",
        description: "Risk correlation & prioritized remediation",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
    ],
  },
  {
    group: "Cryptographic Ledger",
    phaseNum: "4",
    color: "emerald",
    subtitle: "Merkle proof & governance",
    items: [
      {
        id: "cryptographic-ledger",
        label: "Cryptographic Ledger",
        icon: "⛓",
        description: "Hash-chained audit trail",
        roles: ["ADMIN", "AUDITOR", "SECURITY_ANALYST", "POLICY_REVIEWER", "POLICY_AUTHOR"],
      },
      {
        id: "merkle-audit",
        label: "Merkle Inclusion Proofs",
        icon: "🌲",
        description: "Merkle proofs & auditor verification",
        roles: ["ADMIN", "AUDITOR", "SECURITY_ANALYST", "POLICY_REVIEWER", "POLICY_AUTHOR", "VIEWER"],
      },
      {
        id: "approvals",
        label: "Maker-Checker Approval",
        icon: "⚖️",
        description: "Dual-control approval workflow",
        roles: ["ADMIN", "POLICY_REVIEWER", "POLICY_AUTHOR", "AUDITOR"],
      },
    ],
  },
  {
    group: "SOC Operations",
    phaseNum: null,
    color: "rose",
    subtitle: "Response & compliance",
    items: [
      {
        id: "incidents",
        label: "Security Incidents",
        icon: "🚨",
        description: "Incident correlation & investigation workspace",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
      {
        id: "incident-response",
        label: "Incident Response",
        icon: "🛑",
        description: "Containment decision engine & response authorization",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
      {
        id: "executive-security",
        label: "Executive Command",
        icon: "👑",
        description: "Unified security intelligence & executive risk posture",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
      {
        id: "security-scenarios",
        label: "Scenario Replay",
        icon: "🎬",
        description: "End-to-end evidence scenario orchestration & replay",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
      {
        id: "compliance-intelligence",
        label: "Compliance Controls",
        icon: "⚖️",
        description: "Compliance intelligence & evidence-backed assurance",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
      {
        id: "security-analytics",
        label: "Provenance Analytics",
        icon: "📈",
        description: "Security analytics & cryptographic evidence packages",
        roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
      },
      {
        id: "users",
        label: "User RBAC",
        icon: "👥",
        description: "Identity & RBAC governance",
        roles: ["ADMIN"],
      },
    ],
  },
];

// Color mappings for each phase
const phaseColors = {
  cyan:    { pill: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40",    dot: "bg-cyan-400",    header: "text-cyan-300",    border: "border-l-cyan-500/60" },
  violet:  { pill: "bg-violet-500/20 text-violet-300 border-violet-500/40", dot: "bg-violet-400", header: "text-violet-300", border: "border-l-violet-500/60" },
  amber:   { pill: "bg-amber-500/20 text-amber-300 border-amber-500/40",  dot: "bg-amber-400",  header: "text-amber-300",  border: "border-l-amber-500/60" },
  emerald: { pill: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40", dot: "bg-emerald-400", header: "text-emerald-300", border: "border-l-emerald-500/60" },
  rose:    { pill: "bg-rose-500/20 text-rose-300 border-rose-500/40",    dot: "bg-rose-400",    header: "text-rose-300",    border: "border-l-rose-500/60" },
  slate:   { pill: "bg-slate-700/40 text-slate-300 border-slate-600/40", dot: "bg-slate-400",   header: "text-slate-300",   border: "border-l-slate-500/40" },
};

const roleBadgeStyles = {
  ADMIN: "bg-purple-950/70 border-purple-500/50 text-purple-300",
  SECURITY_ANALYST: "bg-cyan-950/70 border-cyan-500/50 text-cyan-300",
  POLICY_AUTHOR: "bg-emerald-950/70 border-emerald-500/50 text-emerald-300",
  POLICY_REVIEWER: "bg-indigo-950/70 border-indigo-500/50 text-indigo-300",
  AUDITOR: "bg-amber-950/70 border-amber-500/50 text-amber-300",
  VIEWER: "bg-slate-800 border-slate-600 text-slate-300",
};

export default function Sidebar({ activePage, onNavigate }) {
  const { user, logout } = useAuth();
  const userRole = user?.role || "VIEWER";

  return (
    <aside className="w-72 flex-shrink-0 flex flex-col bg-sentinel-900/80 border-r border-white/10 backdrop-blur-md relative z-20">

      {/* ── Brand Header ─────────────────────────────────── */}
      <div className="px-4 py-5 border-b border-white/10">
        <div className="flex items-center gap-3">
          {/* Logo mark */}
          <div className="relative flex items-center justify-center w-9 h-9">
            <div className="absolute inset-0 bg-accent-cyan/20 rounded-lg animate-pulse-slow" />
            <span className="relative text-accent-cyan text-lg font-bold font-mono">ST</span>
          </div>
          <div>
            <p className="text-xs font-bold text-accent-cyan tracking-[0.2em] uppercase">
              Sentinel-Trace
            </p>
            <p className="text-[10px] text-slate-400 mt-0.5">Zero-Trust SIEM Intelligence</p>
          </div>
        </div>
      </div>

      {/* ── Active Identity Bar ──────────────────────────── */}
      {user && (
        <div className="px-3 py-3 border-b border-white/5 bg-white/[0.01]">
          <div className="p-2.5 rounded-xl bg-sentinel-950/80 border border-white/5 space-y-1.5">
            <div className="flex items-center justify-between gap-1">
              <span className="text-xs font-bold text-slate-200 truncate">
                {user.full_name}
              </span>
              <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0" title="Authenticated" />
            </div>
            <div className="flex items-center justify-between gap-1">
              <span
                className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider truncate ${
                  roleBadgeStyles[user.role] || "border-slate-700 text-slate-400"
                }`}
              >
                {user.role.replace("_", " ")}
              </span>
              <span className="text-[9px] font-mono text-slate-500 truncate">
                @{user.username}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ── Navigation by Architectural Phases ───────────── */}
      <nav className="flex-1 overflow-y-auto px-2 py-2 space-y-1">
        {NAV_GROUPS.map((section) => {
          const visibleItems = section.items.filter(
            (item) => !item.roles || item.roles.includes(userRole)
          );
          if (visibleItems.length === 0) return null;

          const c = phaseColors[section.color] || phaseColors.slate;

          return (
            <div key={section.group} className="mb-1">

              {/* ── Phase Header: numbered pill + title on ONE line ── */}
              <div className="flex items-center gap-2 px-2 pt-3 pb-1.5">
                {section.phaseNum ? (
                  <span className={`text-[9px] font-mono font-black px-1.5 py-0.5 rounded border ${c.pill} shrink-0 leading-none`}>
                    P{section.phaseNum}
                  </span>
                ) : (
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-500 shrink-0" />
                )}
                <div className="min-w-0">
                  <p className={`text-[11px] font-bold font-mono uppercase tracking-wide leading-none ${c.header}`}>
                    {section.group}
                  </p>
                  <p className="text-[9px] text-slate-500 font-mono mt-0.5 leading-none truncate">
                    {section.subtitle}
                  </p>
                </div>
              </div>

              {/* ── Items in this Phase ─ left-border accent ── */}
              <div className={`ml-3 pl-3 border-l border-slate-700/60 space-y-0.5`}>
                {visibleItems.map((item) => {
                  const isActive = activePage === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => onNavigate(item.id)}
                      title={item.description}
                      className={[
                        "w-full text-left flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono transition-all cursor-pointer",
                        isActive
                          ? `bg-accent-cyan/15 text-accent-cyan font-bold border border-accent-cyan/25`
                          : "text-slate-400 hover:text-white hover:bg-white/5",
                      ].join(" ")}
                    >
                      <span className="text-xs w-4 text-center leading-none shrink-0">{item.icon}</span>
                      <span className="truncate">{item.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </nav>

      {/* ── Footer / Profile & Sign Out ───────────────────── */}
      <div className="px-4 py-3 border-t border-white/10 space-y-2 bg-sentinel-950/40">
        <div className="flex items-center justify-between text-xs font-mono">
          <button
            onClick={() => onNavigate("profile")}
            className={`px-2.5 py-1.5 rounded-lg border transition text-left flex items-center gap-1.5 cursor-pointer ${
              activePage === "profile"
                ? "bg-accent-cyan/10 border-accent-cyan/40 text-accent-cyan font-bold"
                : "bg-white/5 border-white/5 text-slate-300 hover:bg-white/10 hover:text-white"
            }`}
          >
            <span>👤</span>
            <span>My Profile</span>
          </button>

          <button
            onClick={logout}
            className="px-2.5 py-1.5 rounded-lg bg-red-950/40 hover:bg-red-900/60 border border-red-500/30 text-red-300 transition flex items-center gap-1 cursor-pointer"
            title="Sign out of current identity session"
          >
            <span>🚪</span>
            <span>Sign Out</span>
          </button>
        </div>

        <p className="text-[9px] text-slate-600 text-center leading-tight pt-1">
          SENTINEL-TRACE<br />
          Identity & RBAC Governance Active
        </p>
      </div>
    </aside>
  );
}
