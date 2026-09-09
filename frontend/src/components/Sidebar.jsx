/**
 * components/Sidebar.jsx
 * ----------------------
 * Role-aware primary navigation sidebar for SENTINEL-TRACE.
 *
 * Sprint 4A — Identity & Role-Based Access Control (RBAC).
 */

import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";

const ALL_NAV_ITEMS = [
  {
    id: "dashboard",
    label: "Dashboard",
    icon: "⬡",
    sprint: 0,
    description: "System overview",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "evidence-vault",
    label: "Evidence Vault",
    icon: "🔒",
    sprint: 1,
    description: "Raw log preservation & verification",
    roles: ["ADMIN", "SECURITY_ANALYST", "AUDITOR"],
  },
  {
    id: "log-ingestion",
    label: "Log Ingestion",
    icon: "📥",
    sprint: 1,
    description: "Multi-format ingest",
    roles: ["ADMIN", "SECURITY_ANALYST"],
  },
  {
    id: "normalization",
    label: "Normalization",
    icon: "⚙",
    sprint: 2,
    description: "OCSF canonical alignment & parsing",
    roles: ["ADMIN", "SECURITY_ANALYST", "AUDITOR"],
  },
  {
    id: "semantic-policies",
    label: "Semantic Policies",
    icon: "📋",
    sprint: 3,
    description: "Policy registry & versioning",
    roles: ["ADMIN", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR"],
  },
  {
    id: "semantic-intelligence",
    label: "Semantic Intelligence",
    icon: "🧠",
    sprint: 3,
    description: "Interpretation & drift detection",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_REVIEWER", "AUDITOR"],
  },
  {
    id: "users",
    label: "User Management",
    icon: "👥",
    sprint: 4,
    description: "Identity & RBAC governance",
    roles: ["ADMIN"],
  },
  {
    id: "approvals",
    label: "Policy Governance",
    icon: "⚖️",
    sprint: 4,
    description: "Dual-control maker-checker workflow (Sprint 4B)",
    roles: ["ADMIN", "POLICY_REVIEWER", "POLICY_AUTHOR", "AUDITOR"],
  },
  {
    id: "cryptographic-ledger",
    label: "Cryptographic Ledger",
    icon: "⛓",
    sprint: 5,
    description: "Hash-chained audit trail (Sprint 5A)",
    roles: ["ADMIN", "AUDITOR", "SECURITY_ANALYST", "POLICY_REVIEWER", "POLICY_AUTHOR"],
  },
  {
    id: "merkle-audit",
    label: "Merkle Audit",
    icon: "🌲",
    sprint: 5,
    description: "Merkle proofs & auditor verification (Sprint 5B)",
    roles: ["ADMIN", "AUDITOR", "SECURITY_ANALYST", "POLICY_REVIEWER", "POLICY_AUTHOR", "VIEWER"],
  },
  {
    id: "detection-rules",
    label: "Detection Rules",
    icon: "🎯",
    sprint: 6,
    description: "Detection rule registry & field dependencies (Sprint 6A)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "detection-trust",
    label: "Detection Trust",
    icon: "🛡️",
    sprint: 6,
    description: "Rule trust evaluation & semantic drift binding (Sprint 6B)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "detection-rule-governance",
    label: "Rule Governance",
    icon: "🏛️",
    sprint: 6,
    description: "Dual-control approval, versioning & audit (Sprint 6C)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "detection-execution",
    label: "Rule Execution",
    icon: "⚡",
    sprint: 7,
    description: "Real-time deterministic rule execution engine (Sprint 7A)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "risk-remediation",
    label: "Risk & Remediation",
    icon: "🛡️",
    sprint: 7,
    description: "Risk correlation, concentration & prioritized remediation (Sprint 7B)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "incidents",
    label: "Security Incidents",
    icon: "🚨",
    sprint: 8,
    description: "Incident correlation, evidence linking & investigation workspace (Sprint 8A)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "incident-response",
    label: "Incident Response",
    icon: "🛑",
    sprint: 8,
    description: "Containment decision engine, maker-checker authorization & response verification (Sprint 8B)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "security-assurance",
    label: "Security Assurance",
    icon: "💎",
    sprint: 9,
    description: "Continuous security assurance & platform health intelligence (Sprint 9A)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "assurance-remediation",
    label: "Assurance Recovery",
    icon: "🔄",
    sprint: 9,
    description: "Continuous assurance governance, remediation & recovery verification (Sprint 9B)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "executive-security",
    label: "Executive Command",
    icon: "👑",
    sprint: 10,
    description: "Unified security intelligence & executive risk posture command center (Sprint 10A)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "security-scenarios",
    label: "Scenario Replay",
    icon: "🎬",
    sprint: 10,
    description: "End-to-end security scenario orchestration & cross-domain evidence replay (Sprint 10B)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "compliance-intelligence",
    label: "Compliance SOC",
    icon: "⚖️",
    sprint: 11,
    description: "Compliance intelligence, security control governance & evidence-backed assurance (Sprint 11A)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "threat-intelligence",
    label: "Threat Intelligence",
    icon: "🌐",
    sprint: 11,
    description: "Threat feeds, IOC normalization, trust scoring, adversary context & event correlation (Sprint 11B)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "investigations",
    label: "SOC Investigations",
    icon: "🔍",
    sprint: 12,
    description: "Unified SOC case management, cross-domain evidence binding & maker-checker governance (Sprint 12A)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "security-analytics",
    label: "Security Analytics",
    icon: "📈",
    sprint: 12,
    description: "Cross-domain security analytics, reporting, evidence packages & 17-stage provenance (Sprint 12B)",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
  {
    id: "alerts",
    label: "Drift & Security Alerts",
    icon: "🔔",
    sprint: 3,
    description: "Semantic drift & risk alerts",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_REVIEWER", "AUDITOR"],
  },
  {
    id: "system-health",
    label: "System Health",
    icon: "📊",
    sprint: 0,
    description: "Infrastructure status",
    roles: ["ADMIN", "SECURITY_ANALYST", "POLICY_AUTHOR", "POLICY_REVIEWER", "AUDITOR", "VIEWER"],
  },
];

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
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);

  // Filter navigation items by active user role
  const userRole = user?.role || "VIEWER";
  const visibleNavItems = ALL_NAV_ITEMS.filter(
    (item) => !item.roles || item.roles.includes(userRole)
  );

  return (
    <aside className="w-64 flex-shrink-0 flex flex-col bg-sentinel-900/80 border-r border-white/10 backdrop-blur-md relative z-20">

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
            <p className="text-[10px] text-slate-500 mt-0.5">v1.0.0 · Sprint 10B Live</p>
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

      {/* ── Navigation ───────────────────────────────────── */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-0.5">
        {visibleNavItems.map((item) => {
          const isActive = activePage === item.id;
          const isDisabled = item.sprint > 10;

          return (
            <button
              key={item.id}
              onClick={() => !isDisabled && onNavigate(item.id)}
              title={isDisabled ? `Planned for future sprint (${item.sprint})` : item.description}
              className={[
                "nav-link w-full text-left group flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-mono transition cursor-pointer",
                isActive ? "bg-accent-cyan/15 text-accent-cyan font-bold border border-accent-cyan/30" : "text-slate-400 hover:text-white hover:bg-white/5",
                isDisabled ? "opacity-40 cursor-not-allowed hover:bg-transparent hover:text-slate-400" : "",
              ].join(" ")}
            >
              <span className="text-base w-5 text-center leading-none">{item.icon}</span>
              <span className="flex-1 truncate">{item.label}</span>
              {isDisabled ? (
                <span className="text-[9px] font-mono text-slate-600 bg-slate-800/60 border border-slate-700 px-1.5 py-0.5 rounded">
                  S{item.sprint}
                </span>
              ) : item.sprint > 0 ? (
                <span className="text-[9px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-1.5 py-0.5 rounded">
                  LIVE
                </span>
              ) : null}
            </button>
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
          SENTINEL-TRACE · SIH 2026<br />
          Identity & RBAC Governance Active
        </p>
      </div>
    </aside>
  );
}
