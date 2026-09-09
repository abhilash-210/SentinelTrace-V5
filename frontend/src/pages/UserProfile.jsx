/**
 * pages/UserProfile.jsx
 * ---------------------
 * Authenticated User Identity Profile & Security Governance View.
 *
 * Sprint 4A — Identity & Role-Based Access Control (RBAC).
 */

import React from "react";
import { useAuth } from "../context/AuthContext";

export default function UserProfile({ onNavigate }) {
  const { user, permissions } = useAuth();

  if (!user) {
    return (
      <main className="flex-1 p-8 flex items-center justify-center">
        <p className="text-slate-400 font-mono">No authenticated identity active.</p>
      </main>
    );
  }

  const roleColors = {
    ADMIN: "bg-purple-950/70 border-purple-500/60 text-purple-300",
    SECURITY_ANALYST: "bg-cyan-950/70 border-cyan-500/60 text-cyan-300",
    POLICY_AUTHOR: "bg-emerald-950/70 border-emerald-500/60 text-emerald-300",
    POLICY_REVIEWER: "bg-indigo-950/70 border-indigo-500/60 text-indigo-300",
    AUDITOR: "bg-amber-950/70 border-amber-500/60 text-amber-300",
    VIEWER: "bg-slate-900 border-slate-700 text-slate-300",
  };

  return (
    <main className="flex-1 overflow-y-auto p-8 space-y-8 bg-sentinel-950">
      
      {/* ── Page Header ─────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-white/10 pb-6">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <span className="text-2xl">👤</span>
            <h1 className="text-2xl font-bold tracking-tight text-white font-mono">
              Identity Profile & Governance Scope
            </h1>
          </div>
          <p className="text-sm text-slate-400">
            Authenticated identity context, granted RBAC capabilities, and security boundaries.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span
            className={`px-3 py-1.5 rounded-xl border text-xs font-mono font-bold uppercase tracking-wider ${
              roleColors[user.role] || "border-white/20 text-white"
            }`}
          >
            Role: {user.role}
          </span>
          <span className="px-3 py-1.5 rounded-xl border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 text-xs font-mono font-semibold flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            {user.is_active ? "ACCOUNT ACTIVE" : "DEACTIVATED"}
          </span>
        </div>
      </div>

      {/* ── Identity Card Grid ───────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* User Card */}
        <div className="bg-sentinel-900/80 border border-white/10 rounded-2xl p-6 backdrop-blur-xl space-y-6 shadow-lg">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-accent-cyan/20 to-accent-blue/20 border border-accent-cyan/40 flex items-center justify-center text-2xl font-bold text-accent-cyan font-mono shadow-inner">
              {user.username.substring(0, 2).toUpperCase()}
            </div>
            <div className="space-y-0.5">
              <h2 className="text-lg font-bold text-white leading-tight">
                {user.full_name}
              </h2>
              <p className="text-xs text-accent-cyan font-mono">@{user.username}</p>
              <p className="text-xs text-slate-400">{user.email}</p>
            </div>
          </div>

          <div className="pt-4 border-t border-white/5 space-y-3 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-white/5">
              <span className="text-slate-500">User Identifier:</span>
              <span className="text-slate-300 font-semibold">{user.user_id}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-white/5">
              <span className="text-slate-500">Account Status:</span>
              <span className="text-emerald-400">
                {user.is_active ? "Active / Verified" : "Suspended"}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-white/5">
              <span className="text-slate-500">Created Timestamp:</span>
              <span className="text-slate-300">
                {user.created_at ? new Date(user.created_at).toLocaleString() : "Pre-seeded Initial"}
              </span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-500">Last Login:</span>
              <span className="text-accent-cyan">
                {user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "Active Session"}
              </span>
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-sentinel-950/80 border border-white/5 text-[11px] text-slate-400 space-y-1">
            <p className="font-semibold text-slate-300">🔒 Zero Trust Self-Elevation Guard</p>
            <p className="text-slate-500 leading-tight">
              Users cannot alter their own RBAC roles or assign higher privileges. Role assignment requires administrative governance.
            </p>
          </div>
        </div>

        {/* Permissions & Capabilities */}
        <div className="lg:col-span-2 bg-sentinel-900/80 border border-white/10 rounded-2xl p-6 backdrop-blur-xl space-y-6 shadow-lg">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="space-y-0.5">
              <h3 className="text-base font-bold text-white font-mono">
                Granted RBAC Permissions
              </h3>
              <p className="text-xs text-slate-400">
                Decentralized capabilities evaluated per API transaction against the system role matrix.
              </p>
            </div>
            <span className="text-xs font-mono px-3 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-300">
              {permissions.length} Grants Active
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {permissions.map((perm) => (
              <div
                key={perm}
                className="p-3 rounded-xl bg-sentinel-950/70 border border-white/5 flex items-center justify-between gap-2"
              >
                <div className="space-y-0.5 truncate">
                  <p className="text-xs font-mono font-bold text-accent-cyan truncate">
                    {perm}
                  </p>
                  <p className="text-[10px] text-slate-500 truncate">
                    Verified by JWT Authorization token
                  </p>
                </div>
                <span className="text-emerald-400 text-xs shrink-0 font-mono">✓ ALLOWED</span>
              </div>
            ))}
          </div>

          {permissions.length === 0 && (
            <p className="text-xs text-slate-500 font-mono text-center py-6">
              No specific action permissions granted for this role.
            </p>
          )}

          <div className="p-4 rounded-xl bg-accent-cyan/5 border border-accent-cyan/20 text-xs text-slate-300 flex items-start gap-3">
            <span className="text-lg">🛡️</span>
            <div>
              <p className="font-semibold text-accent-cyan font-mono">
                Cryptographic Attribution (WHO · WHAT · WHEN)
              </p>
              <p className="text-slate-400 text-[11px] mt-0.5 leading-relaxed">
                Every mutation in SentinelTrace binds user identity <code className="text-accent-cyan">{user.username}</code> ({user.user_id}) and role <code className="text-accent-cyan">{user.role}</code> to the operational audit log.
              </p>
            </div>
          </div>
        </div>

      </div>

    </main>
  );
}
