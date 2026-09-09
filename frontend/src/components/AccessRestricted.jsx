/**
 * components/AccessRestricted.jsx
 * ------------------------------
 * Professional 403 Access Denied UX component with detailed permission context.
 *
 * Sprint 4A — Identity & Role-Based Access Control (RBAC).
 */

import React from "react";
import { useAuth } from "../context/AuthContext";

export default function AccessRestricted({ requiredPermission, requiredRole, actionName }) {
  const { user } = useAuth();

  return (
    <div className="flex-1 flex items-center justify-center p-8 bg-sentinel-950">
      <div className="max-w-md w-full bg-sentinel-900/90 border border-red-500/30 rounded-2xl p-8 backdrop-blur-xl shadow-2xl text-center space-y-6 animate-fade-in relative overflow-hidden">
        {/* Glow effect */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-48 h-1 bg-gradient-to-r from-transparent via-red-500 to-transparent" />
        <div className="absolute -top-12 -left-12 w-32 h-32 bg-red-500/10 rounded-full blur-2xl pointer-events-none" />

        {/* Shield Icon */}
        <div className="w-16 h-16 mx-auto rounded-2xl bg-red-950/60 border border-red-500/40 flex items-center justify-center text-3xl shadow-inner text-red-400">
          🛡️
        </div>

        {/* Header */}
        <div className="space-y-2">
          <span className="inline-block px-3 py-1 rounded-full text-[11px] font-mono font-semibold tracking-wider uppercase bg-red-500/10 text-red-400 border border-red-500/30">
            HTTP 403 Forbidden
          </span>
          <h2 className="text-2xl font-bold text-white tracking-wide">
            ACCESS RESTRICTED
          </h2>
          <p className="text-slate-400 text-sm leading-relaxed">
            You do not have the required permissions to perform {actionName ? `"${actionName}"` : "this action"}.
          </p>
        </div>

        {/* Context Breakdown */}
        <div className="bg-sentinel-950/70 border border-white/5 rounded-xl p-4 text-left space-y-3 font-mono text-xs">
          <div className="flex justify-between items-center py-1 border-b border-white/5">
            <span className="text-slate-500">Current Role:</span>
            <span className="font-semibold text-accent-cyan bg-accent-cyan/10 px-2 py-0.5 rounded border border-accent-cyan/20">
              {user?.role || "ANONYMOUS"}
            </span>
          </div>
          {requiredPermission && (
            <div className="flex justify-between items-center py-1 border-b border-white/5">
              <span className="text-slate-500">Required Permission:</span>
              <span className="font-semibold text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-500/20">
                {requiredPermission}
              </span>
            </div>
          )}
          {requiredRole && (
            <div className="flex justify-between items-center py-1">
              <span className="text-slate-500">Required Role:</span>
              <span className="font-semibold text-amber-400 bg-amber-950/40 px-2 py-0.5 rounded border border-amber-500/20">
                {requiredRole}
              </span>
            </div>
          )}
        </div>

        <p className="text-[11px] text-slate-500 leading-tight">
          If you believe this is in error, contact your SentinelTrace System Administrator for role adjustment.
        </p>
      </div>
    </div>
  );
}
