/**
 * pages/Login.jsx
 * ---------------
 * SentinelTrace Authentication & Sign-in Page.
 *
 * Sprint 4A — Identity & Role-Based Access Control (RBAC).
 */

import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";

const DEMO_ACCOUNTS = [
  {
    role: "ADMIN",
    title: "System Administrator",
    username: "admin_demo",
    password: "SentinelDemo!2026",
    badgeColor: "border-purple-500/40 text-purple-300 bg-purple-950/50",
    desc: "Full administrative access and user identity management.",
  },
  {
    role: "SECURITY_ANALYST",
    title: "Security Analyst",
    username: "analyst_demo",
    password: "SentinelDemo!2026",
    badgeColor: "border-cyan-500/40 text-cyan-300 bg-cyan-950/50",
    desc: "Ingests raw logs, triggers OCSF normalization, executes semantic interpretation.",
  },
  {
    role: "POLICY_AUTHOR",
    title: "Policy Author",
    username: "author_demo",
    password: "SentinelDemo!2026",
    badgeColor: "border-emerald-500/40 text-emerald-300 bg-emerald-950/50",
    desc: "Creates and edits vendor-scoped semantic policies in DRAFT state.",
  },
  {
    role: "POLICY_REVIEWER",
    title: "Governance Reviewer",
    username: "reviewer_demo",
    password: "SentinelDemo!2026",
    badgeColor: "border-indigo-500/40 text-indigo-300 bg-indigo-950/50",
    desc: "Inspects semantic policies, compares versions, monitors drift alerts.",
  },
  {
    role: "AUDITOR",
    title: "Security Auditor",
    username: "auditor_demo",
    password: "SentinelDemo!2026",
    badgeColor: "border-amber-500/40 text-amber-300 bg-amber-950/50",
    desc: "Read-only inspection of Evidence Vault, OCSF events, and full traceability audit trails.",
  },
  {
    role: "VIEWER",
    title: "Read-Only Viewer",
    username: "viewer_demo",
    password: "SentinelDemo!2026",
    badgeColor: "border-slate-500/40 text-slate-300 bg-slate-900/60",
    desc: "Dashboard metrics and general security telemetry read-only overview.",
  },
];

export default function Login({ onLoginSuccess }) {
  const { login } = useAuth();
  const [username, setUsername] = useState("analyst_demo");
  const [password, setPassword] = useState("SentinelDemo!2026");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showDemoAccounts, setShowDemoAccounts] = useState(false);

  const handleSubmit = async (e) => {
    e?.preventDefault();
    if (!username.trim() || !password) {
      setError("Please enter both username/email and password.");
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      await login(username.trim(), password);
      if (onLoginSuccess) {
        onLoginSuccess();
      }
    } catch (err) {
      setError(err.message || "Failed to authenticate. Check your credentials.");
    } finally {
      setIsLoading(false);
    }
  };

  const selectDemoAccount = (demo) => {
    setUsername(demo.username);
    setPassword(demo.password);
    setError(null);
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-sentinel-950 bg-radial-vignette p-4 md:p-8 relative overflow-hidden">
      {/* Background Cyber Grid Elements */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f29370f_1px,transparent_1px),linear-gradient(to_bottom,#1f29370f_1px,transparent_1px)] bg-[size:4rem_4rem] pointer-events-none" />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-accent-cyan/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/4 left-1/3 w-[400px] h-[250px] bg-indigo-500/10 rounded-full blur-[100px] pointer-events-none" />

      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-12 gap-8 z-10 items-center">
        
        {/* Left / Main Login Form */}
        <div className="lg:col-span-6 bg-sentinel-950/80 border border-white/10 rounded-2xl p-8 backdrop-blur-3xl shadow-[0_0_40px_rgba(0,0,0,0.8)] space-y-6 relative overflow-hidden ring-1 ring-white/5">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-accent-cyan to-transparent opacity-50" />
          <div className="absolute -top-32 -left-32 w-64 h-64 bg-accent-cyan/10 rounded-full blur-[80px] pointer-events-none" />

          {/* Logo & Branding */}
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-accent-cyan/10 border border-accent-cyan/30 shadow-inner">
                <span className="text-accent-cyan font-mono font-bold text-lg">ST</span>
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-wider text-white font-mono uppercase">
                  SENTINEL<span className="text-accent-cyan">TRACE</span>
                </h1>
                <p className="text-[10px] font-mono text-slate-400 tracking-widest uppercase">
                  Sprint 4A · Identity & RBAC
                </p>
              </div>
            </div>
            <p className="text-sm text-slate-400 pt-2 leading-relaxed">
              Verifiable Security Event Intelligence & Semantic Trust Governance
            </p>
          </div>

          {/* Error Banner */}
          {error && (
            <div className="p-3.5 rounded-xl bg-red-950/60 border border-red-500/40 text-red-300 text-xs flex items-center gap-2.5 animate-fade-in">
              <span className="text-base">⚠️</span>
              <span>{error}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300 flex items-center justify-between">
                <span>Username or Email</span>
                <span className="text-[10px] text-slate-500">Required</span>
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. analyst_demo or admin@sentineltrace.io"
                className="w-full px-4 py-2.5 bg-sentinel-950/80 border border-white/10 rounded-xl text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-cyan/50 focus:ring-1 focus:ring-accent-cyan/50 font-mono transition"
                required
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300 flex items-center justify-between">
                <span>Password</span>
                <span className="text-[10px] text-slate-500">Bcrypt Hashed</span>
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-4 py-2.5 bg-sentinel-950/80 border border-white/10 rounded-xl text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-cyan/50 focus:ring-1 focus:ring-accent-cyan/50 font-mono transition"
                required
              />
            </div>

            <button
              id="sign-in-btn"
              type="submit"
              disabled={isLoading}
              className="w-full mt-4 py-3.5 px-4 bg-gradient-to-r from-accent-cyan to-accent-blue hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-sentinel-950 font-bold font-mono text-sm rounded-xl transition-all duration-300 flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(6,182,212,0.3)] hover:shadow-[0_0_30px_rgba(6,182,212,0.6)] hover:-translate-y-0.5 cursor-pointer"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-sentinel-950 border-t-transparent rounded-full animate-spin" />
                  <span>Authenticating Identity...</span>
                </>
              ) : (
                <>
                  <span>🔐</span>
                  <span>Sign In to SentinelTrace</span>
                </>
              )}
            </button>
          </form>

          {/* Security Notice */}
          <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[11px] text-slate-500 font-mono">
            <span>TLS / JWT Verification</span>
            <span>Zero Trust Architecture</span>
          </div>
        </div>

        {/* Right / Demo Accounts Quick Selector */}
        <div className="lg:col-span-6 space-y-4">
          <div className="bg-sentinel-900/60 border border-white/10 rounded-2xl p-6 backdrop-blur-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-base">👥</span>
                <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                  <span className="text-accent-cyan">◆</span> Access Control Roles
                </h2>
              </div>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Select an identity profile to authenticate with the associated permissions. Each role enforces strict Zero Trust boundaries:
            </p>

            <div className="relative pt-1">
              <button
                type="button"
                onClick={() => setShowDemoAccounts(!showDemoAccounts)}
                className="w-full text-left p-3.5 rounded-xl border border-white/10 bg-sentinel-950/80 hover:bg-sentinel-950 hover:border-accent-cyan/50 focus:outline-none focus:border-accent-cyan/50 focus:ring-1 focus:ring-accent-cyan/50 transition flex items-center justify-between cursor-pointer"
              >
                <div className="flex flex-col gap-1.5">
                  <span className="text-sm font-semibold text-accent-cyan">
                    {DEMO_ACCOUNTS.find(a => a.username === username)?.title || "Select your role..."}
                  </span>
                  <span className="text-[10px] text-slate-500 line-clamp-1 pr-4">
                    {DEMO_ACCOUNTS.find(a => a.username === username)?.desc || "Choose an account type to view its capabilities."}
                  </span>
                </div>
                <span className="text-slate-400 shrink-0">
                  {showDemoAccounts ? "▲" : "▼"}
                </span>
              </button>

              {showDemoAccounts && (
                <div className="absolute z-50 mt-2 w-full bg-sentinel-950 border border-white/10 rounded-xl shadow-2xl overflow-hidden max-h-[320px] overflow-y-auto">
                  {DEMO_ACCOUNTS.map((acc) => {
                    const isSelected = username === acc.username;
                    return (
                      <button
                        key={acc.role}
                        type="button"
                        onClick={() => {
                          selectDemoAccount(acc);
                          setShowDemoAccounts(false);
                        }}
                        className={`w-full text-left p-3 border-b border-white/5 last:border-b-0 transition hover:bg-sentinel-900 cursor-pointer ${
                          isSelected ? "bg-accent-cyan/10" : ""
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1 mb-1">
                          <span className={`text-xs font-semibold ${isSelected ? "text-white" : "text-slate-300"}`}>
                            {acc.title}
                          </span>
                          <span
                            className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase shrink-0 ${acc.badgeColor}`}
                          >
                            {acc.role}
                          </span>
                        </div>
                        <p className="text-[10px] text-slate-500 line-clamp-2 leading-tight">
                          {acc.desc}
                        </p>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-accent-cyan/5 border border-accent-cyan/15 text-[11px] text-slate-400 font-mono space-y-1">
            <p className="text-accent-cyan font-semibold">⚡ Sprint 4A RBAC Active</p>
            <p className="text-slate-500 leading-relaxed">
              All backend endpoints enforce role-permission checks. Switching roles immediately alters accessible tabs and sensitive action permissions.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}
