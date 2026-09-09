/**
 * pages/UserManagement.jsx
 * ------------------------
 * Admin-only User & Identity Governance Interface.
 *
 * Sprint 4A — Identity & Role-Based Access Control (RBAC).
 */

import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import AccessRestricted from "../components/AccessRestricted";

const ROLES = [
  "ADMIN",
  "SECURITY_ANALYST",
  "POLICY_AUTHOR",
  "POLICY_REVIEWER",
  "AUDITOR",
  "VIEWER",
];

const roleColors = {
  ADMIN: "bg-purple-950/70 border-purple-500/60 text-purple-300",
  SECURITY_ANALYST: "bg-cyan-950/70 border-cyan-500/60 text-cyan-300",
  POLICY_AUTHOR: "bg-emerald-950/70 border-emerald-500/60 text-emerald-300",
  POLICY_REVIEWER: "bg-indigo-950/70 border-indigo-500/60 text-indigo-300",
  AUDITOR: "bg-amber-950/70 border-amber-500/60 text-amber-300",
  VIEWER: "bg-slate-900 border-slate-700 text-slate-300",
};

export default function UserManagement() {
  const { user, hasPermission, authFetch } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("ALL");

  // Create Modal State
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState({
    username: "",
    email: "",
    full_name: "",
    password: "",
    role: "SECURITY_ANALYST",
    is_active: true,
  });
  const [createError, setCreateError] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Edit Modal State
  const [editingUser, setEditingUser] = useState(null);
  const [editRole, setEditRole] = useState("");
  const [editActive, setEditActive] = useState(true);

  const fetchUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await authFetch("/api/v1/users?limit=100");
      if (!res.ok) {
        if (res.status === 403) {
          setError("ACCESS_DENIED");
          setLoading(false);
          return;
        }
        throw new Error(`Failed to load users: HTTP ${res.status}`);
      }
      const data = await res.json();
      setUsers(data.items || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  if (!hasPermission("USER_READ") && !hasPermission("USER_MANAGE")) {
    return (
      <AccessRestricted
        requiredPermission="USER_MANAGE"
        requiredRole="ADMIN"
        actionName="User & Identity Governance"
      />
    );
  }

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setCreateError(null);
    try {
      const res = await authFetch("/api/v1/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(createForm),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: "Creation failed" }));
        throw new Error(errData.detail || "Failed to create user.");
      }
      setIsCreateOpen(false);
      setCreateForm({
        username: "",
        email: "",
        full_name: "",
        password: "",
        role: "SECURITY_ANALYST",
        is_active: true,
      });
      fetchUsers();
    } catch (err) {
      setCreateError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUpdateUser = async () => {
    if (!editingUser) return;
    try {
      const res = await authFetch(`/api/v1/users/${editingUser.user_id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          role: editRole,
          is_active: editActive,
        }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: "Update failed" }));
        alert(`Error: ${errData.detail || "Could not update user"}`);
        return;
      }
      setEditingUser(null);
      fetchUsers();
    } catch (err) {
      alert(`Error updating user: ${err.message}`);
    }
  };

  const filteredUsers = users.filter((u) => {
    const matchesSearch =
      u.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.full_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.user_id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRole = roleFilter === "ALL" || u.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  return (
    <main className="flex-1 overflow-y-auto p-8 space-y-8 bg-sentinel-950">
      
      {/* ── Page Header ─────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-white/10 pb-6">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🛡️</span>
            <h1 className="text-2xl font-bold tracking-tight text-white font-mono">
              User & Identity Governance
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider bg-purple-950/80 border border-purple-500/50 text-purple-300">
              Admin Only
            </span>
          </div>
          <p className="text-sm text-slate-400">
            Manage system identities, configure RBAC role assignments, and enforce account lifecycles.
          </p>
        </div>

        {hasPermission("USER_MANAGE") && (
          <button
            onClick={() => setIsCreateOpen(true)}
            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-accent-cyan to-accent-blue text-sentinel-950 font-mono font-bold text-xs hover:opacity-90 shadow-lg shadow-accent-cyan/15 flex items-center gap-2 cursor-pointer transition"
          >
            <span>+</span>
            <span>Register New Identity</span>
          </button>
        )}
      </div>

      {/* ── Filter Bar ──────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row gap-4 justify-between items-center bg-sentinel-900/60 border border-white/10 rounded-2xl p-4 backdrop-blur-xl">
        <div className="w-full sm:w-80 relative">
          <input
            type="text"
            placeholder="Search username, email, full name, ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full px-4 py-2 bg-sentinel-950 border border-white/10 rounded-xl text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-cyan/50 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs text-slate-500 font-mono">Filter Role:</span>
          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="px-3 py-2 bg-sentinel-950 border border-white/10 rounded-xl text-xs text-slate-300 font-mono focus:outline-none focus:border-accent-cyan/50"
          >
            <option value="ALL">All Roles ({users.length})</option>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* ── Users Table ─────────────────────────────────── */}
      <div className="bg-sentinel-900/80 border border-white/10 rounded-2xl overflow-hidden backdrop-blur-xl shadow-lg">
        {loading ? (
          <div className="p-12 text-center space-y-3 font-mono text-slate-400">
            <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-xs">Loading identity registry...</p>
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs">
            No user identities match the query.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr className="border-b border-white/10 bg-white/[0.02] text-slate-400 uppercase text-[10px] tracking-wider">
                  <th className="p-4">User Identifier</th>
                  <th className="p-4">Identity</th>
                  <th className="p-4">Email</th>
                  <th className="p-4">RBAC Role</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">Created</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300">
                {filteredUsers.map((u) => (
                  <tr key={u.user_id} className="hover:bg-white/[0.02] transition">
                    <td className="p-4 font-bold text-accent-cyan">{u.user_id}</td>
                    <td className="p-4">
                      <div>
                        <p className="font-semibold text-white">{u.full_name}</p>
                        <p className="text-[10px] text-slate-500">@{u.username}</p>
                      </div>
                    </td>
                    <td className="p-4 text-slate-400">{u.email}</td>
                    <td className="p-4">
                      <span
                        className={`px-2.5 py-1 rounded-lg border text-[10px] font-bold uppercase ${
                          roleColors[u.role] || "border-white/20 text-white"
                        }`}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td className="p-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold ${
                          u.is_active
                            ? "text-emerald-400 bg-emerald-950/40 border border-emerald-500/20"
                            : "text-red-400 bg-red-950/40 border border-red-500/20"
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            u.is_active ? "bg-emerald-400" : "bg-red-400"
                          }`}
                        />
                        {u.is_active ? "ACTIVE" : "DEACTIVATED"}
                      </span>
                    </td>
                    <td className="p-4 text-[10px] text-slate-500">
                      {u.created_at ? new Date(u.created_at).toLocaleDateString() : "System Seed"}
                    </td>
                    <td className="p-4 text-right">
                      {hasPermission("USER_MANAGE") && (
                        <button
                          onClick={() => {
                            setEditingUser(u);
                            setEditRole(u.role);
                            setEditActive(u.is_active);
                          }}
                          className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-accent-cyan text-[11px] transition cursor-pointer"
                        >
                          Edit Role / Status
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Create User Modal ────────────────────────────── */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/10 rounded-2xl max-w-lg w-full p-6 space-y-5 animate-fade-in shadow-2xl">
            <div className="flex justify-between items-center border-b border-white/10 pb-3">
              <h2 className="text-base font-bold text-white font-mono flex items-center gap-2">
                <span>➕</span> Register New Identity
              </h2>
              <button
                onClick={() => setIsCreateOpen(false)}
                className="text-slate-400 hover:text-white font-mono text-sm"
              >
                ✕
              </button>
            </div>

            {createError && (
              <div className="p-3 rounded-xl bg-red-950/60 border border-red-500/40 text-red-300 text-xs font-mono">
                {createError}
              </div>
            )}

            <form onSubmit={handleCreateSubmit} className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-slate-300 block mb-1">Username</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. sec_auditor_02"
                  value={createForm.username}
                  onChange={(e) =>
                    setCreateForm({ ...createForm, username: e.target.value })
                  }
                  className="w-full px-3 py-2 bg-sentinel-950 border border-white/10 rounded-xl text-slate-200 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. John Doe"
                  value={createForm.full_name}
                  onChange={(e) =>
                    setCreateForm({ ...createForm, full_name: e.target.value })
                  }
                  className="w-full px-3 py-2 bg-sentinel-950 border border-white/10 rounded-xl text-slate-200 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="e.g. jdoe@sentineltrace.io"
                  value={createForm.email}
                  onChange={(e) =>
                    setCreateForm({ ...createForm, email: e.target.value })
                  }
                  className="w-full px-3 py-2 bg-sentinel-950 border border-white/10 rounded-xl text-slate-200 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Initial Password</label>
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={createForm.password}
                  onChange={(e) =>
                    setCreateForm({ ...createForm, password: e.target.value })
                  }
                  className="w-full px-3 py-2 bg-sentinel-950 border border-white/10 rounded-xl text-slate-200 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Assign RBAC Role</label>
                <select
                  value={createForm.role}
                  onChange={(e) =>
                    setCreateForm({ ...createForm, role: e.target.value })
                  }
                  className="w-full px-3 py-2 bg-sentinel-950 border border-white/10 rounded-xl text-slate-200 focus:outline-none focus:border-accent-cyan"
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-xl bg-accent-cyan text-sentinel-950 font-bold hover:opacity-90 disabled:opacity-50"
                >
                  {isSubmitting ? "Creating..." : "Save Identity"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Edit User Modal ──────────────────────────────── */}
      {editingUser && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-sentinel-900 border border-white/10 rounded-2xl max-w-md w-full p-6 space-y-5 animate-fade-in shadow-2xl font-mono text-xs">
            <div className="flex justify-between items-center border-b border-white/10 pb-3">
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <span>⚙️</span> Edit User: {editingUser.username}
              </h2>
              <button
                onClick={() => setEditingUser(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-slate-400 block mb-1">Assign New Role</label>
                <select
                  value={editRole}
                  onChange={(e) => setEditRole(e.target.value)}
                  className="w-full px-3 py-2 bg-sentinel-950 border border-white/10 rounded-xl text-slate-200 focus:outline-none focus:border-accent-cyan"
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Account State</label>
                <select
                  value={editActive ? "true" : "false"}
                  onChange={(e) => setEditActive(e.target.value === "true")}
                  className="w-full px-3 py-2 bg-sentinel-950 border border-white/10 rounded-xl text-slate-200 focus:outline-none focus:border-accent-cyan"
                >
                  <option value="true">Active (Can Authenticate)</option>
                  <option value="false">Deactivated (Blocked)</option>
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-white/10">
                <button
                  onClick={() => setEditingUser(null)}
                  className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleUpdateUser}
                  className="px-4 py-2 rounded-xl bg-accent-cyan text-sentinel-950 font-bold hover:opacity-90"
                >
                  Apply Changes
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

    </main>
  );
}
