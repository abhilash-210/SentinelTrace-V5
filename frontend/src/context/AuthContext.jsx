/**
 * context/AuthContext.jsx
 * ----------------------
 * React Context providing global authentication state, JWT lifecycle management,
 * and RBAC permission checks across SentinelTrace.
 *
 * Sprint 4A — Identity & Role-Based Access Control (RBAC).
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from "react";

const AuthContext = createContext(null);

const API_BASE = "http://localhost:8000";

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(() => localStorage.getItem("sentinel_token"));
  const [permissions, setPermissions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState(null);

  // Fetch /api/v1/auth/me using current token
  const fetchMe = useCallback(async (jwtToken) => {
    if (!jwtToken) {
      setUser(null);
      setPermissions([]);
      setLoading(false);
      return null;
    }
    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/me`, {
        headers: {
          Authorization: `Bearer ${jwtToken}`,
        },
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setPermissions(data.permissions || []);
        setLoading(false);
        return data.user;
      } else {
        // Token expired or invalid
        localStorage.removeItem("sentinel_token");
        setToken(null);
        setUser(null);
        setPermissions([]);
        setLoading(false);
        return null;
      }
    } catch (err) {
      console.error("Auth verification error:", err);
      setLoading(false);
      return null;
    }
  }, []);

  // Initialize auth on load
  useEffect(() => {
    if (token) {
      fetchMe(token);
    } else {
      setLoading(false);
    }
  }, [token, fetchMe]);

  // Login handler
  const login = async (username, password) => {
    setAuthError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: "Authentication failed." }));
        const msg = errData.detail || "Invalid username or password.";
        setAuthError(msg);
        throw new Error(msg);
      }
      const data = await res.json();
      localStorage.setItem("sentinel_token", data.access_token);
      setToken(data.access_token);
      setUser(data.user);
      setPermissions(data.permissions || []);
      return data.user;
    } catch (err) {
      setAuthError(err.message);
      throw err;
    }
  };

  // Logout handler
  const logout = () => {
    localStorage.removeItem("sentinel_token");
    setToken(null);
    setUser(null);
    setPermissions([]);
    setAuthError(null);
  };

  // RBAC Permission checker helper
  const hasPermission = (permissionName) => {
    if (!user) return false;
    if (user.role === "ADMIN") return true;
    return permissions.includes(permissionName);
  };

  // Role checker helper
  const hasRole = (roleNames) => {
    if (!user) return false;
    if (Array.isArray(roleNames)) {
      return roleNames.includes(user.role);
    }
    return user.role === roleNames;
  };

  // Authenticated fetch wrapper helper
  const authFetch = async (url, options = {}) => {
    const headers = {
      ...(options.headers || {}),
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    return fetch(url.startsWith("http") ? url : `${API_BASE}${url}`, {
      ...options,
      headers,
    });
  };

  const value = {
    user,
    token,
    permissions,
    loading,
    authError,
    isAuthenticated: !!user,
    login,
    logout,
    hasPermission,
    hasRole,
    authFetch,
    fetchMe,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
