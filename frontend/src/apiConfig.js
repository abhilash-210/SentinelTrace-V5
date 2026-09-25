/**
 * Centralised API Configuration for SentinelTrace Frontend
 * In development: defaults to http://localhost:8000
 * In production: points to https://sentineltrace-v5.onrender.com or custom VITE_API_BASE_URL
 */
export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ||
  (typeof window !== "undefined" && window.location.hostname !== "localhost"
    ? "https://sentineltrace-v5.onrender.com"
    : "http://localhost:8000")
).replace(/\/$/, "");

export const API_V1_URL = `${API_BASE_URL}/api/v1`;

export function getAuthHeaders() {
  const token = typeof window !== "undefined" ? localStorage.getItem("sentinel_token") : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}
