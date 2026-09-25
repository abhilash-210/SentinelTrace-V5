/**
 * Centralised API Configuration for SentinelTrace Frontend
 * In development, defaults to http://localhost:8000.
 * In production (Vercel/Netlify/Render), set VITE_API_BASE_URL to your deployed backend URL.
 */
export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000").replace(/\/$/, "");
export const API_V1_URL = `${API_BASE_URL}/api/v1`;
