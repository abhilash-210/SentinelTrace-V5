/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // SENTINEL-TRACE brand palette
        sentinel: {
          950: "#020817",
          900: "#0a1628",
          800: "#0f2040",
          700: "#1a3a5c",
          600: "#1e4d7b",
          500: "#2563a8",
          400: "#3b82c4",
          300: "#60a5e0",
        },
        accent: {
          cyan:   "#06b6d4",
          green:  "#10b981",
          amber:  "#f59e0b",
          red:    "#ef4444",
          purple: "#8b5cf6",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      backgroundImage: {
        "grid-pattern": "linear-gradient(rgba(6,182,212,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(6,182,212,0.05) 1px, transparent 1px)",
        "hero-glow": "radial-gradient(ellipse 80% 60% at 50% -10%, rgba(6,182,212,0.15), transparent)",
      },
      backgroundSize: {
        "grid": "40px 40px",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4,0,0.6,1) infinite",
        "fade-in":    "fadeIn 0.5s ease-in-out",
        "slide-in":   "slideIn 0.4s ease-out",
      },
      keyframes: {
        fadeIn:  { "0%": { opacity: "0" },                   "100%": { opacity: "1" } },
        slideIn: { "0%": { transform: "translateX(-16px)", opacity: "0" }, "100%": { transform: "translateX(0)", opacity: "1" } },
      },
    },
  },
  plugins: [],
}
