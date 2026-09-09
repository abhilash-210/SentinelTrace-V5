/**
 * StatusCard.jsx
 * --------------
 * Reusable status card component for SENTINEL-TRACE dashboard.
 *
 * Props:
 *   title        — Card title
 *   value        — Primary metric or status text
 *   icon         — Emoji or icon string
 *   status       — "online" | "pending" | "offline" | "future"
 *   sprint       — Sprint number when this feature becomes active
 *   description  — Secondary description text
 */

const STATUS_CONFIG = {
  online:  { dot: "bg-accent-green",  ring: "border-accent-green/20",  label: "Active"   },
  pending: { dot: "bg-accent-amber",  ring: "border-accent-amber/20",  label: "Pending"  },
  offline: { dot: "bg-slate-500",     ring: "border-slate-500/20",     label: "Offline"  },
  future:  { dot: "bg-slate-700",     ring: "border-slate-700/20",     label: "Upcoming" },
};

export default function StatusCard({
  title,
  value,
  icon,
  status = "offline",
  sprint,
  description,
}) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.offline;
  const isFuture = status === "future";

  return (
    <div
      className={[
        "glass-card p-5 flex flex-col gap-3 border transition-all duration-300",
        cfg.ring,
        isFuture
          ? "opacity-60 cursor-not-allowed"
          : "hover:border-accent-cyan/30 hover:shadow-lg hover:shadow-accent-cyan/5 hover:-translate-y-0.5",
      ].join(" ")}
    >
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="text-2xl">{icon}</div>
        <div className="flex items-center gap-1.5">
          <span className={`w-2 h-2 rounded-full ${cfg.dot} ${!isFuture ? "animate-pulse" : ""}`} />
          <span className="text-xs text-slate-500">{cfg.label}</span>
        </div>
      </div>

      {/* Content */}
      <div>
        <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
        {description && (
          <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{description}</p>
        )}
      </div>

      {/* Value / Sprint badge */}
      <div className="mt-auto pt-1 border-t border-white/5 flex items-center justify-between">
        {isFuture ? (
          <span className="text-xs text-slate-600 italic">
            Coming in Sprint {sprint}
          </span>
        ) : (
          <span className="text-sm font-mono font-semibold text-accent-cyan">
            {value}
          </span>
        )}
      </div>
    </div>
  );
}
