"use client";

import { useEffect, useState } from "react";
import { listAlerts } from "@/lib/api";

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-900/40 text-red-300 border-red-800",
  high: "bg-orange-900/40 text-orange-300 border-orange-800",
  medium: "bg-yellow-900/40 text-yellow-300 border-yellow-800",
  low: "bg-blue-900/40 text-blue-300 border-blue-800",
  info: "bg-gray-800 text-gray-400 border-gray-700",
};

const STATUS_COLOR: Record<string, string> = {
  open: "text-red-400",
  acknowledged: "text-yellow-400",
  closed: "text-gray-500",
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [liveCount, setLiveCount] = useState(0);
  const [filter, setFilter] = useState<"all" | "open" | "critical">("all");

  useEffect(() => {
    listAlerts()
      .then((data) => setAlerts(data ?? []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  // SSE live stream
  useEffect(() => {
    const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
    const es = new EventSource(`${BASE}/api/v1/alerts/stream`, {
      // Custom headers not supported in EventSource — rely on server accepting without auth in dev
    });
    es.onmessage = (e) => {
      try {
        const alert = JSON.parse(e.data);
        setAlerts((prev) => [alert, ...prev]);
        setLiveCount((n) => n + 1);
      } catch {}
    };
    return () => es.close();
  }, []);

  const visible = alerts.filter((a) => {
    if (filter === "open") return a.status === "open";
    if (filter === "critical") return a.severity === "critical";
    return true;
  });

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-white">
          Alerts{" "}
          {liveCount > 0 && (
            <span className="ml-2 text-xs bg-green-900 text-green-300 border border-green-700 px-2 py-0.5 rounded-full">
              +{liveCount} live
            </span>
          )}
        </h1>
        <div className="flex gap-2">
          {(["all", "open", "critical"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 rounded text-xs font-medium capitalize transition-colors ${
                filter === f
                  ? "bg-blue-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <p className="text-gray-500 text-sm">Loading…</p>
      ) : visible.length === 0 ? (
        <p className="text-gray-500 text-sm text-center py-16">No alerts match the filter.</p>
      ) : (
        <div className="space-y-2">
          {visible.map((a) => (
            <div
              key={a.id}
              className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-4 flex items-start justify-between gap-4"
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-100 truncate">{a.rule_name ?? a.rule_id}</p>
                <p className="mt-1 text-xs text-gray-500 font-mono truncate">{a.id}</p>
                {a.matched_details && a.matched_details.length > 0 && (
                  <p className="mt-1 text-xs text-gray-400">{a.matched_details.join(", ")}</p>
                )}
              </div>
              <div className="flex flex-col items-end gap-1 shrink-0">
                <span className={`text-xs px-2 py-0.5 rounded border capitalize font-medium ${SEV_COLOR[a.severity] ?? SEV_COLOR.info}`}>
                  {a.severity}
                </span>
                <span className={`text-xs capitalize ${STATUS_COLOR[a.status] ?? "text-gray-400"}`}>{a.status}</span>
                <span className="text-xs text-gray-600">{a.fired_at ? new Date(a.fired_at).toLocaleString() : "—"}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
