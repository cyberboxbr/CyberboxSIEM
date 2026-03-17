"use client";

import { useEffect, useState } from "react";
import {
  buildAlertStreamUrl,
  issueAlertStreamToken,
  listAlerts,
  type AlertRecord,
  type AlertStatus,
  type Severity,
} from "@/lib/api";

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "border-red-800 bg-red-900/40 text-red-300",
  high: "border-orange-800 bg-orange-900/40 text-orange-300",
  medium: "border-yellow-800 bg-yellow-900/40 text-yellow-300",
  low: "border-blue-900 bg-blue-900/40 text-blue-300",
};

const STATUS_COLOR: Record<AlertStatus, string> = {
  open: "text-red-400",
  acknowledged: "text-yellow-400",
  in_progress: "text-blue-400",
  closed: "text-gray-500",
};

function mergeAlert(current: AlertRecord[], incoming: AlertRecord): AlertRecord[] {
  return [incoming, ...current.filter((alert) => alert.alert_id !== incoming.alert_id)];
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [liveCount, setLiveCount] = useState(0);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "open" | "critical">("all");

  useEffect(() => {
    listAlerts()
      .then((data) => setAlerts(data))
      .catch(() => {
        setStreamError("Initial alert load failed.");
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    let cancelled = false;
    let stream: EventSource | null = null;

    void issueAlertStreamToken()
      .then((token) => {
        if (cancelled) {
          return;
        }
        stream = new EventSource(buildAlertStreamUrl(token));
        stream.onopen = () => setStreamError(null);
        stream.onmessage = (event) => {
          try {
            const alert = JSON.parse(event.data) as AlertRecord;
            setAlerts((current) => mergeAlert(current, alert));
            setLiveCount((count) => count + 1);
          } catch {
            setStreamError("Live alert stream returned malformed data.");
          }
        };
        stream.onerror = () => {
          setStreamError("Live alert stream disconnected.");
        };
      })
      .catch(() => {
        setStreamError("Unable to open a live alert stream token.");
      });

    return () => {
      cancelled = true;
      stream?.close();
    };
  }, []);

  const visibleAlerts = alerts.filter((alert) => {
    if (filter === "open") {
      return alert.status === "open";
    }
    if (filter === "critical") {
      return alert.severity === "critical";
    }
    return true;
  });

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-white">
          Alerts
          {liveCount > 0 && (
            <span className="ml-2 rounded-full border border-green-700 bg-green-900 px-2 py-0.5 text-xs text-green-300">
              +{liveCount} live
            </span>
          )}
        </h1>
        <div className="flex gap-2">
          {(["all", "open", "critical"] as const).map((nextFilter) => (
            <button
              key={nextFilter}
              onClick={() => setFilter(nextFilter)}
              className={`rounded px-3 py-1 text-xs font-medium capitalize transition-colors ${
                filter === nextFilter
                  ? "bg-blue-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              {nextFilter}
            </button>
          ))}
        </div>
      </div>

      {streamError && (
        <div className="rounded border border-amber-800 bg-amber-950/40 px-4 py-3 text-sm text-amber-200">
          {streamError}
        </div>
      )}

      {loading ? (
        <p className="text-sm text-gray-500">Loading...</p>
      ) : visibleAlerts.length === 0 ? (
        <p className="py-16 text-center text-sm text-gray-500">No alerts match the current filter.</p>
      ) : (
        <div className="space-y-2">
          {visibleAlerts.map((alert) => (
            <div
              key={alert.alert_id}
              className="flex items-start justify-between gap-4 rounded-lg border border-gray-800 bg-gray-900 px-5 py-4"
            >
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium text-gray-100">
                  {alert.rule_title || alert.rule_id}
                </p>
                <p className="mt-1 truncate font-mono text-xs text-gray-500">
                  {alert.alert_id}
                </p>
                {alert.evidence_refs.length > 0 && (
                  <p className="mt-1 text-xs text-gray-400">
                    Evidence: {alert.evidence_refs.slice(0, 3).join(", ")}
                    {alert.evidence_refs.length > 3 ? "..." : ""}
                  </p>
                )}
              </div>
              <div className="flex shrink-0 flex-col items-end gap-1">
                <span
                  className={`rounded border px-2 py-0.5 text-xs font-medium capitalize ${
                    SEVERITY_COLOR[alert.severity]
                  }`}
                >
                  {alert.severity}
                </span>
                <span className={`text-xs capitalize ${STATUS_COLOR[alert.status]}`}>
                  {alert.status}
                </span>
                <span className="text-xs text-gray-600">
                  {new Date(alert.last_seen).toLocaleString()}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
