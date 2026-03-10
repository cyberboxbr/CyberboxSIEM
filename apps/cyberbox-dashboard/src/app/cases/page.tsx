import { listCases } from "@/lib/api";

const STATUS_COLOR: Record<string, string> = {
  open: "text-red-400",
  investigating: "text-yellow-400",
  resolved: "text-green-400",
  closed: "text-gray-500",
};

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-900/40 text-red-300 border-red-800",
  high: "bg-orange-900/40 text-orange-300 border-orange-800",
  medium: "bg-yellow-900/40 text-yellow-300 border-yellow-800",
  low: "bg-blue-900/40 text-blue-300 border-blue-800",
  info: "bg-gray-800 text-gray-400 border-gray-700",
};

function slaDiff(sla_due_at: string | null | undefined): { label: string; color: string } {
  if (!sla_due_at) return { label: "—", color: "text-gray-500" };
  const diff = new Date(sla_due_at).getTime() - Date.now();
  const hours = Math.round(diff / 3_600_000);
  if (diff < 0) return { label: `${Math.abs(hours)}h overdue`, color: "text-red-400" };
  if (hours < 4) return { label: `${hours}h left`, color: "text-yellow-400" };
  return { label: `${hours}h left`, color: "text-gray-400" };
}

export default async function CasesPage() {
  let cases: any[] = [];
  try {
    cases = (await listCases()) ?? [];
  } catch {}

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold text-white">Cases</h1>

      {cases.length === 0 ? (
        <p className="text-gray-500 text-sm text-center py-16">No cases found.</p>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-400 border-b border-gray-800 bg-gray-900">
                <th className="px-5 py-3 text-left font-medium">Title</th>
                <th className="px-5 py-3 text-left font-medium">Severity</th>
                <th className="px-5 py-3 text-left font-medium">Status</th>
                <th className="px-5 py-3 text-left font-medium">Assignee</th>
                <th className="px-5 py-3 text-left font-medium">SLA</th>
                <th className="px-5 py-3 text-left font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => {
                const sla = slaDiff(c.sla_due_at);
                return (
                  <tr key={c.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-5 py-3 text-gray-200 max-w-[240px] truncate">
                      {c.title ?? c.id}
                    </td>
                    <td className="px-5 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded border capitalize font-medium ${SEV_BADGE[c.severity] ?? SEV_BADGE.info}`}>
                        {c.severity}
                      </span>
                    </td>
                    <td className={`px-5 py-3 capitalize font-medium ${STATUS_COLOR[c.status] ?? "text-gray-400"}`}>{c.status}</td>
                    <td className="px-5 py-3 text-gray-400">{c.assignee ?? "—"}</td>
                    <td className={`px-5 py-3 text-xs ${sla.color}`}>{sla.label}</td>
                    <td className="px-5 py-3 text-gray-500 text-xs">
                      {c.created_at ? new Date(c.created_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
