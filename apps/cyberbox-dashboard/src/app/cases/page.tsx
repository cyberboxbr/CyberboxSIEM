import { listCases, type CaseRecord, type CaseStatus, type Severity } from "@/lib/api";

const STATUS_COLOR: Record<CaseStatus, string> = {
  open: "text-red-400",
  in_progress: "text-yellow-400",
  resolved: "text-green-400",
  closed: "text-gray-500",
};

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: "border-red-800 bg-red-900/40 text-red-300",
  high: "border-orange-800 bg-orange-900/40 text-orange-300",
  medium: "border-yellow-800 bg-yellow-900/40 text-yellow-300",
  low: "border-blue-900 bg-blue-900/40 text-blue-300",
};

function slaDiff(slaDueAt: string | undefined): { label: string; color: string } {
  if (!slaDueAt) {
    return { label: "-", color: "text-gray-500" };
  }

  const diff = new Date(slaDueAt).getTime() - Date.now();
  const hours = Math.round(diff / 3_600_000);
  if (diff < 0) {
    return { label: `${Math.abs(hours)}h overdue`, color: "text-red-400" };
  }
  if (hours < 4) {
    return { label: `${hours}h left`, color: "text-yellow-400" };
  }
  return { label: `${hours}h left`, color: "text-gray-400" };
}

export default async function CasesPage() {
  let cases: CaseRecord[] = [];
  try {
    cases = await listCases();
  } catch {}

  return (
    <div className="space-y-4 p-6">
      <h1 className="text-xl font-semibold text-white">Cases</h1>

      {cases.length === 0 ? (
        <p className="py-16 text-center text-sm text-gray-500">No cases found.</p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 bg-gray-900 text-xs text-gray-400">
                <th className="px-5 py-3 text-left font-medium">Title</th>
                <th className="px-5 py-3 text-left font-medium">Severity</th>
                <th className="px-5 py-3 text-left font-medium">Status</th>
                <th className="px-5 py-3 text-left font-medium">Assignee</th>
                <th className="px-5 py-3 text-left font-medium">SLA</th>
                <th className="px-5 py-3 text-left font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((incident) => {
                const sla = slaDiff(incident.sla_due_at);
                return (
                  <tr
                    key={incident.case_id}
                    className="border-b border-gray-800/50 hover:bg-gray-800/30"
                  >
                    <td className="max-w-[240px] truncate px-5 py-3 text-gray-200">
                      {incident.title || incident.case_id}
                    </td>
                    <td className="px-5 py-3">
                      <span
                        className={`rounded border px-2 py-0.5 text-xs font-medium capitalize ${
                          SEVERITY_BADGE[incident.severity]
                        }`}
                      >
                        {incident.severity}
                      </span>
                    </td>
                    <td
                      className={`px-5 py-3 font-medium capitalize ${
                        STATUS_COLOR[incident.status]
                      }`}
                    >
                      {incident.status}
                    </td>
                    <td className="px-5 py-3 text-gray-400">{incident.assignee ?? "-"}</td>
                    <td className={`px-5 py-3 text-xs ${sla.color}`}>{sla.label}</td>
                    <td className="px-5 py-3 text-xs text-gray-500">
                      {new Date(incident.created_at).toLocaleString()}
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
