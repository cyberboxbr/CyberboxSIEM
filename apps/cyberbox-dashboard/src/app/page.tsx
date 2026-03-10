import { listAlerts, listRules, listCases, getCoverage } from "@/lib/api";

async function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
      <p className="text-xs text-gray-400 uppercase tracking-wider">{label}</p>
      <p className="mt-1 text-3xl font-bold text-white">{value}</p>
      {sub && <p className="mt-1 text-xs text-gray-500">{sub}</p>}
    </div>
  );
}

export default async function DashboardPage() {
  const [alerts, rules, cases, coverage] = await Promise.allSettled([
    listAlerts(),
    listRules(),
    listCases(),
    getCoverage(),
  ]);

  const alertList: any[] = alerts.status === "fulfilled" ? (alerts.value ?? []) : [];
  const ruleList: any[] = rules.status === "fulfilled" ? (rules.value ?? []) : [];
  const caseList: any[] = cases.status === "fulfilled" ? (cases.value ?? []) : [];
  const cov: any = coverage.status === "fulfilled" ? coverage.value : {};

  const openAlerts = alertList.filter((a) => a.status === "open").length;
  const criticalAlerts = alertList.filter((a) => a.severity === "critical").length;
  const enabledRules = ruleList.filter((r) => r.enabled).length;
  const openCases = caseList.filter((c) => c.status === "open").length;
  const tacticCount = cov?.tactics ? Object.keys(cov.tactics).length : 0;
  const techniqueCount = cov?.techniques ? Object.keys(cov.techniques).length : 0;

  const recentAlerts: any[] = alertList.slice(0, 8);

  const severityColor: Record<string, string> = {
    critical: "text-red-400",
    high: "text-orange-400",
    medium: "text-yellow-400",
    low: "text-blue-400",
    info: "text-gray-400",
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold text-white">Dashboard</h1>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Open Alerts" value={openAlerts} sub={`${criticalAlerts} critical`} />
        <StatCard label="Active Rules" value={enabledRules} sub={`${ruleList.length} total`} />
        <StatCard label="Open Cases" value={openCases} sub={`${caseList.length} total`} />
        <StatCard label="ATT&CK Coverage" value={`${techniqueCount}`} sub={`techniques across ${tacticCount} tactics`} />
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg">
        <div className="px-5 py-4 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-300">Recent Alerts</h2>
        </div>
        {recentAlerts.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-gray-500">No alerts yet</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-400 border-b border-gray-800">
                <th className="px-5 py-3 text-left font-medium">Rule</th>
                <th className="px-5 py-3 text-left font-medium">Severity</th>
                <th className="px-5 py-3 text-left font-medium">Status</th>
                <th className="px-5 py-3 text-left font-medium">Fired At</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.map((a) => (
                <tr key={a.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-5 py-3 text-gray-200 font-mono text-xs truncate max-w-[200px]">{a.rule_name ?? a.rule_id}</td>
                  <td className={`px-5 py-3 capitalize font-medium ${severityColor[a.severity] ?? "text-gray-300"}`}>{a.severity}</td>
                  <td className="px-5 py-3 text-gray-400 capitalize">{a.status}</td>
                  <td className="px-5 py-3 text-gray-500 text-xs">{a.fired_at ? new Date(a.fired_at).toLocaleString() : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
