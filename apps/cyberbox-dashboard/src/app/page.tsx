import {
  getCoverage,
  listAlerts,
  listCases,
  listRules,
  type AlertRecord,
  type CaseRecord,
  type CoverageReport,
  type DetectionRule,
  type Severity,
} from "@/lib/api";

function StatCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: string | number;
  sub?: string;
}) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
      <p className="text-xs uppercase tracking-wider text-gray-400">{label}</p>
      <p className="mt-1 text-3xl font-bold text-white">{value}</p>
      {sub && <p className="mt-1 text-xs text-gray-500">{sub}</p>}
    </div>
  );
}

function emptyCoverage(): CoverageReport {
  return {
    covered_techniques: [],
    total_covered: 0,
    total_in_framework: 0,
    coverage_pct: 0,
  };
}

export default async function DashboardPage() {
  const [alerts, rules, cases, coverage] = await Promise.allSettled([
    listAlerts(),
    listRules(),
    listCases(),
    getCoverage(),
  ]);

  const alertList: AlertRecord[] = alerts.status === "fulfilled" ? alerts.value : [];
  const ruleList: DetectionRule[] = rules.status === "fulfilled" ? rules.value : [];
  const caseList: CaseRecord[] = cases.status === "fulfilled" ? cases.value : [];
  const coverageReport: CoverageReport =
    coverage.status === "fulfilled" ? coverage.value : emptyCoverage();

  const openAlerts = alertList.filter((alert) => alert.status === "open").length;
  const criticalAlerts = alertList.filter((alert) => alert.severity === "critical").length;
  const enabledRules = ruleList.filter((rule) => rule.enabled).length;
  const activeCases = caseList.filter((incident) =>
    incident.status === "open" || incident.status === "in_progress",
  ).length;
  const tacticCount = new Set(
    coverageReport.covered_techniques.map((technique) => technique.tactic ?? "unmapped"),
  ).size;
  const techniqueCount = coverageReport.total_covered;
  const recentAlerts = alertList.slice(0, 8);

  const severityColor: Record<Severity, string> = {
    critical: "text-red-400",
    high: "text-orange-400",
    medium: "text-yellow-400",
    low: "text-blue-400",
  };

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-xl font-semibold text-white">Dashboard</h1>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Open Alerts" value={openAlerts} sub={`${criticalAlerts} critical`} />
        <StatCard label="Active Rules" value={enabledRules} sub={`${ruleList.length} total`} />
        <StatCard label="Active Cases" value={activeCases} sub={`${caseList.length} total`} />
        <StatCard
          label="ATT&CK Coverage"
          value={techniqueCount}
          sub={`${tacticCount} tactics, ${coverageReport.coverage_pct.toFixed(1)}% overall`}
        />
      </div>

      <div className="rounded-lg border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-gray-300">Recent Alerts</h2>
        </div>
        {recentAlerts.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-gray-500">No alerts yet</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-400">
                <th className="px-5 py-3 text-left font-medium">Rule</th>
                <th className="px-5 py-3 text-left font-medium">Severity</th>
                <th className="px-5 py-3 text-left font-medium">Status</th>
                <th className="px-5 py-3 text-left font-medium">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.map((alert) => (
                <tr
                  key={alert.alert_id}
                  className="border-b border-gray-800/50 hover:bg-gray-800/30"
                >
                  <td className="max-w-[240px] truncate px-5 py-3 text-xs font-medium text-gray-200">
                    {alert.rule_title || alert.rule_id}
                  </td>
                  <td
                    className={`px-5 py-3 font-medium capitalize ${
                      severityColor[alert.severity]
                    }`}
                  >
                    {alert.severity}
                  </td>
                  <td className="px-5 py-3 capitalize text-gray-400">{alert.status}</td>
                  <td className="px-5 py-3 text-xs text-gray-500">
                    {new Date(alert.last_seen).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
