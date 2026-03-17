"use client";

import { useEffect, useState } from "react";
import {
  createRule,
  deleteRule,
  listRules,
  type DetectionRule,
  type Severity,
} from "@/lib/api";

const DEFAULT_YAML = `title: New Rule
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    Image|contains: suspicious.exe
  condition: selection
level: medium
`;

function extractRuleTitle(sigmaSource: string): string {
  const match = sigmaSource.match(/^\s*title:\s*(.+)$/im);
  return match?.[1]?.trim() || "Untitled rule";
}

function inferSeverity(sigmaSource: string): Severity {
  const match = sigmaSource.match(/^\s*level:\s*(.+)$/im);
  switch (match?.[1]?.trim().toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "low":
      return "low";
    default:
      return "medium";
  }
}

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed";
}

export default function RulesPage() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [yaml, setYaml] = useState(DEFAULT_YAML);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadRules = () => {
    setLoading(true);
    listRules()
      .then((data) => setRules(data))
      .catch((loadError: unknown) => {
        setError(toErrorMessage(loadError));
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleCreate = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await createRule("default", {
        sigma_source: yaml,
        schedule_or_stream: "stream",
        severity: inferSeverity(yaml),
        enabled: true,
      });
      setShowForm(false);
      setYaml(DEFAULT_YAML);
      loadRules();
    } catch (createError: unknown) {
      setError(toErrorMessage(createError));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (ruleId: string) => {
    if (!confirm("Delete this rule?")) {
      return;
    }

    try {
      await deleteRule("default", ruleId);
      loadRules();
    } catch (deleteError: unknown) {
      alert(toErrorMessage(deleteError));
    }
  };

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Detection Rules</h1>
          <p className="mt-1 text-sm text-gray-400">
            Preview authoring surface wired to the live rule API contract.
          </p>
        </div>
        <button
          onClick={() => setShowForm((value) => !value)}
          className="rounded bg-blue-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-500"
        >
          {showForm ? "Cancel" : "+ New Rule"}
        </button>
      </div>

      {showForm && (
        <div className="space-y-3 rounded-lg border border-gray-800 bg-gray-900 p-5">
          <p className="text-xs font-medium text-gray-400">Sigma Source</p>
          <textarea
            className="h-56 w-full rounded border border-gray-700 bg-gray-950 p-3 font-mono text-xs text-gray-200 focus:border-blue-500 focus:outline-none"
            value={yaml}
            onChange={(event) => setYaml(event.target.value)}
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            onClick={handleCreate}
            disabled={submitting}
            className="rounded bg-green-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-green-500 disabled:opacity-50"
          >
            {submitting ? "Creating..." : "Create Rule"}
          </button>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-gray-500">Loading...</p>
      ) : rules.length === 0 ? (
        <p className="py-16 text-center text-sm text-gray-500">No rules. Create one above.</p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-400">
                <th className="px-5 py-3 text-left font-medium">Rule</th>
                <th className="px-5 py-3 text-left font-medium">Severity</th>
                <th className="px-5 py-3 text-left font-medium">Mode</th>
                <th className="px-5 py-3 text-left font-medium">Enabled</th>
                <th className="px-5 py-3 text-left font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr
                  key={rule.rule_id}
                  className="border-b border-gray-800/50 hover:bg-gray-800/30"
                >
                  <td className="max-w-[260px] truncate px-5 py-3 text-gray-200">
                    {extractRuleTitle(rule.sigma_source)}
                  </td>
                  <td className="px-5 py-3 capitalize text-gray-400">{rule.severity}</td>
                  <td className="px-5 py-3 capitalize text-gray-400">
                    {rule.schedule_or_stream}
                  </td>
                  <td className="px-5 py-3">
                    <span
                      className={`text-xs font-medium ${
                        rule.enabled ? "text-green-400" : "text-gray-500"
                      }`}
                    >
                      {rule.enabled ? "Yes" : "No"}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <button
                      onClick={() => handleDelete(rule.rule_id)}
                      className="text-xs text-red-400 transition-colors hover:text-red-300"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
