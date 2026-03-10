"use client";

import { useEffect, useState } from "react";
import { listRules, createRule, deleteRule } from "@/lib/api";

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

export default function RulesPage() {
  const [rules, setRules] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [yaml, setYaml] = useState(DEFAULT_YAML);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    listRules()
      .then((d) => setRules(d ?? []))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await createRule("default", { sigma_yaml: yaml });
      setShowForm(false);
      setYaml(DEFAULT_YAML);
      load();
    } catch (e: any) {
      setError(e.message ?? "Failed to create rule");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this rule?")) return;
    try {
      await deleteRule("default", id);
      load();
    } catch (e: any) {
      alert(e.message ?? "Failed to delete rule");
    }
  };

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-white">Detection Rules</h1>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors"
        >
          {showForm ? "Cancel" : "+ New Rule"}
        </button>
      </div>

      {showForm && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-3">
          <p className="text-xs text-gray-400 font-medium">Sigma YAML</p>
          <textarea
            className="w-full h-56 bg-gray-950 border border-gray-700 rounded p-3 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500"
            value={yaml}
            onChange={(e) => setYaml(e.target.value)}
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            onClick={handleCreate}
            disabled={submitting}
            className="px-4 py-1.5 rounded bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white text-sm font-medium transition-colors"
          >
            {submitting ? "Creating…" : "Create Rule"}
          </button>
        </div>
      )}

      {loading ? (
        <p className="text-gray-500 text-sm">Loading…</p>
      ) : rules.length === 0 ? (
        <p className="text-gray-500 text-sm text-center py-16">No rules. Create one above.</p>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-400 border-b border-gray-800">
                <th className="px-5 py-3 text-left font-medium">Name</th>
                <th className="px-5 py-3 text-left font-medium">Level</th>
                <th className="px-5 py-3 text-left font-medium">Status</th>
                <th className="px-5 py-3 text-left font-medium">Enabled</th>
                <th className="px-5 py-3 text-left font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-5 py-3 text-gray-200 max-w-[240px] truncate">{r.name ?? r.id}</td>
                  <td className="px-5 py-3 text-gray-400 capitalize">{r.level ?? "—"}</td>
                  <td className="px-5 py-3 text-gray-400 capitalize">{r.status ?? "—"}</td>
                  <td className="px-5 py-3">
                    <span className={`text-xs font-medium ${r.enabled ? "text-green-400" : "text-gray-500"}`}>
                      {r.enabled ? "Yes" : "No"}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <button
                      onClick={() => handleDelete(r.id)}
                      className="text-xs text-red-400 hover:text-red-300 transition-colors"
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
