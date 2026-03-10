"use client";

import { useState } from "react";
import { nlqSearch } from "@/lib/api";

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<any[] | null>(null);
  const [sql, setSql] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResults(null);
    setSql(null);
    try {
      const res = await nlqSearch("default", query);
      setResults(res?.rows ?? res?.results ?? []);
      setSql(res?.sql ?? null);
    } catch (e: any) {
      setError(e.message ?? "Search failed");
    } finally {
      setLoading(false);
    }
  };

  const columns: string[] = results && results.length > 0 ? Object.keys(results[0]) : [];

  return (
    <div className="p-6 space-y-5">
      <h1 className="text-xl font-semibold text-white">NLQ Search</h1>

      <div className="flex gap-3">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSearch()}
          placeholder='e.g. "show me failed logins in the last hour"'
          className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <button
          onClick={handleSearch}
          disabled={loading || !query.trim()}
          className="px-5 py-2 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-medium transition-colors"
        >
          {loading ? "Searching…" : "Search"}
        </button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {sql && (
        <div className="bg-gray-900 border border-gray-800 rounded p-4">
          <p className="text-xs text-gray-500 mb-2 font-medium">Generated SQL</p>
          <pre className="text-xs font-mono text-blue-300 whitespace-pre-wrap">{sql}</pre>
        </div>
      )}

      {results !== null && (
        results.length === 0 ? (
          <p className="text-gray-500 text-sm text-center py-12">No results found.</p>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-x-auto">
            <p className="px-5 py-3 text-xs text-gray-400 border-b border-gray-800">
              {results.length} row{results.length !== 1 ? "s" : ""}
            </p>
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-gray-800 text-gray-400">
                  {columns.map((col) => (
                    <th key={col} className="px-4 py-2 text-left font-medium whitespace-nowrap">
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {results.map((row, i) => (
                  <tr key={i} className="border-b border-gray-800/40 hover:bg-gray-800/30">
                    {columns.map((col) => (
                      <td key={col} className="px-4 py-2 text-gray-300 max-w-[200px] truncate">
                        {typeof row[col] === "object" ? JSON.stringify(row[col]) : String(row[col] ?? "")}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  );
}
