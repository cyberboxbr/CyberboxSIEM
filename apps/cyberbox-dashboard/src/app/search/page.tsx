"use client";

import { useState } from "react";
import { nlqSearch } from "@/lib/api";

type SearchRow = Record<string, unknown>;

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Search failed";
}

function formatCellValue(value: unknown): string {
  if (typeof value === "object" && value !== null) {
    return JSON.stringify(value);
  }
  return String(value ?? "");
}

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchRow[] | null>(null);
  const [generatedWhere, setGeneratedWhere] = useState<string | null>(null);
  const [interpretedAs, setInterpretedAs] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<{ start: string; end: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!query.trim()) {
      return;
    }

    setLoading(true);
    setError(null);
    setResults(null);
    setGeneratedWhere(null);
    setInterpretedAs(null);
    setTimeRange(null);

    try {
      const response = await nlqSearch("default", query);
      setResults(response.rows ?? []);
      setGeneratedWhere(response.generated_where || null);
      setInterpretedAs(response.interpreted_as || null);
      setTimeRange(response.time_range ?? null);
    } catch (searchError: unknown) {
      setError(toErrorMessage(searchError));
    } finally {
      setLoading(false);
    }
  };

  const columns = results && results.length > 0 ? Object.keys(results[0]) : [];

  return (
    <div className="space-y-5 p-6">
      <h1 className="text-xl font-semibold text-white">NLQ Search</h1>

      <div className="flex gap-3">
        <input
          type="text"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => event.key === "Enter" && void handleSearch()}
          placeholder='e.g. "show me failed logins in the last hour"'
          className="flex-1 rounded border border-gray-700 bg-gray-900 px-4 py-2 text-sm text-gray-200 placeholder-gray-500 focus:border-blue-500 focus:outline-none"
        />
        <button
          onClick={() => void handleSearch()}
          disabled={loading || !query.trim()}
          className="rounded bg-blue-600 px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:opacity-50"
        >
          {loading ? "Searching..." : "Search"}
        </button>
      </div>

      {error && (
        <div className="rounded border border-red-800 bg-red-900/30 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {generatedWhere && (
        <div className="rounded border border-gray-800 bg-gray-900 p-4">
          <p className="mb-2 text-xs font-medium text-gray-500">Generated Filter</p>
          <pre className="whitespace-pre-wrap text-xs font-mono text-blue-300">
            {generatedWhere}
          </pre>
          {interpretedAs && (
            <p className="mt-3 text-xs text-gray-400">Interpreted as: {interpretedAs}</p>
          )}
          {timeRange && (
            <p className="mt-1 text-xs text-gray-500">
              Time range: {new Date(timeRange.start).toLocaleString()} to{" "}
              {new Date(timeRange.end).toLocaleString()}
            </p>
          )}
        </div>
      )}

      {results !== null &&
        (results.length === 0 ? (
          <p className="py-12 text-center text-sm text-gray-500">No results found.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-900">
            <p className="border-b border-gray-800 px-5 py-3 text-xs text-gray-400">
              {results.length} row{results.length !== 1 ? "s" : ""}
            </p>
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-gray-800 text-gray-400">
                  {columns.map((column) => (
                    <th
                      key={column}
                      className="whitespace-nowrap px-4 py-2 text-left font-medium"
                    >
                      {column}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {results.map((row, index) => (
                  <tr
                    key={`${index}-${columns.join("-")}`}
                    className="border-b border-gray-800/40 hover:bg-gray-800/30"
                  >
                    {columns.map((column) => (
                      <td
                        key={column}
                        className="max-w-[200px] truncate px-4 py-2 text-gray-300"
                      >
                        {formatCellValue(row[column])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
    </div>
  );
}
