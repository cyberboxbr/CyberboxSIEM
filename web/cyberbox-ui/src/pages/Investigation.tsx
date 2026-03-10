import { FormEvent, useState } from 'react';
import { runSearch } from '../api/client';

export function Investigation() {
  const [query, setQuery] = useState(
    'SELECT event_id, tenant_id, source, event_time, ingest_time FROM events_hot ORDER BY ingest_time DESC LIMIT 25',
  );
  const [searchRows, setSearchRows] = useState<Array<Record<string, unknown>>>([]);
  const [statusText, setStatusText] = useState('');

  const onSearch = async (event: FormEvent) => {
    event.preventDefault();
    setStatusText('Running search...');
    try {
      const result = await runSearch(query);
      setSearchRows(result.rows);
      setStatusText(`Search complete. ${result.total} rows available.`);
    } catch (err) {
      setStatusText(`Search failed: ${String(err)}`);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Investigation Query</h1>
      </div>

      <section className="panel">
        <h2>Query Lab</h2>
        <form onSubmit={onSearch} className="stack">
          <textarea value={query} onChange={(e) => setQuery(e.target.value)} rows={4} />
          <button type="submit">Run Search</button>
        </form>
        <p className="status">{statusText}</p>
        <pre className="results">{JSON.stringify(searchRows, null, 2)}</pre>
      </section>
    </div>
  );
}
