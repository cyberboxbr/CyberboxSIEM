import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  LookupTable,
  createLookupTable,
  getLookupEntries,
  getLookupTables,
  updateLookupEntries,
} from '../api/client';

/* ── SVG Icons ────────────────────────────────────── */

const tableIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/><line x1="9" y1="3" x2="9" y2="21"/><line x1="15" y1="3" x2="15" y2="21"/>
  </svg>
);
const plusIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
  </svg>
);
const searchIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>
);
const editIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
  </svg>
);
const saveIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
  </svg>
);
const refreshIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
  </svg>
);
const trashIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
  </svg>
);
const xIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
  </svg>
);
const dbIcon = (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
  </svg>
);

/* ── Component ────────────────────────────────────── */

export function LookupTables() {
  const [tables, setTables] = useState<LookupTable[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchText, setSearchText] = useState('');

  // Selected table
  const [selectedTable, setSelectedTable] = useState<string | null>(null);
  const [entries, setEntries] = useState<Array<Record<string, string>>>([]);
  const [entriesLoading, setEntriesLoading] = useState(false);
  const [entrySearch, setEntrySearch] = useState('');

  // Edit mode
  const [editing, setEditing] = useState(false);
  const [editRows, setEditRows] = useState<Array<Record<string, string>>>([]);

  // Create modal
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [newColumns, setNewColumns] = useState('');
  const [creating, setCreating] = useState(false);

  const loadTables = useCallback(async () => {
    try {
      setLoading(true);
      const t = await getLookupTables();
      setTables(t);
      setError('');
    } catch (err) { setError(String(err)); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { loadTables(); }, [loadTables]);

  const loadEntries = useCallback(async (name: string) => {
    setEntriesLoading(true);
    try {
      const e = await getLookupEntries(name);
      setEntries(e);
      setEditing(false);
    } catch (err) { setError(String(err)); }
    finally { setEntriesLoading(false); }
  }, []);

  const handleSelectTable = (name: string) => {
    setSelectedTable(name);
    setEntrySearch('');
    setEditing(false);
    loadEntries(name);
  };

  const handleCreate = async () => {
    if (!newName.trim() || !newColumns.trim()) return;
    setCreating(true);
    try {
      await createLookupTable({
        name: newName.trim().toLowerCase().replace(/\s+/g, '_'),
        columns: newColumns.split(',').map((c) => c.trim()).filter(Boolean),
        rows: [],
      });
      setShowCreate(false);
      setNewName('');
      setNewColumns('');
      await loadTables();
    } catch (err) { setError(String(err)); }
    finally { setCreating(false); }
  };

  const handleStartEdit = () => {
    setEditRows(entries.map((r) => ({ ...r })));
    setEditing(true);
  };

  const handleSaveEntries = async () => {
    if (!selectedTable) return;
    try {
      const updated = await updateLookupEntries(selectedTable, editRows);
      setEntries(updated);
      setEditing(false);
    } catch (err) { setError(String(err)); }
  };

  const handleCellChange = (rowIdx: number, col: string, value: string) => {
    setEditRows((prev) => {
      const next = [...prev];
      next[rowIdx] = { ...next[rowIdx], [col]: value };
      return next;
    });
  };

  const handleAddRow = () => {
    const selected = tables.find((t) => t.name === selectedTable);
    if (!selected) return;
    const emptyRow: Record<string, string> = {};
    selected.columns.forEach((c) => { emptyRow[c] = ''; });
    setEditRows((prev) => [...prev, emptyRow]);
  };

  const handleDeleteRow = (idx: number) => {
    setEditRows((prev) => prev.filter((_, i) => i !== idx));
  };

  /* ── Derived ──────────────────────────────────── */

  const filteredTables = useMemo(() => {
    if (!searchText) return tables;
    const q = searchText.toLowerCase();
    return tables.filter((t) => t.name.toLowerCase().includes(q));
  }, [tables, searchText]);

  const selectedMeta = useMemo(() => tables.find((t) => t.name === selectedTable), [tables, selectedTable]);

  const columns = selectedMeta?.columns ?? [];

  const displayRows = useMemo(() => {
    const rows = editing ? editRows : entries;
    if (!entrySearch) return rows;
    const q = entrySearch.toLowerCase();
    return rows.filter((r) => Object.values(r).some((v) => v.toLowerCase().includes(q)));
  }, [editing, editRows, entries, entrySearch]);

  const totalRows = useMemo(() => tables.reduce((s, t) => s + t.row_count, 0), [tables]);

  return (
    <div className="page lt-page">
      {/* ── Header ──────────────────────────────── */}
      <div className="re-header">
        <div className="re-header-left">
          <h1 className="re-title">Lookup Tables</h1>
          <div className="re-stats">
            <span className="re-stat">{tables.length} tables</span>
            <span className="re-stat-sep" />
            <span className="re-stat">{totalRows.toLocaleString()} total rows</span>
          </div>
        </div>
        <div className="re-header-actions">
          <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={loadTables}>
            {refreshIcon} Refresh
          </button>
          <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={() => setShowCreate(true)}>
            {plusIcon} New Table
          </button>
        </div>
      </div>

      {error && <div className="cd-error">{error}</div>}

      {/* ── Layout ──────────────────────────────── */}
      <div className="lt-layout">
        {/* ── Sidebar: Table list ────────────────── */}
        <div className="re-sidebar">
          <div className="re-search-wrap">
            {searchIcon}
            <input
              className="re-search"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder="Search tables..."
            />
          </div>

          <div className="re-rule-list">
            {loading ? (
              <p className="empty-state">Loading...</p>
            ) : filteredTables.length === 0 ? (
              <p className="empty-state">No tables found.</p>
            ) : (
              filteredTables.map((t) => (
                <div
                  key={t.name}
                  className={`lt-table-item ${selectedTable === t.name ? 'lt-table-item--selected' : ''}`}
                  onClick={() => handleSelectTable(t.name)}
                >
                  <div className="lt-table-icon">{dbIcon}</div>
                  <div className="re-rule-info">
                    <span className="re-rule-name">{t.name}</span>
                    <div className="re-rule-meta">
                      <span className="re-rule-mode">{t.columns.length} cols</span>
                      <span className="re-rule-mode">{t.row_count.toLocaleString()} rows</span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* ── Main: Table Viewer ─────────────────── */}
        <div className="re-main">
          {!selectedTable ? (
            <div className="lt-empty-main">
              <div className="lt-empty-icon">{tableIcon}</div>
              <h3 className="lt-empty-title">Select a Lookup Table</h3>
              <p className="lt-empty-desc">Choose a table from the sidebar to view and edit its entries, or create a new one.</p>
            </div>
          ) : (
            <div className="re-panel">
              {/* Table header */}
              <div className="re-panel-header">
                <div className="cd-panel-title">
                  {dbIcon}
                  <span>{selectedTable}</span>
                  <span className="cd-count-badge">{selectedMeta?.row_count ?? 0}</span>
                </div>
                <div className="lt-table-actions">
                  {!editing ? (
                    <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={handleStartEdit}>
                      {editIcon} Edit
                    </button>
                  ) : (
                    <>
                      <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={handleAddRow}>
                        {plusIcon} Add Row
                      </button>
                      <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleSaveEntries}>
                        {saveIcon} Save
                      </button>
                      <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setEditing(false)}>
                        {xIcon} Cancel
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Column chips */}
              <div className="lt-col-chips">
                {columns.map((col) => (
                  <span key={col} className="lt-col-chip">{col}</span>
                ))}
              </div>

              {/* Search within entries */}
              <div className="lt-entry-search">
                {searchIcon}
                <input
                  className="re-search"
                  value={entrySearch}
                  onChange={(e) => setEntrySearch(e.target.value)}
                  placeholder={`Search ${selectedMeta?.row_count ?? 0} entries...`}
                />
              </div>

              {/* Data table */}
              {entriesLoading ? (
                <div className="lt-table-loading">Loading entries...</div>
              ) : displayRows.length === 0 ? (
                <div className="lt-table-loading">
                  {entries.length === 0 ? 'No entries in this table.' : 'No entries match your search.'}
                </div>
              ) : (
                <div className="lt-data-wrap">
                  <table className="lt-data-table">
                    <thead>
                      <tr>
                        {editing && <th className="lt-th lt-th--action">#</th>}
                        {columns.map((col) => (
                          <th key={col} className="lt-th">{col}</th>
                        ))}
                        {editing && <th className="lt-th lt-th--action" />}
                      </tr>
                    </thead>
                    <tbody>
                      {displayRows.map((row, ri) => (
                        <tr key={ri} className="lt-tr">
                          {editing && <td className="lt-td lt-td--idx">{ri + 1}</td>}
                          {columns.map((col) => (
                            <td key={col} className="lt-td">
                              {editing ? (
                                <input
                                  className="lt-cell-input"
                                  value={editRows[ri]?.[col] ?? ''}
                                  onChange={(e) => handleCellChange(ri, col, e.target.value)}
                                />
                              ) : (
                                <span className="lt-cell-value">{row[col] ?? ''}</span>
                              )}
                            </td>
                          ))}
                          {editing && (
                            <td className="lt-td lt-td--action">
                              <button type="button" className="lt-delete-btn" onClick={() => handleDeleteRow(ri)} title="Delete row">
                                {trashIcon}
                              </button>
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── Create Modal ────────────────────────── */}
      {showCreate && (
        <div className="cd-modal-overlay" onClick={() => setShowCreate(false)}>
          <div className="cd-modal" onClick={(e) => e.stopPropagation()}>
            <h3 className="cd-modal-title">Create Lookup Table</h3>
            <p className="cd-modal-subtitle">Define a name and column schema for the new table.</p>
            <div className="cd-modal-field">
              <label className="cd-modal-label">Table Name</label>
              <input
                className="cd-inline-input"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g. approved_binaries"
              />
            </div>
            <div className="cd-modal-field">
              <label className="cd-modal-label">Columns (comma-separated)</label>
              <input
                className="cd-inline-input"
                value={newColumns}
                onChange={(e) => setNewColumns(e.target.value)}
                placeholder="e.g. hash, name, vendor, approved_by"
              />
            </div>
            <div className="cd-modal-actions">
              <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setShowCreate(false)}>Cancel</button>
              <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleCreate} disabled={creating || !newName.trim() || !newColumns.trim()}>
                {creating ? 'Creating...' : 'Create Table'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
