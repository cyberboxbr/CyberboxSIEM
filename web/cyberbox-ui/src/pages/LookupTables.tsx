import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Database,
  PencilLine,
  Plus,
  RefreshCcw,
  Save,
  Search,
  Table2,
  Trash2,
  XCircle,
} from 'lucide-react';

import {
  createLookupTable,
  getLookupEntries,
  getLookupTables,
  updateLookupEntries,
  type LookupTable,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceModal } from '@/components/workspace/modal-shell';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { WorkspaceTableShell } from '@/components/workspace/table-shell';
import { cn } from '@/lib/utils';

export function LookupTables() {
  const [tables, setTables] = useState<LookupTable[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [searchText, setSearchText] = useState('');
  const [selectedTable, setSelectedTable] = useState<string | null>(null);
  const [entries, setEntries] = useState<Array<Record<string, string>>>([]);
  const [entriesLoading, setEntriesLoading] = useState(false);
  const [entrySearch, setEntrySearch] = useState('');
  const [editing, setEditing] = useState(false);
  const [editRows, setEditRows] = useState<Array<Record<string, string>>>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [newColumns, setNewColumns] = useState('');
  const [creating, setCreating] = useState(false);

  const loadTables = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      setTables(await getLookupTables());
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadEntries = useCallback(async (name: string) => {
    setEntriesLoading(true);
    try {
      setEntries(await getLookupEntries(name));
      setEditing(false);
    } catch (err) {
      setError(String(err));
    } finally {
      setEntriesLoading(false);
    }
  }, []);

  useEffect(() => { void loadTables(); }, [loadTables]);

  const filteredTables = useMemo(() => {
    if (!searchText) return tables;
    const query = searchText.toLowerCase();
    return tables.filter((table) => table.name.toLowerCase().includes(query));
  }, [tables, searchText]);

  const selectedMeta = useMemo(
    () => tables.find((table) => table.name === selectedTable),
    [tables, selectedTable],
  );

  const columns = selectedMeta?.columns ?? [];

  const displayRows = useMemo(() => {
    const source = editing ? editRows : entries;
    const query = entrySearch.toLowerCase();
    const indexed = source.map((row, index) => ({ row, index }));
    if (!query) return indexed;
    return indexed.filter(({ row }) => Object.values(row).some((value) => value.toLowerCase().includes(query)));
  }, [editing, editRows, entries, entrySearch]);

  const totalRows = useMemo(() => tables.reduce((sum, table) => sum + table.row_count, 0), [tables]);

  const handleSelectTable = (name: string) => {
    setSelectedTable(name);
    setEntrySearch('');
    setEditing(false);
    void loadEntries(name);
  };

  const handleCreate = async () => {
    if (!newName.trim() || !newColumns.trim()) return;
    setCreating(true);
    setMessage('Creating lookup table...');
    try {
      const normalizedName = newName.trim().toLowerCase().replace(/\s+/g, '_');
      await createLookupTable({
        name: normalizedName,
        columns: newColumns.split(',').map((column) => column.trim()).filter(Boolean),
        rows: [],
      });
      setShowCreate(false);
      setNewName('');
      setNewColumns('');
      await loadTables();
      handleSelectTable(normalizedName);
      setMessage('Lookup table created.');
    } catch (err) {
      setMessage(String(err));
    } finally {
      setCreating(false);
    }
  };

  const handleStartEdit = () => {
    setEditRows(entries.map((row) => ({ ...row })));
    setEditing(true);
  };

  const handleSaveEntries = async () => {
    if (!selectedTable) return;
    setMessage('Saving lookup entries...');
    try {
      const updated = await updateLookupEntries(selectedTable, editRows);
      setEntries(updated);
      setEditing(false);
      await loadTables();
      setMessage('Lookup entries saved.');
    } catch (err) {
      setMessage(String(err));
    }
  };

  const handleCellChange = (rowIdx: number, col: string, value: string) => {
    setEditRows((current) => {
      const next = [...current];
      next[rowIdx] = { ...next[rowIdx], [col]: value };
      return next;
    });
  };

  const handleAddRow = () => {
    if (!selectedMeta) return;
    const nextRow: Record<string, string> = {};
    selectedMeta.columns.forEach((column) => { nextRow[column] = ''; });
    setEditRows((current) => [...current, nextRow]);
  };

  const handleDeleteRow = (rowIdx: number) => {
    setEditRows((current) => current.filter((_, index) => index !== rowIdx));
  };

  return (
    <div className="space-y-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.45fr)_360px]">
        <Card className="overflow-hidden border-primary/15 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.15),transparent_40%),linear-gradient(145deg,hsl(var(--card)),hsl(var(--card)/0.85))]">
          <CardContent className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(250px,0.85fr)]">
            <div>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant="outline" className="border-primary/25 bg-primary/10 text-primary">Lookup table workspace</Badge>
                <Badge variant="secondary" className="bg-background/55">{tables.length} tables</Badge>
              </div>
              <div className="max-w-2xl font-display text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-foreground sm:text-[3rem]">
                Keep enrichment data editable, searchable, and close to the detections that use it.
              </div>
              <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
                This board gives you a faster way to browse lookup schemas, edit rows, and keep enrichment sources current without dropping back to raw JSON.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button type="button" onClick={() => setShowCreate(true)}>
                  <Plus className="h-4 w-4" />
                  New table
                </Button>
                <Button type="button" variant="outline" onClick={() => void loadTables()} disabled={loading}>
                  <RefreshCcw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
                  Refresh tables
                </Button>
              </div>
            </div>
            <div className="grid gap-3 rounded-[28px] border border-border/70 bg-background/35 p-4">
              <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Total rows</div>
                <div className="mt-3 font-display text-4xl font-semibold tracking-[-0.04em] text-foreground">{totalRows.toLocaleString()}</div>
              </div>
              <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-1">
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Tables</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{tables.length}</div>
                </div>
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Selected rows</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{selectedMeta?.row_count ?? 0}</div>
                </div>
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Columns</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{columns.length}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Table search</CardTitle>
            <CardDescription>Find a table by name and jump directly into its row set.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div>
              <div className="mb-2 text-sm font-medium text-foreground">Search tables</div>
              <div className="relative">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input className="pl-11" value={searchText} onChange={(event) => setSearchText(event.target.value)} placeholder="approved_binaries, suspicious_ips..." />
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}
      {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Tables" value={String(tables.length)} hint="Lookup schemas available to enrich detections and search." icon={Database} />
        <WorkspaceMetricCard label="Rows" value={totalRows.toLocaleString()} hint="Total records stored across every lookup table." icon={Table2} />
        <WorkspaceMetricCard label="Visible" value={String(filteredTables.length)} hint="Tables matching the current search query." icon={Search} />
        <WorkspaceMetricCard label="Selected columns" value={String(columns.length)} hint={selectedTable ? `Schema for ${selectedTable}` : 'Pick a table to inspect its schema.'} icon={PencilLine} />
      </section>

      <section className="grid gap-6 xl:grid-cols-[320px_minmax(0,1fr)]">
        <Card className="overflow-hidden">
          <CardHeader className="pb-4">
            <CardTitle>Tables</CardTitle>
            <CardDescription>Select a lookup source to inspect its schema and edit its rows.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {loading ? (
              <Card className="animate-pulse"><CardContent className="h-[220px] p-4" /></Card>
            ) : !filteredTables.length ? (
              <WorkspaceEmptyState title="No tables found" body="Try a broader search or create a new lookup table." />
            ) : (
              filteredTables.map((table) => (
                <button
                  key={table.name}
                  type="button"
                  className={cn(
                    'w-full rounded-[24px] border px-4 py-4 text-left transition-colors',
                    selectedTable === table.name
                      ? 'border-primary/30 bg-primary/10'
                      : 'border-border/70 bg-background/35 hover:bg-muted/40',
                  )}
                  onClick={() => handleSelectTable(table.name)}
                >
                  <div className="flex items-start gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-border/70 bg-card/70 text-primary">
                      <Database className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="font-medium text-foreground">{table.name}</div>
                      <div className="mt-1 flex flex-wrap gap-2 text-sm text-muted-foreground">
                        <span>{table.columns.length} columns</span>
                        <span>{table.row_count.toLocaleString()} rows</span>
                      </div>
                    </div>
                  </div>
                </button>
              ))
            )}
          </CardContent>
        </Card>

        {!selectedTable ? (
          <WorkspaceEmptyState title="Select a lookup table" body="Choose a table from the left side to browse its schema and edit its rows." />
        ) : (
          <Card>
            <CardHeader className="pb-4">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <CardTitle>{selectedTable}</CardTitle>
                  <CardDescription className="mt-2">
                    {selectedMeta?.row_count ?? 0} rows across {columns.length} columns.
                  </CardDescription>
                </div>
                <div className="flex flex-wrap gap-3">
                  {!editing ? (
                    <Button type="button" variant="outline" onClick={handleStartEdit}>
                      <PencilLine className="h-4 w-4" />
                      Edit rows
                    </Button>
                  ) : (
                    <>
                      <Button type="button" variant="outline" onClick={handleAddRow}>
                        <Plus className="h-4 w-4" />
                        Add row
                      </Button>
                      <Button type="button" onClick={() => void handleSaveEntries()}>
                        <Save className="h-4 w-4" />
                        Save
                      </Button>
                      <Button type="button" variant="outline" onClick={() => setEditing(false)}>
                        <XCircle className="h-4 w-4" />
                        Cancel
                      </Button>
                    </>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="flex flex-wrap gap-2">
                {columns.map((column) => <Badge key={column} variant="outline">{column}</Badge>)}
              </div>

              <div>
                <div className="mb-2 text-sm font-medium text-foreground">Search rows</div>
                <div className="relative">
                  <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input className="pl-11" value={entrySearch} onChange={(event) => setEntrySearch(event.target.value)} placeholder={`Search ${selectedMeta?.row_count ?? 0} entries...`} />
                </div>
              </div>

              {entriesLoading ? (
                <Card className="animate-pulse"><CardContent className="h-[320px] p-4" /></Card>
              ) : !displayRows.length ? (
                <WorkspaceEmptyState title={entries.length === 0 ? 'No entries in this table' : 'No entries match your search'} body={entries.length === 0 ? 'Start editing to add the first row to this lookup table.' : 'Try a different row search to bring matching values into view.'} />
              ) : (
                <WorkspaceTableShell>
                  <table className="min-w-full border-collapse text-sm">
                    <thead>
                      <tr className="border-b border-border/70 bg-card/70">
                        {editing && <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">#</th>}
                        {columns.map((column) => (
                          <th key={column} className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">
                            {column}
                          </th>
                        ))}
                        {editing && <th className="px-4 py-3 text-right text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Actions</th>}
                      </tr>
                    </thead>
                    <tbody>
                      {displayRows.map(({ row, index }) => (
                        <tr key={`${selectedTable}-${index}`} className="border-b border-border/70 last:border-b-0">
                          {editing && <td className="px-4 py-3 text-muted-foreground">{index + 1}</td>}
                          {columns.map((column) => (
                            <td key={column} className="px-4 py-3 align-top">
                              {editing ? (
                                <Input
                                  value={editRows[index]?.[column] ?? ''}
                                  onChange={(event) => handleCellChange(index, column, event.target.value)}
                                  className="h-10 rounded-xl"
                                />
                              ) : (
                                <span className="text-foreground">{row[column] ?? ''}</span>
                              )}
                            </td>
                          ))}
                          {editing && (
                            <td className="px-4 py-3 text-right">
                              <Button type="button" size="sm" variant="outline" onClick={() => handleDeleteRow(index)}>
                                <Trash2 className="h-4 w-4" />
                                Delete
                              </Button>
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </WorkspaceTableShell>
              )}
            </CardContent>
          </Card>
        )}
      </section>

      <WorkspaceModal
        open={showCreate}
        title="Create lookup table"
        description="Define a lookup schema first, then start adding rows from the main table editor."
        onClose={() => setShowCreate(false)}
        panelClassName="max-w-xl"
      >
        <div>
          <div className="mb-2 text-sm font-medium text-foreground">Table name</div>
          <Input value={newName} onChange={(event) => setNewName(event.target.value)} placeholder="approved_binaries" />
        </div>
        <div>
          <div className="mb-2 text-sm font-medium text-foreground">Columns</div>
          <Textarea value={newColumns} onChange={(event) => setNewColumns(event.target.value)} rows={4} placeholder="hash, name, vendor, approved_by" />
        </div>
        <div className="flex flex-wrap justify-end gap-3">
          <Button type="button" variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
          <Button type="button" onClick={() => void handleCreate()} disabled={creating || !newName.trim() || !newColumns.trim()}>
            {creating ? 'Creating...' : 'Create table'}
          </Button>
        </div>
      </WorkspaceModal>
    </div>
  );
}
