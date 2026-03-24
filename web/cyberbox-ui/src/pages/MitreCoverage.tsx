import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ArrowRight,
  Crosshair,
  RefreshCcw,
  Search,
  Shield,
} from 'lucide-react';

import { getCoverage, type CoverageReport, type CoveredTechnique } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';

const TACTICS = [
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
] as const;

const TACTIC_LABELS: Record<string, string> = {
  'initial-access': 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral Movement',
  collection: 'Collection',
  'command-and-control': 'Command and Control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
};

function normalizeTactic(tactic: string | null | undefined): string {
  if (!tactic) return 'unknown';
  return tactic.toLowerCase().replace(/[\s_]+/g, '-');
}

function coverageTone(value: number): string {
  if (value >= 50) return 'text-emerald-300';
  if (value >= 25) return 'text-amber-100';
  return 'text-rose-200';
}

export function MitreCoverage() {
  const [report, setReport] = useState<CoverageReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [selectedTechnique, setSelectedTechnique] = useState<CoveredTechnique | null>(null);
  const [tacticFilter, setTacticFilter] = useState<'all' | string>('all');
  const [searchValue, setSearchValue] = useState('');

  const loadCoverage = async (showLoader: boolean) => {
    if (showLoader) setLoading(true);
    setError('');
    try {
      const data = await getCoverage();
      setReport(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { void loadCoverage(true); }, []);

  const byTactic = useMemo(() => {
    if (!report) return {} as Record<string, CoveredTechnique[]>;
    const map: Record<string, CoveredTechnique[]> = {};
    report.covered_techniques.forEach((technique) => {
      const key = normalizeTactic(technique.tactic);
      if (!map[key]) map[key] = [];
      map[key].push(technique);
    });
    Object.values(map).forEach((group) => {
      group.sort((left, right) => right.rule_count - left.rule_count || left.technique_id.localeCompare(right.technique_id));
    });
    return map;
  }, [report]);

  const filteredTechniques = useMemo(() => {
    if (!report) return [];
    const query = searchValue.trim().toLowerCase();
    return report.covered_techniques.filter((technique) => {
      const tactic = normalizeTactic(technique.tactic);
      if (tacticFilter !== 'all' && tactic !== tacticFilter) return false;
      if (!query) return true;
      return [technique.technique_id, technique.technique_name, technique.tactic, ...technique.rule_ids]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(query);
    });
  }, [report, searchValue, tacticFilter]);

  const tacticCounts = useMemo(
    () => TACTICS.map((tactic) => ({ tactic, count: (byTactic[tactic] ?? []).length })),
    [byTactic],
  );

  const maxTacticCount = useMemo(
    () => Math.max(1, ...tacticCounts.map((item) => item.count)),
    [tacticCounts],
  );

  if (loading && !report) {
    return <Card><CardContent className="h-[320px] animate-pulse p-6" /></Card>;
  }

  if (!report) {
    return (
      <WorkspaceEmptyState
        title="Coverage data unavailable"
        body={`We couldn’t load the current MITRE ATT&CK mapping.${error ? ` ${error}` : ''}`}
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}
        <span className="text-xs text-muted-foreground">{filteredTechniques.length} techniques</span>

        <div className="relative ml-2">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input type="text" value={searchValue} onChange={(e) => setSearchValue(e.target.value)} placeholder="T1059, PowerShell..." className="h-7 rounded-md border border-border/70 bg-card/60 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring" />
        </div>

        <div className="ml-auto flex items-center gap-2">
          <select value={tacticFilter} onChange={(e) => setTacticFilter(e.target.value)} className="h-7 rounded-md border border-border/70 bg-card/60 px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring">
            <option value="all">All tactics</option>
            {TACTICS.map((tactic) => <option key={tactic} value={tactic}>{TACTIC_LABELS[tactic]}</option>)}
          </select>
          <Button type="button" size="sm" variant="outline" onClick={() => { setRefreshing(true); void loadCoverage(false); }} disabled={refreshing}>
            <RefreshCcw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} /> Refresh
          </Button>
        </div>
      </div>

      {/* ── KPI row ──────────────────────────────────────────────────── */}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Coverage" value={`${report.coverage_pct.toFixed(1)}%`} hint={`${report.total_covered} of ${report.total_in_framework}`} />
        <WorkspaceMetricCard label="Techniques" value={String(report.total_covered)} hint="Backed by rules" />
        <WorkspaceMetricCard label="Visible" value={String(filteredTechniques.length)} hint="Matching filters" />
        <WorkspaceMetricCard label="Tactics hit" value={String(tacticCounts.filter((item) => item.count > 0).length)} hint="With coverage" />
      </section>

      <Card>
        <CardHeader className="pb-4">
          <CardTitle>ATT&CK matrix</CardTitle>
          <CardDescription>A horizontal tactic board showing all covered techniques and the depth of rule support behind them.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-flow-col auto-cols-[minmax(220px,1fr)] gap-4 overflow-x-auto pb-2">
            {TACTICS.map((tactic) => {
              const techniques = (byTactic[tactic] ?? []).filter((technique) =>
                tacticFilter === 'all' ? true : normalizeTactic(technique.tactic) === tacticFilter,
              );
              return (
                <div key={tactic} className="min-w-[220px] rounded-lg border border-border/70 bg-background/35 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-medium text-foreground">{TACTIC_LABELS[tactic]}</div>
                    <Badge variant={techniques.length ? 'success' : 'secondary'}>{techniques.length}</Badge>
                  </div>
                  <div className="mt-4 space-y-3">
                    {techniques.length === 0 ? (
                      <div className="rounded-lg border border-dashed border-border/70 bg-card/55 px-3 py-4 text-sm text-muted-foreground">
                        No mapped techniques yet.
                      </div>
                    ) : (
                      techniques.map((technique) => (
                        <button
                          key={technique.technique_id}
                          type="button"
                          className="w-full rounded-lg border border-border/70 bg-card/70 px-3 py-3 text-left transition-colors hover:bg-muted/45"
                          onClick={() => setSelectedTechnique(technique)}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="font-medium text-foreground">{technique.technique_id}</div>
                              <div className="mt-1 line-clamp-2 text-sm text-muted-foreground">{technique.technique_name}</div>
                            </div>
                            <Badge variant="outline">{technique.rule_count}</Badge>
                          </div>
                        </button>
                      ))
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <section className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Coverage by tactic</CardTitle>
            <CardDescription>Technique counts per tactic lane, sized relative to the strongest-covered lane.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {tacticCounts.map((item) => (
              <div key={item.tactic} className="grid gap-3 sm:grid-cols-[180px_minmax(0,1fr)_40px] sm:items-center">
                <div className="text-sm font-medium text-foreground">{TACTIC_LABELS[item.tactic]}</div>
                <div className="h-2 overflow-hidden rounded-full bg-muted/60">
                  <div className="h-full rounded-full bg-primary" style={{ width: `${item.count ? (item.count / maxTacticCount) * 100 : 0}%` }} />
                </div>
                <div className="text-right text-sm text-muted-foreground">{item.count}</div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Technique detail</CardTitle>
            <CardDescription>Click a technique from the matrix to inspect how many rules are mapped to it.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!selectedTechnique ? (
              <WorkspaceEmptyState title="No technique selected" body="Choose a technique in the ATT&CK matrix to inspect its mapped rules." />
            ) : (
              <>
                <div className="rounded-lg border border-border/70 bg-background/35 p-4">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{selectedTechnique.technique_id}</Badge>
                    <Badge variant="secondary">{selectedTechnique.rule_count} rules</Badge>
                  </div>
                  <div className="mt-4 font-display text-2xl font-semibold tracking-[-0.03em] text-foreground">{selectedTechnique.technique_name}</div>
                  <div className="mt-2 text-sm text-muted-foreground">{TACTIC_LABELS[normalizeTactic(selectedTechnique.tactic)] ?? selectedTechnique.tactic}</div>
                </div>
                <div className="space-y-3">
                  {selectedTechnique.rule_ids.length ? (
                    selectedTechnique.rule_ids.map((ruleId) => (
                      <div key={ruleId} className="flex items-center justify-between gap-3 rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                        <code className="text-sm text-foreground">{ruleId}</code>
                        <ArrowRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    ))
                  ) : (
                    <div className="rounded-lg border border-dashed border-border/70 bg-background/35 px-4 py-4 text-sm text-muted-foreground">
                      No rules are currently attached to this technique.
                    </div>
                  )}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
