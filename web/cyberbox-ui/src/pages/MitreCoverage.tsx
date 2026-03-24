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
    <div className="space-y-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.45fr)_360px]">
        <Card className="overflow-hidden border-primary/15 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.15),transparent_40%),linear-gradient(145deg,hsl(var(--card)),hsl(var(--card)/0.85))]">
          <CardContent className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(250px,0.85fr)]">
            <div>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant="outline" className="border-primary/25 bg-primary/10 text-primary">ATT&CK coverage workspace</Badge>
                <Badge variant="secondary" className="bg-background/55">{report.total_covered} mapped techniques</Badge>
              </div>
              <div className="max-w-2xl font-display text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-foreground sm:text-[3rem]">
                See where your detections already reach and where coverage is still thin.
              </div>
              <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
                The ATT&CK board highlights which tactics are covered, which techniques have the heaviest rule backing, and where the biggest gaps still live.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button type="button" variant="outline" onClick={() => { setRefreshing(true); void loadCoverage(false); }} disabled={refreshing}>
                  <RefreshCcw className={refreshing ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
                  Refresh coverage
                </Button>
              </div>
            </div>
            <div className="grid gap-3 rounded-[28px] border border-border/70 bg-background/35 p-4">
              <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Framework coverage</div>
                <div className={`mt-3 font-display text-4xl font-semibold tracking-[-0.04em] ${coverageTone(report.coverage_pct)}`}>
                  {report.coverage_pct.toFixed(1)}%
                </div>
              </div>
              <div className="rounded-full bg-muted/60">
                <div
                  className={`h-2 rounded-full ${report.coverage_pct >= 50 ? 'bg-emerald-400' : report.coverage_pct >= 25 ? 'bg-amber-300' : 'bg-rose-400'}`}
                  style={{ width: `${Math.max(report.coverage_pct, 4)}%` }}
                />
              </div>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Covered</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{report.total_covered}</div>
                </div>
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Framework total</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{report.total_in_framework}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Filters</CardTitle>
            <CardDescription>Focus on a tactic lane or search for a technique, rule ID, or ATT&CK identifier.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div>
              <div className="mb-2 text-sm font-medium text-foreground">Tactic</div>
              <Select value={tacticFilter} onChange={(event) => setTacticFilter(event.target.value)}>
                <option value="all">All tactics</option>
                {TACTICS.map((tactic) => <option key={tactic} value={tactic}>{TACTIC_LABELS[tactic]}</option>)}
              </Select>
            </div>
            <div>
              <div className="mb-2 text-sm font-medium text-foreground">Search</div>
              <div className="relative">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input className="pl-11" value={searchValue} onChange={(event) => setSearchValue(event.target.value)} placeholder="T1059, PowerShell, rule id..." />
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Coverage" value={`${report.coverage_pct.toFixed(1)}%`} hint="Mapped techniques versus the total ATT&CK framework set." icon={Shield} />
        <WorkspaceMetricCard label="Techniques" value={String(report.total_covered)} hint="Techniques currently backed by one or more rules." icon={Crosshair} />
        <WorkspaceMetricCard label="Visible" value={String(filteredTechniques.length)} hint="Techniques matching the active filter set." icon={Search} />
        <WorkspaceMetricCard label="Tactics hit" value={String(tacticCounts.filter((item) => item.count > 0).length)} hint="Tactic lanes with at least one mapped technique." icon={Activity} />
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
                <div key={tactic} className="min-w-[220px] rounded-[24px] border border-border/70 bg-background/35 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-medium text-foreground">{TACTIC_LABELS[tactic]}</div>
                    <Badge variant={techniques.length ? 'success' : 'secondary'}>{techniques.length}</Badge>
                  </div>
                  <div className="mt-4 space-y-3">
                    {techniques.length === 0 ? (
                      <div className="rounded-[18px] border border-dashed border-border/70 bg-card/55 px-3 py-4 text-sm text-muted-foreground">
                        No mapped techniques yet.
                      </div>
                    ) : (
                      techniques.map((technique) => (
                        <button
                          key={technique.technique_id}
                          type="button"
                          className="w-full rounded-[18px] border border-border/70 bg-card/70 px-3 py-3 text-left transition-colors hover:bg-muted/45"
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

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
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
                <div className="rounded-[24px] border border-border/70 bg-background/35 p-4">
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
                      <div key={ruleId} className="flex items-center justify-between gap-3 rounded-[20px] border border-border/70 bg-background/35 px-4 py-3">
                        <code className="text-sm text-foreground">{ruleId}</code>
                        <ArrowRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    ))
                  ) : (
                    <div className="rounded-[20px] border border-dashed border-border/70 bg-background/35 px-4 py-4 text-sm text-muted-foreground">
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
