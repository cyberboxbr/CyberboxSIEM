import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Bot,
  FlaskConical,
  History,
  Plus,
  RefreshCcw,
  Save,
  Search,
  Shield,
  Sparkles,
  Trash2,
} from 'lucide-react';

import {
  backtestRule,
  createRule,
  deleteRule,
  dryRunRule,
  generateRule,
  getRuleVersions,
  getRules,
  restoreRuleVersion,
  tuneRule,
  updateRule,
  type BacktestResult,
  type DetectionMode,
  type DetectionRule,
  type DryRunResult,
  type RuleVersion,
  type Severity,
  type TuneRuleResult,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';

const fieldClass = 'flex h-8 w-full rounded-lg border border-border/80 bg-background/45 px-3 py-1 text-xs text-foreground transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring';

function ruleName(rule: DetectionRule) {
  const title = (rule.compiled_plan as Record<string, unknown>)?.title;
  return typeof title === 'string' && title ? title : `Rule ${rule.rule_id.slice(0, 8)}`;
}

function sevVariant(severity: Severity): 'destructive' | 'warning' | 'info' | 'secondary' {
  if (severity === 'critical') return 'destructive';
  if (severity === 'high') return 'warning';
  if (severity === 'medium') return 'info';
  return 'secondary';
}

export function RuleEditor() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [searchText, setSearchText] = useState('');
  const [filterMode, setFilterMode] = useState<'' | DetectionMode>('');
  const [filterSeverity, setFilterSeverity] = useState<'' | Severity>('');
  const [filterEnabled, setFilterEnabled] = useState<'' | 'true' | 'false'>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [sigmaSource, setSigmaSource] = useState('');
  const [severity, setSeverity] = useState<Severity>('medium');
  const [mode, setMode] = useState<DetectionMode>('stream');
  const [enabled, setEnabled] = useState(true);
  const [intervalSeconds, setIntervalSeconds] = useState(300);
  const [lookbackSeconds, setLookbackSeconds] = useState(600);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const [sampleEvent, setSampleEvent] = useState('{\n  "event_code": 1,\n  "process_name": "powershell.exe",\n  "cmdline": "powershell -enc AAAA"\n}');
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null);
  const [dryRunning, setDryRunning] = useState(false);
  const [btFrom, setBtFrom] = useState('');
  const [btTo, setBtTo] = useState('');
  const [btResult, setBtResult] = useState<BacktestResult | null>(null);
  const [backtesting, setBacktesting] = useState(false);
  const [versions, setVersions] = useState<RuleVersion[]>([]);
  const [activeTab, setActiveTab] = useState<'dryrun' | 'backtest' | 'versions'>('dryrun');

  const [showGenerate, setShowGenerate] = useState(false);
  const [generateDesc, setGenerateDesc] = useState('');
  const [generateExplanation, setGenerateExplanation] = useState('');
  const [generating, setGenerating] = useState(false);
  const [tuneResult, setTuneResult] = useState<TuneRuleResult | null>(null);
  const [tuning, setTuning] = useState(false);

  const loadRules = useCallback(async () => {
    try {
      setLoading(true);
      setRules(await getRules());
      setError('');
    } catch (cause) {
      setError(String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadRules(); }, [loadRules]);

  const selectRule = useCallback((rule: DetectionRule) => {
    setSelectedRuleId(rule.rule_id);
    setSigmaSource(rule.sigma_source ?? '');
    setSeverity(rule.severity);
    setMode(rule.schedule_or_stream);
    setEnabled(rule.enabled);
    setIntervalSeconds(rule.schedule?.interval_seconds ?? 300);
    setLookbackSeconds(rule.schedule?.lookback_seconds ?? 600);
    setDryRunResult(null);
    setBtResult(null);
    setVersions([]);
    setTuneResult(null);
    setGenerateExplanation('');
  }, []);

  useEffect(() => {
    if (!selectedRuleId && !sigmaSource && rules.length > 0) selectRule(rules[0]);
  }, [rules, selectedRuleId, selectRule, sigmaSource]);

  const filteredRules = useMemo(() => rules.filter((rule) => {
    if (filterMode && rule.schedule_or_stream !== filterMode) return false;
    if (filterSeverity && rule.severity !== filterSeverity) return false;
    if (filterEnabled === 'true' && !rule.enabled) return false;
    if (filterEnabled === 'false' && rule.enabled) return false;
    if (!searchText) return true;
    const q = searchText.toLowerCase();
    return ruleName(rule).toLowerCase().includes(q) || rule.sigma_source.toLowerCase().includes(q) || rule.rule_id.toLowerCase().includes(q);
  }), [filterEnabled, filterMode, filterSeverity, rules, searchText]);

  const stats = useMemo(() => ({
    total: rules.length,
    enabled: rules.filter((r) => r.enabled).length,
    stream: rules.filter((r) => r.schedule_or_stream === 'stream').length,
    scheduled: rules.filter((r) => r.schedule_or_stream === 'scheduled').length,
  }), [rules]);

  const newRule = () => {
    setSelectedRuleId(null);
    setSigmaSource('title: New Rule\nstatus: experimental\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\nlevel: medium');
    setSeverity('medium');
    setMode('stream');
    setEnabled(true);
    setIntervalSeconds(300);
    setLookbackSeconds(600);
    setDryRunResult(null);
    setBtResult(null);
    setVersions([]);
    setTuneResult(null);
    setGenerateExplanation('');
  };

  const saveRule = async () => {
    setSaving(true);
    try {
      const payload = {
        sigma_source: sigmaSource,
        severity,
        schedule_or_stream: mode,
        enabled,
        schedule: mode === 'scheduled' ? { interval_seconds: intervalSeconds, lookback_seconds: lookbackSeconds } : undefined,
      };
      if (selectedRuleId) await updateRule(selectedRuleId, payload);
      else setSelectedRuleId((await createRule(payload)).rule_id);
      await loadRules();
      setError('');
    } catch (cause) {
      setError(String(cause));
    } finally {
      setSaving(false);
    }
  };

  const removeRule = async () => {
    if (!selectedRuleId || !window.confirm('Delete this rule?')) return;
    setDeleting(true);
    try {
      await deleteRule(selectedRuleId);
      newRule();
      await loadRules();
    } catch (cause) {
      setError(String(cause));
    } finally {
      setDeleting(false);
    }
  };

  const runDry = async () => {
    setDryRunning(true);
    try {
      setDryRunResult(await dryRunRule({ sigma_source: sigmaSource, severity, sample_event: JSON.parse(sampleEvent) }));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setDryRunning(false);
    }
  };

  const runBacktest = async () => {
    if (!selectedRuleId || !btFrom || !btTo) return;
    setBacktesting(true);
    try {
      setBtResult(await backtestRule(selectedRuleId, { from: new Date(btFrom).toISOString(), to: new Date(btTo).toISOString() }));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBacktesting(false);
    }
  };

  const loadVersions = async () => {
    if (!selectedRuleId) return;
    try {
      setVersions(await getRuleVersions(selectedRuleId));
    } catch (cause) {
      setError(String(cause));
    }
  };

  const restoreVersion = async (version: number) => {
    if (!selectedRuleId) return;
    try {
      selectRule(await restoreRuleVersion(selectedRuleId, version));
      await loadRules();
    } catch (cause) {
      setError(String(cause));
    }
  };

  const generate = async () => {
    if (!generateDesc.trim()) return;
    setGenerating(true);
    try {
      const result = await generateRule({ description: generateDesc.trim() });
      setSigmaSource(result.sigma_source);
      setGenerateExplanation(result.explanation);
      setShowGenerate(false);
    } catch (cause) {
      setError(String(cause));
    } finally {
      setGenerating(false);
    }
  };

  const tune = async () => {
    if (!selectedRuleId) return;
    setTuning(true);
    try {
      setTuneResult(await tuneRule(selectedRuleId));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setTuning(false);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Rules" value={String(stats.total)} hint="Total in catalog" />
        <WorkspaceMetricCard label="Enabled" value={String(stats.enabled)} hint="Active detections" />
        <WorkspaceMetricCard label="Stream" value={String(stats.stream)} hint="Real-time evaluation" />
        <WorkspaceMetricCard label="Scheduled" value={String(stats.scheduled)} hint="Interval-based" />
      </section>

      <section className="grid gap-3 xl:grid-cols-[280px_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <div className="flex items-start justify-between gap-3">
              <div><CardTitle>Detection catalog</CardTitle><CardDescription>Search, filter, and jump between live rules.</CardDescription></div>
              <Button type="button" variant="outline" size="icon" onClick={() => void loadRules()}><RefreshCcw className="h-4 w-4" /></Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="relative"><Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input className="pl-11" value={searchText} onChange={(e) => setSearchText(e.target.value)} placeholder="Search rules..." /></div>
            <div className="grid gap-3">
              <select className={fieldClass} value={filterMode} onChange={(e) => setFilterMode(e.target.value as '' | DetectionMode)}><option value="">All modes</option><option value="stream">Stream</option><option value="scheduled">Scheduled</option></select>
              <select className={fieldClass} value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value as '' | Severity)}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
              <select className={fieldClass} value={filterEnabled} onChange={(e) => setFilterEnabled(e.target.value as '' | 'true' | 'false')}><option value="">All states</option><option value="true">Enabled</option><option value="false">Disabled</option></select>
            </div>
            <Button type="button" className="w-full" onClick={newRule}><Plus className="h-4 w-4" />New rule</Button>
            <div className="max-h-[720px] space-y-3 overflow-y-auto pr-1">
              {loading ? <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-6 text-sm text-muted-foreground">Loading rules...</div> : filteredRules.map((rule) => <button key={rule.rule_id} type="button" className={cn('w-full rounded-lg border p-4 text-left transition-colors', selectedRuleId === rule.rule_id ? 'border-primary/30 bg-primary/10' : 'border-border/70 bg-background/35 hover:bg-muted/45')} onClick={() => selectRule(rule)}><div className="flex items-start justify-between gap-3"><div className="min-w-0"><div className="truncate font-medium text-foreground">{ruleName(rule)}</div><div className="mt-2 flex flex-wrap gap-2"><Badge variant={sevVariant(rule.severity)}>{rule.severity}</Badge><Badge variant="outline">{rule.schedule_or_stream}</Badge>{!rule.enabled && <Badge variant="secondary">disabled</Badge>}</div></div><Shield className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" /></div></button>)}
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4">
          {error && <WorkspaceStatusBanner tone="danger">{error}</WorkspaceStatusBanner>}

          <Card>
            <CardHeader>
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div><CardTitle>{selectedRuleId ? 'Edit rule' : 'New rule'}</CardTitle><CardDescription>{selectedRuleId ? selectedRuleId : 'Create a new detection with Sigma source and execution settings.'}</CardDescription></div>
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" onClick={() => setShowGenerate((v) => !v)}><Sparkles className="h-4 w-4" />AI generate</Button>
                  {selectedRuleId && <Button type="button" variant="outline" onClick={() => void tune()} disabled={tuning}><Bot className="h-4 w-4" />{tuning ? 'Tuning...' : 'AI tune'}</Button>}
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              {showGenerate && <div className="grid gap-3 rounded-lg border border-border/70 bg-background/35 p-4 lg:grid-cols-[minmax(0,1fr)_auto]"><Input value={generateDesc} onChange={(e) => setGenerateDesc(e.target.value)} placeholder="Describe the detection you want to generate..." /><Button type="button" onClick={() => void generate()} disabled={generating}>{generating ? 'Generating...' : 'Generate'}</Button></div>}
                  {generateExplanation && <WorkspaceStatusBanner>{generateExplanation}</WorkspaceStatusBanner>}
              <Textarea value={sigmaSource} onChange={(e) => setSigmaSource(e.target.value)} className="min-h-[360px] font-mono text-[13px]" spellCheck={false} />
              <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-5">
                <div><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Severity</div><select className={fieldClass} value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
                <div><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Mode</div><select className={fieldClass} value={mode} onChange={(e) => setMode(e.target.value as DetectionMode)}><option value="stream">Stream</option><option value="scheduled">Scheduled</option></select></div>
                <div><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">State</div><button type="button" className={cn('flex h-11 w-full items-center justify-center rounded-2xl border text-sm font-medium transition-colors', enabled ? 'border-primary/30 bg-primary/12 text-primary' : 'border-border/80 bg-background/45 text-muted-foreground')} onClick={() => setEnabled((v) => !v)}>{enabled ? 'Enabled' : 'Disabled'}</button></div>
                {mode === 'scheduled' && <><div><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Interval</div><Input type="number" value={intervalSeconds} onChange={(e) => setIntervalSeconds(Number(e.target.value))} min={1} /></div><div><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Lookback</div><Input type="number" value={lookbackSeconds} onChange={(e) => setLookbackSeconds(Number(e.target.value))} min={1} /></div></>}
              </div>
              <div className="flex flex-wrap gap-3">
                <Button type="button" onClick={() => void saveRule()} disabled={saving}><Save className="h-4 w-4" />{saving ? 'Saving...' : 'Save rule'}</Button>
                {selectedRuleId && <Button type="button" variant="destructive" onClick={() => void removeRule()} disabled={deleting}><Trash2 className="h-4 w-4" />{deleting ? 'Deleting...' : 'Delete'}</Button>}
              </div>
            </CardContent>
          </Card>

          {tuneResult && <Card><CardHeader><CardTitle>AI tune suggestion</CardTitle><CardDescription>{tuneResult.explanation}</CardDescription></CardHeader><CardContent className="space-y-4">{tuneResult.changes.length > 0 && <div className="space-y-2">{tuneResult.changes.map((change) => <div key={change} className="rounded-lg border border-border/70 bg-background/35 px-4 py-3 text-sm text-foreground">{change}</div>)}</div>}<div className="grid gap-4 xl:grid-cols-2"><div><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Current</div><pre className="overflow-x-auto rounded-lg border border-border/70 bg-background/35 p-4 text-xs text-foreground">{sigmaSource}</pre></div><div><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Suggested</div><pre className="overflow-x-auto rounded-lg border border-primary/20 bg-primary/10 p-4 text-xs text-foreground">{tuneResult.suggested_sigma_source}</pre></div></div><div className="flex flex-wrap gap-2"><Button type="button" onClick={() => { setSigmaSource(tuneResult.suggested_sigma_source); setTuneResult(null); }}>Accept suggestion</Button><Button type="button" variant="outline" onClick={() => setTuneResult(null)}>Dismiss</Button></div></CardContent></Card>}

          <Card>
            <CardHeader><CardTitle>Rule lab</CardTitle><CardDescription>Dry-run the Sigma, backtest it, and restore older versions.</CardDescription></CardHeader>
            <CardContent className="space-y-5">
              <div className="flex flex-wrap gap-2">
                <Button type="button" variant={activeTab === 'dryrun' ? 'default' : 'outline'} size="sm" onClick={() => setActiveTab('dryrun')}><FlaskConical className="h-4 w-4" />Dry run</Button>
                {selectedRuleId && <Button type="button" variant={activeTab === 'backtest' ? 'default' : 'outline'} size="sm" onClick={() => setActiveTab('backtest')}><History className="h-4 w-4" />Backtest</Button>}
                {selectedRuleId && <Button type="button" variant={activeTab === 'versions' ? 'default' : 'outline'} size="sm" onClick={() => { setActiveTab('versions'); void loadVersions(); }}><History className="h-4 w-4" />Versions</Button>}
              </div>

              {activeTab === 'dryrun' && <div className="space-y-4"><Textarea value={sampleEvent} onChange={(e) => setSampleEvent(e.target.value)} className="min-h-[180px] font-mono text-[13px]" spellCheck={false} /><div className="flex flex-wrap items-center gap-3"><Button type="button" onClick={() => void runDry()} disabled={dryRunning}>{dryRunning ? 'Running...' : 'Run dry test'}</Button>{dryRunResult && <Badge variant={dryRunResult.matched ? 'success' : 'secondary'}>{dryRunResult.matched ? 'matched' : 'no match'}</Badge>}</div>{dryRunResult && <div className="rounded-lg border border-border/70 bg-background/35 p-4 text-sm">{dryRunResult.matched_conditions.length > 0 && <div className="mb-2 text-foreground">Conditions: {dryRunResult.matched_conditions.join(', ')}</div>}{dryRunResult.error && <div className="text-destructive">{dryRunResult.error}</div>}</div>}</div>}

              {activeTab === 'backtest' && selectedRuleId && <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]"><Input type="datetime-local" value={btFrom} onChange={(e) => setBtFrom(e.target.value)} /><Input type="datetime-local" value={btTo} onChange={(e) => setBtTo(e.target.value)} /><Button type="button" className="lg:self-end" onClick={() => void runBacktest()} disabled={backtesting || !btFrom || !btTo}>{backtesting ? 'Running...' : 'Run backtest'}</Button>{btResult && <div className="lg:col-span-3 grid gap-3 sm:grid-cols-4">{[{ label: 'Events', value: btResult.total_events_scanned }, { label: 'Matched', value: btResult.matched_count }, { label: 'Rate', value: Number(btResult.match_rate_pct.toFixed(2)) }, { label: 'Samples', value: btResult.sample_event_ids.length }].map((item) => <div key={item.label} className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">{item.label}</div><div className="mt-2 text-xl font-semibold text-foreground">{item.label === 'Rate' ? `${item.value}%` : item.value}</div></div>)}</div>}</div>}

              {activeTab === 'versions' && selectedRuleId && <div className="space-y-3">{versions.length === 0 ? <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-6 text-sm text-muted-foreground">No versions recorded yet.</div> : versions.map((version) => <div key={version.version} className="flex flex-col gap-3 rounded-lg border border-border/70 bg-background/35 p-4 sm:flex-row sm:items-center sm:justify-between"><div className="flex flex-wrap items-center gap-2"><Badge variant="outline">v{version.version}</Badge><Badge variant={sevVariant(version.severity)}>{version.severity}</Badge><Badge variant={version.enabled ? 'success' : 'secondary'}>{version.enabled ? 'enabled' : 'disabled'}</Badge><span className="text-sm text-muted-foreground">{new Date(version.created_at).toLocaleString()}</span></div><Button type="button" variant="outline" size="sm" onClick={() => void restoreVersion(version.version)}>Restore</Button></div>)}</div>}
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}
