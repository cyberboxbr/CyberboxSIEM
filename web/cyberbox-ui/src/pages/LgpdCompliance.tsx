import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Download, RefreshCcw } from 'lucide-react';

import {
  getLgpdConfig,
  lgpdAnonymize,
  lgpdBreachReport,
  lgpdExport,
  type LgpdAnonymizeResponse,
  type LgpdBreachReportInput,
  type LgpdBreachReportResponse,
  type LgpdConfig,
  type LgpdExportResponse,
} from '@/api/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';

const DATA_CATEGORIES = [
  'personal_identification',
  'financial',
  'health',
  'biometric',
  'location',
  'communications',
  'behavioral',
] as const;

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function categoryLabel(category: string): string {
  return category.replace(/_/g, ' ');
}

export function LgpdCompliance() {
  const [config, setConfig] = useState<LgpdConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [configError, setConfigError] = useState('');

  const [exportSubject, setExportSubject] = useState('');
  const [exportLoading, setExportLoading] = useState(false);
  const [exportResult, setExportResult] = useState<LgpdExportResponse | null>(null);
  const [exportError, setExportError] = useState('');

  const [anonSubject, setAnonSubject] = useState('');
  const [anonBefore, setAnonBefore] = useState('');
  const [anonLoading, setAnonLoading] = useState(false);
  const [anonResult, setAnonResult] = useState<LgpdAnonymizeResponse | null>(null);
  const [anonError, setAnonError] = useState('');

  const [breachDescription, setBreachDescription] = useState('');
  const [breachCount, setBreachCount] = useState(0);
  const [breachCategories, setBreachCategories] = useState<Set<string>>(new Set());
  const [reportedToAnpd, setReportedToAnpd] = useState(false);
  const [breachLoading, setBreachLoading] = useState(false);
  const [breachResult, setBreachResult] = useState<LgpdBreachReportResponse | null>(null);
  const [breachError, setBreachError] = useState('');

  const loadConfig = useCallback(async () => {
    setConfigLoading(true);
    try {
      setConfig(await getLgpdConfig());
      setConfigError('');
    } catch (err) {
      setConfigError(String(err));
    } finally {
      setConfigLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  const onExport = async (event: FormEvent) => {
    event.preventDefault();
    setExportLoading(true);
    setExportResult(null);
    setExportError('');

    try {
      const response = await lgpdExport({ subject_id: exportSubject.trim() });
      const blob = new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `lgpd-export-${response.subject_id}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setExportResult(response);
    } catch (err) {
      setExportError(String(err));
    } finally {
      setExportLoading(false);
    }
  };

  const onAnonymize = async (event: FormEvent) => {
    event.preventDefault();
    setAnonLoading(true);
    setAnonResult(null);
    setAnonError('');

    try {
      const response = await lgpdAnonymize({
        subject_id: anonSubject.trim(),
        before: anonBefore ? new Date(anonBefore).toISOString() : undefined,
      });
      setAnonResult(response);
    } catch (err) {
      setAnonError(String(err));
    } finally {
      setAnonLoading(false);
    }
  };

  const toggleBreachCategory = (category: string) => {
    setBreachCategories((current) => {
      const next = new Set(current);
      if (next.has(category)) next.delete(category);
      else next.add(category);
      return next;
    });
  };

  const onBreachReport = async (event: FormEvent) => {
    event.preventDefault();
    setBreachLoading(true);
    setBreachResult(null);
    setBreachError('');

    try {
      const input: LgpdBreachReportInput = {
        description: breachDescription.trim(),
        data_categories: Array.from(breachCategories),
        estimated_subjects_affected: breachCount,
        reported_to_anpd: reportedToAnpd,
      };
      setBreachResult(await lgpdBreachReport(input));
    } catch (err) {
      setBreachError(String(err));
    } finally {
      setBreachLoading(false);
    }
  };

  const stats = useMemo(() => ({
    workflows: '3',
    dpoReady: config?.dpo_email ? 'Ready' : 'Missing',
    categories: String(DATA_CATEGORIES.length),
    selectedCategories: String(breachCategories.size),
  }), [breachCategories.size, config?.dpo_email]);

  return (
    <div className="flex flex-col gap-3">
      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {configError && <WorkspaceStatusBanner tone="warning">{configError}</WorkspaceStatusBanner>}

        <span className="text-xs text-muted-foreground">
          {config?.controller_name ?? 'Controller config pending'}
        </span>

        <div className="ml-auto flex items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={() => void loadConfig()} disabled={configLoading}>
            <RefreshCcw className={cn('h-3.5 w-3.5', configLoading && 'animate-spin')} /> Refresh
          </Button>
        </div>
      </div>

      {/* ── KPI row ──────────────────────────────────────────────────── */}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Workflows" value={stats.workflows} hint="Privacy flows available." />
        <WorkspaceMetricCard label="DPO" value={stats.dpoReady} hint="DPO contact status in config." />
        <WorkspaceMetricCard label="Categories" value={stats.categories} hint="Categories for breach classification." />
        <WorkspaceMetricCard label="Selected" value={stats.selectedCategories} hint="Categories selected in breach form." />
      </section>

      <section className="grid gap-3 xl:grid-cols-3">
        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Data subject export</CardTitle>
            <CardDescription>Generate the DSAR package for a subject and download the resulting JSON export immediately.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-2" onSubmit={(event) => void onExport(event)}>
              <div>
                <div className="mb-2 text-sm font-medium text-foreground">Subject ID</div>
                <Input
                  value={exportSubject}
                  onChange={(event) => setExportSubject(event.target.value)}
                  placeholder="user@example.com or CPF"
                  required
                />
              </div>
              <WorkspaceStatusBanner tone="neutral">
                The export contains controller metadata, the generation timestamp, and the matched events for the selected subject.
              </WorkspaceStatusBanner>
              <Button type="submit" className="w-full justify-center" disabled={exportLoading || !exportSubject.trim()}>
                <Download className="h-4 w-4" />
                {exportLoading ? 'Exporting...' : 'Export subject data'}
              </Button>
              {exportResult && (
                <WorkspaceStatusBanner tone="success">
                  Exported <strong>{exportResult.total_events}</strong> event(s) for <strong>{exportResult.subject_id}</strong> at{' '}
                  <strong>{formatTimestamp(exportResult.generated_at)}</strong>. Download started automatically.
                </WorkspaceStatusBanner>
              )}
              {exportError && <WorkspaceStatusBanner tone="warning">{exportError}</WorkspaceStatusBanner>}
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Anonymize subject data</CardTitle>
            <CardDescription>Remove identifiable subject values from matching events, optionally constrained by a cutoff time.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-2" onSubmit={(event) => void onAnonymize(event)}>
              <div>
                <div className="mb-2 text-sm font-medium text-foreground">Subject ID</div>
                <Input
                  value={anonSubject}
                  onChange={(event) => setAnonSubject(event.target.value)}
                  placeholder="user@example.com"
                  required
                />
              </div>
              <div>
                <div className="mb-2 text-sm font-medium text-foreground">Optional cutoff</div>
                <Input type="datetime-local" value={anonBefore} onChange={(event) => setAnonBefore(event.target.value)} />
              </div>
              <WorkspaceStatusBanner tone="neutral">
                When a cutoff is provided, only matching events before that timestamp are anonymized.
              </WorkspaceStatusBanner>
              <Button type="submit" className="w-full justify-center" disabled={anonLoading || !anonSubject.trim()}>
                {anonLoading ? 'Anonymizing...' : 'Run anonymization'}
              </Button>
              {anonResult && (
                <WorkspaceStatusBanner tone="success">
                  Anonymized <strong>{anonResult.anonymized_events}</strong> event(s) in tenant <strong>{anonResult.tenant_id}</strong>.
                </WorkspaceStatusBanner>
              )}
              {anonError && <WorkspaceStatusBanner tone="warning">{anonError}</WorkspaceStatusBanner>}
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Breach report</CardTitle>
            <CardDescription>Capture the incident summary, data categories, affected subject count, and ANPD notification status.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-2" onSubmit={(event) => void onBreachReport(event)}>
              <div>
                <div className="mb-2 text-sm font-medium text-foreground">Description</div>
                <Textarea
                  rows={4}
                  value={breachDescription}
                  onChange={(event) => setBreachDescription(event.target.value)}
                  placeholder="Describe the breach incident and what was exposed."
                  required
                />
              </div>
              <div>
                <div className="mb-2 text-sm font-medium text-foreground">Estimated subjects affected</div>
                <Input
                  type="number"
                  min={0}
                  value={String(breachCount)}
                  onChange={(event) => setBreachCount(Number(event.target.value))}
                  required
                />
              </div>
              <div>
                <div className="mb-2 text-sm font-medium text-foreground">Data categories</div>
                <div className="flex flex-wrap gap-2">
                  {DATA_CATEGORIES.map((category) => {
                    const active = breachCategories.has(category);
                    return (
                      <button
                        key={category}
                        type="button"
                        className={cn(
                          'rounded-full border px-3 py-2 text-xs font-semibold uppercase tracking-[0.22em] transition-colors',
                          active
                            ? 'border-primary/25 bg-primary/10 text-primary'
                            : 'border-border/70 bg-background/35 text-muted-foreground hover:bg-muted/40',
                        )}
                        onClick={() => toggleBreachCategory(category)}
                      >
                        {categoryLabel(category)}
                      </button>
                    );
                  })}
                </div>
              </div>
              <label className="flex items-center gap-3 rounded-lg border border-border/70 bg-background/35 px-4 py-3 text-sm text-foreground">
                <input type="checkbox" checked={reportedToAnpd} onChange={(event) => setReportedToAnpd(event.target.checked)} />
                Already reported to ANPD
              </label>
              <Button type="submit" className="w-full justify-center" disabled={breachLoading || !breachDescription.trim()}>
                {breachLoading ? 'Submitting...' : 'Submit breach report'}
              </Button>
              {breachResult && (
                <WorkspaceStatusBanner tone="success">
                  Incident <strong>{breachResult.incident_id}</strong> was recorded at <strong>{formatTimestamp(breachResult.reported_at)}</strong>.
                  ANPD deadline: <strong>{formatTimestamp(breachResult.anpd_notification_deadline)}</strong>.
                </WorkspaceStatusBanner>
              )}
              {breachError && <WorkspaceStatusBanner tone="warning">{breachError}</WorkspaceStatusBanner>}
            </form>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
