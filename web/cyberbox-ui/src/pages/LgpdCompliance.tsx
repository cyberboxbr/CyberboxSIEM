import { FormEvent, useCallback, useEffect, useState } from 'react';
import {
  getLgpdConfig,
  lgpdAnonymize,
  lgpdBreachReport,
  lgpdExport,
  LgpdBreachReportInput,
  LgpdBreachReportResponse,
  LgpdConfig,
} from '../api/client';

const s = {
  panelBg: 'rgba(9,21,35,0.82)',
  border: 'rgba(88,143,186,0.35)',
  inputBg: 'rgba(4,12,21,0.75)',
  text: '#dbe4f3',
  dim: 'rgba(219,228,243,0.5)',
  accent: '#4a9eda',
  good: '#58d68d',
  bad: '#f45d5d',
} as const;

const DATA_CATEGORIES = [
  'personal_identification',
  'financial',
  'health',
  'biometric',
  'location',
  'communications',
  'behavioral',
] as const;

function ActionCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className="panel"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
      }}
    >
      <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: s.text }}>{title}</h3>
      {children}
    </div>
  );
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

export function LgpdCompliance() {
  const [config, setConfig] = useState<LgpdConfig | null>(null);
  const [configError, setConfigError] = useState('');

  const [exportSubject, setExportSubject] = useState('');
  const [exportLoading, setExportLoading] = useState(false);
  const [exportResult, setExportResult] = useState<string | null>(null);
  const [exportError, setExportError] = useState('');

  const [anonSubject, setAnonSubject] = useState('');
  const [anonBefore, setAnonBefore] = useState('');
  const [anonLoading, setAnonLoading] = useState(false);
  const [anonResult, setAnonResult] = useState<{ anonymized_events: number; tenant_id: string } | null>(null);
  const [anonError, setAnonError] = useState('');

  const [brDescription, setBrDescription] = useState('');
  const [brCount, setBrCount] = useState(0);
  const [brCategories, setBrCategories] = useState<Set<string>>(new Set());
  const [brReportedToAnpd, setBrReportedToAnpd] = useState(false);
  const [brLoading, setBrLoading] = useState(false);
  const [brResult, setBrResult] = useState<LgpdBreachReportResponse | null>(null);
  const [brError, setBrError] = useState('');

  const loadConfig = useCallback(async () => {
    try {
      setConfig(await getLgpdConfig());
      setConfigError('');
    } catch (err) {
      setConfigError(String(err));
    }
  }, []);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  const onExport = async (e: FormEvent) => {
    e.preventDefault();
    setExportLoading(true);
    setExportResult(null);
    setExportError('');
    try {
      const resp = await lgpdExport({ subject_id: exportSubject.trim() });
      const blob = new Blob([JSON.stringify(resp, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `lgpd-export-${resp.subject_id}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setExportResult(
        `Exported ${resp.total_events} event(s) at ${formatTimestamp(resp.generated_at)}. Download started.`,
      );
    } catch (err) {
      setExportError(String(err));
    } finally {
      setExportLoading(false);
    }
  };

  const toggleBrCategory = (category: string) => {
    setBrCategories((prev) => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };

  const onAnonymize = async (e: FormEvent) => {
    e.preventDefault();
    setAnonLoading(true);
    setAnonResult(null);
    setAnonError('');
    try {
      const resp = await lgpdAnonymize({
        subject_id: anonSubject.trim(),
        before: anonBefore ? new Date(anonBefore).toISOString() : undefined,
      });
      setAnonResult({
        anonymized_events: resp.anonymized_events,
        tenant_id: resp.tenant_id,
      });
    } catch (err) {
      setAnonError(String(err));
    } finally {
      setAnonLoading(false);
    }
  };

  const onBreachReport = async (e: FormEvent) => {
    e.preventDefault();
    setBrLoading(true);
    setBrResult(null);
    setBrError('');
    try {
      const input: LgpdBreachReportInput = {
        description: brDescription,
        data_categories: Array.from(brCategories),
        estimated_subjects_affected: brCount,
        reported_to_anpd: brReportedToAnpd,
      };
      const resp = await lgpdBreachReport(input);
      setBrResult(resp);
    } catch (err) {
      setBrError(String(err));
    } finally {
      setBrLoading(false);
    }
  };

  const checkLabel = (active: boolean): React.CSSProperties => ({
    display: 'inline-flex',
    alignItems: 'center',
    gap: 4,
    cursor: 'pointer',
    fontSize: 12,
    flexDirection: 'row',
    color: active ? s.text : s.dim,
    padding: '2px 6px',
    borderRadius: 4,
    border: `1px solid ${active ? `${s.accent}55` : s.border}`,
    background: active ? `${s.accent}15` : 'transparent',
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">LGPD Compliance</h1>
      </div>

      <div className="panel" style={{ display: 'flex', gap: 24, alignItems: 'center', fontSize: 13 }}>
        {config ? (
          <>
            <div>
              <span style={{ color: s.dim }}>DPO Email: </span>
              <strong>{config.dpo_email}</strong>
            </div>
            <div>
              <span style={{ color: s.dim }}>Legal Basis: </span>
              <strong>{config.legal_basis}</strong>
            </div>
            <div>
              <span style={{ color: s.dim }}>Controller: </span>
              <strong>{config.controller_name}</strong>
            </div>
          </>
        ) : configError ? (
          <span style={{ color: s.bad }}>{configError}</span>
        ) : (
          <span style={{ color: s.dim }}>Loading config...</span>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
        <ActionCard title="Data Subject Export">
          <form onSubmit={onExport} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <label>
              Subject ID
              <input
                value={exportSubject}
                onChange={(e) => setExportSubject(e.target.value)}
                required
                placeholder="user@example.com or CPF"
              />
            </label>
            <p style={{ margin: 0, fontSize: 12, color: s.dim }}>
              Downloads the full DSAR package, including controller metadata, export time, and matched events.
            </p>
            <button
              type="submit"
              disabled={exportLoading}
              style={{
                padding: '8px 16px',
                background: 'rgba(74,158,218,0.2)',
                borderColor: s.accent,
                fontWeight: 700,
              }}
            >
              {exportLoading ? 'Exporting...' : 'Export Data'}
            </button>
            {exportResult && <p style={{ fontSize: 12, color: s.good, margin: 0 }}>{exportResult}</p>}
            {exportError && <p style={{ fontSize: 12, color: s.bad, margin: 0 }}>{exportError}</p>}
          </form>
        </ActionCard>

        <ActionCard title="Anonymize Subject Data">
          <form onSubmit={onAnonymize} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <label>
              Subject ID
              <input
                value={anonSubject}
                onChange={(e) => setAnonSubject(e.target.value)}
                required
                placeholder="user@example.com"
              />
            </label>
            <label>
              Optional Cutoff
              <input
                type="datetime-local"
                value={anonBefore}
                onChange={(e) => setAnonBefore(e.target.value)}
              />
            </label>
            <p style={{ margin: 0, fontSize: 12, color: s.dim }}>
              The current backend anonymizes all matching payload values for the subject within the selected time window.
            </p>
            <button
              type="submit"
              disabled={anonLoading || !anonSubject.trim()}
              style={{
                padding: '8px 16px',
                background: 'rgba(245,166,35,0.2)',
                borderColor: '#f5a623',
                fontWeight: 700,
              }}
            >
              {anonLoading ? 'Anonymizing...' : 'Anonymize'}
            </button>
            {anonResult && (
              <p style={{ fontSize: 12, color: s.good, margin: 0 }}>
                Anonymized {anonResult.anonymized_events} event(s) in tenant {anonResult.tenant_id}.
              </p>
            )}
            {anonError && <p style={{ fontSize: 12, color: s.bad, margin: 0 }}>{anonError}</p>}
          </form>
        </ActionCard>

        <ActionCard title="Breach Report">
          <form onSubmit={onBreachReport} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <label>
              Description
              <textarea
                value={brDescription}
                onChange={(e) => setBrDescription(e.target.value)}
                required
                rows={3}
                style={{ resize: 'vertical', fontSize: 12 }}
                placeholder="Describe the breach incident..."
              />
            </label>
            <label>
              Estimated Subjects Affected
              <input
                type="number"
                min={0}
                value={brCount}
                onChange={(e) => setBrCount(Number(e.target.value))}
                required
              />
            </label>
            <div>
              <span style={{ fontSize: 12, color: s.dim, marginBottom: 4, display: 'block' }}>Data categories:</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {DATA_CATEGORIES.map((category) => (
                  <label key={category} style={checkLabel(brCategories.has(category))}>
                    <input
                      type="checkbox"
                      checked={brCategories.has(category)}
                      onChange={() => toggleBrCategory(category)}
                      style={{ width: 14, height: 14 }}
                    />
                    {category.replace(/_/g, ' ')}
                  </label>
                ))}
              </div>
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: s.text }}>
              <input
                type="checkbox"
                checked={brReportedToAnpd}
                onChange={(e) => setBrReportedToAnpd(e.target.checked)}
              />
              Already reported to ANPD
            </label>
            <button
              type="submit"
              disabled={brLoading}
              style={{
                padding: '8px 16px',
                background: 'rgba(244,93,93,0.2)',
                borderColor: s.bad,
                fontWeight: 700,
              }}
            >
              {brLoading ? 'Submitting...' : 'Submit Breach Report'}
            </button>
            {brResult && (
              <div style={{ fontSize: 12, color: s.good, margin: 0 }}>
                <p style={{ margin: 0 }}>
                  Incident ID: <code>{brResult.incident_id}</code>
                </p>
                <p style={{ margin: '4px 0 0' }}>Reported At: {formatTimestamp(brResult.reported_at)}</p>
                <p style={{ margin: '4px 0 0' }}>
                  ANPD Deadline: {formatTimestamp(brResult.anpd_notification_deadline)}
                </p>
                <p style={{ margin: '4px 0 0' }}>
                  Reported to ANPD: <strong>{brResult.reported_to_anpd ? 'Yes' : 'No'}</strong>
                </p>
              </div>
            )}
            {brError && <p style={{ fontSize: 12, color: s.bad, margin: 0 }}>{brError}</p>}
          </form>
        </ActionCard>
      </div>
    </div>
  );
}
