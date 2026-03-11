import { FormEvent, useCallback, useEffect, useState } from 'react';
import {
  getLgpdConfig,
  lgpdAnonymize,
  lgpdBreachReport,
  lgpdExport,
  LgpdBreachReportInput,
  LgpdConfig,
} from '../api/client';

// ---------------------------------------------------------------------------
// Dark theme tokens
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// PII field presets
// ---------------------------------------------------------------------------

const PII_FIELDS = [
  'email',
  'ip_address',
  'username',
  'hostname',
  'phone_number',
  'cpf',
  'full_name',
  'address',
] as const;

const DATA_CATEGORIES = [
  'personal_identification',
  'financial',
  'health',
  'biometric',
  'location',
  'communications',
  'behavioral',
] as const;

// ---------------------------------------------------------------------------
// Card wrapper
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function LgpdCompliance() {
  // Config
  const [config, setConfig] = useState<LgpdConfig | null>(null);
  const [configError, setConfigError] = useState('');

  // Export
  const [exportSubject, setExportSubject] = useState('');
  const [exportLoading, setExportLoading] = useState(false);
  const [exportResult, setExportResult] = useState<string | null>(null);
  const [exportError, setExportError] = useState('');

  // Anonymize
  const [anonSubject, setAnonSubject] = useState('');
  const [anonFields, setAnonFields] = useState<Set<string>>(new Set());
  const [anonLoading, setAnonLoading] = useState(false);
  const [anonCount, setAnonCount] = useState<number | null>(null);
  const [anonError, setAnonError] = useState('');

  // Breach report
  const [brDescription, setBrDescription] = useState('');
  const [brCount, setBrCount] = useState(0);
  const [brCategories, setBrCategories] = useState<Set<string>>(new Set());
  const [brLoading, setBrLoading] = useState(false);
  const [brResult, setBrResult] = useState<{ report_id: string; dpo_notified: boolean } | null>(null);
  const [brError, setBrError] = useState('');

  const loadConfig = useCallback(async () => {
    try {
      setConfig(await getLgpdConfig());
    } catch (err) {
      setConfigError(String(err));
    }
  }, []);

  useEffect(() => { loadConfig(); }, [loadConfig]);

  // ─── Export handler ──────────────────────────────────────────────────────

  const onExport = async (e: FormEvent) => {
    e.preventDefault();
    setExportLoading(true);
    setExportResult(null);
    setExportError('');
    try {
      const resp = await lgpdExport({ subject_identifier: exportSubject });
      // Trigger download
      const blob = new Blob([JSON.stringify(resp.events, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `lgpd-export-${exportSubject}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setExportResult(`Exported ${resp.events.length} event(s). Download started.`);
    } catch (err) {
      setExportError(String(err));
    } finally {
      setExportLoading(false);
    }
  };

  // ─── Anonymize handler ───────────────────────────────────────────────────

  const toggleAnonField = (f: string) => {
    setAnonFields((prev) => {
      const next = new Set(prev);
      if (next.has(f)) next.delete(f);
      else next.add(f);
      return next;
    });
  };

  const onAnonymize = async (e: FormEvent) => {
    e.preventDefault();
    setAnonLoading(true);
    setAnonCount(null);
    setAnonError('');
    try {
      const resp = await lgpdAnonymize({
        subject_identifier: anonSubject,
        fields: Array.from(anonFields),
      });
      setAnonCount(resp.anonymized_count);
    } catch (err) {
      setAnonError(String(err));
    } finally {
      setAnonLoading(false);
    }
  };

  // ─── Breach report handler ──────────────────────────────────────────────

  const toggleBrCategory = (c: string) => {
    setBrCategories((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });
  };

  const onBreachReport = async (e: FormEvent) => {
    e.preventDefault();
    setBrLoading(true);
    setBrResult(null);
    setBrError('');
    try {
      const input: LgpdBreachReportInput = {
        description: brDescription,
        affected_subjects_count: brCount,
        data_categories: Array.from(brCategories),
      };
      const resp = await lgpdBreachReport(input);
      setBrResult(resp);
    } catch (err) {
      setBrError(String(err));
    } finally {
      setBrLoading(false);
    }
  };

  // ─── checkbox style ──────────────────────────────────────────────────────

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
    border: `1px solid ${active ? s.accent + '55' : s.border}`,
    background: active ? `${s.accent}15` : 'transparent',
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">LGPD Compliance</h1>
      </div>

      {/* Config display */}
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

      {/* Three action cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
        {/* Data Subject Export */}
        <ActionCard title="Data Subject Export">
          <form onSubmit={onExport} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <label>
              Subject Identifier
              <input
                value={exportSubject}
                onChange={(e) => setExportSubject(e.target.value)}
                required
                placeholder="user@example.com or CPF"
              />
            </label>
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

        {/* Anonymize PII */}
        <ActionCard title="Anonymize PII">
          <form onSubmit={onAnonymize} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <label>
              Subject Identifier
              <input
                value={anonSubject}
                onChange={(e) => setAnonSubject(e.target.value)}
                required
                placeholder="user@example.com"
              />
            </label>
            <div>
              <span style={{ fontSize: 12, color: s.dim, marginBottom: 4, display: 'block' }}>Fields to anonymize:</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {PII_FIELDS.map((f) => (
                  <label key={f} style={checkLabel(anonFields.has(f))}>
                    <input
                      type="checkbox"
                      checked={anonFields.has(f)}
                      onChange={() => toggleAnonField(f)}
                      style={{ width: 14, height: 14 }}
                    />
                    {f}
                  </label>
                ))}
              </div>
            </div>
            <button
              type="submit"
              disabled={anonLoading || anonFields.size === 0}
              style={{
                padding: '8px 16px',
                background: 'rgba(245,166,35,0.2)',
                borderColor: '#f5a623',
                fontWeight: 700,
              }}
            >
              {anonLoading ? 'Anonymizing...' : 'Anonymize'}
            </button>
            {anonCount !== null && (
              <p style={{ fontSize: 12, color: s.good, margin: 0 }}>
                Anonymized {anonCount} record(s).
              </p>
            )}
            {anonError && <p style={{ fontSize: 12, color: s.bad, margin: 0 }}>{anonError}</p>}
          </form>
        </ActionCard>

        {/* Breach Report */}
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
              Affected Subjects Count
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
                {DATA_CATEGORIES.map((c) => (
                  <label key={c} style={checkLabel(brCategories.has(c))}>
                    <input
                      type="checkbox"
                      checked={brCategories.has(c)}
                      onChange={() => toggleBrCategory(c)}
                      style={{ width: 14, height: 14 }}
                    />
                    {c.replace(/_/g, ' ')}
                  </label>
                ))}
              </div>
            </div>
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
                <p style={{ margin: 0 }}>Report ID: <code>{brResult.report_id}</code></p>
                <p style={{ margin: '4px 0 0' }}>
                  DPO Notified: <strong>{brResult.dpo_notified ? 'Yes' : 'No'}</strong>
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
