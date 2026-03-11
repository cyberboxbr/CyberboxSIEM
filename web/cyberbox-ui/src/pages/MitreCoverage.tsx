import { useEffect, useMemo, useState } from 'react';
import {
  CoverageReport,
  CoveredTechnique,
  getCoverage,
} from '../api/client';

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
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'collection': 'Collection',
  'command-and-control': 'Command and Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
};

function normalizeTactic(tactic: string): string {
  return tactic.toLowerCase().replace(/[\s_]+/g, '-');
}

export function MitreCoverage() {
  const [report, setReport] = useState<CoverageReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedTechnique, setSelectedTechnique] = useState<CoveredTechnique | null>(null);

  const loadCoverage = async () => {
    try {
      setLoading(true);
      const data = await getCoverage();
      setReport(data);
      setError('');
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCoverage();
  }, []);

  // Group covered techniques by tactic
  const byTactic = useMemo(() => {
    if (!report) return {};
    const map: Record<string, CoveredTechnique[]> = {};
    for (const t of report.covered_techniques) {
      const key = normalizeTactic(t.tactic);
      if (!map[key]) map[key] = [];
      map[key].push(t);
    }
    return map;
  }, [report]);

  // Collect all technique IDs that are covered for quick lookup
  const coveredIds = useMemo(() => {
    if (!report) return new Set<string>();
    return new Set(report.covered_techniques.map((t) => t.technique_id));
  }, [report]);

  const panelStyle: React.CSSProperties = {
    border: '1px solid var(--border)',
    borderRadius: 14,
    background: 'var(--panel-bg)',
    padding: 16,
  };

  if (loading) return <div className="page"><p className="empty-state">Loading coverage data...</p></div>;
  if (!report) return <div className="page"><p className="empty-state">Failed to load coverage. {error}</p></div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">MITRE ATT&CK Coverage</h1>
        <div className="page-header-meta">
          <button type="button" className="btn-refresh" onClick={loadCoverage}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div style={{ color: '#f45d5d', fontSize: 13 }}>{error}</div>}

      {/* Coverage Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
        <div className="kpi-card" style={{ textAlign: 'center' }}>
          <span className="kpi-label">Coverage</span>
          <span
            className="kpi-value"
            style={{
              color: report.coverage_pct > 50 ? '#58d68d' : report.coverage_pct > 25 ? '#d4bc00' : '#f45d5d',
              fontSize: 36,
            }}
          >
            {report.coverage_pct.toFixed(1)}%
          </span>
        </div>
        <div className="kpi-card" style={{ textAlign: 'center' }}>
          <span className="kpi-label">Covered Techniques</span>
          <span className="kpi-value good">{report.total_covered}</span>
        </div>
        <div className="kpi-card" style={{ textAlign: 'center' }}>
          <span className="kpi-label">Total in Framework</span>
          <span className="kpi-value">{report.total_in_framework}</span>
        </div>
      </div>

      {/* Coverage progress bar */}
      <div style={{ height: 8, borderRadius: 4, background: 'rgba(88,143,186,0.15)', overflow: 'hidden' }}>
        <div
          style={{
            height: '100%',
            width: `${report.coverage_pct}%`,
            borderRadius: 4,
            background: report.coverage_pct > 50 ? '#58d68d' : report.coverage_pct > 25 ? '#d4bc00' : '#f45d5d',
            transition: 'width 0.4s ease',
          }}
        />
      </div>

      {/* Matrix Grid */}
      <div style={panelStyle}>
        <h2 className="panel-title">ATT&CK Matrix</h2>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: `repeat(${TACTICS.length}, minmax(0, 1fr))`,
            gap: 4,
            overflowX: 'auto',
          }}
        >
          {/* Tactic headers */}
          {TACTICS.map((tactic) => (
            <div
              key={tactic}
              style={{
                padding: '8px 4px',
                fontSize: 10,
                fontWeight: 700,
                color: '#dbe4f3',
                textAlign: 'center',
                borderBottom: '1px solid var(--border)',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
              title={TACTIC_LABELS[tactic] ?? tactic}
            >
              {TACTIC_LABELS[tactic] ?? tactic}
            </div>
          ))}

          {/* Technique cells */}
          {(() => {
            // Find max techniques per tactic to determine rows
            const maxRows = Math.max(1, ...TACTICS.map((t) => (byTactic[t] ?? []).length));
            const rows: React.ReactNode[] = [];
            for (let i = 0; i < maxRows; i++) {
              for (const tactic of TACTICS) {
                const techniques = byTactic[tactic] ?? [];
                const tech = techniques[i];
                if (tech) {
                  rows.push(
                    <div
                      key={`${tactic}-${i}`}
                      onClick={() => setSelectedTechnique(tech)}
                      style={{
                        padding: '6px 4px',
                        borderRadius: 4,
                        background: 'rgba(88,214,141,0.12)',
                        border: '1px solid rgba(88,214,141,0.25)',
                        cursor: 'pointer',
                        textAlign: 'center',
                        fontSize: 9,
                        color: '#58d68d',
                        position: 'relative',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={`${tech.technique_id}: ${tech.technique_name} (${tech.rule_count} rules)`}
                    >
                      <div style={{ fontWeight: 600 }}>{tech.technique_id}</div>
                      <div style={{ fontSize: 8, opacity: 0.8, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {tech.technique_name}
                      </div>
                      {tech.rule_count > 0 && (
                        <span
                          style={{
                            position: 'absolute',
                            top: 2,
                            right: 2,
                            background: '#58d68d',
                            color: '#050a14',
                            fontSize: 8,
                            fontWeight: 700,
                            borderRadius: 3,
                            padding: '0 3px',
                            lineHeight: '14px',
                          }}
                        >
                          {tech.rule_count}
                        </span>
                      )}
                    </div>,
                  );
                } else {
                  rows.push(
                    <div
                      key={`${tactic}-${i}-empty`}
                      style={{
                        padding: '6px 4px',
                        borderRadius: 4,
                        background: 'rgba(88,143,186,0.06)',
                        border: '1px solid transparent',
                      }}
                    />,
                  );
                }
              }
            }
            return rows;
          })()}
        </div>
      </div>

      {/* Technique Detail */}
      {selectedTechnique && (
        <div style={panelStyle}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <h2 className="panel-title" style={{ margin: 0 }}>
              {selectedTechnique.technique_id}: {selectedTechnique.technique_name}
            </h2>
            <button
              type="button"
              onClick={() => setSelectedTechnique(null)}
              style={{ padding: '4px 10px', fontSize: 11 }}
            >
              Close
            </button>
          </div>
          <div style={{ fontSize: 12, color: 'rgba(219,228,243,0.55)', marginBottom: 10 }}>
            Tactic: {selectedTechnique.tactic} | Rules covering: {selectedTechnique.rule_count}
          </div>
          {selectedTechnique.rule_ids.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {selectedTechnique.rule_ids.map((ruleId) => (
                <div
                  key={ruleId}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 6,
                    border: '1px solid var(--border)',
                    background: 'rgba(4,12,21,0.5)',
                    fontSize: 12,
                  }}
                >
                  <code
                    style={{
                      background: 'rgba(88,143,186,0.15)',
                      padding: '1px 6px',
                      borderRadius: 4,
                      color: '#9fd3ff',
                    }}
                  >
                    {ruleId}
                  </code>
                </div>
              ))}
            </div>
          ) : (
            <p className="empty-state">No rules mapped.</p>
          )}
        </div>
      )}

      {/* Uncovered Tactics Summary */}
      <div style={panelStyle}>
        <h2 className="panel-title">Coverage by Tactic</h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {TACTICS.map((tactic) => {
            const count = (byTactic[tactic] ?? []).length;
            return (
              <div key={tactic} style={{ display: 'grid', gridTemplateColumns: '180px 1fr 40px', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 500, color: '#dbe4f3' }}>
                  {TACTIC_LABELS[tactic] ?? tactic}
                </span>
                <div style={{ height: 6, borderRadius: 3, background: 'rgba(88,143,186,0.15)', overflow: 'hidden' }}>
                  <div
                    style={{
                      height: '100%',
                      width: count > 0 ? `${Math.min(100, count * 10)}%` : '0%',
                      borderRadius: 3,
                      background: count > 0 ? '#58d68d' : 'transparent',
                      transition: 'width 0.3s ease',
                    }}
                  />
                </div>
                <span style={{ fontSize: 12, color: count > 0 ? '#58d68d' : 'rgba(219,228,243,0.35)', textAlign: 'right' }}>
                  {count}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
