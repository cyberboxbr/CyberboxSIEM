import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  BacktestResult,
  DetectionMode,
  DetectionRule,
  DryRunResult,
  RuleVersion,
  Severity,
  TuneRuleResult,
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
} from '../api/client';

/* ── SVG Icons ────────────────────────────────────── */

const plusIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
  </svg>
);
const sparkleIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 2l3 7h7l-5.5 4.5 2 7L12 16l-6.5 4.5 2-7L2 9h7z"/>
  </svg>
);
const playIcon = (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="5 3 19 12 5 21 5 3"/>
  </svg>
);
const historyIcon = (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
  </svg>
);
const trashIcon = (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
  </svg>
);
const saveIcon = (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
  </svg>
);
const refreshIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
  </svg>
);
const searchIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>
);
const checkIcon = (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
);
const xIcon = (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
  </svg>
);

/* ── Component ────────────────────────────────────── */

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
  const [showVersions, setShowVersions] = useState(false);

  const [showGenerate, setShowGenerate] = useState(false);
  const [generateDesc, setGenerateDesc] = useState('');
  const [generating, setGenerating] = useState(false);
  const [generateExplanation, setGenerateExplanation] = useState('');

  const [tuneResult, setTuneResult] = useState<TuneRuleResult | null>(null);
  const [tuning, setTuning] = useState(false);

  // Active right tab
  const [activeTab, setActiveTab] = useState<'dryrun' | 'backtest' | 'versions'>('dryrun');

  const loadRules = useCallback(async () => {
    try {
      setLoading(true);
      const r = await getRules();
      setRules(r);
      setError('');
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadRules(); }, [loadRules]);

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      if (filterMode && r.schedule_or_stream !== filterMode) return false;
      if (filterSeverity && r.severity !== filterSeverity) return false;
      if (filterEnabled === 'true' && !r.enabled) return false;
      if (filterEnabled === 'false' && r.enabled) return false;
      if (searchText) {
        const title = String((r.compiled_plan as Record<string, unknown>)?.title ?? '');
        const source = r.sigma_source ?? '';
        const q = searchText.toLowerCase();
        if (!title.toLowerCase().includes(q) && !source.toLowerCase().includes(q) && !r.rule_id.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [rules, filterMode, filterSeverity, filterEnabled, searchText]);

  const selectRule = (rule: DetectionRule) => {
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
    setShowVersions(false);
    setTuneResult(null);
    setGenerateExplanation('');
  };

  const handleNewRule = () => {
    setSelectedRuleId(null);
    setSigmaSource('title: New Rule\nstatus: experimental\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\nlevel: medium');
    setSeverity('medium');
    setMode('stream');
    setEnabled(true);
    setDryRunResult(null);
    setBtResult(null);
    setVersions([]);
    setShowVersions(false);
    setTuneResult(null);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      if (selectedRuleId) {
        await updateRule(selectedRuleId, {
          sigma_source: sigmaSource, severity,
          schedule_or_stream: mode, enabled,
          schedule: mode === 'scheduled' ? { interval_seconds: intervalSeconds, lookback_seconds: lookbackSeconds } : undefined,
        });
      } else {
        const created = await createRule({
          sigma_source: sigmaSource, severity,
          schedule_or_stream: mode, enabled,
          schedule: mode === 'scheduled' ? { interval_seconds: intervalSeconds, lookback_seconds: lookbackSeconds } : undefined,
        });
        setSelectedRuleId(created.rule_id);
      }
      await loadRules();
      setError('');
    } catch (err) { setError(String(err)); }
    finally { setSaving(false); }
  };

  const handleDelete = async () => {
    if (!selectedRuleId || !confirm('Delete this rule?')) return;
    setDeleting(true);
    try {
      await deleteRule(selectedRuleId);
      setSelectedRuleId(null);
      setSigmaSource('');
      await loadRules();
    } catch (err) { setError(String(err)); }
    finally { setDeleting(false); }
  };

  const handleDryRun = async () => {
    setDryRunning(true);
    try {
      const result = await dryRunRule({ sigma_source: sigmaSource, severity, sample_event: JSON.parse(sampleEvent) });
      setDryRunResult(result);
    } catch (err) { setError(String(err)); }
    finally { setDryRunning(false); }
  };

  const handleBacktest = async () => {
    if (!selectedRuleId || !btFrom || !btTo) return;
    setBacktesting(true);
    try {
      const result = await backtestRule(selectedRuleId, { from: new Date(btFrom).toISOString(), to: new Date(btTo).toISOString() });
      setBtResult(result);
    } catch (err) { setError(String(err)); }
    finally { setBacktesting(false); }
  };

  const handleLoadVersions = async () => {
    if (!selectedRuleId) return;
    try {
      const v = await getRuleVersions(selectedRuleId);
      setVersions(v);
      setShowVersions(true);
      setActiveTab('versions');
    } catch (err) { setError(String(err)); }
  };

  const handleRestore = async (version: number) => {
    if (!selectedRuleId) return;
    try {
      const restored = await restoreRuleVersion(selectedRuleId, version);
      setSigmaSource(restored.sigma_source ?? '');
      setSeverity(restored.severity);
      setMode(restored.schedule_or_stream);
      setEnabled(restored.enabled);
      await loadRules();
    } catch (err) { setError(String(err)); }
  };

  const handleGenerate = async () => {
    if (!generateDesc.trim()) return;
    setGenerating(true);
    try {
      const result = await generateRule({ description: generateDesc.trim() });
      setSigmaSource(result.sigma_source);
      setGenerateExplanation(result.explanation);
      setShowGenerate(false);
    } catch (err) { setError(String(err)); }
    finally { setGenerating(false); }
  };

  const handleTune = async () => {
    if (!selectedRuleId) return;
    setTuning(true);
    try {
      const result = await tuneRule(selectedRuleId);
      setTuneResult(result);
    } catch (err) { setError(String(err)); }
    finally { setTuning(false); }
  };

  /* ── Stats ──────────────────────────────────────── */
  const stats = useMemo(() => {
    const s = { total: rules.length, stream: 0, scheduled: 0, enabled: 0, disabled: 0 };
    rules.forEach((r) => {
      if (r.schedule_or_stream === 'stream') s.stream++;
      else s.scheduled++;
      if (r.enabled) s.enabled++;
      else s.disabled++;
    });
    return s;
  }, [rules]);

  return (
    <div className="page re-page">
      {/* ── Header ──────────────────────────────── */}
      <div className="re-header">
        <div className="re-header-left">
          <h1 className="re-title">Detection Engineering</h1>
          <div className="re-stats">
            <span className="re-stat">{stats.total} rules</span>
            <span className="re-stat-sep" />
            <span className="re-stat">{stats.stream} stream</span>
            <span className="re-stat">{stats.scheduled} scheduled</span>
            <span className="re-stat-sep" />
            <span className="re-stat re-stat--good">{stats.enabled} enabled</span>
            <span className="re-stat re-stat--dim">{stats.disabled} disabled</span>
          </div>
        </div>
        <div className="re-header-actions">
          <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={loadRules}>
            {refreshIcon} Refresh
          </button>
          <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleNewRule}>
            {plusIcon} New Rule
          </button>
        </div>
      </div>

      {error && <div className="cd-error">{error}</div>}

      {/* ── Main Layout ─────────────────────────── */}
      <div className="re-layout">
        {/* ── Sidebar: Rule List ─────────────────── */}
        <div className="re-sidebar">
          <div className="re-search-wrap">
            {searchIcon}
            <input
              className="re-search"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder="Search rules..."
            />
          </div>

          <div className="re-filters">
            <select className="re-filter-select" value={filterMode} onChange={(e) => setFilterMode(e.target.value as '' | DetectionMode)}>
              <option value="">All modes</option>
              <option value="stream">Stream</option>
              <option value="scheduled">Scheduled</option>
            </select>
            <select className="re-filter-select" value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value as '' | Severity)}>
              <option value="">All sev</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select className="re-filter-select" value={filterEnabled} onChange={(e) => setFilterEnabled(e.target.value as '' | 'true' | 'false')}>
              <option value="">All</option>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
          </div>

          <div className="re-rule-list">
            {loading ? (
              <p className="empty-state">Loading...</p>
            ) : filteredRules.length === 0 ? (
              <p className="empty-state">No rules found.</p>
            ) : (
              filteredRules.map((r) => {
                const title = String((r.compiled_plan as Record<string, unknown>)?.title ?? r.rule_id.slice(0, 12));
                const isSelected = r.rule_id === selectedRuleId;
                return (
                  <div
                    key={r.rule_id}
                    className={`re-rule-item ${isSelected ? 're-rule-item--selected' : ''}`}
                    onClick={() => selectRule(r)}
                  >
                    <div className="re-rule-sev-dot" data-severity={r.severity} />
                    <div className="re-rule-info">
                      <span className="re-rule-name">{title}</span>
                      <div className="re-rule-meta">
                        <span className="re-rule-mode">{r.schedule_or_stream}</span>
                        <span className={`re-rule-status ${r.enabled ? 're-rule-status--on' : ''}`}>
                          {r.enabled ? 'ON' : 'OFF'}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* ── Main Editor Area ───────────────────── */}
        <div className="re-main">
          {/* Editor Panel */}
          <div className="re-panel">
            <div className="re-panel-header">
              <div className="cd-panel-title">
                <span>{selectedRuleId ? 'EDIT RULE' : 'NEW RULE'}</span>
                {selectedRuleId && (
                  <span className="re-rule-id">{selectedRuleId.slice(0, 8)}</span>
                )}
              </div>
              <div className="re-ai-btns">
                <button type="button" className="re-ai-btn" onClick={() => setShowGenerate(!showGenerate)}>
                  {sparkleIcon} AI Generate
                </button>
                {selectedRuleId && (
                  <button type="button" className="re-ai-btn" onClick={handleTune} disabled={tuning}>
                    {sparkleIcon} {tuning ? 'Tuning...' : 'AI Tune'}
                  </button>
                )}
              </div>
            </div>

            {/* AI Generate input */}
            {showGenerate && (
              <div className="re-ai-generate">
                <input
                  className="re-ai-input"
                  value={generateDesc}
                  onChange={(e) => setGenerateDesc(e.target.value)}
                  placeholder="Describe the detection rule in natural language..."
                />
                <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleGenerate} disabled={generating}>
                  {generating ? 'Generating...' : 'Generate'}
                </button>
              </div>
            )}

            {generateExplanation && (
              <div className="re-ai-explanation">{generateExplanation}</div>
            )}

            {/* YAML Editor */}
            <textarea
              className="re-code-editor"
              value={sigmaSource}
              onChange={(e) => setSigmaSource(e.target.value)}
              rows={18}
              spellCheck={false}
            />

            {/* Metadata row */}
            <div className="re-meta-row">
              <div className="re-meta-field">
                <label className="re-meta-label">Severity</label>
                <select className="re-meta-select" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="re-meta-field">
                <label className="re-meta-label">Mode</label>
                <select className="re-meta-select" value={mode} onChange={(e) => setMode(e.target.value as DetectionMode)}>
                  <option value="stream">Stream</option>
                  <option value="scheduled">Scheduled</option>
                </select>
              </div>
              <div className="re-meta-field re-meta-toggle">
                <label className="re-toggle-label">
                  <div className={`re-toggle ${enabled ? 're-toggle--on' : ''}`} onClick={() => setEnabled(!enabled)}>
                    <div className="re-toggle-thumb" />
                  </div>
                  <span>{enabled ? 'Enabled' : 'Disabled'}</span>
                </label>
              </div>
              {mode === 'scheduled' && (
                <>
                  <div className="re-meta-field">
                    <label className="re-meta-label">Interval (s)</label>
                    <input className="re-meta-input" type="number" value={intervalSeconds} onChange={(e) => setIntervalSeconds(Number(e.target.value))} min={1} />
                  </div>
                  <div className="re-meta-field">
                    <label className="re-meta-label">Lookback (s)</label>
                    <input className="re-meta-input" type="number" value={lookbackSeconds} onChange={(e) => setLookbackSeconds(Number(e.target.value))} min={1} />
                  </div>
                </>
              )}
            </div>

            {/* Action buttons */}
            <div className="re-editor-actions">
              <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleSave} disabled={saving}>
                {saveIcon} {saving ? 'Saving...' : 'Save Rule'}
              </button>
              {selectedRuleId && (
                <button type="button" className="cd-action-btn cd-action-btn--close" onClick={handleDelete} disabled={deleting}>
                  {trashIcon} {deleting ? 'Deleting...' : 'Delete'}
                </button>
              )}
            </div>
          </div>

          {/* AI Tune Diff Panel */}
          {tuneResult && (
            <div className="re-panel re-tune-panel">
              <div className="re-panel-header">
                <div className="cd-panel-title">
                  {sparkleIcon} <span>AI TUNE SUGGESTION</span>
                </div>
              </div>
              <div className="re-tune-explanation">{tuneResult.explanation}</div>
              {tuneResult.changes.length > 0 && (
                <ul className="re-tune-changes">
                  {tuneResult.changes.map((ch, i) => <li key={i}>{ch}</li>)}
                </ul>
              )}
              <div className="re-tune-diff">
                <div className="re-tune-col">
                  <span className="re-tune-col-label">CURRENT</span>
                  <pre className="re-tune-code">{sigmaSource}</pre>
                </div>
                <div className="re-tune-col">
                  <span className="re-tune-col-label re-tune-col-label--new">SUGGESTED</span>
                  <pre className="re-tune-code">{tuneResult.suggested_sigma_source}</pre>
                </div>
              </div>
              <div className="re-tune-actions">
                <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={() => { setSigmaSource(tuneResult.suggested_sigma_source); setTuneResult(null); }}>
                  {checkIcon} Accept
                </button>
                <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setTuneResult(null)}>
                  {xIcon} Dismiss
                </button>
              </div>
            </div>
          )}

          {/* ── Testing Tabs ─────────────────────── */}
          <div className="re-panel">
            <div className="re-tabs">
              <button className={`re-tab ${activeTab === 'dryrun' ? 're-tab--active' : ''}`} onClick={() => setActiveTab('dryrun')}>
                {playIcon} Dry-Run
              </button>
              {selectedRuleId && (
                <button className={`re-tab ${activeTab === 'backtest' ? 're-tab--active' : ''}`} onClick={() => setActiveTab('backtest')}>
                  {historyIcon} Backtest
                </button>
              )}
              {selectedRuleId && (
                <button className={`re-tab ${activeTab === 'versions' ? 're-tab--active' : ''}`} onClick={() => { setActiveTab('versions'); if (!showVersions) handleLoadVersions(); }}>
                  {historyIcon} Versions
                </button>
              )}
            </div>

            {/* Dry-Run */}
            {activeTab === 'dryrun' && (
              <div className="re-tab-content">
                <label className="re-meta-label" style={{ marginBottom: 6, display: 'block' }}>Sample Event (JSON)</label>
                <textarea
                  className="re-code-editor re-code-editor--small"
                  value={sampleEvent}
                  onChange={(e) => setSampleEvent(e.target.value)}
                  rows={5}
                  spellCheck={false}
                />
                <div className="re-dryrun-actions">
                  <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleDryRun} disabled={dryRunning}>
                    {playIcon} {dryRunning ? 'Running...' : 'Run Test'}
                  </button>
                  {dryRunResult && (
                    <div className={`re-dryrun-result ${dryRunResult.matched ? 're-dryrun-result--match' : 're-dryrun-result--miss'}`}>
                      <span className="re-dryrun-badge">
                        {dryRunResult.matched ? checkIcon : xIcon}
                        {dryRunResult.matched ? 'MATCHED' : 'NO MATCH'}
                      </span>
                      {dryRunResult.matched_conditions.length > 0 && (
                        <span className="re-dryrun-conditions">
                          {dryRunResult.matched_conditions.join(', ')}
                        </span>
                      )}
                      {dryRunResult.error && (
                        <span className="re-dryrun-error">{dryRunResult.error}</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Backtest */}
            {activeTab === 'backtest' && selectedRuleId && (
              <div className="re-tab-content">
                <div className="re-backtest-inputs">
                  <div className="re-meta-field">
                    <label className="re-meta-label">From</label>
                    <input className="re-meta-input" type="datetime-local" value={btFrom} onChange={(e) => setBtFrom(e.target.value)} />
                  </div>
                  <div className="re-meta-field">
                    <label className="re-meta-label">To</label>
                    <input className="re-meta-input" type="datetime-local" value={btTo} onChange={(e) => setBtTo(e.target.value)} />
                  </div>
                  <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleBacktest} disabled={backtesting || !btFrom || !btTo} style={{ alignSelf: 'flex-end' }}>
                    {playIcon} {backtesting ? 'Running...' : 'Run Backtest'}
                  </button>
                </div>
                {btResult && (
                  <div className="re-backtest-results">
                    <div className="re-bt-stat">
                      <span className="re-bt-value">{btResult.total_events_scanned.toLocaleString()}</span>
                      <span className="re-bt-label">Events Scanned</span>
                    </div>
                    <div className="re-bt-stat">
                      <span className="re-bt-value re-bt-value--warn">{btResult.matched_count}</span>
                      <span className="re-bt-label">Matched</span>
                    </div>
                    <div className="re-bt-stat">
                      <span className="re-bt-value re-bt-value--accent">{btResult.match_rate_pct.toFixed(2)}%</span>
                      <span className="re-bt-label">Match Rate</span>
                    </div>
                    <div className="re-bt-stat">
                      <span className="re-bt-value">{btResult.sample_event_ids.length}</span>
                      <span className="re-bt-label">Samples</span>
                    </div>
                    {btResult.sample_event_ids.length > 0 && (
                      <div className="re-bt-samples">
                        Sample IDs: {btResult.sample_event_ids.map((id) => id.slice(0, 8)).join(', ')}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Versions */}
            {activeTab === 'versions' && selectedRuleId && (
              <div className="re-tab-content">
                {versions.length === 0 ? (
                  <p className="empty-state">No versions recorded.</p>
                ) : (
                  <div className="re-version-list">
                    {versions.map((v) => (
                      <div key={v.version} className="re-version-item">
                        <div className="re-version-info">
                          <span className="re-version-num">v{v.version}</span>
                          <span className={`cd-sev-badge cd-sev-badge--${v.severity}`}>{v.severity.toUpperCase()}</span>
                          <span className={`re-rule-status ${v.enabled ? 're-rule-status--on' : ''}`}>
                            {v.enabled ? 'enabled' : 'disabled'}
                          </span>
                          <span className="re-version-time">{new Date(v.created_at).toLocaleString()}</span>
                        </div>
                        <button type="button" className="cd-action-btn cd-action-btn--small" onClick={() => handleRestore(v.version)}>
                          Restore
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
