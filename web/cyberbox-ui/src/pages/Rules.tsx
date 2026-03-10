import { FormEvent, useMemo, useState } from 'react';
import {
  DetectionMode,
  DetectionRule,
  Severity,
  createRule,
  deleteRule,
  updateRule,
} from '../api/client';

interface RulesProps {
  rules: DetectionRule[];
  onRefresh: () => Promise<void>;
  onStatusText: (msg: string) => void;
  statusText: string;
}

export function Rules({ rules, onRefresh, onStatusText, statusText }: RulesProps) {
  const [sigmaSource, setSigmaSource] = useState(
    'title: Suspicious PowerShell\nproduct: windows\ndetection:\n  selection:\n    - powershell',
  );
  const [severity, setSeverity] = useState<Severity>('high');
  const [mode, setMode] = useState<DetectionMode>('stream');
  const [intervalSeconds, setIntervalSeconds] = useState(30);
  const [lookbackSeconds, setLookbackSeconds] = useState(300);
  const [ruleScheduleDrafts, setRuleScheduleDrafts] = useState<
    Record<string, { intervalSeconds: number; lookbackSeconds: number }>
  >({});
  const [ruleModeFilter, setRuleModeFilter] = useState<'all' | DetectionMode>('all');
  const [ruleEnabledFilter, setRuleEnabledFilter] = useState<'all' | 'enabled' | 'disabled'>('all');
  const [ruleSeverityFilter, setRuleSeverityFilter] = useState<'all' | Severity>('all');
  const [ruleSearchText, setRuleSearchText] = useState('');

  const filteredRules = useMemo(() => {
    const search = ruleSearchText.trim().toLowerCase();
    const ranked = rules
      .filter((rule) => {
        if (ruleModeFilter !== 'all' && rule.schedule_or_stream !== ruleModeFilter) return false;
        if (ruleEnabledFilter === 'enabled' && !rule.enabled) return false;
        if (ruleEnabledFilter === 'disabled' && rule.enabled) return false;
        if (ruleSeverityFilter !== 'all' && rule.severity !== ruleSeverityFilter) return false;
        if (!search) return true;
        return (
          rule.rule_id.toLowerCase().includes(search) ||
          rule.sigma_source.toLowerCase().includes(search) ||
          rule.severity.toLowerCase().includes(search)
        );
      })
      .map((rule) => {
        const health = rule.scheduler_health;
        const riskScore =
          (health?.error_count ?? 0) * 1_000_000 +
          (health?.last_run_duration_seconds ?? 0) * 1_000 +
          (health?.match_count ?? 0);
        return { rule, riskScore };
      });
    ranked.sort((a, b) => b.riskScore - a.riskScore);
    return ranked.map((entry) => entry.rule);
  }, [rules, ruleModeFilter, ruleEnabledFilter, ruleSeverityFilter, ruleSearchText]);

  const onCreateRule = async (event: FormEvent) => {
    event.preventDefault();
    onStatusText('Creating rule...');
    try {
      await createRule({
        sigma_source: sigmaSource,
        schedule_or_stream: mode,
        schedule:
          mode === 'scheduled'
            ? { interval_seconds: intervalSeconds, lookback_seconds: lookbackSeconds }
            : undefined,
        severity,
        enabled: true,
      });
      await onRefresh();
      onStatusText(`${mode === 'scheduled' ? 'Scheduled' : 'Stream'} rule created.`);
    } catch (err) {
      onStatusText(`Create rule failed: ${String(err)}`);
    }
  };

  const onToggleRuleEnabled = async (rule: DetectionRule) => {
    onStatusText(`${rule.enabled ? 'Disabling' : 'Enabling'} rule ${rule.rule_id.slice(0, 8)}...`);
    try {
      await updateRule(rule.rule_id, { enabled: !rule.enabled });
      await onRefresh();
      onStatusText(`Rule ${rule.rule_id.slice(0, 8)} ${rule.enabled ? 'disabled' : 'enabled'}.`);
    } catch (err) {
      onStatusText(`Rule toggle failed: ${String(err)}`);
    }
  };

  const onDeleteRule = async (rule: DetectionRule) => {
    onStatusText(`Deleting rule ${rule.rule_id.slice(0, 8)}...`);
    try {
      await deleteRule(rule.rule_id);
      await onRefresh();
      onStatusText(`Rule ${rule.rule_id.slice(0, 8)} deleted.`);
    } catch (err) {
      onStatusText(`Delete rule failed: ${String(err)}`);
    }
  };

  const onSaveRuleSchedule = async (rule: DetectionRule) => {
    const draft = ruleScheduleDrafts[rule.rule_id] ?? {
      intervalSeconds: rule.schedule?.interval_seconds ?? 30,
      lookbackSeconds: rule.schedule?.lookback_seconds ?? 300,
    };
    onStatusText(`Updating schedule for ${rule.rule_id.slice(0, 8)}...`);
    try {
      await updateRule(rule.rule_id, {
        schedule_or_stream: 'scheduled',
        schedule: {
          interval_seconds: draft.intervalSeconds,
          lookback_seconds: draft.lookbackSeconds,
        },
      });
      await onRefresh();
      onStatusText(`Schedule updated for ${rule.rule_id.slice(0, 8)}.`);
    } catch (err) {
      onStatusText(`Update schedule failed: ${String(err)}`);
    }
  };

  const setRuleDraft = (
    ruleId: string,
    field: 'intervalSeconds' | 'lookbackSeconds',
    value: number,
  ) => {
    setRuleScheduleDrafts((current) => ({
      ...current,
      [ruleId]: {
        intervalSeconds: current[ruleId]?.intervalSeconds ?? 30,
        lookbackSeconds: current[ruleId]?.lookbackSeconds ?? 300,
        [field]: value,
      },
    }));
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Rule Authoring</h1>
      </div>

      <div className="grid">
        <section className="panel">
          <h2>Create Rule</h2>
          <form onSubmit={onCreateRule} className="stack">
            <label>
              Mode
              <select value={mode} onChange={(e) => setMode(e.target.value as DetectionMode)}>
                <option value="stream">Stream</option>
                <option value="scheduled">Scheduled</option>
              </select>
            </label>
            <label>
              Severity
              <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>
            {mode === 'scheduled' && (
              <div className="stack">
                <label>
                  Interval Seconds
                  <input
                    type="number"
                    min={5}
                    max={3600}
                    value={intervalSeconds}
                    onChange={(e) => setIntervalSeconds(Number(e.target.value))}
                  />
                </label>
                <label>
                  Lookback Seconds
                  <input
                    type="number"
                    min={30}
                    max={86400}
                    value={lookbackSeconds}
                    onChange={(e) => setLookbackSeconds(Number(e.target.value))}
                  />
                </label>
              </div>
            )}
            <label>
              Sigma Source
              <textarea
                value={sigmaSource}
                onChange={(e) => setSigmaSource(e.target.value)}
                rows={8}
              />
            </label>
            <button type="submit">
              Create {mode === 'scheduled' ? 'Scheduled' : 'Stream'} Rule
            </button>
          </form>
          <p className="status">{statusText}</p>
        </section>

        <section className="panel">
          <h2>Rule Summary</h2>
          <div className="rule-filters">
            <label>
              Mode
              <select
                value={ruleModeFilter}
                onChange={(e) => setRuleModeFilter(e.target.value as 'all' | DetectionMode)}
              >
                <option value="all">All</option>
                <option value="stream">Stream</option>
                <option value="scheduled">Scheduled</option>
              </select>
            </label>
            <label>
              Enabled
              <select
                value={ruleEnabledFilter}
                onChange={(e) =>
                  setRuleEnabledFilter(e.target.value as 'all' | 'enabled' | 'disabled')
                }
              >
                <option value="all">All</option>
                <option value="enabled">Enabled</option>
                <option value="disabled">Disabled</option>
              </select>
            </label>
            <label>
              Severity
              <select
                value={ruleSeverityFilter}
                onChange={(e) => setRuleSeverityFilter(e.target.value as 'all' | Severity)}
              >
                <option value="all">All</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>
            <label>
              Text Search
              <input
                value={ruleSearchText}
                onChange={(e) => setRuleSearchText(e.target.value)}
                placeholder="rule id / sigma text"
              />
            </label>
          </div>
          <p className="status">
            Showing {filteredRules.length} of {rules.length} rules
          </p>
          <ul className="list">
            {filteredRules.map((rule) => (
              <li key={rule.rule_id}>
                <div className="rule-line">
                  <span>
                    <strong>{rule.schedule_or_stream}</strong> {rule.rule_id.slice(0, 8)}{' '}
                    {rule.severity} {rule.enabled ? '[enabled]' : '[disabled]'}
                    {rule.schedule
                      ? ` (${rule.schedule.interval_seconds}s interval / ${rule.schedule.lookback_seconds}s lookback)`
                      : ''}
                  </span>
                  <span className="rule-actions">
                    <button type="button" onClick={() => onToggleRuleEnabled(rule)}>
                      {rule.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button type="button" onClick={() => onDeleteRule(rule)}>
                      Delete
                    </button>
                  </span>
                </div>
                {rule.scheduler_health && (
                  <div
                    className={`rule-health ${rule.scheduler_health.error_count > 0 ? 'rule-health-bad' : ''}`}
                  >
                    run:{rule.scheduler_health.run_count} skip:{' '}
                    {rule.scheduler_health.skipped_by_interval_count} match:{' '}
                    {rule.scheduler_health.match_count} err:{rule.scheduler_health.error_count}{' '}
                    last: {rule.scheduler_health.last_run_duration_seconds.toFixed(3)}s
                  </div>
                )}
                {rule.schedule_or_stream === 'scheduled' && (
                  <div className="rule-schedule-edit">
                    <label>
                      Interval
                      <input
                        type="number"
                        min={5}
                        max={3600}
                        value={
                          ruleScheduleDrafts[rule.rule_id]?.intervalSeconds ??
                          rule.schedule?.interval_seconds ??
                          30
                        }
                        onChange={(e) =>
                          setRuleDraft(rule.rule_id, 'intervalSeconds', Number(e.target.value))
                        }
                      />
                    </label>
                    <label>
                      Lookback
                      <input
                        type="number"
                        min={30}
                        max={86400}
                        value={
                          ruleScheduleDrafts[rule.rule_id]?.lookbackSeconds ??
                          rule.schedule?.lookback_seconds ??
                          300
                        }
                        onChange={(e) =>
                          setRuleDraft(rule.rule_id, 'lookbackSeconds', Number(e.target.value))
                        }
                      />
                    </label>
                    <button type="button" onClick={() => onSaveRuleSchedule(rule)}>
                      Save Schedule
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
