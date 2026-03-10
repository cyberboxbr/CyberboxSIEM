import { AlertRecord, acknowledgeAlert, assignAlert, ingestSampleEvent } from '../api/client';

interface AlertsProps {
  alerts: AlertRecord[];
  onRefresh: () => Promise<void>;
  onStatusText: (msg: string) => void;
  statusText: string;
  assignee: string;
  onAssigneeChange: (value: string) => void;
  sampleMessage: string;
  onSampleMessageChange: (value: string) => void;
}

export function Alerts({
  alerts,
  onRefresh,
  onStatusText,
  statusText,
  assignee,
  onAssigneeChange,
  sampleMessage,
  onSampleMessageChange,
}: AlertsProps) {
  const onIngest = async () => {
    onStatusText('Ingesting sample event...');
    try {
      await ingestSampleEvent(sampleMessage);
      await onRefresh();
      onStatusText('Sample event ingested.');
    } catch (err) {
      onStatusText(`Ingest failed: ${String(err)}`);
    }
  };

  const onAcknowledge = async (alert: AlertRecord) => {
    onStatusText(`Acknowledging alert ${alert.alert_id.slice(0, 8)}...`);
    try {
      await acknowledgeAlert(alert.alert_id);
      await onRefresh();
      onStatusText(`Alert ${alert.alert_id.slice(0, 8)} acknowledged.`);
    } catch (err) {
      onStatusText(`Acknowledge failed: ${String(err)}`);
    }
  };

  const onAssign = async (alert: AlertRecord) => {
    onStatusText(`Assigning alert ${alert.alert_id.slice(0, 8)}...`);
    try {
      await assignAlert(alert.alert_id, assignee);
      await onRefresh();
      onStatusText(`Alert ${alert.alert_id.slice(0, 8)} assigned to ${assignee}.`);
    } catch (err) {
      onStatusText(`Assign failed: ${String(err)}`);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Alert Queue</h1>
      </div>

      <div className="grid">
        <section className="panel">
          <h2>Operator Flow</h2>
          <div className="stack">
            <label>
              Sample Event Message
              <textarea
                value={sampleMessage}
                onChange={(e) => onSampleMessageChange(e.target.value)}
                rows={3}
              />
            </label>
            <button onClick={onIngest}>Ingest Sample Event</button>
            <button onClick={() => onRefresh().catch((err) => onStatusText(String(err)))}>
              Refresh
            </button>
            <label>
              Default Assignee
              <input value={assignee} onChange={(e) => onAssigneeChange(e.target.value)} />
            </label>
          </div>
          <p className="status">{statusText}</p>
        </section>

        <section className="panel">
          <h2>Active Alerts</h2>
          <ul className="list">
            {alerts.map((alert) => (
              <li key={alert.alert_id}>
                <div className="alert-line">
                  <span>
                    <strong>{alert.status}</strong> rule {alert.rule_id.slice(0, 8)} assignee:{' '}
                    {alert.assignee ?? 'unassigned'}
                  </span>
                  <span className="alert-actions">
                    <button type="button" onClick={() => onAcknowledge(alert)}>
                      Ack
                    </button>
                    <button type="button" onClick={() => onAssign(alert)}>
                      Assign
                    </button>
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
