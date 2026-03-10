import { useEffect, useState } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';

import {
  AlertRecord,
  DetectionRule,
  getAlerts,
  getRules,
  healthCheck,
} from './api/client';
import { TopNav } from './components/TopNav';
import { Alerts } from './pages/Alerts';
import { Audit } from './pages/Audit';
import { Dashboard } from './pages/Dashboard';
import { Investigation } from './pages/Investigation';
import { Rules } from './pages/Rules';
import './styles.css';

function App() {
  const [health, setHealth] = useState('unknown');
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [statusText, setStatusText] = useState('');
  const [assignee, setAssignee] = useState('tier1-analyst');
  const [sampleMessage, setSampleMessage] = useState('powershell -enc AAAA');

  const refresh = async () => {
    const [healthResp, rulesResp, alertsResp] = await Promise.all([
      healthCheck(),
      getRules(),
      getAlerts(),
    ]);
    setHealth(healthResp.status);
    setRules(rulesResp);
    setAlerts(alertsResp);
  };

  useEffect(() => {
    refresh().catch((err) => setStatusText(String(err)));
  }, []);

  return (
    <BrowserRouter>
      <TopNav health={health} />
      <div className="app-layout">
        <Routes>
          <Route
            path="/"
            element={
              <Dashboard
                rules={rules}
                alerts={alerts}
                health={health}
                onRefresh={refresh}
              />
            }
          />
          <Route
            path="/alerts"
            element={
              <Alerts
                alerts={alerts}
                onRefresh={refresh}
                onStatusText={setStatusText}
                statusText={statusText}
                assignee={assignee}
                onAssigneeChange={setAssignee}
                sampleMessage={sampleMessage}
                onSampleMessageChange={setSampleMessage}
              />
            }
          />
          <Route
            path="/rules"
            element={
              <Rules
                rules={rules}
                onRefresh={refresh}
                onStatusText={setStatusText}
                statusText={statusText}
              />
            }
          />
          <Route path="/investigate" element={<Investigation />} />
          <Route path="/audit" element={<Audit />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
