import { useCallback, useEffect, useRef, useState } from 'react';
import { getWsToken, getAlerts } from '../api/client';
import type { AlertRecord, AlertsPage } from '../api/client';

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function sortAlerts(alerts: AlertRecord[]): AlertRecord[] {
  return [...alerts].sort((a, b) => {
    // Sort by last_seen descending (newest first)
    return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
  });
}

function deduplicateAlerts(existing: AlertRecord[], incoming: AlertRecord[]): AlertRecord[] {
  const map = new Map<string, AlertRecord>();
  for (const a of existing) {
    map.set(a.alert_id, a);
  }
  for (const a of incoming) {
    map.set(a.alert_id, a);
  }
  return Array.from(map.values());
}

export interface UseAlertStreamResult {
  alerts: AlertRecord[];
  connected: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

export function useAlertStream(): UseAlertStreamResult {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const backoffRef = useRef(1000);
  const mountedRef = useRef(true);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const mergeAndSort = useCallback((prev: AlertRecord[], incoming: AlertRecord[]): AlertRecord[] => {
    return sortAlerts(deduplicateAlerts(prev, incoming));
  }, []);

  const fetchInitialAlerts = useCallback(async () => {
    try {
      const page: AlertsPage = await getAlerts();
      if (mountedRef.current) {
        setAlerts((prev) => mergeAndSort(prev, page.alerts));
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(`Failed to fetch alerts: ${String(err)}`);
      }
    }
  }, [mergeAndSort]);

  const connectWebSocket = useCallback(async () => {
    if (!mountedRef.current) return;
    // Stop retrying after too many failures (e.g. API offline, using mock data)
    if (backoffRef.current > 30000) return;

    try {
      const { token } = await getWsToken();
      if (!mountedRef.current) return;

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const wsUrl = `${protocol}//${host}/api/v1/alerts/ws?token=${encodeURIComponent(token)}`;

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        setConnected(true);
        setError(null);
        backoffRef.current = 1000;
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;
        try {
          const alert: AlertRecord = JSON.parse(event.data);
          setAlerts((prev) => mergeAndSort(prev, [alert]));
        } catch {
          // ignore malformed messages
        }
      };

      ws.onerror = () => {
        if (!mountedRef.current) return;
        setError('WebSocket connection error');
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;
        setConnected(false);
        wsRef.current = null;
        scheduleReconnect();
      };
    } catch (err) {
      if (!mountedRef.current) return;
      setConnected(false);
      setError(null); // suppress error when using mock fallback
      scheduleReconnect();
    }
  }, [mergeAndSort]);

  const scheduleReconnect = useCallback(() => {
    if (!mountedRef.current) return;
    const delay = backoffRef.current;
    backoffRef.current = Math.min(delay * 2, 30000);
    reconnectTimerRef.current = setTimeout(() => {
      if (mountedRef.current) {
        connectWebSocket();
      }
    }, delay);
  }, [connectWebSocket]);

  const refresh = useCallback(async () => {
    await fetchInitialAlerts();
  }, [fetchInitialAlerts]);

  useEffect(() => {
    mountedRef.current = true;
    fetchInitialAlerts();
    connectWebSocket();

    return () => {
      mountedRef.current = false;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [fetchInitialAlerts, connectWebSocket]);

  return { alerts, connected, error, refresh };
}
