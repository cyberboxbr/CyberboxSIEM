import { useEffect, useRef, useCallback } from 'react';

const ACTIVITY_EVENTS: (keyof WindowEventMap)[] = [
  'mousemove',
  'mousedown',
  'keydown',
  'scroll',
  'touchstart',
  'pointerdown',
];

/**
 * Tracks user activity and calls `onTimeout` after `timeoutMs` of inactivity.
 * Shows a warning callback `warningMs` before the timeout fires.
 */
export function useIdleTimeout(
  timeoutMs: number,
  onTimeout: () => void,
  warningMs = 60_000,
  onWarning?: () => void,
  enabled = true,
) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const warningRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onTimeoutRef = useRef(onTimeout);
  const onWarningRef = useRef(onWarning);

  onTimeoutRef.current = onTimeout;
  onWarningRef.current = onWarning;

  const resetTimers = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    if (warningRef.current) clearTimeout(warningRef.current);

    // Schedule warning (e.g. 1 min before timeout)
    if (onWarningRef.current && timeoutMs > warningMs) {
      warningRef.current = setTimeout(() => {
        onWarningRef.current?.();
      }, timeoutMs - warningMs);
    }

    // Schedule logout
    timerRef.current = setTimeout(() => {
      onTimeoutRef.current();
    }, timeoutMs);
  }, [timeoutMs, warningMs]);

  useEffect(() => {
    if (!enabled) {
      if (timerRef.current) clearTimeout(timerRef.current);
      if (warningRef.current) clearTimeout(warningRef.current);
      return;
    }

    resetTimers();

    const handler = () => resetTimers();
    for (const event of ACTIVITY_EVENTS) {
      window.addEventListener(event, handler, { passive: true });
    }

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      if (warningRef.current) clearTimeout(warningRef.current);
      for (const event of ACTIVITY_EVENTS) {
        window.removeEventListener(event, handler);
      }
    };
  }, [enabled, resetTimers]);
}
