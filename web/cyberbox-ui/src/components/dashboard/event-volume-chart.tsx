import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
  type PointerEvent as ReactPointerEvent,
} from 'react';

interface DashboardEventVolumeChartProps {
  data: Array<{
    time: string;
    count: number;
  }>;
}

const MIN_WIDTH = 320;
const MIN_HEIGHT = 220;
const PADDING = {
  top: 28,
  right: 20,
  bottom: 34,
  left: 54,
};
const GRID_STEPS = 4;
const MAX_X_TICKS = 6;

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function formatCompact(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1).replace(/\.0$/, '')}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1).replace(/\.0$/, '')}K`;
  return String(value);
}

function roundUpToNiceStep(value: number): number {
  if (value <= 0) return 1;

  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;

  if (normalized <= 1) return magnitude;
  if (normalized <= 2) return 2 * magnitude;
  if (normalized <= 5) return 5 * magnitude;
  return 10 * magnitude;
}

function buildLinePath(points: Array<{ x: number; y: number }>): string {
  return points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ');
}

function buildAreaPath(points: Array<{ x: number; y: number }>, baselineY: number): string {
  if (!points.length) return '';

  const first = points[0];
  const last = points[points.length - 1];

  return `${buildLinePath(points)} L ${last.x} ${baselineY} L ${first.x} ${baselineY} Z`;
}

function visibleTickIndices(length: number): number[] {
  if (length <= 1) return [0];
  if (length <= MAX_X_TICKS) return Array.from({ length }, (_, index) => index);

  const tickSet = new Set<number>([0, length - 1]);
  const step = Math.ceil(length / MAX_X_TICKS);

  for (let index = step; index < length - 1; index += step) {
    tickSet.add(index);
  }

  return Array.from(tickSet).sort((left, right) => left - right);
}

export default function DashboardEventVolumeChart({ data }: DashboardEventVolumeChartProps) {
  const frameRef = useRef<HTMLDivElement | null>(null);
  const [frameSize, setFrameSize] = useState({ width: 0, height: 0 });
  const [activeIndex, setActiveIndex] = useState(Math.max(data.length - 1, 0));
  const gradientId = useId().replace(/:/g, '');

  useEffect(() => {
    setActiveIndex((currentIndex) => clamp(currentIndex, 0, Math.max(data.length - 1, 0)));
  }, [data.length]);

  useEffect(() => {
    const node = frameRef.current;
    if (!node) return undefined;

    const updateSize = (nextWidth: number, nextHeight: number) => {
      const width = Math.round(nextWidth);
      const height = Math.round(nextHeight);

      setFrameSize((currentSize) => (
        currentSize.width === width && currentSize.height === height
          ? currentSize
          : { width, height }
      ));
    };

    updateSize(node.clientWidth, node.clientHeight);

    if (typeof ResizeObserver === 'undefined') {
      const handleResize = () => updateSize(node.clientWidth, node.clientHeight);
      window.addEventListener('resize', handleResize);
      return () => window.removeEventListener('resize', handleResize);
    }

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      updateSize(entry.contentRect.width, entry.contentRect.height);
    });

    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  const width = Math.max(frameSize.width || 0, MIN_WIDTH);
  const height = Math.max(frameSize.height || 0, MIN_HEIGHT);
  const chartWidth = Math.max(width - PADDING.left - PADDING.right, 1);
  const chartHeight = Math.max(height - PADDING.top - PADDING.bottom, 1);
  const baselineY = PADDING.top + chartHeight;
  const peak = useMemo(
    () => Math.max(1, ...data.map((point) => point.count)),
    [data],
  );
  const yMax = useMemo(
    () => roundUpToNiceStep(peak),
    [peak],
  );
  const averageCount = useMemo(
    () => Math.round(data.reduce((sum, point) => sum + point.count, 0) / Math.max(data.length, 1)),
    [data],
  );

  const points = useMemo(
    () => data.map((point, index) => {
      const ratio = data.length === 1 ? 0.5 : index / (data.length - 1);
      return {
        label: point.time,
        value: point.count,
        x: PADDING.left + chartWidth * ratio,
        y: PADDING.top + chartHeight - (point.count / yMax) * chartHeight,
      };
    }),
    [chartHeight, chartWidth, data, yMax],
  );

  const xTicks = useMemo(
    () => visibleTickIndices(points.length),
    [points.length],
  );
  const yTicks = useMemo(
    () => Array.from({ length: GRID_STEPS + 1 }, (_, index) => {
      const value = (yMax / GRID_STEPS) * (GRID_STEPS - index);
      const ratio = yMax === 0 ? 0 : value / yMax;
      return {
        value,
        y: PADDING.top + chartHeight - ratio * chartHeight,
      };
    }),
    [chartHeight, yMax],
  );

  const activePoint = points[activeIndex] ?? points[points.length - 1] ?? null;
  const linePath = useMemo(
    () => buildLinePath(points),
    [points],
  );
  const areaPath = useMemo(
    () => buildAreaPath(points, baselineY),
    [baselineY, points],
  );

  const updateActivePoint = (clientX: number, target: HTMLDivElement) => {
    if (!data.length) return;

    const bounds = target.getBoundingClientRect();
    const usableWidth = Math.max(bounds.width - PADDING.left - PADDING.right, 1);
    const relativeX = clamp(clientX - bounds.left - PADDING.left, 0, usableWidth);
    const nextIndex = data.length === 1
      ? 0
      : Math.round((relativeX / usableWidth) * (data.length - 1));

    setActiveIndex(nextIndex);
  };

  const handlePointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    updateActivePoint(event.clientX, event.currentTarget);
  };

  const handleClick = (event: ReactMouseEvent<HTMLDivElement>) => {
    updateActivePoint(event.clientX, event.currentTarget);
  };

  if (!data.length || !activePoint) return null;

  return (
    <div
      ref={frameRef}
      data-testid="dashboard-event-volume-chart"
      className="relative h-full w-full overflow-hidden rounded-lg border border-border/70 bg-[linear-gradient(180deg,hsl(var(--card)),hsl(var(--card)/0.72))] touch-pan-y"
      onClick={handleClick}
      onPointerDown={handlePointerMove}
      onPointerLeave={() => setActiveIndex(data.length - 1)}
      onPointerMove={handlePointerMove}
    >
      <div className="pointer-events-none absolute left-4 right-4 top-4 flex flex-wrap items-start justify-between gap-3">
        <div className="rounded-lg border border-border/70 bg-background/82 px-3 py-2 shadow-sm backdrop-blur">
          <div className="text-[10px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Peak / average</div>
          <div className="mt-2 flex items-baseline gap-3">
            <span className="font-display text-xl font-semibold tracking-[-0.04em] text-foreground">{formatCompact(peak)}</span>
            <span className="text-sm text-muted-foreground">{formatCompact(averageCount)} avg</span>
          </div>
        </div>

        <div className="rounded-lg border border-primary/20 bg-primary/10 px-3 py-2 text-right shadow-sm backdrop-blur">
          <div className="text-[10px] font-semibold uppercase tracking-[0.24em] text-primary/80">Selected bucket</div>
          <div data-testid="dashboard-chart-selected-label" className="mt-1 text-sm font-medium text-foreground">{activePoint.label}</div>
          <div data-testid="dashboard-chart-selected-value" className="mt-1 font-display text-2xl font-semibold tracking-[-0.04em] text-foreground">
            {formatCompact(activePoint.value)}
            <span className="ml-2 text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">events</span>
          </div>
        </div>
      </div>

      <svg
        width={width}
        height={height}
        className="block h-full w-full"
        role="img"
        aria-label="Event volume chart"
      >
        <defs>
          <linearGradient id={`dashboard-event-fill-${gradientId}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00FFA3" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#00FFA3" stopOpacity="0.03" />
          </linearGradient>
        </defs>

        {yTicks.map((tick) => (
          <g key={tick.value}>
            <line
              x1={PADDING.left}
              x2={width - PADDING.right}
              y1={tick.y}
              y2={tick.y}
              stroke="rgba(148, 163, 184, 0.18)"
              strokeDasharray={tick.value === 0 ? undefined : '4 6'}
            />
            <text
              x={PADDING.left - 10}
              y={tick.y + 4}
              fill="#94a3b8"
              fontSize="11"
              textAnchor="end"
            >
              {formatCompact(Math.round(tick.value))}
            </text>
          </g>
        ))}

        {xTicks.map((index) => {
          const point = points[index];
          if (!point) return null;

          return (
            <text
              key={`${point.label}-${index}`}
              x={point.x}
              y={height - 10}
              fill="#94a3b8"
              fontSize="11"
              textAnchor={index === 0 ? 'start' : index === points.length - 1 ? 'end' : 'middle'}
            >
              {point.label}
            </text>
          );
        })}

        <path
          d={areaPath}
          fill={`url(#dashboard-event-fill-${gradientId})`}
        />

        <path
          d={linePath}
          fill="none"
          stroke="#00FFA3"
          strokeWidth="2.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />

        <line
          x1={activePoint.x}
          x2={activePoint.x}
          y1={PADDING.top}
          y2={baselineY}
          stroke="rgba(0, 255, 163, 0.28)"
          strokeDasharray="4 6"
        />
        <circle cx={activePoint.x} cy={activePoint.y} r="6" fill="#0f172a" stroke="#00FFA3" strokeWidth="3" />
        <circle cx={activePoint.x} cy={activePoint.y} r="16" fill="rgba(0, 255, 163, 0.12)" />
      </svg>
    </div>
  );
}
