interface Props {
  values: number[];
  /** Axis range; defaults to 0-100 because most of our series are percentages. */
  min?: number;
  max?: number;
  height?: number;
  color?: string;
  label: string;
}

/** A tiny dependency-free line chart. Draws nothing misleading when there is too little data. */
export function Sparkline({ values, min = 0, max = 100, height = 44, color = "var(--accent)", label }: Props) {
  const width = 240;
  if (values.length < 2) {
    return (
      <svg role="img" aria-label={`${label}: not enough data yet`} viewBox={`0 0 ${width} ${height}`} width="100%" height={height}>
        <line x1="0" x2={width} y1={height - 1} y2={height - 1} stroke="var(--line)" strokeDasharray="3 4" />
      </svg>
    );
  }
  const span = max - min || 1;
  const x = (i: number) => (i / (values.length - 1)) * width;
  const y = (v: number) => height - 2 - ((Math.min(max, Math.max(min, v)) - min) / span) * (height - 4);
  const line = values.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(" ");
  const last = values[values.length - 1];
  return (
    <svg
      role="img"
      aria-label={`${label}: latest ${last.toFixed(0)}, range ${Math.min(...values).toFixed(0)} to ${Math.max(...values).toFixed(0)}`}
      viewBox={`0 0 ${width} ${height}`}
      width="100%"
      height={height}
      preserveAspectRatio="none"
    >
      <path d={`${line} L${width} ${height} L0 ${height} Z`} fill={color} opacity="0.14" />
      <path d={line} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
