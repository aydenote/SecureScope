import type { SecurityDimensionScore } from '../domains/securityDimensions';
import RiskBadge from './RiskBadge';

interface SecurityRadarChartProps {
  title: string;
  dimensions: SecurityDimensionScore[];
  compact?: boolean;
}

interface Point {
  x: number;
  y: number;
}

const center = 120;
const radius = 78;

export default function SecurityRadarChart({
  title,
  dimensions,
  compact = false,
}: SecurityRadarChartProps) {
  const axisPoints = dimensions.map((_, index) =>
    getPoint(index, dimensions.length, radius)
  );
  const scorePoints = dimensions.map((dimension, index) =>
    getPoint(index, dimensions.length, radius * (dimension.score / 10))
  );
  const polygonPoints = scorePoints
    .map((point) => `${point.x},${point.y}`)
    .join(' ');

  return (
    <section
      className={compact ? 'radar-card radar-card-compact' : 'radar-card'}
    >
      <div className="radar-header">
        <div>
          <p className="eyebrow">
            {compact ? 'Security shape' : 'Security dimensions'}
          </p>
          <h2>{title}</h2>
        </div>
      </div>

      <div className="radar-layout">
        <svg
          className="radar-svg"
          viewBox="0 0 240 240"
          role="img"
          aria-label={`${title} radar chart`}
        >
          {[0.25, 0.5, 0.75, 1].map((scale) => (
            <polygon
              className="radar-grid"
              key={scale}
              points={dimensions
                .map((_, index) => {
                  const point = getPoint(
                    index,
                    dimensions.length,
                    radius * scale
                  );
                  return `${point.x},${point.y}`;
                })
                .join(' ')}
            />
          ))}
          {axisPoints.map((point, index) => (
            <line
              className="radar-axis"
              key={dimensions[index].label}
              x1={center}
              y1={center}
              x2={point.x}
              y2={point.y}
            />
          ))}
          <polygon className="radar-score" points={polygonPoints} />
          {scorePoints.map((point, index) => (
            <circle
              className="radar-point"
              key={dimensions[index].label}
              cx={point.x}
              cy={point.y}
              r="3.5"
            />
          ))}
          {axisPoints.map((point, index) => {
            const labelPoint = getPoint(index, dimensions.length, radius + 22);
            return (
              <text
                className="radar-label"
                key={dimensions[index].label}
                x={labelPoint.x}
                y={labelPoint.y}
              >
                {dimensions[index].label}
              </text>
            );
          })}
        </svg>

        {!compact ? (
          <div className="radar-dimension-list">
            {dimensions.map((dimension) => (
              <div className="radar-dimension-row" key={dimension.label}>
                <span>{dimension.label}</span>
                <strong>{dimension.score}/10</strong>
                <RiskBadge riskLevel={dimension.riskLevel} />
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </section>
  );
}

function getPoint(index: number, total: number, pointRadius: number): Point {
  const angle = -Math.PI / 2 + (2 * Math.PI * index) / total;
  return {
    x: center + pointRadius * Math.cos(angle),
    y: center + pointRadius * Math.sin(angle),
  };
}
