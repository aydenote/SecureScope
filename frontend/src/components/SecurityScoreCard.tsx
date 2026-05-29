import type { RiskLevel } from '../lib/api';
import RiskBadge from './RiskBadge';

interface SecurityScoreCardProps {
  title: string;
  target: string;
  score: number;
  riskLevel: RiskLevel;
  scannedAt?: string;
}

export default function SecurityScoreCard({ title, target, score, riskLevel, scannedAt }: SecurityScoreCardProps) {
  return (
    <section className="score-panel">
      <div>
        <p className="eyebrow">{title}</p>
        <h2>{target}</h2>
        {scannedAt ? <p className="muted">Last scan: {new Date(scannedAt).toLocaleString()}</p> : null}
      </div>
      <div className="score-meter" aria-label={`Security score ${score}`}>
        <strong>{score}</strong>
        <span>/100</span>
      </div>
      <RiskBadge riskLevel={riskLevel} />
    </section>
  );
}
