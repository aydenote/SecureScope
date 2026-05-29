import type { SecurityFinding } from '../lib/api';
import RiskBadge from './RiskBadge';

interface FindingCardProps {
  finding: SecurityFinding;
}

export default function FindingCard({ finding }: FindingCardProps) {
  return (
    <article className="finding-card">
      <div className="finding-heading">
        <h3>{finding.title}</h3>
        <RiskBadge riskLevel={finding.riskLevel} />
      </div>
      <div className="finding-section">
        <p className="eyebrow">Evidence</p>
        <p>{finding.description}</p>
      </div>
      <div className="finding-section recommendation">
        <p className="eyebrow">Recommendation</p>
        <p>{finding.recommendation}</p>
      </div>
    </article>
  );
}
