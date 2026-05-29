import type { SecurityCheckResult } from '../lib/api';
import RiskBadge from './RiskBadge';

interface CheckCardProps {
  check: SecurityCheckResult;
}

export default function CheckCard({ check }: CheckCardProps) {
  return (
    <article className="check-card">
      <div className="finding-heading">
        <h3>{check.name}</h3>
        <RiskBadge riskLevel={check.riskLevel} />
      </div>
      <p className="muted">{check.category}</p>
      <p>{check.summary}</p>
      <span className={check.passed ? 'status-pass' : 'status-fail'}>
        {check.passed ? 'Passed' : 'Needs review'}
      </span>
    </article>
  );
}
