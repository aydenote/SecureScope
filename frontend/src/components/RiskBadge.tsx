import type { RiskLevel } from '../lib/api';

interface RiskBadgeProps {
  riskLevel: RiskLevel;
}

export default function RiskBadge({ riskLevel }: RiskBadgeProps) {
  return <span className={`risk-badge risk-${riskLevel.toLowerCase()}`}>{riskLevel}</span>;
}
