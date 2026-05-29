import type { RiskLevel, SecurityScanSummary } from '../lib/api';

interface FindingSummaryProps {
  scans: SecurityScanSummary[];
}

const trackedRiskLevels: RiskLevel[] = ['Critical', 'High', 'Medium'];

export default function FindingSummary({ scans }: FindingSummaryProps) {
  const counts = trackedRiskLevels.map((riskLevel) => ({
    riskLevel,
    count: scans.reduce(
      (total, scan) =>
        total +
        scan.checks
          .flatMap((check) => check.findings)
          .filter((finding) => finding.riskLevel === riskLevel).length,
      0
    ),
  }));

  return (
    <section className="metric-grid">
      {counts.map((item) => (
        <article className="metric-card" key={item.riskLevel}>
          <p className="eyebrow">
            {item.riskLevel} findings
          </p>
          <strong>{item.count}</strong>
        </article>
      ))}
    </section>
  );
}
