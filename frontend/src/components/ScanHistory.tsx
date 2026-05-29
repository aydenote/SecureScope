import { Link } from 'react-router-dom';
import RiskBadge from './RiskBadge';
import type { SecurityScanSummary } from '../lib/api';

interface ScanHistoryProps {
  scans: SecurityScanSummary[];
}

export default function ScanHistory({ scans }: ScanHistoryProps) {
  if (scans.length === 0) {
    return <p className="muted">No scan history yet.</p>;
  }

  return (
    <section className="history-list">
      {scans.map((scan) => {
        const content = (
          <>
            <div>
              <p className="eyebrow">{scan.scanType}</p>
              <h3>{scan.target}</h3>
              <p className="muted">
                {new Date(scan.scannedAt).toLocaleString()}
              </p>
            </div>
            <div className="history-score">
              <strong>{scan.score}</strong>
              <RiskBadge riskLevel={scan.overallRisk} />
            </div>
          </>
        );

        return scan.scanType === 'Website' ? (
          <Link
            className="history-item"
            to={`/website-scans/${scan.id}`}
            key={`${scan.scanType}-${scan.id}`}
          >
            {content}
          </Link>
        ) : (
          <article className="history-item" key={`${scan.scanType}-${scan.id}`}>
            {content}
          </article>
        );
      })}
    </section>
  );
}
