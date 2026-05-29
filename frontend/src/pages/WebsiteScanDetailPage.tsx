import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import CheckCard from '../components/CheckCard';
import FindingCard from '../components/FindingCard';
import SecurityScoreCard from '../components/SecurityScoreCard';
import { getWebsiteScan } from '../lib/api';

export default function WebsiteScanDetailPage() {
  const { id } = useParams();
  const scan = useQuery({
    queryKey: ['website-scan', id],
    queryFn: () => getWebsiteScan(id!),
    enabled: Boolean(id),
  });

  const findings = scan.data?.checks.flatMap((check) => check.findings) ?? [];

  if (scan.isLoading) {
    return <p className="muted">Loading website scan...</p>;
  }

  if (scan.isError || !scan.data) {
    return (
      <div className="page-stack">
        <p className="error-text">Website scan not found.</p>
        <Link to="/website-security">Start another scan</Link>
      </div>
    );
  }

  return (
    <div className="page-stack">
      <header className="page-header">
        <div>
          <p className="eyebrow">Website Scan</p>
          <h2>{scan.data.target}</h2>
        </div>
        <Link className="button-link" to="/website-security">
          New scan
        </Link>
      </header>

      <SecurityScoreCard
        title="Website security"
        target={scan.data.target}
        score={scan.data.score}
        riskLevel={scan.data.overallRisk}
        scannedAt={scan.data.scannedAt}
      />

      <section className="check-grid">
        {scan.data.checks.map((check) => (
          <CheckCard check={check} key={check.name} />
        ))}{' '}
      </section>

      <section className="page-stack">
        <h2>Findings</h2>
        {findings.map((finding) => (
          <FindingCard
            finding={finding}
            key={`${finding.title}-${finding.riskLevel}`}
          />
        ))}
      </section>
    </div>
  );
}
