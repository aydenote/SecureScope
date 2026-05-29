import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import FindingSummary from '../components/FindingSummary';
import ScanHistory from '../components/ScanHistory';
import SecurityRadarChart from '../components/SecurityRadarChart';
import SecurityScoreCard from '../components/SecurityScoreCard';
import {
  getLatestPcScan,
  getLatestWebsiteScan,
  getRecentScans,
} from '../lib/api';
import {
  getPcDimensions,
  getWebsiteDimensions,
} from '../lib/securityDimensions';

export default function DashboardPage() {
  const pcScan = useQuery({
    queryKey: ['pc-scan', 'latest'],
    queryFn: getLatestPcScan,
  });
  const websiteScan = useQuery({
    queryKey: ['website-scan', 'latest'],
    queryFn: getLatestWebsiteScan,
    retry: false,
  });
  const recentScans = useQuery({
    queryKey: ['scans', 'recent'],
    queryFn: getRecentScans,
  });
  const scansForCounts = [pcScan.data, websiteScan.data].filter(
    (scan) => scan !== undefined
  );

  return (
    <div className="page-stack">
      <header className="page-header">
        <div>
          <p className="eyebrow">Overview</p>
          <h2>Local Security State</h2>
        </div>
      </header>
      {pcScan.isLoading ? (
        <p className="muted">Loading latest PC scan...</p>
      ) : null}
      {pcScan.isError ? (
        <p className="error-text">Unable to reach the backend API.</p>
      ) : null}
      <section className="dashboard-score-grid">
        {pcScan.data ? (
          <SecurityScoreCard
            title="Overall PC security score"
            target={pcScan.data.target}
            score={pcScan.data.score}
            riskLevel={pcScan.data.overallRisk}
            scannedAt={pcScan.data.scannedAt}
          />
        ) : null}
        {websiteScan.data ? (
          <SecurityScoreCard
            title="Latest website scan score"
            target={websiteScan.data.target}
            score={websiteScan.data.score}
            riskLevel={websiteScan.data.overallRisk}
            scannedAt={websiteScan.data.scannedAt}
          />
        ) : (
          <section className="empty-panel">
            <p className="eyebrow">Latest website scan score</p>
            <h2>No website scan yet</h2>
            <Link to="/website-security">Run website scan</Link>
          </section>
        )}
      </section>
      <section className="dashboard-score-grid">
        {pcScan.data ? (
          <SecurityRadarChart
            title="PC security shape"
            dimensions={getPcDimensions(pcScan.data)}
            compact
          />
        ) : null}{' '}
        {websiteScan.data ? (
          <SecurityRadarChart
            title="Website security shape"
            dimensions={getWebsiteDimensions(websiteScan.data)}
            compact
          />
        ) : null}{' '}
      </section>
      <FindingSummary scans={scansForCounts} />
      <section className="page-stack">
        <div>
          <p className="eyebrow">Recent scan history</p>
          <h2>Recent scans</h2>
        </div>
        {recentScans.isLoading ? (
          <p className="muted">Loading scan history...</p>
        ) : null}
        {recentScans.isError ? (
          <p className="error-text">Unable to load scan history.</p>
        ) : null}
        {recentScans.data ? <ScanHistory scans={recentScans.data} /> : null}
      </section>
      <section className="quick-actions">
        <Link to="/pc-security">Review PC checks</Link>
        <Link to="/website-security">Scan a website</Link>
      </section>
    </div>
  );
}
