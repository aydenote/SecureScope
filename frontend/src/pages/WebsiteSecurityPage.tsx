import { FormEvent, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import CheckCard from '../components/CheckCard';
import FindingCard from '../components/FindingCard';
import SecurityRadarChart from '../components/SecurityRadarChart';
import SecurityScoreCard from '../components/SecurityScoreCard';
import { getLatestWebsiteScan, startWebsiteScan } from '../lib/api';
import { getWebsiteDimensions } from '../lib/securityDimensions';

export default function WebsiteSecurityPage() {
  const [url, setUrl] = useState('https://example.com');
  const queryClient = useQueryClient();
  const latestScan = useQuery({
    queryKey: ['website-scan', 'latest'],
    queryFn: getLatestWebsiteScan,
    retry: false,
  });
  const scan = useMutation({
    mutationFn: startWebsiteScan,
    onSuccess: (data) => {
      queryClient.setQueryData(['website-scan', 'latest'], data);
      queryClient.setQueryData(['website-scan', String(data.id)], data);
      void queryClient.invalidateQueries({ queryKey: ['scans', 'recent'] });
    },
  });

  const currentScan = scan.data ?? latestScan.data;
  const findings = currentScan?.checks.flatMap((check) => check.findings) ?? [];

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    scan.mutate(url);
  }

  return (
    <div className="page-stack">
      <header className="page-header">
        <div>
          <p className="eyebrow">
            Website Security
          </p>
          <h2>
            Configuration scan
          </h2>
        </div>
      </header>
      <form className="scan-form" onSubmit={handleSubmit}>
        <label htmlFor="website-url">
          Website URL
        </label>
        <div className="input-row">
          <input
            id="website-url"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://example.com"
          />
          <button type="submit" disabled={scan.isPending}>
            {scan.isPending ? (
              'Scanning...'
            ) : (
              'Scan'
            )}
          </button>
        </div>
        {scan.isPending ? (
          <p className="muted">
            Scanning one page and collecting response headers...
          </p>
        ) : null}{' '}
        {scan.isError ? (
          <p className="error-text">
            Website scan failed. Check that the API is running.
          </p>
        ) : null}
      </form>
      {latestScan.isLoading ? (
        <p className="muted">
          Loading latest website scan...
        </p>
      ) : null}{' '}
      {currentScan ? (
        <>
          <SecurityScoreCard
            title="Latest website scan results"
            target={currentScan.target}
            score={currentScan.score}
            riskLevel={currentScan.overallRisk}
            scannedAt={currentScan.scannedAt}
          />
          <SecurityRadarChart
            title="Website security dimensions"
            dimensions={getWebsiteDimensions(currentScan)}
          />{' '}
          <section className="check-grid">
            {currentScan.checks.map((check) => (
              <CheckCard check={check} key={check.name} />
            ))}
          </section>
          <section className="page-stack">
            <h2>
              Findings
            </h2>
            {findings.length === 0 ? (
              <p className="muted">
                No findings in the latest website scan.
              </p>
            ) : null}
            {findings.map((finding) => (
              <FindingCard
                finding={finding}
                key={`${finding.title}-${finding.riskLevel}`}
              />
            ))}
          </section>
        </>
      ) : null}
    </div>
  );
}
