import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import CheckCard from '../components/CheckCard';
import FindingCard from '../components/FindingCard';
import SecurityRadarChart from '../components/SecurityRadarChart';
import SecurityScoreCard from '../components/SecurityScoreCard';
import { getLatestPcScan, startPcScan } from '../lib/api';
import { getPcDimensions } from '../lib/securityDimensions';

export default function PcSecurityPage() {
  const queryClient = useQueryClient();
  const scan = useQuery({
    queryKey: ['pc-scan', 'latest'],
    queryFn: getLatestPcScan,
  });
  const runScan = useMutation({
    mutationFn: startPcScan,
    onSuccess: (data) => {
      queryClient.setQueryData(['pc-scan', 'latest'], data);
      void queryClient.invalidateQueries({ queryKey: ['scans', 'recent'] });
    },
  });

  const findings = scan.data?.checks.flatMap((check) => check.findings) ?? [];
  const expectedChecks = [
    'Microsoft Defender',
    'Windows Firewall',
    'BitLocker',
    'Startup Apps',
  ];
  const visibleChecks = expectedChecks
    .map((name) => scan.data?.checks.find((check) => check.name === name))
    .filter((check) => check !== undefined);

  return (
    <div className="page-stack">
      <header className="page-header">
        <div>
          <p className="eyebrow">PC Security</p>
          <h2>Windows status checks</h2>
        </div>
        <button onClick={() => runScan.mutate()} disabled={runScan.isPending}>
          {runScan.isPending ? 'Scanning...' : 'Run scan'}
        </button>
      </header>

      {scan.data ? (
        <>
          <SecurityScoreCard
            title="Latest PC scan"
            target={scan.data.target}
            score={scan.data.score}
            riskLevel={scan.data.overallRisk}
            scannedAt={scan.data.scannedAt}
          />
          <SecurityRadarChart
            title="PC security dimensions"
            dimensions={getPcDimensions(scan.data)}
          />{' '}
        </>
      ) : null}

      <section className="check-grid">
        {visibleChecks.map((check) => (
          <CheckCard check={check} key={check.name} />
        ))}{' '}
      </section>

      <section className="page-stack">
        <h2>Findings</h2>
        {findings.length === 0 ? (
          <p className="muted">No findings in the latest PC scan.</p>
        ) : null}{' '}
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
