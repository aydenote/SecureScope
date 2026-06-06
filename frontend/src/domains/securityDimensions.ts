import type {
  RiskLevel,
  SecurityCheckResult,
  SecurityScanSummary,
} from '../lib/api';

export interface SecurityDimensionScore {
  label: string;
  score: number;
  riskLevel: RiskLevel;
}

const pcDimensionChecks = [
  { label: 'Defender', checkName: 'Microsoft Defender' },
  { label: 'Firewall', checkName: 'Windows Firewall' },
  { label: 'BitLocker', checkName: 'BitLocker' },
  { label: 'Startup', checkName: 'Startup Apps' },
  { label: 'Updates', checkName: 'Operating system updates' },
];

export function getPcDimensions(
  scan: SecurityScanSummary
): SecurityDimensionScore[] {
  const dimensions = pcDimensionChecks.map((dimension) => {
    const check = scan.checks.find((item) => item.name === dimension.checkName);
    return {
      label: dimension.label,
      score: check ? scoreCheck(check) : 5,
      riskLevel: check?.riskLevel ?? 'Info',
    };
  });

  return [
    ...dimensions,
    {
      label: 'Overall',
      score: Math.round(scan.score / 10),
      riskLevel: scan.overallRisk,
    },
  ];
}

export function getWebsiteDimensions(
  scan: SecurityScanSummary
): SecurityDimensionScore[] {
  return [
    scoreWebsiteDimension(scan, 'HTTPS', ['Website is not using HTTPS'], 0),
    scoreWebsiteDimension(
      scan,
      'HSTS',
      ['Missing Strict-Transport-Security'],
      0
    ),
    scoreWebsiteDimension(scan, 'CSP', ['Missing Content-Security-Policy'], 4),
    scoreWebsiteDimension(scan, 'Frame', ['Missing X-Frame-Options'], 3),
    scoreWebsiteDimension(
      scan,
      'Content',
      ['Missing X-Content-Type-Options'],
      6
    ),
    scoreWebsiteDimension(
      scan,
      'Privacy',
      ['Missing Referrer-Policy', 'Missing Permissions-Policy'],
      6
    ),
  ];
}

function scoreWebsiteDimension(
  scan: SecurityScanSummary,
  label: string,
  findingTitles: string[],
  fallbackScore: number
): SecurityDimensionScore {
  const findings = scan.checks.flatMap((check) => check.findings);
  const matchedFindings = findings.filter((finding) =>
    findingTitles.includes(finding.title)
  );

  if (matchedFindings.length === 0) {
    return { label, score: 10, riskLevel: 'Info' };
  }

  const score = Math.max(
    0,
    fallbackScore - Math.max(0, matchedFindings.length - 1) * 2
  );
  return {
    label,
    score,
    riskLevel: highestRisk(matchedFindings.map((finding) => finding.riskLevel)),
  };
}

function scoreCheck(check: SecurityCheckResult): number {
  if (check.passed && check.findings.length === 0) {
    return 10;
  }

  const highestFindingRisk = highestRisk(
    check.findings.map((finding) => finding.riskLevel)
  );
  const riskLevel =
    check.findings.length > 0 ? highestFindingRisk : check.riskLevel;

  return riskLevelToDimensionScore(riskLevel, check.passed);
}

function riskLevelToDimensionScore(
  riskLevel: RiskLevel,
  passed: boolean
): number {
  if (!passed && riskLevel === 'Info') {
    return 5;
  }

  switch (riskLevel) {
    case 'Critical':
      return 0;
    case 'High':
      return 2;
    case 'Medium':
      return 5;
    case 'Low':
      return 7;
    case 'Info':
      return 10;
  }
}

function highestRisk(riskLevels: RiskLevel[]): RiskLevel {
  if (riskLevels.includes('Critical')) {
    return 'Critical';
  }

  if (riskLevels.includes('High')) {
    return 'High';
  }

  if (riskLevels.includes('Medium')) {
    return 'Medium';
  }

  if (riskLevels.includes('Low')) {
    return 'Low';
  }

  return 'Info';
}
