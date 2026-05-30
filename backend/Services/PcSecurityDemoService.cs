using SecureScope.Api.Models;

namespace SecureScope.Api.Services;

public class PcSecurityDemoService(SecurityScoreService scoreService)
{
    public SecurityScanSummary CreateScan()
    {
        var checks = CreateChecks();
        var score = scoreService.CalculateScore(checks);

        return new SecurityScanSummary
        {
            ScanType = SecurityScanType.Pc,
            Target = "Demo Windows PC",
            Score = score,
            OverallRisk = scoreService.CalculateOverallRisk(score),
            ScannedAt = DateTimeOffset.UtcNow,
            Checks = checks
        };
    }

    private static List<SecurityCheckResult> CreateChecks()
    {
        return
        [
            new SecurityCheckResult
            {
                Name = "Microsoft Defender",
                Category = "Endpoint protection",
                Passed = true,
                RiskLevel = RiskLevel.Info,
                Summary = "Demo data: real-time protection, antivirus, and antispyware protection are enabled."
            },
            new SecurityCheckResult
            {
                Name = "Windows Firewall",
                Category = "Network protection",
                Passed = true,
                RiskLevel = RiskLevel.Info,
                Summary = "Demo data: Domain, Private, and Public firewall profiles are enabled."
            },
            new SecurityCheckResult
            {
                Name = "BitLocker",
                Category = "Disk encryption",
                Passed = false,
                RiskLevel = RiskLevel.High,
                Summary = "Demo data: protection needs review on the operating system volume.",
                Findings =
                [
                    new SecurityFinding
                    {
                        RiskLevel = RiskLevel.High,
                        Title = "BitLocker protection needs review on C:",
                        Description = "Demo evidence: BitLocker protection is disabled on the operating system volume.",
                        Recommendation = "Review BitLocker in Windows Security or Control Panel and enable protection where appropriate."
                    }
                ]
            },
            new SecurityCheckResult
            {
                Name = "Startup Apps",
                Category = "System hardening",
                Passed = true,
                RiskLevel = RiskLevel.Info,
                Summary = "Demo data: startup applications were reviewed and no risky locations were detected."
            },
            new SecurityCheckResult
            {
                Name = "Operating system updates",
                Category = "Patch status",
                Passed = true,
                RiskLevel = RiskLevel.Info,
                Summary = "Demo data: no pending security-related updates were detected."
            }
        ];
    }
}
