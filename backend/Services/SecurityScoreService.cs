using SecureScope.Api.Models;

namespace SecureScope.Api.Services;

public class SecurityScoreService
{
    public int CalculateScore(IEnumerable<SecurityCheckResult> checks)
    {
        var penalty = checks.Sum(CalculateCheckPenalty); 

        return Math.Clamp(100 - penalty, 0, 100);
    }

    private static int CalculateCheckPenalty(SecurityCheckResult check) 
    {
        if (check.Findings.Count > 0) 
        {
            return check.Findings.Sum(finding => finding.RiskLevel switch 
            {
                RiskLevel.Critical => 25,
                RiskLevel.High => 18,
                RiskLevel.Medium => 10,
                RiskLevel.Low => 4,
                _ => 1
            });
        }

        return check.RiskLevel switch 
        {
            RiskLevel.Critical => 25,
            RiskLevel.High => 18,
            RiskLevel.Medium => 10,
            RiskLevel.Low => 4,
            _ => check.Passed ? 0 : 1
        };
    }

    public RiskLevel CalculateOverallRisk(int score)
    {
        return score switch
        {
            < 40 => RiskLevel.Critical,
            < 60 => RiskLevel.High,
            < 75 => RiskLevel.Medium,
            < 90 => RiskLevel.Low,
            _ => RiskLevel.Info
        };
    }
}
