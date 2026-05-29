namespace SecureScope.Api.Models;

public class SecurityScanSummary
{
    public int Id { get; set; }
    public SecurityScanType ScanType { get; set; }
    public string Target { get; set; } = string.Empty;
    public int Score { get; set; }
    public RiskLevel OverallRisk { get; set; }
    public DateTimeOffset ScannedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<SecurityCheckResult> Checks { get; set; } = [];
}
