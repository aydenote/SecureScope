namespace SecureScope.Api.Models;

public class SecurityCheckResult
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public bool Passed { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public string Summary { get; set; } = string.Empty;
    public List<SecurityFinding> Findings { get; set; } = [];
    public int SecurityScanSummaryId { get; set; }
}
