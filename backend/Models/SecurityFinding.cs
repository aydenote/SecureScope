namespace SecureScope.Api.Models;

public class SecurityFinding
{
    public int Id { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public int SecurityCheckResultId { get; set; }
}
