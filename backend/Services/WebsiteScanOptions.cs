namespace SecureScope.Api.Services;

public class WebsiteScanOptions
{
    public bool EnforceAllowlist { get; set; }
    public string[] AllowedHosts { get; set; } = [];
    public int MaxRedirects { get; set; } = 3;
    public int TimeoutSeconds { get; set; } = 10;
}
