namespace SecureScope.Api.Models;

public record PublicDemoConfig(
    bool PcDemoMode,
    bool WebsiteAllowlistEnforced,
    IReadOnlyCollection<string> WebsiteAllowedHosts);
