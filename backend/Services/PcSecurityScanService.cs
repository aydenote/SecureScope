using SecureScope.Api.Models;

namespace SecureScope.Api.Services;

public class PcSecurityScanService(
    SecurityScoreService scoreService,
    DefenderCheckService defenderCheckService,
    FirewallCheckService firewallCheckService,
    BitLockerCheckService bitLockerCheckService,
    StartupAppsCheckService startupAppsCheckService,
    WindowsUpdateCheckService windowsUpdateCheckService) 
{
    public async Task<SecurityScanSummary> RunScanAsync(CancellationToken cancellationToken = default) 
    {
        var checks = await CreateChecksAsync(cancellationToken); 
        var score = scoreService.CalculateScore(checks);

        return new SecurityScanSummary
        {
            ScanType = SecurityScanType.Pc,
            Target = Environment.MachineName,
            Score = score,
            OverallRisk = scoreService.CalculateOverallRisk(score),
            ScannedAt = DateTimeOffset.UtcNow,
            Checks = checks
        };
    }

    public async Task<SecurityScanSummary> GetPreviewScanAsync(CancellationToken cancellationToken = default) 
    {
        var scan = await RunScanAsync(cancellationToken); 
        scan.Target = "This PC";
        return scan;
    }

    private async Task<List<SecurityCheckResult>> CreateChecksAsync(CancellationToken cancellationToken) 
    {
        var defenderCheck = await defenderCheckService.CheckAsync(cancellationToken); 
        var firewallCheck = await firewallCheckService.CheckAsync(cancellationToken); 
        var bitLockerCheck = await bitLockerCheckService.CheckAsync(cancellationToken); 
        var startupAppsCheck = await startupAppsCheckService.CheckAsync(cancellationToken); 
        var windowsUpdateCheck = await windowsUpdateCheckService.CheckAsync(cancellationToken); 

        return
        [
            defenderCheck, 
            firewallCheck, 
            bitLockerCheck, 
            startupAppsCheck, 
            windowsUpdateCheck 
        ];
    }
}
