using System.Diagnostics;
using System.Text.Json;
using SecureScope.Api.Models;

namespace SecureScope.Api.Services;

public class DefenderCheckService 
{
    private static readonly TimeSpan SignatureMaxAge = TimeSpan.FromDays(7); 
    private static readonly TimeSpan QuickScanMaxAge = TimeSpan.FromDays(14); 

    public async Task<SecurityCheckResult> CheckAsync(CancellationToken cancellationToken = default) 
    {
        if (!OperatingSystem.IsWindows())
        {
            return CreateUnavailableResult("Microsoft Defender status is only available on Windows."); 
        }

        try
        {
            var output = await RunPowerShellAsync(cancellationToken); 
            var status = ParseStatus(output); 

            return BuildResult(status); 
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or JsonException)
        {
            return CreateUnavailableResult($"Unable to read Microsoft Defender status: {ex.Message}"); 
        }
        catch (UnauthorizedAccessException ex)
        {
            return CreateUnavailableResult($"Permission denied while reading Microsoft Defender status: {ex.Message}"); 
        }
    }

    private static async Task<string> RunPowerShellAsync(CancellationToken cancellationToken) 
    {
        const string command = """
            Get-MpComputerStatus |
              Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime |
              ConvertTo-Json -Compress
            """;

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -Command \"{command.Replace("\"", "\\\"")}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        if (!process.Start())
        {
            throw new InvalidOperationException("PowerShell could not be started.");
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken);

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(stderr)
                ? $"PowerShell exited with code {process.ExitCode}."
                : stderr.Trim());
        }

        if (string.IsNullOrWhiteSpace(stdout))
        {
            throw new InvalidOperationException("PowerShell returned no Defender status data.");
        }

        return stdout;
    }

    private static DefenderStatus ParseStatus(string json) 
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        return new DefenderStatus
        {
            RealTimeProtectionEnabled = GetBoolean(root, "RealTimeProtectionEnabled"),
            AntivirusEnabled = GetBoolean(root, "AntivirusEnabled"),
            AntispywareEnabled = GetBoolean(root, "AntispywareEnabled"),
            AntivirusSignatureLastUpdated = GetDateTimeOffset(root, "AntivirusSignatureLastUpdated"),
            QuickScanEndTime = GetDateTimeOffset(root, "QuickScanEndTime")
        };
    }

    private static SecurityCheckResult BuildResult(DefenderStatus status) 
    {
        var now = DateTimeOffset.UtcNow;
        var findings = new List<SecurityFinding>();

        if (status.RealTimeProtectionEnabled == false)
        {
            findings.Add(new SecurityFinding
            {
                RiskLevel = RiskLevel.High,
                Title = "Real-time protection is disabled",
                Description = "Microsoft Defender reports that real-time protection is not enabled.",
                Recommendation = "Open Windows Security and enable Microsoft Defender real-time protection."
            });
        }

        if (status.AntivirusSignatureLastUpdated is not null &&
            now - status.AntivirusSignatureLastUpdated.Value.ToUniversalTime() > SignatureMaxAge) 
        {
            findings.Add(new SecurityFinding
            {
                RiskLevel = RiskLevel.Medium,
                Title = "Antivirus signatures are older than 7 days",
                Description = $"Microsoft Defender signatures were last updated on {status.AntivirusSignatureLastUpdated.Value.LocalDateTime:g}.",
                Recommendation = "Run Windows Update or update Microsoft Defender security intelligence."
            });
        }

        if (status.QuickScanEndTime is not null &&
            now - status.QuickScanEndTime.Value.ToUniversalTime() > QuickScanMaxAge) 
        {
            findings.Add(new SecurityFinding
            {
                RiskLevel = RiskLevel.Low,
                Title = "Quick scan is older than 14 days",
                Description = $"The last Microsoft Defender quick scan completed on {status.QuickScanEndTime.Value.LocalDateTime:g}.",
                Recommendation = "Run a Microsoft Defender quick scan."
            });
        }

        var coreProtectionEnabled = status.RealTimeProtectionEnabled == true
            && status.AntivirusEnabled == true
            && status.AntispywareEnabled == true;

        return new SecurityCheckResult
        {
            Name = "Microsoft Defender",
            Category = "Endpoint protection",
            Passed = coreProtectionEnabled && findings.Count == 0,
            RiskLevel = GetRiskLevel(coreProtectionEnabled, findings),
            Summary = CreateSummary(status),
            Findings = findings
        };
    }

    private static SecurityCheckResult CreateUnavailableResult(string reason) 
    {
        return new SecurityCheckResult
        {
            Name = "Microsoft Defender",
            Category = "Endpoint protection",
            Passed = false,
            RiskLevel = RiskLevel.Info,
            Summary = reason,
            Findings = []
        };
    }

    private static RiskLevel GetRiskLevel(bool coreProtectionEnabled, IReadOnlyCollection<SecurityFinding> findings) 
    {
        if (!coreProtectionEnabled || findings.Any(finding => finding.RiskLevel == RiskLevel.High))
        {
            return RiskLevel.High;
        }

        if (findings.Any(finding => finding.RiskLevel == RiskLevel.Medium))
        {
            return RiskLevel.Medium;
        }

        return findings.Count > 0 ? RiskLevel.Low : RiskLevel.Info;
    }

    private static string CreateSummary(DefenderStatus status) 
    {
        return $"Real-time protection: {FormatStatus(status.RealTimeProtectionEnabled)}; " +
            $"Antivirus: {FormatStatus(status.AntivirusEnabled)}; " +
            $"Antispyware: {FormatStatus(status.AntispywareEnabled)}; " +
            $"Signatures updated: {FormatDate(status.AntivirusSignatureLastUpdated)}; " +
            $"Last quick scan: {FormatDate(status.QuickScanEndTime)}.";
    }

    private static bool? GetBoolean(JsonElement root, string propertyName) 
    {
        if (!root.TryGetProperty(propertyName, out var property) || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        return property.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String when bool.TryParse(property.GetString(), out var value) => value,
            _ => null
        };
    }

    private static DateTimeOffset? GetDateTimeOffset(JsonElement root, string propertyName) 
    {
        if (!root.TryGetProperty(propertyName, out var property) || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.String &&
            DateTimeOffset.TryParse(property.GetString(), out var dateTimeOffset))
        {
            return dateTimeOffset;
        }

        return null;
    }

    private static string FormatStatus(bool? value) 
    {
        return value switch
        {
            true => "enabled",
            false => "disabled",
            null => "unknown"
        };
    }

    private static string FormatDate(DateTimeOffset? value) 
    {
        return value?.LocalDateTime.ToString("g") ?? "unknown";
    }

    private sealed class DefenderStatus 
    {
        public bool? RealTimeProtectionEnabled { get; init; }
        public bool? AntivirusEnabled { get; init; }
        public bool? AntispywareEnabled { get; init; }
        public DateTimeOffset? AntivirusSignatureLastUpdated { get; init; }
        public DateTimeOffset? QuickScanEndTime { get; init; }
    }
}
