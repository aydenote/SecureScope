using System.Diagnostics;
using System.Text.Json;
using SecureScope.Api.Models;

namespace SecureScope.Api.Services;

public class WindowsUpdateCheckService 
{
    public async Task<SecurityCheckResult> CheckAsync(CancellationToken cancellationToken = default) 
    {
        if (!OperatingSystem.IsWindows())
        {
            return CreateUnavailableResult("Windows Update status is only available on Windows."); 
        }

        try
        {
            var output = await RunPowerShellAsync(cancellationToken); 
            var updates = ParseUpdates(output); 
            return BuildResult(updates); 
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or JsonException)
        {
            return CreateUnavailableResult($"Unable to read Windows Update status: {ex.Message}"); 
        }
        catch (UnauthorizedAccessException ex)
        {
            return CreateUnavailableResult($"Permission denied while reading Windows Update status: {ex.Message}"); 
        }
    }

    private static async Task<string> RunPowerShellAsync(CancellationToken cancellationToken) 
    {
        const string command = """
            $session = New-Object -ComObject Microsoft.Update.Session;
            $searcher = $session.CreateUpdateSearcher();
            $result = $searcher.Search("IsInstalled=0 and IsHidden=0");
            $updates = @();
            foreach ($update in $result.Updates) {
              $updates += [pscustomobject]@{
                Title=[string]$update.Title;
                MsrcSeverity=[string]$update.MsrcSeverity;
                IsDownloaded=[bool]$update.IsDownloaded;
                LastDeploymentChangeTime=$update.LastDeploymentChangeTime
              }
            }
            $updates | ConvertTo-Json -Compress
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
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(stderr) ? $"PowerShell exited with code {process.ExitCode}." : stderr.Trim());
        }

        return string.IsNullOrWhiteSpace(stdout) ? "[]" : stdout;
    }

    private static List<PendingUpdate> ParseUpdates(string json) 
    {
        using var document = JsonDocument.Parse(json);
        var updates = new List<PendingUpdate>();

        if (document.RootElement.ValueKind == JsonValueKind.Array)
        {
            updates.AddRange(document.RootElement.EnumerateArray().Select(ParseUpdate));
        }
        else if (document.RootElement.ValueKind == JsonValueKind.Object)
        {
            updates.Add(ParseUpdate(document.RootElement));
        }

        return updates;
    }

    private static PendingUpdate ParseUpdate(JsonElement item) 
    {
        return new PendingUpdate(
            GetString(item, "Title") ?? "Unknown update",
            GetString(item, "MsrcSeverity") ?? string.Empty,
            GetBoolean(item, "IsDownloaded") ?? false);
    }

    private static SecurityCheckResult BuildResult(IReadOnlyCollection<PendingUpdate> updates) 
    {
        var findings = new List<SecurityFinding>();
        var securityUpdates = updates
            .Where(update =>
                update.Title.Contains("Security", StringComparison.OrdinalIgnoreCase) ||
                update.MsrcSeverity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ||
                update.MsrcSeverity.Equals("Important", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (securityUpdates.Count > 0)
        {
            findings.Add(new SecurityFinding
            {
                RiskLevel = securityUpdates.Any(update => update.MsrcSeverity.Equals("Critical", StringComparison.OrdinalIgnoreCase)) ? RiskLevel.High : RiskLevel.Medium,
                Title = "Pending Windows security updates",
                Description = $"Evidence: {securityUpdates.Count} pending security-related update(s): {string.Join("; ", securityUpdates.Take(5).Select(update => update.Title))}{(securityUpdates.Count > 5 ? "; ..." : string.Empty)}.",
                Recommendation = "Open Windows Update and install pending security updates."
            });
        }

        return new SecurityCheckResult
        {
            Name = "Operating system updates",
            Category = "Patch status",
            Passed = findings.Count == 0,
            RiskLevel = findings.FirstOrDefault()?.RiskLevel ?? RiskLevel.Info,
            Summary = updates.Count == 0
                ? "Windows Update reported no pending non-hidden updates."
                : $"Windows Update reported {updates.Count} pending non-hidden update(s), including {securityUpdates.Count} security-related update(s).",
            Findings = findings
        };
    }

    private static SecurityCheckResult CreateUnavailableResult(string reason) 
    {
        return new SecurityCheckResult
        {
            Name = "Operating system updates",
            Category = "Patch status",
            Passed = false,
            RiskLevel = RiskLevel.Info,
            Summary = reason,
            Findings = []
        };
    }

    private static string? GetString(JsonElement root, string propertyName) 
    {
        return root.TryGetProperty(propertyName, out var property) ? property.ToString() : null;
    }

    private static bool? GetBoolean(JsonElement root, string propertyName) 
    {
        if (!root.TryGetProperty(propertyName, out var property))
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

    private sealed record PendingUpdate(string Title, string MsrcSeverity, bool IsDownloaded); 
}
