using System.Diagnostics;
using System.Text.Json;
using SecureScope.Api.Models;

namespace SecureScope.Api.Services;

public class StartupAppsCheckService 
{
    private const int HighStartupItemCount = 15; 

    public async Task<SecurityCheckResult> CheckAsync(CancellationToken cancellationToken = default) 
    {
        if (!OperatingSystem.IsWindows())
        {
            return CreateUnavailableResult("Startup Apps inventory is only available on Windows."); 
        }

        try
        {
            var output = await RunPowerShellAsync(cancellationToken); 
            var items = ParseItems(output); 
            return BuildResult(items); 
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or JsonException)
        {
            return CreateUnavailableResult($"Unable to read Startup Apps inventory: {ex.Message}"); 
        }
        catch (UnauthorizedAccessException ex)
        {
            return CreateUnavailableResult($"Permission denied while reading Startup Apps inventory: {ex.Message}"); 
        }
    }

    private static async Task<string> RunPowerShellAsync(CancellationToken cancellationToken) 
    {
        const string command = """
            $items = @();
            $runKeys = @(
              @{Scope='CurrentUser'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'},
              @{Scope='LocalMachine'; Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'},
              @{Scope='LocalMachine32'; Path='HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'}
            );
            foreach ($key in $runKeys) {
              if (Test-Path $key.Path) {
                $props = Get-ItemProperty $key.Path;
                foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
                  $items += [pscustomobject]@{Source=$key.Scope; Name=$prop.Name; Command=[string]$prop.Value}
                }
              }
            }
            $folders = @(
              @{Scope='CurrentUserStartupFolder'; Path=[Environment]::GetFolderPath('Startup')},
              @{Scope='CommonStartupFolder'; Path=[Environment]::GetFolderPath('CommonStartup')}
            );
            foreach ($folder in $folders) {
              if ($folder.Path -and (Test-Path $folder.Path)) {
                Get-ChildItem $folder.Path -File | ForEach-Object {
                  $items += [pscustomobject]@{Source=$folder.Scope; Name=$_.Name; Command=$_.FullName}
                }
              }
            }
            $items | ConvertTo-Json -Compress
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

    private static List<StartupItem> ParseItems(string json) 
    {
        using var document = JsonDocument.Parse(json);
        var items = new List<StartupItem>();

        if (document.RootElement.ValueKind == JsonValueKind.Array)
        {
            items.AddRange(document.RootElement.EnumerateArray().Select(ParseItem));
        }
        else if (document.RootElement.ValueKind == JsonValueKind.Object)
        {
            items.Add(ParseItem(document.RootElement));
        }

        return items;
    }

    private static StartupItem ParseItem(JsonElement item) 
    {
        return new StartupItem(
            GetString(item, "Source") ?? "Unknown",
            GetString(item, "Name") ?? "Unknown",
            GetString(item, "Command") ?? string.Empty);
    }

    private static SecurityCheckResult BuildResult(IReadOnlyCollection<StartupItem> items) 
    {
        var findings = new List<SecurityFinding>();

        if (items.Count > HighStartupItemCount)
        {
            findings.Add(new SecurityFinding
            {
                RiskLevel = RiskLevel.Medium,
                Title = "High number of startup apps",
                Description = $"Evidence: {items.Count} startup entries were found across Run registry keys and Startup folders.",
                Recommendation = "Review Startup Apps in Windows Settings and disable entries that are unnecessary or unrecognized."
            });
        }

        var riskyLocations = items
            .Where(item => item.Command.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) || item.Command.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase))
            .Take(5)
            .ToList();

        if (riskyLocations.Count > 0)
        {
            findings.Add(new SecurityFinding
            {
                RiskLevel = RiskLevel.Low,
                Title = "Startup apps reference temporary or downloads locations",
                Description = $"Evidence: {string.Join("; ", riskyLocations.Select(item => $"{item.Name} -> {item.Command}"))}.",
                Recommendation = "Verify these startup entries are expected. Startup commands from temporary or downloads folders can be suspicious."
            });
        }

        return new SecurityCheckResult
        {
            Name = "Startup Apps",
            Category = "System hardening",
            Passed = findings.Count == 0,
            RiskLevel = findings.Any(finding => finding.RiskLevel == RiskLevel.Medium) ? RiskLevel.Medium : findings.Count > 0 ? RiskLevel.Low : RiskLevel.Info,
            Summary = items.Count == 0
                ? "No startup entries were found in common Run registry keys or Startup folders."
                : $"Found {items.Count} startup item(s): {string.Join("; ", items.Take(10).Select(item => $"{item.Name} ({item.Source})"))}{(items.Count > 10 ? "; ..." : string.Empty)}.",
            Findings = findings
        };
    }

    private static SecurityCheckResult CreateUnavailableResult(string reason) 
    {
        return new SecurityCheckResult
        {
            Name = "Startup Apps",
            Category = "System hardening",
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

    private sealed record StartupItem(string Source, string Name, string Command); 
}
