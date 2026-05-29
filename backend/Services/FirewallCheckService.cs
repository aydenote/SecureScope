using System.Diagnostics;
using System.Text.Json;
using SecureScope.Api.Models;

namespace SecureScope.Api.Services;

public class FirewallCheckService 
{
    private static readonly string[] ExpectedProfiles = ["Domain", "Private", "Public"]; 

    public async Task<SecurityCheckResult> CheckAsync(CancellationToken cancellationToken = default) 
    {
        if (!OperatingSystem.IsWindows())
        {
            return CreateUnavailableResult("Windows Firewall status is only available on Windows."); 
        }

        try
        {
            var output = await RunPowerShellAsync(cancellationToken); 
            var profiles = ParseProfiles(output); 

            return BuildResult(profiles); 
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or JsonException)
        {
            return CreateUnavailableResult($"Unable to read Windows Firewall status: {ex.Message}"); 
        }
        catch (UnauthorizedAccessException ex)
        {
            return CreateUnavailableResult($"Permission denied while reading Windows Firewall status: {ex.Message}"); 
        }
    }

    private static async Task<string> RunPowerShellAsync(CancellationToken cancellationToken) 
    {
        const string command = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress";

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -Command \"{command}\"",
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
            throw new InvalidOperationException("PowerShell returned no firewall profile data.");
        }

        return stdout;
    }

    private static IReadOnlyDictionary<string, bool?> ParseProfiles(string json) 
    {
        using var document = JsonDocument.Parse(json);
        var profiles = new Dictionary<string, bool?>(StringComparer.OrdinalIgnoreCase);

        if (document.RootElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in document.RootElement.EnumerateArray())
            {
                AddProfile(profiles, item);
            }
        }
        else if (document.RootElement.ValueKind == JsonValueKind.Object)
        {
            AddProfile(profiles, document.RootElement);
        }
        else
        {
            throw new JsonException("Unexpected firewall profile JSON format.");
        }

        return profiles;
    }

    private static void AddProfile(Dictionary<string, bool?> profiles, JsonElement item) 
    {
        if (!item.TryGetProperty("Name", out var nameProperty))
        {
            return;
        }

        var name = nameProperty.GetString();
        if (string.IsNullOrWhiteSpace(name))
        {
            return;
        }

        profiles[name] = GetBoolean(item, "Enabled");
    }

    private static SecurityCheckResult BuildResult(IReadOnlyDictionary<string, bool?> profiles) 
    {
        var findings = new List<SecurityFinding>();

        foreach (var profileName in ExpectedProfiles)
        {
            profiles.TryGetValue(profileName, out var enabled);

            if (enabled == false)
            {
                findings.Add(new SecurityFinding
                {
                    RiskLevel = RiskLevel.High,
                    Title = $"{profileName} firewall profile is disabled",
                    Description = $"Evidence: Get-NetFirewallProfile reported Name={profileName}, Enabled=False.",
                    Recommendation = $"Review Windows Security and enable the {profileName} firewall profile if this is not intentional."
                });
            }
        }

        return new SecurityCheckResult
        {
            Name = "Windows Firewall",
            Category = "Network protection",
            Passed = findings.Count == 0 && ExpectedProfiles.All(profile => profiles.TryGetValue(profile, out var enabled) && enabled == true),
            RiskLevel = findings.Count > 0 ? RiskLevel.High : RiskLevel.Info,
            Summary = CreateSummary(profiles),
            Findings = findings
        };
    }

    private static SecurityCheckResult CreateUnavailableResult(string reason) 
    {
        return new SecurityCheckResult
        {
            Name = "Windows Firewall",
            Category = "Network protection",
            Passed = false,
            RiskLevel = RiskLevel.Info,
            Summary = reason,
            Findings = []
        };
    }

    private static string CreateSummary(IReadOnlyDictionary<string, bool?> profiles) 
    {
        var evidence = ExpectedProfiles.Select(profile =>
        {
            profiles.TryGetValue(profile, out var enabled);
            return $"{profile}: {FormatStatus(enabled)}";
        });

        return $"Firewall profile evidence from Get-NetFirewallProfile: {string.Join("; ", evidence)}.";
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

    private static string FormatStatus(bool? enabled) 
    {
        return enabled switch
        {
            true => "enabled",
            false => "disabled",
            null => "unknown"
        };
    }
}
