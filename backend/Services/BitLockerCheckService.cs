using System.Diagnostics;
using System.Text.Json;
using SecureScope.Api.Models;

namespace SecureScope.Api.Services;

public class BitLockerCheckService 
{
    public async Task<SecurityCheckResult> CheckAsync(CancellationToken cancellationToken = default) 
    {
        if (!OperatingSystem.IsWindows())
        {
            return CreateUnavailableResult("BitLocker status is only available on Windows."); 
        }

        try
        {
            var output = await RunPowerShellAsync(cancellationToken); 
            var volumes = ParseVolumes(output); 
            return BuildResult(volumes); 
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or JsonException)
        {
            return CreateUnavailableResult($"Unable to read BitLocker status: {ex.Message}"); 
        }
        catch (UnauthorizedAccessException ex)
        {
            return CreateUnavailableResult($"Permission denied while reading BitLocker status: {ex.Message}"); 
        }
    }

    private static async Task<string> RunPowerShellAsync(CancellationToken cancellationToken) 
    {
        const string command = "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage | ConvertTo-Json -Compress";

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
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(stderr) ? $"PowerShell exited with code {process.ExitCode}." : stderr.Trim());
        }

        return string.IsNullOrWhiteSpace(stdout)
            ? throw new InvalidOperationException("PowerShell returned no BitLocker volume data.")
            : stdout;
    }

    private static List<BitLockerVolume> ParseVolumes(string json) 
    {
        using var document = JsonDocument.Parse(json);
        var volumes = new List<BitLockerVolume>();

        if (document.RootElement.ValueKind == JsonValueKind.Array)
        {
            volumes.AddRange(document.RootElement.EnumerateArray().Select(ParseVolume));
        }
        else if (document.RootElement.ValueKind == JsonValueKind.Object)
        {
            volumes.Add(ParseVolume(document.RootElement));
        }

        return volumes;
    }

    private static BitLockerVolume ParseVolume(JsonElement item) 
    {
        return new BitLockerVolume(
            GetString(item, "MountPoint") ?? "Unknown",
            GetString(item, "VolumeStatus") ?? "Unknown",
            GetString(item, "ProtectionStatus") ?? "Unknown",
            GetNumber(item, "EncryptionPercentage"));
    }

    private static SecurityCheckResult BuildResult(IReadOnlyCollection<BitLockerVolume> volumes) 
    {
        var findings = new List<SecurityFinding>();

        foreach (var volume in volumes.Where(volume => volume.MountPoint.EndsWith(':')))
        {
            var protectionOn = volume.ProtectionStatus.Equals("On", StringComparison.OrdinalIgnoreCase) || volume.ProtectionStatus == "1";
            var fullyEncrypted = volume.EncryptionPercentage is null or >= 100;

            if (!protectionOn || !fullyEncrypted)
            {
                findings.Add(new SecurityFinding
                {
                    RiskLevel = RiskLevel.High,
                    Title = $"BitLocker protection needs review on {volume.MountPoint}",
                    Description = $"Evidence: MountPoint={volume.MountPoint}, ProtectionStatus={volume.ProtectionStatus}, VolumeStatus={volume.VolumeStatus}, EncryptionPercentage={FormatPercent(volume.EncryptionPercentage)}.",
                    Recommendation = "Review BitLocker in Windows Security or Control Panel and enable protection for local fixed drives where appropriate."
                });
            }
        }

        return new SecurityCheckResult
        {
            Name = "BitLocker",
            Category = "Disk encryption",
            Passed = volumes.Count > 0 && findings.Count == 0,
            RiskLevel = findings.Count > 0 ? RiskLevel.High : RiskLevel.Info,
            Summary = volumes.Count == 0
                ? "No BitLocker volumes were returned by Get-BitLockerVolume."
                : $"BitLocker evidence: {string.Join("; ", volumes.Select(volume => $"{volume.MountPoint} protection={volume.ProtectionStatus}, encrypted={FormatPercent(volume.EncryptionPercentage)}"))}.",
            Findings = findings
        };
    }

    private static SecurityCheckResult CreateUnavailableResult(string reason) 
    {
        return new SecurityCheckResult
        {
            Name = "BitLocker",
            Category = "Disk encryption",
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

    private static double? GetNumber(JsonElement root, string propertyName) 
    {
        return root.TryGetProperty(propertyName, out var property) && property.TryGetDouble(out var value) ? value : null;
    }

    private static string FormatPercent(double? value) 
    {
        return value is null ? "unknown" : $"{value:0}%";
    }

    private sealed record BitLockerVolume(string MountPoint, string VolumeStatus, string ProtectionStatus, double? EncryptionPercentage); 
}
