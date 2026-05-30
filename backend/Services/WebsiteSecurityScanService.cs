using System.Net; 
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using SecureScope.Api.Models;

namespace SecureScope.Api.Services;

public class WebsiteSecurityScanService(
    HttpClient httpClient,
    SecurityScoreService scoreService,
    IOptions<WebsiteScanOptions> options)
{
    private static readonly SecurityHeaderRequirement[] SecurityHeaders = 
    [
        new("Strict-Transport-Security", RiskLevel.High, "Add Strict-Transport-Security on HTTPS responses to require future HTTPS connections."),
        new("Content-Security-Policy", RiskLevel.Medium, "Add a Content-Security-Policy that matches the site's script, style, image, and framing needs."),
        new("X-Frame-Options", RiskLevel.Medium, "Add X-Frame-Options or an equivalent CSP frame-ancestors directive to reduce clickjacking risk."),
        new("X-Content-Type-Options", RiskLevel.Low, "Add X-Content-Type-Options: nosniff to reduce MIME-sniffing risk."),
        new("Referrer-Policy", RiskLevel.Low, "Add a Referrer-Policy header that limits cross-origin referrer leakage."),
        new("Permissions-Policy", RiskLevel.Low, "Add a Permissions-Policy header to restrict browser features the site does not need.")
    ];
    private readonly WebsiteScanOptions scanOptions = options.Value;

    public async Task<SecurityScanSummary> RunScanAsync(string url, CancellationToken cancellationToken = default) 
    {
        var target = NormalizeUrl(url); 
        using var response = await SendFollowingRedirectsAsync(target, cancellationToken);

        var evidence = WebsiteScanEvidence.FromResponse(response); 
        var checks = CreateChecks(evidence); 
        var score = scoreService.CalculateScore(checks);

        return new SecurityScanSummary
        {
            ScanType = SecurityScanType.Website,
            Target = evidence.FinalUrl,
            Score = score,
            OverallRisk = scoreService.CalculateOverallRisk(score),
            ScannedAt = DateTimeOffset.UtcNow,
            Checks = checks
        };
    }

    private async Task<HttpResponseMessage> SendFollowingRedirectsAsync(
        Uri initialTarget,
        CancellationToken cancellationToken)
    {
        var target = initialTarget;

        for (var redirectCount = 0; redirectCount <= scanOptions.MaxRedirects; redirectCount++)
        {
            await ValidateTargetAsync(target, cancellationToken);

            using var request = new HttpRequestMessage(HttpMethod.Get, target);
            request.Headers.UserAgent.ParseAdd("SecureScope/0.1 passive-security-scanner");

            var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            if (!IsRedirect(response.StatusCode))
            {
                return response;
            }

            if (redirectCount == scanOptions.MaxRedirects)
            {
                response.Dispose();
                throw new ArgumentException($"The website exceeded the redirect limit of {scanOptions.MaxRedirects}.");
            }

            if (response.Headers.Location is null ||
                !Uri.TryCreate(target, response.Headers.Location, out var redirectTarget))
            {
                response.Dispose();
                throw new ArgumentException("The website returned an invalid redirect URL.");
            }

            response.Dispose();
            target = redirectTarget;
        }

        throw new ArgumentException("The website redirect chain could not be completed.");
    }

    private async Task ValidateTargetAsync(Uri target, CancellationToken cancellationToken)
    {
        if (target.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("Only http and https URLs are supported.");
        }

        if (!string.IsNullOrEmpty(target.UserInfo))
        {
            throw new ArgumentException("Website URLs with embedded credentials are not supported.");
        }

        if (!target.IsDefaultPort && target.Port is not (80 or 443))
        {
            throw new ArgumentException("Only ports 80 and 443 are supported.");
        }

        if (scanOptions.EnforceAllowlist &&
            !scanOptions.AllowedHosts.Contains(target.Host, StringComparer.OrdinalIgnoreCase))
        {
            throw new ArgumentException("This public demo only scans approved example websites.");
        }

        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(target.DnsSafeHost, cancellationToken);
        }
        catch (SocketException ex)
        {
            throw new ArgumentException("The website host could not be resolved.", ex);
        }

        if (addresses.Length == 0)
        {
            throw new ArgumentException("The website host did not resolve to an IP address.");
        }

        if (addresses.Any(IsBlockedAddress))
        {
            throw new ArgumentException("Local, private, and reserved network addresses cannot be scanned.");
        }
    }

    private static bool IsRedirect(HttpStatusCode statusCode)
    {
        return statusCode is HttpStatusCode.MovedPermanently
            or HttpStatusCode.Found
            or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;
    }

    private static bool IsBlockedAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) ||
            address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.None) ||
            address.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return IsBlockedAddress(address.MapToIPv4());
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            return address.IsIPv6LinkLocal ||
                address.IsIPv6Multicast ||
                (bytes[0] & 0xfe) == 0xfc;
        }

        var octets = address.GetAddressBytes();
        return octets[0] is 0 or 10 or 127 ||
            octets[0] >= 224 ||
            (octets[0] == 100 && octets[1] is >= 64 and <= 127) ||
            (octets[0] == 169 && octets[1] == 254) ||
            (octets[0] == 172 && octets[1] is >= 16 and <= 31) ||
            (octets[0] == 192 && octets[1] == 168) ||
            (octets[0] == 198 && octets[1] is 18 or 19);
    }

    private static Uri NormalizeUrl(string url) 
    {
        var trimmed = url.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            throw new ArgumentException("A website URL is required.");
        }

        if (!trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = $"https://{trimmed}";
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("The website URL is not valid.");
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("Only http and https URLs are supported.");
        }

        return uri;
    }

    private static List<SecurityCheckResult> CreateChecks(WebsiteScanEvidence evidence) 
    {
        return
        [
            CreateHttpResponseCheck(evidence),
            CreateHttpsCheck(evidence),
            CreateSecurityHeadersCheck(evidence),
            CreateCookieCheck(evidence)
        ];
    }

    private static SecurityCheckResult CreateHttpResponseCheck(WebsiteScanEvidence evidence) 
    {
        var statusCode = (int)evidence.StatusCode; 

        return new SecurityCheckResult
        {
            Name = "HTTP response",
            Category = "Website reachability",
            Passed = statusCode is >= 200 and < 500, 
            RiskLevel = statusCode >= 500 ? RiskLevel.Medium : RiskLevel.Info, 
            Summary = $"Request completed with HTTP {statusCode}. Collected {evidence.Headers.Count} response header group(s) and {evidence.SetCookieHeaders.Count} Set-Cookie header(s)." 
        };
    }

    private static SecurityCheckResult CreateHttpsCheck(WebsiteScanEvidence evidence) 
    {
        var findings = new List<SecurityFinding>();

        if (!evidence.UsesHttps)
        {
            findings.Add(new SecurityFinding
            {
                RiskLevel = RiskLevel.High,
                Title = "Website is not using HTTPS",
                Description = $"Evidence: the final response URL used the {evidence.FinalUri.Scheme.ToUpperInvariant()} scheme for host {evidence.FinalUri.Host}.", 
                Recommendation = "Serve the site over HTTPS and redirect HTTP requests to HTTPS."
            });
        }

        return new SecurityCheckResult
        {
            Name = "HTTPS usage",
            Category = "Transport security",
            Passed = evidence.UsesHttps,
            RiskLevel = findings.Count > 0 ? RiskLevel.High : RiskLevel.Info,
            Summary = evidence.UsesHttps
                ? $"The final response used HTTPS for host {evidence.FinalUri.Host}." 
                : $"The final response did not use HTTPS for host {evidence.FinalUri.Host}.", 
            Findings = findings
        };
    }

    private static SecurityCheckResult CreateSecurityHeadersCheck(WebsiteScanEvidence evidence) 
    {
        var findings = new List<SecurityFinding>();

        foreach (var requiredHeader in SecurityHeaders)
        {
            if (evidence.Headers.ContainsKey(requiredHeader.Name))
            {
                continue;
            }

            if (requiredHeader.Name == "Strict-Transport-Security" && !evidence.UsesHttps)
            {
                continue;
            }

            findings.Add(new SecurityFinding
            {
                RiskLevel = requiredHeader.RiskLevel,
                Title = $"Missing {requiredHeader.Name}",
                Description = $"Evidence: {requiredHeader.Name} was not present in the response headers for host {evidence.FinalUri.Host}.", 
                Recommendation = requiredHeader.Recommendation
            });
        }

        var presentSecurityHeaderCount = SecurityHeaders.Count(header => evidence.Headers.ContainsKey(header.Name)); 
        var missingHeaderNames = findings.Select(finding => finding.Title.Replace("Missing ", string.Empty, StringComparison.Ordinal)).ToList(); 

        return new SecurityCheckResult
        {
            Name = "Security headers",
            Category = "Browser hardening",
            Passed = findings.Count == 0,
            RiskLevel = GetHighestRisk(findings),
            Summary = findings.Count == 0 
                ? $"All {SecurityHeaders.Length} checked security headers are present." 
                : $"Checked {SecurityHeaders.Length} security headers. Present: {presentSecurityHeaderCount}. Missing: {findings.Count} ({string.Join(", ", missingHeaderNames)}).", 
            Findings = findings
        };
    }

    private static SecurityCheckResult CreateCookieCheck(WebsiteScanEvidence evidence) 
    {
        return new SecurityCheckResult
        {
            Name = "Set-Cookie headers",
            Category = "Session configuration",
            Passed = true,
            RiskLevel = RiskLevel.Info,
            Summary = evidence.SetCookieHeaders.Count == 0
                ? "No Set-Cookie headers were returned by the scanned response."
                : $"The response returned {evidence.SetCookieHeaders.Count} Set-Cookie header(s). Raw cookie values are hidden in the dashboard summary." 
        };
    }

    private static RiskLevel GetHighestRisk(IReadOnlyCollection<SecurityFinding> findings) 
    {
        if (findings.Any(finding => finding.RiskLevel == RiskLevel.Critical))
        {
            return RiskLevel.Critical;
        }

        if (findings.Any(finding => finding.RiskLevel == RiskLevel.High))
        {
            return RiskLevel.High;
        }

        if (findings.Any(finding => finding.RiskLevel == RiskLevel.Medium))
        {
            return RiskLevel.Medium;
        }

        return findings.Any() ? RiskLevel.Low : RiskLevel.Info;
    }

    private sealed record SecurityHeaderRequirement(string Name, RiskLevel RiskLevel, string Recommendation); 

    private sealed class WebsiteScanEvidence 
    {
        public required string FinalUrl { get; init; }
        public required Uri FinalUri { get; init; } 
        public required HttpStatusCode StatusCode { get; init; }
        public required Dictionary<string, IReadOnlyList<string>> Headers { get; init; }
        public required List<string> SetCookieHeaders { get; init; }
        public required bool UsesHttps { get; init; }

        public static WebsiteScanEvidence FromResponse(HttpResponseMessage response) 
        {
            var headers = response.Headers
                .Concat(response.Content.Headers)
                .GroupBy(header => header.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => (IReadOnlyList<string>)group.SelectMany(header => header.Value).ToList(),
                    StringComparer.OrdinalIgnoreCase);

            var setCookieHeaders = headers.TryGetValue("Set-Cookie", out var cookies)
                ? cookies.ToList()
                : [];

            var finalUri = response.RequestMessage?.RequestUri ?? new Uri("about:blank"); 

            return new WebsiteScanEvidence
            {
                FinalUrl = finalUri.ToString(), 
                FinalUri = finalUri, 
                StatusCode = response.StatusCode,
                Headers = headers,
                SetCookieHeaders = setCookieHeaders,
                UsesHttps = response.RequestMessage?.RequestUri?.Scheme == Uri.UriSchemeHttps
            };
        }
    }
}
