# SecureScope

SecureScope is a defensive, read-only security dashboard for checking a Windows PC's local security posture and the passive security configuration of authorized websites.

It combines a C# ASP.NET Core backend for local system inspection and HTTP scanning with a React dashboard for fast, clear review of scores, findings, and scan history.

## 1. Project Overview

SecureScope helps users answer two practical questions:

- Is this Windows PC configured with basic security protections enabled?
- Does this website expose common browser security protections through response headers?

The application is designed for local use. It reads security status, evaluates the result through a rule-based policy engine, stores scan summaries in SQLite, and presents the findings in a web dashboard.

SecureScope is defensive by design. It does not change Windows settings, run exploit payloads, brute force paths, crawl sites, or perform destructive actions.

## 2. Problem

Basic security posture checks are often spread across multiple places:

- Windows Security for Defender status
- Firewall configuration panels
- PowerShell commands for deeper system state
- Browser developer tools or curl for website headers
- Manual notes for tracking previous scans

This makes it easy to miss stale antivirus signatures, disabled firewall profiles, missing website security headers, or trends across repeated checks.

## 3. Solution

SecureScope provides one local dashboard that:

- Collects read-only Windows security signals.
- Performs a single passive GET request for website checks.
- Converts raw evidence into normalized security findings.
- Scores scans using a simple rule-based policy engine.
- Stores scan results locally in SQLite.
- Shows PC status, website status, finding counts, and recent scan history.

## 4. Key Features

- PC security score and check cards
- Microsoft Defender read-only status check
- Windows Firewall profile status check
- BitLocker read-only status check
- Startup Apps read-only inventory check
- Windows Update pending update check
- Passive website scan by URL
- Website security header checks
- User-friendly website scan summaries that hide raw header and cookie values
- Security dimension radar charts for PC and website status
- Finding severity labels: Info, Low, Medium, High, Critical
- Latest PC scan and latest website scan views
- Recent scan history
- Local SQLite persistence
- Swagger UI in development

## 5. Architecture

```text
SecureScope
├── frontend
│   ├── React + TypeScript + Vite
│   ├── React Router pages
│   └── TanStack Query API client
│
└── backend
    ├── ASP.NET Core Web API
    ├── Scan services
    ├── Rule-based scoring
    ├── EF Core
    └── SQLite
```

The frontend talks to the backend through `/api/*` endpoints. During local development, Vite proxies API requests to the backend so browser CORS issues are avoided.

## 6. Tech Stack

Frontend:

- React
- TypeScript
- Vite
- React Router
- TanStack Query

Backend:

- C#
- ASP.NET Core Web API
- .NET 10
- Entity Framework Core
- SQLite
- PowerShell for read-only Windows security status

React and C# are used together because they fit different parts of the problem. React provides a responsive dashboard for scanning workflows, loading states, and result exploration. C# and ASP.NET Core provide strong system integration, typed backend models, reliable HTTP services, and a natural path for Windows-specific read-only checks.

## 7. Backend Design

The backend exposes small API endpoints and delegates scanning logic to services:

- `PcSecurityScanService`
- `DefenderCheckService`
- `FirewallCheckService`
- `BitLockerCheckService`
- `StartupAppsCheckService`
- `WindowsUpdateCheckService`
- `WebsiteSecurityScanService`
- `SecurityScoreService`

Core models:

- `RiskLevel`
- `SecurityFinding`
- `SecurityCheckResult`
- `SecurityScanSummary`

The backend stores scan summaries, checks, and findings in SQLite through EF Core.

### Rule-Based Policy Engine

SecureScope uses a rule-based policy engine rather than machine learning or opaque scoring.

Each check returns:

- whether the check passed
- risk level
- summary evidence
- findings
- recommendations

Examples:

- If Defender real-time protection is disabled, create a High risk finding.
- If antivirus signatures are older than 7 days, create a Medium risk finding.
- If a firewall profile is disabled, create a High risk finding.
- If a website is missing `Content-Security-Policy`, create a Medium risk finding.

The `SecurityScoreService` applies deterministic penalties based on risk levels and produces a score from 0 to 100. This keeps scoring explainable and easy to adjust as policies evolve.

Website and PC detail pages also derive 0-to-10 dimension scores for radar visualization. These dimension scores are calculated from the same scan results and findings, but they are optimized for quick visual comparison rather than long-term persistence.

## 8. Frontend Design

The frontend is organized around pages and focused reusable components.

Pages:

- `DashboardPage`
- `PcSecurityPage`
- `WebsiteSecurityPage`
- `WebsiteScanDetailPage`

Components:

- `SecurityScoreCard`
- `FindingCard`
- `RiskBadge`
- `CheckCard`
- `FindingSummary`
- `ScanHistory`
- `SecurityRadarChart`

TanStack Query handles API fetching, loading states, cache updates, and error states. React Router handles navigation between dashboard, PC checks, website scan form, and website scan details.

The UI avoids showing raw response header or cookie values directly in summary cards. Long values such as `Content-Security-Policy` or `Set-Cookie` can be difficult to read and may clutter the dashboard. Instead, cards show user-facing summaries such as checked header counts, missing header names, HTTP status, and cookie header counts. Findings still keep concise evidence and recommendations.

## 9. Security Scanning Scope

PC checks are read-only:

- Microsoft Defender status through `Get-MpComputerStatus`
- Windows Firewall profile status through `Get-NetFirewallProfile`
- BitLocker volume status through `Get-BitLockerVolume`
- Startup Apps through common Run registry keys and Startup folders
- Windows Update pending update status through the Windows Update COM API

Website checks are passive:

- Normalize the provided URL
- Allow only `http` and `https`
- Allow only ports `80` and `443`
- Reject local, private, and reserved network addresses
- Resolve DNS and validate every redirect destination
- Limit redirects and apply an HTTP timeout
- Send a limited passive GET request flow without crawling additional paths
- Collect final URL, HTTP status code, response headers, `Set-Cookie` headers, and HTTPS usage
- Summarize collected headers and cookies without displaying raw values in dashboard cards
- Check common browser security headers:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`

Website scans should only be used on websites you own or are explicitly authorized to test.

The hosted portfolio demo enables an allowlist. It only scans approved example hosts and applies a per-client rate limit of five website scan requests per minute. Local development keeps the allowlist optional so authorized targets can be tested manually.

## 10. What This Tool Does Not Do

SecureScope does not:

- Modify Windows Defender settings
- Modify Windows Firewall settings
- Change registry keys
- Install software
- Remove files
- Run exploit payloads
- Crawl entire websites
- Brute force directories or paths
- Perform vulnerability exploitation
- Replace a professional security assessment

It is a defensive visibility tool, not an attack tool.

## 11. API Examples

Health check:

```bash
curl http://localhost:5000/api/health
```

Run a PC scan:

```bash
curl -X POST http://localhost:5000/api/pc-scans
```

Get latest PC scan:

```bash
curl http://localhost:5000/api/pc-scans/latest
```

Run a website scan:

```bash
curl -X POST http://localhost:5000/api/website-scans \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Get latest website scan:

```bash
curl http://localhost:5000/api/website-scans/latest
```

Get a website scan by ID:

```bash
curl http://localhost:5000/api/website-scans/1
```

Get recent scan history:

```bash
curl http://localhost:5000/api/scans/recent
```

## 12. How To Run Locally

Prerequisites:

- .NET 10 SDK
- Node.js 20 or newer
- Windows for real Defender and Firewall checks

Start the backend:

```bash
cd backend
dotnet restore
dotnet run
```

The backend defaults to:

```text
http://localhost:5000
```

Start the frontend in another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

If the backend runs on a different port, start the frontend with:

```bash
VITE_API_BASE_URL=http://localhost:<backend-port> npm run dev
```

Swagger is available in development:

```text
http://localhost:5000/swagger
```

### Hosted Demo Configuration

Production uses `backend/appsettings.Production.json`:

- PC scans return a clearly labeled sample Windows report.
- Website scans enforce the approved host allowlist.
- Website scan requests are rate limited per client IP.

When deploying the API, configure the deployed frontend origin:

```text
Frontend__AllowedOrigins__0=https://<your-vercel-project>.vercel.app
```

When deploying the frontend to Vercel, configure the API URL:

```text
VITE_API_BASE_URL=https://<your-api-host>
```

`frontend/vercel.json` contains the SPA rewrite needed for React Router deep links.

## 13. Portfolio Demo Checklist

Recommended presentation order:

1. Deploy the React frontend to Vercel.
2. Deploy the ASP.NET Core API to Azure App Service or another .NET-compatible host.
3. Add the deployed frontend origin to `Frontend__AllowedOrigins__0`.
4. Set the Vercel `VITE_API_BASE_URL` environment variable.
5. Add a README screenshot showing the dashboard and website scan result.
6. Record a one-to-two-minute Windows video showing a real local PC scan.
7. Add the live demo URL and video URL near the top of this README.

Suggested video flow:

1. Start SecureScope locally on Windows.
2. Run a PC scan.
3. Show Defender, Firewall, BitLocker, Startup Apps, and Windows Update results.
4. Open one finding and explain its evidence and recommendation.
5. State that the PowerShell commands are read-only and do not change security settings.

## 14. Future Improvements

- Add scan export to JSON or CSV
- Add configurable scoring policies
- Add policy profiles for home, developer, and small business machines
- Add website cookie attribute checks such as `Secure`, `HttpOnly`, and `SameSite`
- Add TLS certificate metadata collection
- Add scheduled local scans
- Add filtering and search for scan history
- Add unit tests for policy rules and parser behavior
