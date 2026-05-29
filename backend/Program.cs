using Microsoft.EntityFrameworkCore;
using SecureScope.Api.Data;
using SecureScope.Api.Models;
using SecureScope.Api.Services;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<SecureScopeDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=securescope.db"));

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("Frontend", policy =>
    {
        policy
            .SetIsOriginAllowed(origin =>
            {
                if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
                {
                    return false;
                }

                return (uri.Host == "localhost" || uri.Host == "127.0.0.1")
                    && uri.Port is >= 5173 and <= 5179;
            })
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services.AddScoped<PcSecurityScanService>();
builder.Services.AddScoped<SecurityScoreService>();
builder.Services.AddScoped<DefenderCheckService>(); 
builder.Services.AddScoped<FirewallCheckService>(); 
builder.Services.AddScoped<BitLockerCheckService>(); 
builder.Services.AddScoped<StartupAppsCheckService>(); 
builder.Services.AddScoped<WindowsUpdateCheckService>(); 
builder.Services.AddHttpClient<WebsiteSecurityScanService>(); 

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SecureScopeDbContext>();
    db.Database.EnsureCreated();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("Frontend");

app.MapGet("/api/health", () => Results.Ok(new
{
    status = "healthy",
    service = "SecureScope API",
    timestamp = DateTimeOffset.UtcNow
}));

app.MapPost("/api/pc-scans", async (
    PcSecurityScanService scanService,
    SecureScopeDbContext db,
    CancellationToken cancellationToken) =>
{
    var summary = await scanService.RunScanAsync(cancellationToken); 
    db.ScanSummaries.Add(summary);
    await db.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/pc-scans/latest", summary);
});

app.MapGet("/api/pc-scans/latest", async (
    SecureScopeDbContext db,
    PcSecurityScanService scanService,
    CancellationToken cancellationToken) =>
{
    var latest = await db.ScanSummaries
        .Include(scan => scan.Checks)
        .ThenInclude(check => check.Findings)
        .Where(scan => scan.ScanType == SecurityScanType.Pc)
        .OrderByDescending(scan => scan.Id)
        .FirstOrDefaultAsync(cancellationToken);

    return Results.Ok(latest ?? await scanService.GetPreviewScanAsync(cancellationToken)); 
});

app.MapGet("/api/scans/recent", async ( 
    SecureScopeDbContext db, 
    CancellationToken cancellationToken) => 
{ 
    var scans = await db.ScanSummaries 
        .Include(summary => summary.Checks) 
        .ThenInclude(check => check.Findings) 
        .OrderByDescending(summary => summary.Id) 
        .Take(8) 
        .ToListAsync(cancellationToken); 

    return Results.Ok(scans); 
}); 

app.MapPost("/api/website-scans", async (
    WebsiteScanRequest request,
    WebsiteSecurityScanService scanService,
    SecureScopeDbContext db,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Url))
    {
        return Results.BadRequest(new { message = "A website URL is required." });
    }

    SecurityScanSummary summary; 
    try 
    {
        summary = await scanService.RunScanAsync(request.Url, cancellationToken); 
    }
    catch (ArgumentException ex) 
    {
        return Results.BadRequest(new { message = ex.Message }); 
    }

    db.ScanSummaries.Add(summary);
    await db.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/website-scans/{summary.Id}", summary);
});

app.MapGet("/api/website-scans/latest", async ( 
    SecureScopeDbContext db, 
    CancellationToken cancellationToken) => 
{ 
    var latest = await db.ScanSummaries 
        .Include(summary => summary.Checks) 
        .ThenInclude(check => check.Findings) 
        .Where(summary => summary.ScanType == SecurityScanType.Website) 
        .OrderByDescending(summary => summary.Id) 
        .FirstOrDefaultAsync(cancellationToken); 

    return latest is null ? Results.NotFound() : Results.Ok(latest); 
}); 

app.MapGet("/api/website-scans/{id:int}", async (
    int id,
    SecureScopeDbContext db,
    CancellationToken cancellationToken) =>
{
    var scan = await db.ScanSummaries
        .Include(summary => summary.Checks)
        .ThenInclude(check => check.Findings)
        .FirstOrDefaultAsync(summary => summary.Id == id && summary.ScanType == SecurityScanType.Website, cancellationToken);

    return scan is null ? Results.NotFound() : Results.Ok(scan);
});

app.Run();
