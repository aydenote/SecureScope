using Microsoft.EntityFrameworkCore;
using SecureScope.Api.Models;

namespace SecureScope.Api.Data;

public class SecureScopeDbContext(DbContextOptions<SecureScopeDbContext> options) : DbContext(options)
{
    public DbSet<SecurityScanSummary> ScanSummaries => Set<SecurityScanSummary>();
    public DbSet<SecurityCheckResult> CheckResults => Set<SecurityCheckResult>();
    public DbSet<SecurityFinding> Findings => Set<SecurityFinding>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<SecurityScanSummary>()
            .HasMany(summary => summary.Checks)
            .WithOne()
            .HasForeignKey(check => check.SecurityScanSummaryId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<SecurityCheckResult>()
            .HasMany(check => check.Findings)
            .WithOne()
            .HasForeignKey(finding => finding.SecurityCheckResultId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
