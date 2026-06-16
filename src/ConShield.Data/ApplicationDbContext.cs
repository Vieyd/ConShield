using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<UserException> UserExceptions => Set<UserException>();
    public DbSet<SecurityEventEntry> SecurityEvents => Set<SecurityEventEntry>();
    public DbSet<IncidentRecord> Incidents => Set<IncidentRecord>();
    public DbSet<SiemAlertRecord> SiemAlerts => Set<SiemAlertRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<UserException>(entity =>
        {
            entity.ToTable("UserExceptions");
            entity.Property(x => x.UserLogin).HasMaxLength(128).IsRequired();
            entity.Property(x => x.SourceSystem).HasMaxLength(128).IsRequired();
            entity.Property(x => x.ExceptionType).HasMaxLength(128).IsRequired();
            entity.Property(x => x.Description).HasMaxLength(1000).IsRequired();
            entity.Property(x => x.CreatedBy).HasMaxLength(128).IsRequired();
            entity.Property(x => x.CreatedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.ExpiresAtUtc).HasColumnType("timestamp with time zone");
        });

        modelBuilder.Entity<SecurityEventEntry>(entity =>
        {
            entity.ToTable("SecurityEvents");
            entity.Property(x => x.OccurredAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.Description).HasMaxLength(2000).IsRequired();
            entity.Property(x => x.UserName).HasMaxLength(128);
            entity.Property(x => x.SourceIp).HasMaxLength(64);
            entity.Property(x => x.SourceSystem).HasMaxLength(128);
            entity.Property(x => x.ExternalEventType).HasMaxLength(128);
            entity.Property(x => x.SourceHost).HasMaxLength(256);
            entity.HasIndex(x => new { x.SourceSystem, x.ExternalEventId })
                .IsUnique()
                .HasFilter("\"SourceSystem\" IS NOT NULL AND \"ExternalEventId\" IS NOT NULL");
        });

        modelBuilder.Entity<IncidentRecord>(entity =>
        {
            entity.ToTable("Incidents");
            entity.Property(x => x.CreatedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.Name).HasMaxLength(256).IsRequired();
            entity.Property(x => x.Status).HasMaxLength(64).IsRequired();
            entity.Property(x => x.Notes).HasMaxLength(2000);
        });

        modelBuilder.Entity<SiemAlertRecord>(entity =>
        {
            entity.ToTable("SiemAlerts");
            entity.Property(x => x.CreatedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.RuleCode).HasMaxLength(128).IsRequired();
            entity.Property(x => x.RuleName).HasMaxLength(256).IsRequired();
            entity.Property(x => x.TriggerKey).HasMaxLength(256).IsRequired();
            entity.Property(x => x.Status).HasMaxLength(64).IsRequired();
            entity.Property(x => x.Description).HasMaxLength(2000).IsRequired();
            entity.Property(x => x.SourceEventIdsJson).HasMaxLength(2000);
        });
    }
}
