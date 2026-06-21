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
    public DbSet<SecurityEventOutboxMessage> SecurityEventOutboxMessages => Set<SecurityEventOutboxMessage>();
    public DbSet<SecurityEventInboxReceipt> SecurityEventInboxReceipts => Set<SecurityEventInboxReceipt>();
    public DbSet<DeadLetterQuarantineMessage> DeadLetterQuarantineMessages => Set<DeadLetterQuarantineMessage>();
    public DbSet<DeadLetterReplayRequest> DeadLetterReplayRequests => Set<DeadLetterReplayRequest>();
    public DbSet<IncidentRecord> Incidents => Set<IncidentRecord>();
    public DbSet<SiemAlertRecord> SiemAlerts => Set<SiemAlertRecord>();
    public DbSet<Sensor> Sensors => Set<Sensor>();
    public DbSet<SensorCredential> SensorCredentials => Set<SensorCredential>();

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

        modelBuilder.Entity<Sensor>(entity =>
        {
            entity.ToTable("Sensors", table =>
                table.HasCheckConstraint("CK_Sensors_SensorId_NotEmpty", "\"SensorId\" <> '00000000-0000-0000-0000-000000000000'"));
            entity.Property(x => x.DisplayName).HasMaxLength(128).IsRequired();
            entity.Property(x => x.SourceSystem).HasMaxLength(128).IsRequired();
            entity.Property(x => x.CertificateFingerprintSha256).HasMaxLength(64).IsFixedLength();
            entity.Property(x => x.LastSeenAtUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.RevokedAtUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.CreatedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.UpdatedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.HasIndex(x => x.SensorId).IsUnique();
            entity.HasIndex(x => x.LastSeenAtUtc);
            entity.HasIndex(x => x.RevokedAtUtc);
            entity.HasIndex(x => x.CertificateFingerprintSha256)
                .IsUnique()
                .HasFilter("\"CertificateFingerprintSha256\" IS NOT NULL");
        });

        modelBuilder.Entity<SensorCredential>(entity =>
        {
            entity.ToTable("SensorCredentials", table =>
            {
                table.HasCheckConstraint("CK_SensorCredentials_CredentialId_NotEmpty", "\"CredentialId\" <> '00000000-0000-0000-0000-000000000000'");
                table.HasCheckConstraint("CK_SensorCredentials_VerifierSha256_Length", "octet_length(\"VerifierSha256\") = 32");
            });
            entity.Property(x => x.VerifierSha256).HasColumnType("bytea").IsRequired();
            entity.Property(x => x.CreatedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.RotatedAtUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.RevokedAtUtc).HasColumnType("timestamp with time zone");
            entity.HasIndex(x => x.CredentialId).IsUnique();
            entity.HasIndex(x => x.SensorId);
            entity.HasOne(x => x.Sensor)
                .WithMany(x => x.Credentials)
                .HasForeignKey(x => x.SensorId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<SecurityEventOutboxMessage>(entity =>
        {
            entity.ToTable("SecurityEventOutbox", table =>
                table.HasCheckConstraint("CK_SecurityEventOutbox_AttemptCount_NonNegative", "\"AttemptCount\" >= 0"));
            entity.Property(x => x.MessageType).HasMaxLength(128).IsRequired();
            entity.Property(x => x.PayloadJson).HasMaxLength(65536).IsRequired();
            entity.Property(x => x.Status)
                .HasConversion<string>()
                .HasMaxLength(32)
                .IsRequired();
            entity.Property(x => x.CreatedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.AvailableAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.LastAttemptAtUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.LockedUntilUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.DeliveredAtUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.LastErrorCode).HasMaxLength(64);
            entity.Property(x => x.LastErrorSummary).HasMaxLength(512);
            entity.HasIndex(x => x.MessageId).IsUnique();
            entity.HasIndex(x => new { x.SecurityEventId, x.MessageType }).IsUnique();
            entity.HasIndex(x => new { x.Status, x.AvailableAtUtc, x.LockedUntilUtc });
            entity.HasOne(x => x.SecurityEvent)
                .WithMany()
                .HasForeignKey(x => x.SecurityEventId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<SecurityEventInboxReceipt>(entity =>
        {
            entity.ToTable("SecurityEventInboxReceipts", table =>
                table.HasCheckConstraint("CK_SecurityEventInboxReceipts_DeliveryCount_Positive", "\"DeliveryCount\" >= 1"));
            entity.Property(x => x.MessageType).HasMaxLength(128).IsRequired();
            entity.Property(x => x.PayloadSha256).HasMaxLength(64).IsRequired();
            entity.Property(x => x.RoutingKey).HasMaxLength(128).IsRequired();
            entity.Property(x => x.ReceivedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.ProcessedAtUtc).HasColumnType("timestamp with time zone");
            entity.HasIndex(x => x.MessageId).IsUnique();
            entity.HasIndex(x => x.SecurityEventId);
        });

        modelBuilder.Entity<DeadLetterQuarantineMessage>(entity =>
        {
            entity.ToTable("DeadLetterQuarantineMessages", table =>
            {
                table.HasCheckConstraint("CK_DeadLetterQuarantineMessages_CaptureCount_Positive", "\"CaptureCount\" >= 1");
                table.HasCheckConstraint("CK_DeadLetterQuarantineMessages_PayloadLength_NonNegative", "\"PayloadLength\" >= 0");
            });
            entity.Property(x => x.QuarantineId).IsRequired();
            entity.Property(x => x.PayloadSha256).HasMaxLength(64).IsRequired();
            entity.Property(x => x.SyntheticFingerprint).HasMaxLength(128).IsRequired();
            entity.Property(x => x.MessageType).HasMaxLength(128);
            entity.Property(x => x.OriginalExchange).HasMaxLength(128).IsRequired();
            entity.Property(x => x.OriginalRoutingKey).HasMaxLength(128).IsRequired();
            entity.Property(x => x.DeadLetterExchange).HasMaxLength(128).IsRequired();
            entity.Property(x => x.DeadLetterQueue).HasMaxLength(128).IsRequired();
            entity.Property(x => x.ContentType).HasMaxLength(128);
            entity.Property(x => x.CapturedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.FirstDeadLetteredAtUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.LastDeadLetteredAtUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.DeadLetterReason).HasMaxLength(64).IsRequired();
            entity.Property(x => x.ValidationCategory).HasMaxLength(64).IsRequired();
            entity.Property(x => x.ReplayEligibility).HasConversion<string>().HasMaxLength(32).IsRequired();
            entity.Property(x => x.PayloadJson).HasMaxLength(262144);
            entity.Property(x => x.HeaderSummaryJson).HasMaxLength(4096);
            entity.Property(x => x.EligibilityExplanation).HasMaxLength(512).IsRequired();
            entity.HasIndex(x => x.QuarantineId).IsUnique();
            entity.HasIndex(x => new { x.OriginalMessageId, x.PayloadSha256 })
                .IsUnique()
                .HasFilter("\"OriginalMessageId\" IS NOT NULL");
            entity.HasIndex(x => x.SyntheticFingerprint)
                .IsUnique()
                .HasFilter("\"OriginalMessageId\" IS NULL");
            entity.HasIndex(x => x.CapturedAtUtc);
            entity.HasIndex(x => x.ReplayEligibility);
            entity.HasIndex(x => x.DeadLetterReason);
            entity.HasIndex(x => x.OriginalMessageId);
            entity.HasIndex(x => x.PayloadSha256);
        });

        modelBuilder.Entity<DeadLetterReplayRequest>(entity =>
        {
            entity.ToTable("DeadLetterReplayRequests", table =>
                table.HasCheckConstraint("CK_DeadLetterReplayRequests_AttemptCount_NonNegative", "\"AttemptCount\" >= 0"));
            entity.Property(x => x.ReplayRequestId).IsRequired();
            entity.Property(x => x.RequestedBy).HasMaxLength(128).IsRequired();
            entity.Property(x => x.RequestedAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.Reason).HasMaxLength(500).IsRequired();
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(32).IsRequired();
            entity.Property(x => x.AvailableAtUtc).HasColumnType("timestamp with time zone").IsRequired();
            entity.Property(x => x.LockedUntilUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.PublishedAtUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.CompletedAtUtc).HasColumnType("timestamp with time zone");
            entity.Property(x => x.LastErrorCode).HasMaxLength(64);
            entity.Property(x => x.LastErrorSummary).HasMaxLength(512);
            entity.HasIndex(x => x.ReplayRequestId).IsUnique();
            entity.HasIndex(x => new { x.Status, x.AvailableAtUtc, x.LockedUntilUtc });
            entity.HasIndex(x => x.QuarantineMessageId);
            entity.HasIndex(x => x.AvailableAtUtc);
            entity.HasIndex(x => x.Status);
            entity.HasIndex(x => x.QuarantineMessageId)
                .IsUnique()
                .HasFilter("\"Status\" IN ('Pending', 'Processing')");
            entity.HasOne(x => x.QuarantineMessage)
                .WithMany(x => x.ReplayRequests)
                .HasForeignKey(x => x.QuarantineMessageId)
                .OnDelete(DeleteBehavior.Restrict);
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
