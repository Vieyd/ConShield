using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace ConShield.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDeadLetterQuarantine : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeadLetterQuarantineMessages",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    QuarantineId = table.Column<Guid>(type: "uuid", nullable: false),
                    OriginalMessageId = table.Column<Guid>(type: "uuid", nullable: true),
                    PayloadSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SyntheticFingerprint = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    MessageType = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    SchemaVersion = table.Column<int>(type: "integer", nullable: true),
                    SecurityEventId = table.Column<long>(type: "bigint", nullable: true),
                    OriginalExchange = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    OriginalRoutingKey = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    DeadLetterExchange = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    DeadLetterQueue = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ContentType = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    CapturedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FirstDeadLetteredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastDeadLetteredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    DeadLetterReason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ValidationCategory = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ReplayEligibility = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    PayloadJson = table.Column<string>(type: "character varying(262144)", maxLength: 262144, nullable: true),
                    PayloadBytes = table.Column<byte[]>(type: "bytea", nullable: true),
                    PayloadLength = table.Column<int>(type: "integer", nullable: false),
                    HeaderSummaryJson = table.Column<string>(type: "character varying(4096)", maxLength: 4096, nullable: true),
                    CaptureCount = table.Column<int>(type: "integer", nullable: false),
                    EligibilityExplanation = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeadLetterQuarantineMessages", x => x.Id);
                    table.CheckConstraint("CK_DeadLetterQuarantineMessages_CaptureCount_Positive", "\"CaptureCount\" >= 1");
                    table.CheckConstraint("CK_DeadLetterQuarantineMessages_PayloadLength_NonNegative", "\"PayloadLength\" >= 0");
                });

            migrationBuilder.CreateTable(
                name: "DeadLetterReplayRequests",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    ReplayRequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    QuarantineMessageId = table.Column<long>(type: "bigint", nullable: false),
                    RequestedBy = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false),
                    AvailableAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LockedUntilUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LockToken = table.Column<Guid>(type: "uuid", nullable: true),
                    PublishedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastErrorCode = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    LastErrorSummary = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    ReplaySequence = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeadLetterReplayRequests", x => x.Id);
                    table.CheckConstraint("CK_DeadLetterReplayRequests_AttemptCount_NonNegative", "\"AttemptCount\" >= 0");
                    table.ForeignKey(
                        name: "FK_DeadLetterReplayRequests_DeadLetterQuarantineMessages_Quara~",
                        column: x => x.QuarantineMessageId,
                        principalTable: "DeadLetterQuarantineMessages",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterQuarantineMessages_CapturedAtUtc",
                table: "DeadLetterQuarantineMessages",
                column: "CapturedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterQuarantineMessages_DeadLetterReason",
                table: "DeadLetterQuarantineMessages",
                column: "DeadLetterReason");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterQuarantineMessages_OriginalMessageId",
                table: "DeadLetterQuarantineMessages",
                column: "OriginalMessageId");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterQuarantineMessages_OriginalMessageId_PayloadSha256",
                table: "DeadLetterQuarantineMessages",
                columns: new[] { "OriginalMessageId", "PayloadSha256" },
                unique: true,
                filter: "\"OriginalMessageId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterQuarantineMessages_PayloadSha256",
                table: "DeadLetterQuarantineMessages",
                column: "PayloadSha256");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterQuarantineMessages_QuarantineId",
                table: "DeadLetterQuarantineMessages",
                column: "QuarantineId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterQuarantineMessages_ReplayEligibility",
                table: "DeadLetterQuarantineMessages",
                column: "ReplayEligibility");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterQuarantineMessages_SyntheticFingerprint",
                table: "DeadLetterQuarantineMessages",
                column: "SyntheticFingerprint",
                unique: true,
                filter: "\"OriginalMessageId\" IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterReplayRequests_AvailableAtUtc",
                table: "DeadLetterReplayRequests",
                column: "AvailableAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterReplayRequests_QuarantineMessageId",
                table: "DeadLetterReplayRequests",
                column: "QuarantineMessageId",
                unique: true,
                filter: "\"Status\" IN ('Pending', 'Processing')");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterReplayRequests_ReplayRequestId",
                table: "DeadLetterReplayRequests",
                column: "ReplayRequestId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterReplayRequests_Status",
                table: "DeadLetterReplayRequests",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_DeadLetterReplayRequests_Status_AvailableAtUtc_LockedUntilU~",
                table: "DeadLetterReplayRequests",
                columns: new[] { "Status", "AvailableAtUtc", "LockedUntilUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeadLetterReplayRequests");

            migrationBuilder.DropTable(
                name: "DeadLetterQuarantineMessages");
        }
    }
}
