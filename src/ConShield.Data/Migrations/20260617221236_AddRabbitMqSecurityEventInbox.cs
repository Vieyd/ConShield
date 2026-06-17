using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace ConShield.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddRabbitMqSecurityEventInbox : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SecurityEventInboxReceipts",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    MessageId = table.Column<Guid>(type: "uuid", nullable: false),
                    SecurityEventId = table.Column<long>(type: "bigint", nullable: false),
                    MessageType = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    SchemaVersion = table.Column<int>(type: "integer", nullable: false),
                    PayloadSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RoutingKey = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ReceivedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ProcessedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Redelivered = table.Column<bool>(type: "boolean", nullable: false),
                    DeliveryCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityEventInboxReceipts", x => x.Id);
                    table.CheckConstraint("CK_SecurityEventInboxReceipts_DeliveryCount_Positive", "\"DeliveryCount\" >= 1");
                });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEventInboxReceipts_MessageId",
                table: "SecurityEventInboxReceipts",
                column: "MessageId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEventInboxReceipts_SecurityEventId",
                table: "SecurityEventInboxReceipts",
                column: "SecurityEventId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SecurityEventInboxReceipts");
        }
    }
}
