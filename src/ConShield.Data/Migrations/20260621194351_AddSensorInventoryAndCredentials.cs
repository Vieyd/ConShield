using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace ConShield.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSensorInventoryAndCredentials : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Sensors",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    SensorId = table.Column<Guid>(type: "uuid", nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    SourceSystem = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    LastSeenAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CertificateFingerprintSha256 = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Sensors", x => x.Id);
                    table.CheckConstraint("CK_Sensors_SensorId_NotEmpty", "\"SensorId\" <> '00000000-0000-0000-0000-000000000000'");
                });

            migrationBuilder.CreateTable(
                name: "SensorCredentials",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CredentialId = table.Column<Guid>(type: "uuid", nullable: false),
                    SensorId = table.Column<long>(type: "bigint", nullable: false),
                    VerifierSha256 = table.Column<byte[]>(type: "bytea", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RotatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SensorCredentials", x => x.Id);
                    table.CheckConstraint("CK_SensorCredentials_CredentialId_NotEmpty", "\"CredentialId\" <> '00000000-0000-0000-0000-000000000000'");
                    table.CheckConstraint("CK_SensorCredentials_VerifierSha256_Length", "octet_length(\"VerifierSha256\") = 32");
                    table.ForeignKey(
                        name: "FK_SensorCredentials_Sensors_SensorId",
                        column: x => x.SensorId,
                        principalTable: "Sensors",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SensorCredentials_CredentialId",
                table: "SensorCredentials",
                column: "CredentialId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SensorCredentials_SensorId",
                table: "SensorCredentials",
                column: "SensorId");

            migrationBuilder.CreateIndex(
                name: "IX_Sensors_CertificateFingerprintSha256",
                table: "Sensors",
                column: "CertificateFingerprintSha256",
                unique: true,
                filter: "\"CertificateFingerprintSha256\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_Sensors_LastSeenAtUtc",
                table: "Sensors",
                column: "LastSeenAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Sensors_RevokedAtUtc",
                table: "Sensors",
                column: "RevokedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Sensors_SensorId",
                table: "Sensors",
                column: "SensorId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SensorCredentials");

            migrationBuilder.DropTable(
                name: "Sensors");
        }
    }
}
