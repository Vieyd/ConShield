using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ConShield.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddExternalSecurityEventIngestion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ExternalEventId",
                table: "SecurityEvents",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ExternalEventType",
                table: "SecurityEvents",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SourceHost",
                table: "SecurityEvents",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SourceSystem",
                table: "SecurityEvents",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_SourceSystem_ExternalEventId",
                table: "SecurityEvents",
                columns: new[] { "SourceSystem", "ExternalEventId" },
                unique: true,
                filter: "\"SourceSystem\" IS NOT NULL AND \"ExternalEventId\" IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SecurityEvents_SourceSystem_ExternalEventId",
                table: "SecurityEvents");

            migrationBuilder.DropColumn(
                name: "ExternalEventId",
                table: "SecurityEvents");

            migrationBuilder.DropColumn(
                name: "ExternalEventType",
                table: "SecurityEvents");

            migrationBuilder.DropColumn(
                name: "SourceHost",
                table: "SecurityEvents");

            migrationBuilder.DropColumn(
                name: "SourceSystem",
                table: "SecurityEvents");
        }
    }
}
