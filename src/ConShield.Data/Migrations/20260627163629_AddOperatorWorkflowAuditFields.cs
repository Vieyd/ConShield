using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ConShield.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddOperatorWorkflowAuditFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "AcknowledgedAtUtc",
                table: "SiemAlerts",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AcknowledgedBy",
                table: "SiemAlerts",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ClosedAtUtc",
                table: "Incidents",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Conclusion",
                table: "Incidents",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AcknowledgedAtUtc",
                table: "SiemAlerts");

            migrationBuilder.DropColumn(
                name: "AcknowledgedBy",
                table: "SiemAlerts");

            migrationBuilder.DropColumn(
                name: "ClosedAtUtc",
                table: "Incidents");

            migrationBuilder.DropColumn(
                name: "Conclusion",
                table: "Incidents");
        }
    }
}
