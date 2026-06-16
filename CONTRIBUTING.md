# Contributing

ConShield is currently maintained as a personal student portfolio project. Contributions, experiments, and issues should keep the security-monitoring focus clear.

## Development

1. Use .NET 8 SDK.
2. Open `ConShield.sln`.
3. Copy `src/ConShield.Web/appsettings.Development.example.json` to `src/ConShield.Web/appsettings.Development.json` if local settings are missing.
4. Run `dotnet restore`.
5. Run `dotnet build ConShield.sln`.

## Pull Request Checklist

- The solution builds.
- Public docs are updated when behavior changes.
- No local settings, database files, logs, or generated build output are committed.
- Security-sensitive changes mention their assumptions and limitations.
