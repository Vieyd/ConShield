# Security Notes

ConShield is a student cybersecurity portfolio project and is not production-ready yet. This file documents the current security posture and the main hardening tasks.

## Current Controls

- Cookie authentication for signed-in sessions.
- Role-based authorization for administrative actions.
- Anti-forgery validation on mutating MVC actions.
- Audit logging for login attempts and security-relevant operations.
- SIEM-style correlation for selected suspicious patterns.
- PostgreSQL schema management through EF Core migrations.
- Local development configuration is excluded from Git.

## Current Limitations

- Demo users are configured locally instead of managed through a production identity provider.
- Passwords are compared directly in demo mode and are not hashed.
- There is no login rate limiting yet.
- Demo PostgreSQL credentials are local-only and must not be committed.
- Runtime JSONL logs may contain usernames, IP addresses, and event metadata. They must not be committed.
- The app is designed for local portfolio demonstration, not internet exposure.

## Secret Handling

- Keep `src/ConShield.Web/appsettings.Development.json` local.
- Use `src/ConShield.Web/appsettings.Development.example.json` as a public template.
- Do not commit real credentials, tokens, database files, or runtime logs.
- Keep PostgreSQL passwords in local environment variables, user secrets, or ignored development settings.

## Recommended Hardening Roadmap

- Replace demo authentication with ASP.NET Core Identity or another real identity mechanism.
- Hash passwords and enforce password policy.
- Add login throttling and account lockout behavior.
- Add authorization and correlation tests.
- Add security headers and cookie hardening settings.
- Add a documented threat model.
