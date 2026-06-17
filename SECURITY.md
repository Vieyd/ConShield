# Security Notes

ConShield is a student cybersecurity portfolio project and is not production-ready yet. This file documents the current security posture and the main hardening tasks.

## Current Controls

- Cookie authentication for signed-in sessions.
- Role-based authorization for administrative actions.
- Anti-forgery validation on mutating MVC actions.
- Audit logging for login attempts and security-relevant operations.
- SIEM-style correlation for selected suspicious patterns.
- PostgreSQL schema management through EF Core migrations.
- External event ingestion protected by a local API key.
- Validation, request size limit, rate limiting, and idempotency for external events.
- The ingestion rate limiter is scoped only to `POST /api/v1/security-events` and partitions by transport `RemoteIpAddress`.
- Trivy-based container image scanning through a separate console scanner.
- `IMG-001` correlation for critical vulnerabilities in container image scan summaries.
- Local Container Policy Gate with deterministic Allow/Warn/Block decisions.
- `POL-001` correlation for policy Block decisions.
- Local development configuration is excluded from Git.

## Current Limitations

- Demo users are configured locally instead of managed through a production identity provider.
- Passwords are compared directly in demo mode and are not hashed.
- There is no login rate limiting yet.
- Demo PostgreSQL credentials are local-only and must not be committed.
- Ingestion API keys are local-only and must not be committed.
- The ingestion API key is a local prototype mechanism, not production machine identity.
- `X-Forwarded-For` is not trusted by the ingestion limiter unless a trusted reverse proxy is deliberately configured in a future task.
- Runtime JSONL logs may contain usernames, IP addresses, and event metadata. They must not be committed.
- Trivy reports, archives, vulnerability databases, and scanner local config must not be committed.
- `ConShield.ImageScanner` summarizes scan results and does not store full CVE lists in PostgreSQL.
- `ConShield.ImageScanner gate` can optionally launch Docker locally, but only after scan, policy evaluation, and audit submission.
- Container Policy Gate reserves `conshield.image-scanner` and `conshield.container-guard` as distinct source systems for one shared `externalEventId`.
- Container Policy Gate is not a Kubernetes admission controller and does not provide remote policy distribution, waivers, or policy signing.
- Policy evaluation events record requested execution and warning acknowledgement, but they are not a separate audit record of Docker launch success or failure.
- The app is designed for local portfolio demonstration, not internet exposure.

## Secret Handling

- Keep `src/ConShield.Web/appsettings.Development.json` local.
- Use `src/ConShield.Web/appsettings.Development.example.json` as a public template.
- Do not commit real credentials, tokens, database files, or runtime logs.
- Keep PostgreSQL passwords in local environment variables, user secrets, or ignored development settings.
- Keep `ExternalEventIngestion:ApiKey` in local configuration or environment variables only.
- Prefer `CONSHIELD_API_KEY` for the Collector instead of command-line `--api-key`, because command-line arguments may be visible in shell history or process listings.
- Prefer `CONSHIELD_API_KEY` for `ConShield.ImageScanner` for the same reason.
- Keep `CONSHIELD_TRIVY_PATH` local and do not commit Trivy binaries or archives.
- Keep `CONSHIELD_DOCKER_PATH` local when used. Do not store registry credentials or Docker config exports in the repository.

## Recommended Hardening Roadmap

- Replace demo authentication with ASP.NET Core Identity or another real identity mechanism.
- Hash passwords and enforce password policy.
- Add login throttling and account lockout behavior.
- Add authorization and correlation tests.
- Add security headers and cookie hardening settings.
- Add a documented threat model.
- Add API key rotation, mTLS, centralized secret management, and per-source credentials before production exposure.
