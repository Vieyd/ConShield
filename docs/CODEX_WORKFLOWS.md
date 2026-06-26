# Codex workflows

## 1. General workflow

1. Sync `main` with `git fetch --all --prune`, `git switch main`, and `git pull --ff-only`.
2. Check current branch, working tree, and open PR context before editing.
3. Read `docs/CONSHIELD_CODEMAP.md` and use only the relevant map section.
4. Make narrow changes in the files that match the task.
5. Validate locally in proportion to risk.
6. Stage only intended files, commit, push, and open a PR.
7. Wait for GitHub checks.
8. Do not auto-merge unless the user explicitly allows it.

## 2. UI task workflow

1. Read `docs/UI_DESIGN_SYSTEM.md` if it exists.
2. Read the Web UI map in `docs/CONSHIELD_CODEMAP.md`.
3. Prefer changes under `src/ConShield.Web/Views`, `src/ConShield.Web/wwwroot/css`, `src/ConShield.Web/wwwroot/js`, Web display helpers, UI tests, and docs.
4. Keep display/localization changes separate from business logic.
5. For heavy list pages, verify server-side pagination or an explicit server-side cap before polishing tables.
6. Do not touch SIEM correlation logic, EF schema/migrations, RabbitMQ/outbox, Mongo projection, Fedora deployment, or runtime credentials unless explicitly asked.

## 3. Login/auth diagnostics workflow

1. Do not print passwords or secrets.
2. Do not commit `appsettings.Development.json`, local `.env` files, logs, screenshots, or generated diagnostics.
3. Use local diagnostic scripts in `scripts` and focused Web tests.
4. Treat DemoUsers as config-driven, not DB-backed users.
5. Do not rewrite production auth behavior unless the prompt explicitly requests it.

## 4. SIEM workflow

1. Preserve rule codes unless the task explicitly changes rule identity.
2. Separate display text changes from correlation logic changes.
3. Inspect `SiemRuleCatalog`, `SiemCorrelationService`, SIEM controllers/views, and alert/incident models only as needed.
4. Run related rule, alert, incident, and report tests.

## 5. Outbox/RabbitMQ workflow

1. Preserve delivery semantics: idempotency, lock tokens, retry/backoff, mandatory return handling, ack/nack, DLQ capture, and replay safety.
2. If RabbitMQ behavior is touched, validate return, nack, timeout, duplicate, and dead-letter paths.
3. Run outbox/RabbitMQ/DLQ tests and script checks when deployment assets are touched.

## 6. Mongo projection workflow

1. Keep PostgreSQL as the source of truth.
2. Treat MongoDB as a read model/projection.
3. Do not alter ingestion semantics, event identity, or inbox processing unless explicitly asked.
4. Run Mongo projection and RabbitMQ integration tests when projection code changes.

## 7. Fedora/runtime workflow

1. Do not rotate or revoke a real Fedora sensor unless explicitly requested.
2. Do not print sensor secrets, verifier values, API keys, or env file contents.
3. Keep shell scripts parse-clean and shellchecked.
4. Preserve SELinux enforcing posture; do not disable SELinux as a shortcut.
5. Validate `deploy/falco-linux/*.sh` with `bash -n` and `shellcheck`.

## 8. Demo/local workflow

1. Use `Start-ConShield.ps1` for normal local startup/status/shutdown.
2. Use demo scenario and validation scripts for portfolio walkthrough evidence.
3. Use login diagnostics scripts for local login issues without printing passwords.
4. For stale Windows locks, identify the exact PID and ask for a targeted elevated `taskkill /PID <pid> /F /T`.
5. Do not paste secrets into chat, docs, logs, reports, or tests.

## 9. Validation matrix by task type

| Task type | Required validation | Areas to avoid |
| --- | --- | --- |
| UI/docs | build, test, diff check, gitleaks | EF/RabbitMQ/Fedora |
| Auth/login | build, test, secret-safety tests, gitleaks | DB users/production auth rewrite |
| SIEM | build, test, rule tests | rule code changes unless intended |
| RabbitMQ | build, test, outbox/RabbitMQ tests | UI-only changes |
| Fedora | bash -n, shellcheck, script tests | real credential rotation |

## 10. Prompt template snippet

```text
First read docs/CONSHIELD_CODEMAP.md and docs/CODEX_WORKFLOWS.md.
Use only the relevant map section.
Do not rediscover unrelated areas.
Keep changes narrow.
Report touched areas and skipped areas.
```
