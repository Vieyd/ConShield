# Publication Checklist

Use this checklist before creating a public GitHub repository.

## Safe to Commit

- Source code under `src/`.
- `README.md`.
- `SECURITY.md`.
- `CONTRIBUTING.md`.
- `LICENSE`.
- `.editorconfig`.
- `.gitignore`.
- `.github/workflows/dotnet.yml`.
- `docs/`.
- `infra/docker-compose.yml`.

## Do Not Commit

- `.vs/`
- `.idea/`
- `.vscode/`
- `bin/`
- `obj/`
- `logs/`
- `*.jsonl`
- `*.log`
- `*.db`, `*.mdf`, `*.ldf`, `*.sqlite`
- `src/**/appsettings.Development.json`
- Any file with real credentials, tokens, private paths, or personal machine state.

## Before Publishing

1. Run `dotnet build ConShield.sln`.
2. Check that local launch still works from Visual Studio.
3. Search for secrets:

```powershell
rg -n --hidden -g '!**/bin/**' -g '!**/obj/**' -g '!**/.vs/**' "password|secret|token|api_key|ConnectionStrings|AdminIB123|Operator123|LocalDB|UseSqlServer"
```

4. Confirm that only example/demo placeholders are visible in public files.
5. Initialize Git from the project root if needed:

```powershell
git init
git add .
git status --short
```

6. Review `git status` carefully before the first commit.

## Optional Cleanup

Generated folders can be deleted when you are ready. Visual Studio and `dotnet build` will recreate them automatically.

```powershell
Remove-Item -Recurse -Force .vs
Get-ChildItem -Recurse -Directory -Filter bin | Remove-Item -Recurse -Force
Get-ChildItem -Recurse -Directory -Filter obj | Remove-Item -Recurse -Force
Remove-Item -Recurse -Force src/ConShield.Web/logs
```

Only run cleanup when the app is closed in Visual Studio.
