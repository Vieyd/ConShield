param(
    [string]$OutputRoot = '.\artifacts\local',
    [string]$PackName = 'conshield-demo-release-pack',
    [switch]$SkipTests,
    [switch]$SkipFullValidation,
    [switch]$NoArchive,
    [switch]$IncludeEvidenceTemplate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepositoryRoot {
    $directory = Get-Item -LiteralPath $PSScriptRoot
    while ($null -ne $directory -and -not (Test-Path -LiteralPath (Join-Path $directory.FullName 'ConShield.sln'))) {
        $directory = $directory.Parent
    }

    if ($null -eq $directory) {
        throw 'Repository root was not found.'
    }

    return $directory.FullName
}

function ConvertTo-SafeText {
    param(
        [AllowNull()][object]$Value,
        [int]$MaxLength = 500
    )

    if ($null -eq $Value) {
        return ''
    }

    $text = [string]$Value
    $text = $text -replace '[\r\n\t]+', ' '
    $text = $text -replace '(?i)(password|secret|token|api[_ -]?key|authorization|bearer|cookie|credential|connection string)\s*[:=]\s*[^;\s,]+', '$1=[redacted]'
    $text = $text.Trim()
    if ($text.Length -gt $MaxLength) {
        return $text.Substring(0, $MaxLength - 3) + '...'
    }

    return $text
}

function ConvertTo-DisplayPath {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $relative = [System.IO.Path]::GetRelativePath($RepoRoot, $Path)
    return ($relative -replace '\\', '/')
}

function Test-IsUnderPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )

    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $childFull = [System.IO.Path]::GetFullPath($Child)
    return $childFull.StartsWith($parentFull, [System.StringComparison]::OrdinalIgnoreCase)
}

function Remove-SafeGeneratedPath {
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-IsUnderPath -Parent $OutputRoot -Child $Path)) {
        throw "Refusing to remove path outside OutputRoot."
    }

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    try {
        & $Command | Out-Null
        Write-Host ("{0}: OK" -f $Name)
    }
    catch {
        Write-Host ("{0}: FAIL" -f $Name)
        Write-Host ("Failure detail: {0}" -f (ConvertTo-SafeText -Value $_.Exception.Message))
        throw
    }
}

function Copy-ReleaseFile {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$DestinationRoot,
        [string]$DestinationRelativePath
    )

    if ([string]::IsNullOrWhiteSpace($DestinationRelativePath)) {
        $DestinationRelativePath = $RelativePath
    }

    if ($RelativePath -match '(?i)(^|[\\/])(\.env|appsettings\.Development\.json|appsettings\.Local\.json)$') {
        throw "Refusing to package local override: $RelativePath"
    }

    if ($RelativePath -match '(?i)(artifacts[\\/]local|logs[\\/]|screenshots[\\/]|TestResults[\\/]|bin[\\/]|obj[\\/])') {
        throw "Refusing to package generated path: $RelativePath"
    }

    $source = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        return $false
    }

    $destination = Join-Path $DestinationRoot $DestinationRelativePath
    $destinationDirectory = Split-Path -Parent $destination
    if (-not [string]::IsNullOrWhiteSpace($destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }

    Copy-Item -LiteralPath $source -Destination $destination -Force
    return $true
}

function Write-ReleaseReadme {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $lines = @(
        '# ConShield Demo Release Pack',
        '',
        'This local pack contains the published ConShield CLI plus safe documentation, configuration defaults, validation scripts, and demo handoff instructions.',
        '',
        '## Prerequisites',
        '',
        '- .NET 8 SDK or runtime for CLI execution.',
        '- PowerShell 7 for helper scripts.',
        '- Docker Desktop or compatible local services only when running the optional Web/API demo.',
        '',
        '## Quick validation',
        '',
        'From the repository root:',
        '',
        '```powershell',
        'pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1',
        '```',
        '',
        'From this release pack, the published CLI can show its command surface:',
        '',
        '```powershell',
        'dotnet .\bin\conshield-cli\ConShield.Cli.dll --help',
        'dotnet .\bin\conshield-cli\ConShield.Cli.dll validate',
        '```',
        '',
        '## Start local Web/API demo',
        '',
        'Run from the repository root, not from inside the pack:',
        '',
        '```powershell',
        'pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit',
        '```',
        '',
        'Then open:',
        '',
        '```text',
        'http://127.0.0.1:5080/Demo',
        '```',
        '',
        '## Demo readiness and evidence',
        '',
        '```powershell',
        'pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1',
        'pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 -OutputMarkdownPath .\artifacts\local\defense-evidence.md',
        '```',
        '',
        'Generated evidence should stay under artifacts/local and must not be committed.',
        '',
        '## Included content',
        '',
        '- Published CLI under bin/conshield-cli.',
        '- Safe docs under docs.',
        '- Committed default configs under config.',
        '- Safe helper scripts under scripts.',
        '',
        '## Intentionally excluded',
        '',
        '- Secrets, API keys, passwords, tokens, cookies, connection strings, and env values.',
        '- Local overrides such as .env files and appsettings.Development.json.',
        '- Generated evidence, logs, screenshots, raw scanner/runtime payloads, and nested artifacts/local content.',
        '- .git, source bin/obj folders, database files, and local Docker/Falco runtime artifacts.',
        '',
        '## Optional checks',
        '',
        'Real Fedora/Falco rollout, live Docker execution, live Trivy DB/network scanning, external internet-dependent checks, full mTLS, and real certificate/private-key/signing-key flows are intentionally outside this pack.'
    )

    Set-Content -LiteralPath $Path -Value $lines -Encoding UTF8
}

function Test-PackSafety {
    param([Parameter(Mandatory = $true)][string]$PackRoot)

    $forbiddenNamePatterns = @(
        '(?i)(^|[\\/])\.env($|[\\/])',
        '(?i)appsettings\.Development\.json$',
        '(?i)appsettings\.Local\.json$',
        '(?i)\.(log|jsonl|db|sqlite|sqlite3|mdf|ldf)$',
        '(?i)(^|[\\/])artifacts[\\/]local($|[\\/])',
        '(?i)(^|[\\/])\.git($|[\\/])',
        '(?i)(^|[\\/])screenshots($|[\\/])'
    )

    foreach ($file in Get-ChildItem -LiteralPath $PackRoot -Recurse -File) {
        $relative = [System.IO.Path]::GetRelativePath($PackRoot, $file.FullName)
        foreach ($pattern in $forbiddenNamePatterns) {
            if ($relative -match $pattern) {
                throw "Pack safety check failed for path: $relative"
            }
        }
    }
}

$repoRoot = Resolve-RepositoryRoot
$resolvedOutputRoot = if ([System.IO.Path]::IsPathRooted($OutputRoot)) {
    [System.IO.Path]::GetFullPath($OutputRoot)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputRoot))
}

$expectedArtifactsRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'artifacts\local'))
if (-not (Test-IsUnderPath -Parent (Join-Path $repoRoot 'artifacts') -Child $resolvedOutputRoot) -or
    -not $resolvedOutputRoot.Equals($expectedArtifactsRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot must be the repository artifacts/local path.'
}

if ($PackName -notmatch '^[A-Za-z0-9._-]+$') {
    throw 'PackName may contain only letters, digits, dot, underscore, and dash.'
}

$releaseRoot = Join-Path $resolvedOutputRoot $PackName
$publishRoot = Join-Path $resolvedOutputRoot 'conshieldctl'
$archivePath = Join-Path $resolvedOutputRoot ($PackName + '.zip')

Write-Host 'ConShield demo release pack'

New-Item -ItemType Directory -Path $resolvedOutputRoot -Force | Out-Null

Push-Location $repoRoot
try {
    Invoke-LoggedCommand -Name 'Restore' -Command {
        dotnet restore .\ConShield.sln
        if ($LASTEXITCODE -ne 0) { throw 'dotnet restore failed.' }
    }

    Invoke-LoggedCommand -Name 'Build' -Command {
        dotnet build .\ConShield.sln --configuration Release --no-restore
        if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }
    }

    if ($SkipTests) {
        Write-Host 'Test: SKIP'
    }
    else {
        Invoke-LoggedCommand -Name 'Test' -Command {
            dotnet test .\ConShield.sln --configuration Release --no-build
            if ($LASTEXITCODE -ne 0) { throw 'dotnet test failed.' }
        }
    }

    if ($SkipFullValidation) {
        Write-Host 'Full validation: SKIP'
    }
    else {
        Invoke-LoggedCommand -Name 'Full validation' -Command {
            pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1
            if ($LASTEXITCODE -ne 0) { throw 'full validation failed.' }
        }
    }

    Remove-SafeGeneratedPath -OutputRoot $resolvedOutputRoot -Path $publishRoot
    Remove-SafeGeneratedPath -OutputRoot $resolvedOutputRoot -Path $releaseRoot
    if (Test-Path -LiteralPath $archivePath) {
        Remove-SafeGeneratedPath -OutputRoot $resolvedOutputRoot -Path $archivePath
    }

    Invoke-LoggedCommand -Name 'CLI publish' -Command {
        dotnet publish .\src\ConShield.Cli\ConShield.Cli.csproj --configuration Release --no-build --output $publishRoot
        if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed.' }
    }

    New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $releaseRoot 'bin') -Force | Out-Null
    Copy-Item -LiteralPath $publishRoot -Destination (Join-Path $releaseRoot 'bin\conshield-cli') -Recurse -Force

    $docs = @(
        'docs\PRODUCT_POSITIONING.md',
        'docs\COMPETITIVE_ANALYSIS.md',
        'docs\DIPLOMA_DEFENSE_NARRATIVE.md',
        'docs\ROADMAP_TO_PRODUCTION.md',
        'docs\THREAT_MODEL.md',
        'docs\ATTACKER_SCENARIOS.md',
        'docs\SECURITY_REQUIREMENTS.md',
        'docs\REQUIREMENTS_TRACEABILITY_MATRIX.md',
        'docs\RESIDUAL_RISKS.md',
        'docs\ARCHITECTURE.md',
        'docs\ARCHITECTURE_DIAGRAMS.md',
        'docs\DATA_FLOW_MODEL.md',
        'docs\DEPLOYMENT_VIEW.md',
        'docs\SEQUENCE_FLOWS.md',
        'docs\RELEASE_AND_DEMO_PACKAGING.md',
        'docs\CONSHIELD_FULL_VALIDATION_CHECKLIST.md',
        'docs\CONSHIELD_CLI.md',
        'docs\CICD_CONTAINER_GATE.md',
        'docs\DOCKER_LIFECYCLE_COLLECTOR.md',
        'docs\SIGNED_SENSOR_EVENTS.md',
        'docs\SENSOR_TRUST_REGISTRY.md',
        'docs\SIEM_RULES.md',
        'docs\CONTAINER_POLICY.md',
        'docs\OPERATIONS_AND_SIEM_RUNBOOK.md'
    )

    $configs = @(
        'config\siem-rules.default.json',
        'config\container-policy.default.json',
        'config\sensor-registry.default.json'
    )

    $scripts = @(
        'Start-ConShield.ps1',
        'scripts\Test-ConShieldFullValidation.ps1',
        'scripts\Test-ConShieldDemoReadiness.ps1',
        'scripts\Export-ConShieldDefenseEvidence.ps1',
        'scripts\Run-ConShieldDefenseScenario.ps1',
        'scripts\Replay-ConShieldFalcoRuntimeEvent.ps1',
        'scripts\Invoke-ConShieldImageScan.ps1',
        'scripts\Invoke-ConShieldProtectedRun.ps1'
    )

    [void](Copy-ReleaseFile -RepoRoot $repoRoot -RelativePath 'README.md' -DestinationRoot $releaseRoot -DestinationRelativePath 'docs\PROJECT_README.md')

    foreach ($doc in $docs) {
        [void](Copy-ReleaseFile -RepoRoot $repoRoot -RelativePath $doc -DestinationRoot $releaseRoot)
    }

    foreach ($config in $configs) {
        [void](Copy-ReleaseFile -RepoRoot $repoRoot -RelativePath $config -DestinationRoot $releaseRoot)
    }

    foreach ($script in $scripts) {
        [void](Copy-ReleaseFile -RepoRoot $repoRoot -RelativePath $script -DestinationRoot $releaseRoot)
    }

    if ($IncludeEvidenceTemplate) {
        $evidenceDirectory = Join-Path $releaseRoot 'evidence'
        New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $evidenceDirectory 'README.md') -Value @(
            '# Evidence output placeholder',
            '',
            'Generated evidence is intentionally not included by default.',
            'Create it locally under artifacts/local from the repository root when the local Web/API stack is available.'
        ) -Encoding UTF8
    }

    Write-ReleaseReadme -Path (Join-Path $releaseRoot 'README.md')
    Test-PackSafety -PackRoot $releaseRoot
    Write-Host 'Docs index: OK'
    Write-Host ("Release pack: {0}" -f (ConvertTo-DisplayPath -RepoRoot $repoRoot -Path $releaseRoot))

    if ($NoArchive) {
        Write-Host 'Archive: SKIP'
    }
    else {
        Invoke-LoggedCommand -Name 'Archive' -Command {
            Compress-Archive -Path (Join-Path $releaseRoot '*') -DestinationPath $archivePath -Force
        }
        Write-Host ("Archive: {0}" -f (ConvertTo-DisplayPath -RepoRoot $repoRoot -Path $archivePath))
    }

    Write-Host 'Result: PASS'
}
finally {
    Pop-Location
}
