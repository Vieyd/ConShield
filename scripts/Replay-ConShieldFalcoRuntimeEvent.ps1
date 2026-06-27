[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:5080',
    [string]$FixturePath = '.\tests\TestData\Falco\terminal-shell-container.json',
    [string]$MappingPath = '.\config\runtime\falco-mapping-v1.json',
    [string]$SourceSystem = 'conshield.falco-linux-sensor',
    [ValidateRange(1, 3650)]
    [int]$MaxEventAgeDays = 3650,
    [switch]$NoSubmit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$transientEnvironment = New-Object System.Collections.Generic.List[string]
$suppressedEnvironment = @{}

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

function Resolve-RepoPath {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Get-LocalEnvMap {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $path = Join-Path $RepoRoot '.conshield.local.env'
    $values = @{}
    if (-not (Test-Path -LiteralPath $path)) {
        return $values
    }

    Get-Content -LiteralPath $path | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            $name = $Matches[1]
            $value = $Matches[2]
            if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                $value = $value.Substring(1, $value.Length - 2)
            }

            $values[$name] = $value
        }
    }

    return $values
}

function Set-TransientEnvironmentValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Value
    )

    $existing = Get-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    if ($null -ne $existing -and -not [string]::IsNullOrWhiteSpace($existing.Value)) {
        return
    }

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }

    Set-Item -LiteralPath "Env:$Name" -Value $Value
    $script:transientEnvironment.Add($Name) | Out-Null
}

function Suspend-EnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($script:suppressedEnvironment.ContainsKey($Name)) {
        return
    }

    $existing = Get-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    $script:suppressedEnvironment[$Name] = if ($null -ne $existing) { $existing.Value } else { $null }
    Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
}

function Test-WebRoute {
    param([Parameter(Mandatory = $true)][string]$Url)

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 2 -SkipHttpErrorCheck
        return [int]$response.StatusCode -in @(200, 302)
    }
    catch {
        return $false
    }
}

function Get-Sha256Short {
    param([Parameter(Mandatory = $true)][string]$Value)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([Convert]::ToHexString($hash).ToLowerInvariant()).Substring(0, 16)
}

function Find-MappedRule {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)]$Mapping
    )

    $ruleName = [string]$Fixture.rule
    $tags = @($Fixture.tags | ForEach-Object { [string]$_ })
    foreach ($rule in @($Mapping.rules)) {
        $names = @($rule.matchRuleNames | ForEach-Object { [string]$_ })
        if ($names -notcontains $ruleName) {
            continue
        }

        $requiredTags = @($rule.requiredTags | ForEach-Object { [string]$_ })
        $missing = @($requiredTags | Where-Object { $tags -notcontains $_ })
        if ($missing.Count -eq 0) {
            return $rule
        }
    }

    return $null
}

function Invoke-Collector {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string[]]$CollectorArguments
    )

    Push-Location $RepoRoot
    try {
        $output = & dotnet @CollectorArguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = @($output | ForEach-Object { [string]$_ })
    }
}

try {
    $repoRoot = Resolve-RepositoryRoot
    $resolvedFixture = Resolve-RepoPath -RepoRoot $repoRoot -Path $FixturePath
    $resolvedMapping = Resolve-RepoPath -RepoRoot $repoRoot -Path $MappingPath

    if (-not (Test-Path -LiteralPath $resolvedFixture -PathType Leaf)) {
        throw 'Falco replay fixture was not found.'
    }

    if (-not (Test-Path -LiteralPath $resolvedMapping -PathType Leaf)) {
        throw 'Falco mapping file was not found.'
    }

    $fixture = Get-Content -LiteralPath $resolvedFixture -Raw | ConvertFrom-Json
    $mapping = Get-Content -LiteralPath $resolvedMapping -Raw | ConvertFrom-Json
    $mappedRule = Find-MappedRule -Fixture $fixture -Mapping $mapping
    $eventType = if ($null -ne $mappedRule) { [string]$mappedRule.eventType } else { 'container.runtime.unmapped' }
    $expectedRule = if ($null -ne $mappedRule -and [bool]$mappedRule.correlate) { 'RTE-001' } else { '-' }
    $containerId = [string]$fixture.output_fields.'container.id'
    $processName = [string]$fixture.output_fields.'proc.name'
    $safeEventId = Get-Sha256Short -Value ('{0}|{1}|{2}|{3}' -f $fixture.time, $fixture.rule, $containerId, $processName)

    Write-Output 'ConShield Falco runtime replay'

    $webOk = Test-WebRoute -Url ($BaseUrl.TrimEnd('/') + '/Operations/Health')
    Write-Output ('Web: {0}' -f $(if ($webOk) { 'OK' } else { 'FAIL' }))
    if (-not $webOk) {
        Write-Output 'Start local services with: pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit'
        Write-Output 'Result: FAIL'
        exit 1
    }

    Write-Output ('Fixture: {0}' -f (Split-Path -Leaf $resolvedFixture))
    Write-Output ('Mapped event type: {0}' -f $eventType)
    Write-Output ('SourceSystem: {0}' -f $SourceSystem)
    Write-Output ('ExternalEventId: hash:{0}' -f $safeEventId)

    $collectorProject = Join-Path $repoRoot 'src\ConShield.RuntimeCollector\ConShield.RuntimeCollector.csproj'
    $baseCollectorArgs = @(
        'run',
        '--project', $collectorProject,
        '--configuration', 'Release',
        '--',
        'collect',
        '--file', $resolvedFixture,
        '--mapping', $resolvedMapping,
        '--source-system', $SourceSystem,
        '--max-event-age-days', [string]$MaxEventAgeDays
    )

    $validation = Invoke-Collector -RepoRoot $repoRoot -CollectorArguments ($baseCollectorArgs + @('--no-submit'))
    if ($validation.ExitCode -ne 0) {
        Write-Output ('Validation: FAIL (collector_exit_code={0})' -f $validation.ExitCode)
        Write-Output ('Expected rule: {0}' -f $expectedRule)
        Write-Output 'Result: FAIL'
        exit 1
    }

    if ($NoSubmit) {
        Write-Output 'Ingestion: SKIP'
        Write-Output ('Expected rule: {0}' -f $expectedRule)
        Write-Output 'Result: PASS'
        exit 0
    }

    $localEnv = Get-LocalEnvMap -RepoRoot $repoRoot
    Set-TransientEnvironmentValue -Name 'CONSHIELD_EXTERNAL_EVENT_API_KEY' -Value $localEnv['CONSHIELD_EXTERNAL_EVENT_API_KEY']
    Suspend-EnvironmentValue -Name 'CONSHIELD_SENSOR_ID'
    Suspend-EnvironmentValue -Name 'CONSHIELD_SENSOR_CREDENTIAL_ID'

    if ([string]::IsNullOrWhiteSpace($env:CONSHIELD_EXTERNAL_EVENT_API_KEY)) {
        Write-Output 'Ingestion: FAIL (external ingestion credential unavailable)'
        Write-Output 'Configure the local external ingestion key or run with -NoSubmit for parser/mapping validation only.'
        Write-Output ('Expected rule: {0}' -f $expectedRule)
        Write-Output 'Result: FAIL'
        exit 1
    }

    $submitArgs = $baseCollectorArgs + @(
        '--endpoint', $BaseUrl.TrimEnd('/'),
        '--api-key-env', 'CONSHIELD_EXTERNAL_EVENT_API_KEY'
    )
    $submit = Invoke-Collector -RepoRoot $repoRoot -CollectorArguments $submitArgs
    if ($submit.ExitCode -ne 0) {
        Write-Output ('Ingestion: FAIL (collector_exit_code={0})' -f $submit.ExitCode)
        Write-Output ('Expected rule: {0}' -f $expectedRule)
        Write-Output 'Result: FAIL'
        exit 1
    }

    Write-Output 'Ingestion: OK'
    Write-Output ('Expected rule: {0}' -f $expectedRule)
    Write-Output 'Run SIEM correlation from the local UI if the alert and incident are not already present.'
    Write-Output 'Result: PASS'
    exit 0
}
finally {
    foreach ($name in $transientEnvironment) {
        Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    }

    foreach ($name in $suppressedEnvironment.Keys) {
        if ($null -eq $suppressedEnvironment[$name]) {
            Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item -LiteralPath "Env:$name" -Value $suppressedEnvironment[$name]
        }
    }
}
