[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:5080',
    [string]$FixturePath = '.\tests\TestData\Falco\terminal-shell-container.json',
    [string]$MappingPath = '.\config\runtime\falco-mapping-v1.json',
    [string]$RegistryPath = '.\config\sensor-registry.default.json',
    [string]$SensorId = 'demo-falco-linux-01',
    [string]$SourceSystem = 'conshield.falco-linux-sensor',
    [switch]$SimulateUnknownSensor,
    [switch]$SimulateRevokedSensor,
    [switch]$SimulateDisabledSensor,
    [switch]$DemoSignature,
    [switch]$SimulateMissingSignature,
    [switch]$SimulateInvalidSignature,
    [switch]$SimulateStaleSignature,
    [switch]$SimulateReplaySignature,
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

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Value)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($hash).ToLowerInvariant()
}

function Get-DemoSignature {
    param(
        [Parameter(Mandatory = $true)][string]$SensorId,
        [Parameter(Mandatory = $true)][string]$SourceSystem,
        [Parameter(Mandatory = $true)][string]$EventType,
        [Parameter(Mandatory = $true)][string]$TimestampUtc,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$Algorithm,
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$CanonicalPayloadHash
    )

    $demoMaterial = 'conshield-public-demo-signing-material-v1'
    $canonical = @(
        $SensorId.Trim(),
        $SourceSystem.Trim(),
        $EventType.Trim(),
        ([DateTime]::Parse($TimestampUtc).ToUniversalTime().ToString('O', [Globalization.CultureInfo]::InvariantCulture)),
        $Nonce.Trim(),
        $Algorithm.Trim(),
        $KeyId.Trim(),
        $CanonicalPayloadHash.Trim()
    ) -join "`n"
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($demoMaterial))
    try {
        return [Convert]::ToHexString($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))).ToLowerInvariant()
    }
    finally {
        $hmac.Dispose()
    }
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

function Get-SensorTrust {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SensorId,
        [Parameter(Mandatory = $true)][string]$SourceSystem
    )

    $resolvedRegistry = Resolve-RepoPath -RepoRoot $RepoRoot -Path $Path
    if (-not (Test-Path -LiteralPath $resolvedRegistry -PathType Leaf)) {
        return [pscustomobject]@{
            SensorId = $SensorId
            DisplayName = '-'
            SourceSystem = $SourceSystem
            TrustStatus = 'Unknown'
        }
    }

    try {
        $registry = Get-Content -LiteralPath $resolvedRegistry -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 20
        $matches = @($registry.sensors | Where-Object {
            [string]$_.sensorId -eq $SensorId -or [string]$_.sourceSystem -eq $SourceSystem
        } | Select-Object -First 1)
        $sensor = if ($matches.Count -gt 0) { $matches[0] } else { $null }
        if ($null -eq $sensor -or [string]::IsNullOrWhiteSpace([string]$sensor.status)) {
            return [pscustomobject]@{
                SensorId = $SensorId
                DisplayName = '-'
                SourceSystem = $SourceSystem
                TrustStatus = 'Unknown'
            }
        }

        return [pscustomobject]@{
            SensorId = [string]$sensor.sensorId
            DisplayName = [string]$sensor.displayName
            SourceSystem = [string]$sensor.sourceSystem
            TrustStatus = [string]$sensor.status
        }
    }
    catch {
        return [pscustomobject]@{
            SensorId = $SensorId
            DisplayName = '-'
            SourceSystem = $SourceSystem
            TrustStatus = 'Unknown'
        }
    }
}

function Get-EnforcementAction {
    param([Parameter(Mandatory = $true)][string]$TrustStatus)

    switch ($TrustStatus) {
        'Trusted' { return 'AcceptTrusted' }
        'Revoked' { return 'FlagRevokedWithAlert' }
        'Disabled' { return 'FlagDisabledWithAlert' }
        default { return 'AcceptUnknownWithAlert' }
    }
}

function Get-ExpectedRule {
    param(
        [Parameter(Mandatory = $true)][string]$TrustStatus,
        [Parameter(Mandatory = $true)][string]$MappedExpectedRule
    )

    switch ($TrustStatus) {
        'Trusted' { return $MappedExpectedRule }
        'Revoked' { return 'SENSOR-002' }
        'Disabled' { return 'SENSOR-002' }
        default { return 'SENSOR-001' }
    }
}

function Get-SignatureExpectedRule {
    param([Parameter(Mandatory = $true)][string]$SignatureStatus)

    switch ($SignatureStatus) {
        'Missing' { return 'SIGN-001' }
        'Invalid' { return 'SIGN-002' }
        'UnknownKey' { return 'SIGN-002' }
        'Stale' { return 'SIGN-003' }
        'ReplayDetected' { return 'SIGN-003' }
        default { return $null }
    }
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
    $simulationCount = @($SimulateUnknownSensor, $SimulateRevokedSensor, $SimulateDisabledSensor) |
        Where-Object { $_ } |
        Measure-Object |
        Select-Object -ExpandProperty Count
    if ($simulationCount -gt 1) {
        throw 'Specify only one sensor trust simulation mode.'
    }

    $signatureSimulationCount = @($DemoSignature, $SimulateMissingSignature, $SimulateInvalidSignature, $SimulateStaleSignature, $SimulateReplaySignature) |
        Where-Object { $_ } |
        Measure-Object |
        Select-Object -ExpandProperty Count
    if ($signatureSimulationCount -gt 1) {
        throw 'Specify only one signed sensor event simulation mode.'
    }

    if ($SimulateUnknownSensor) {
        $SensorId = 'demo-falco-unknown-01'
        $SourceSystem = 'conshield.falco-unknown-sensor'
    }
    elseif ($SimulateRevokedSensor) {
        $SensorId = 'demo-falco-revoked-01'
        $SourceSystem = 'conshield.falco-revoked-sensor'
    }
    elseif ($SimulateDisabledSensor) {
        $SensorId = 'demo-falco-disabled-01'
        $SourceSystem = 'conshield.falco-disabled-sensor'
    }

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
    $fixtureRaw = Get-Content -LiteralPath $resolvedFixture -Raw -Encoding UTF8
    $mapping = Get-Content -LiteralPath $resolvedMapping -Raw | ConvertFrom-Json
    $sensorTrust = Get-SensorTrust -RepoRoot $repoRoot -Path $RegistryPath -SensorId $SensorId -SourceSystem $SourceSystem
    $mappedRule = Find-MappedRule -Fixture $fixture -Mapping $mapping
    $eventType = if ($null -ne $mappedRule) { [string]$mappedRule.eventType } else { 'container.runtime.unmapped' }
    $mappedExpectedRule = if ($null -ne $mappedRule -and [bool]$mappedRule.correlate) { 'RTE-001' } else { '-' }
    $enforcementAction = Get-EnforcementAction -TrustStatus $sensorTrust.TrustStatus
    $expectedRule = Get-ExpectedRule -TrustStatus $sensorTrust.TrustStatus -MappedExpectedRule $mappedExpectedRule
    $containerId = [string]$fixture.output_fields.'container.id'
    $processName = [string]$fixture.output_fields.'proc.name'
    $safeEventId = Get-Sha256Short -Value ('{0}|{1}|{2}|{3}' -f $fixture.time, $fixture.rule, $containerId, $processName)
    $signatureStatus = if ($DemoSignature) { 'Valid' } elseif ($SimulateMissingSignature) { 'Missing' } elseif ($SimulateInvalidSignature) { 'Invalid' } elseif ($SimulateStaleSignature) { 'Stale' } elseif ($SimulateReplaySignature) { 'ReplayDetected' } else { 'NotRequired' }
    $signatureAlgorithm = 'HMAC-SHA256-DEMO'
    $signatureKeyId = 'demo-signing-key-v1'
    $signatureTimestampUtc = if ($SimulateStaleSignature) { (Get-Date).ToUniversalTime().AddHours(-2).ToString('O', [Globalization.CultureInfo]::InvariantCulture) } else { (Get-Date).ToUniversalTime().ToString('O', [Globalization.CultureInfo]::InvariantCulture) }
    $signatureNonce = if ($SimulateReplaySignature) { 'demo-replay-nonce-0001' } else { 'demo-nonce-' + $safeEventId }
    $canonicalPayloadHash = Get-Sha256Hex -Value $fixtureRaw
    $signatureReason = switch ($signatureStatus) {
        'Valid' { 'signature verified' }
        'Missing' { 'signature value is missing' }
        'Invalid' { 'signature mismatch' }
        'Stale' { 'signature timestamp is outside the accepted window' }
        'ReplayDetected' { 'signature nonce was already observed' }
        default { 'signature is not required' }
    }
    if ($signatureStatus -eq 'Valid' -or $signatureStatus -eq 'Stale' -or $signatureStatus -eq 'ReplayDetected') {
        $null = Get-DemoSignature -SensorId $sensorTrust.SensorId -SourceSystem $SourceSystem -EventType $eventType -TimestampUtc $signatureTimestampUtc -Nonce $signatureNonce -Algorithm $signatureAlgorithm -KeyId $signatureKeyId -CanonicalPayloadHash $canonicalPayloadHash
    }
    $signatureExpectedRule = Get-SignatureExpectedRule -SignatureStatus $signatureStatus
    $expectedRules = @($expectedRule)
    if ($null -ne $signatureExpectedRule) {
        $expectedRules = @($signatureExpectedRule)
    }
    Write-Output 'ConShield Falco runtime replay'

    $webOk = if ($NoSubmit) { $true } else { Test-WebRoute -Url ($BaseUrl.TrimEnd('/') + '/Operations/Health') }
    Write-Output ('Web: {0}' -f $(if ($NoSubmit) { 'SKIP' } elseif ($webOk) { 'OK' } else { 'FAIL' }))
    if (-not $webOk) {
        Write-Output 'Start local services with: pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit'
        Write-Output 'Result: FAIL'
        exit 1
    }

    Write-Output ('Fixture: {0}' -f (Split-Path -Leaf $resolvedFixture))
    Write-Output ('SensorId: {0}' -f $sensorTrust.SensorId)
    Write-Output ('Sensor trust: {0}' -f $sensorTrust.TrustStatus)
    Write-Output ('Enforcement: {0}' -f $enforcementAction)
    Write-Output ('Signature: {0}' -f $signatureStatus)
    Write-Output ('Signature key id: {0}' -f $(if ($signatureStatus -eq 'NotRequired') { '-' } else { $signatureKeyId }))
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
    if ($signatureStatus -ne 'NotRequired') {
        $baseCollectorArgs += @(
            '--signature-sensor-id', $sensorTrust.SensorId,
            '--signature-status', $signatureStatus,
            '--signature-key-id', $signatureKeyId,
            '--signature-nonce', $signatureNonce,
            '--signature-timestamp-utc', $signatureTimestampUtc,
            '--signature-algorithm', $signatureAlgorithm,
            '--signature-canonical-payload-hash', $canonicalPayloadHash,
            '--signature-verification-reason', $signatureReason
        )
    }

    $validation = Invoke-Collector -RepoRoot $repoRoot -CollectorArguments ($baseCollectorArgs + @('--no-submit'))
    if ($validation.ExitCode -ne 0) {
        Write-Output ('Validation: FAIL (collector_exit_code={0})' -f $validation.ExitCode)
        Write-Output ('Expected rules: {0}' -f ($expectedRules -join ','))
        Write-Output 'Result: FAIL'
        exit 1
    }

    if ($NoSubmit) {
        Write-Output 'Ingestion: SKIP'
        Write-Output ('Expected rules: {0}' -f ($expectedRules -join ','))
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
        Write-Output ('Expected rules: {0}' -f ($expectedRules -join ','))
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
        Write-Output ('Expected rules: {0}' -f ($expectedRules -join ','))
        Write-Output 'Result: FAIL'
        exit 1
    }

    Write-Output 'Ingestion: OK'
    Write-Output ('Expected rules: {0}' -f ($expectedRules -join ','))
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
