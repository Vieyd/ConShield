[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:5080',

    [ValidateSet('FullLocalDemo', 'Healthy', 'DefenseDemo', 'FullDemo')]
    [string]$Scenario = 'FullLocalDemo',

    [ValidateRange(15, 600)]
    [int]$TimeoutSeconds = 120,

    [switch]$SkipImageScan,

    [switch]$SkipPolicyGate,

    [switch]$SkipRuntimeDemo,

    [switch]$SkipLifecycleDemo,

    [switch]$SkipCorrelation,

    [switch]$NoOpenBrowser,

    [string]$OutputMarkdownPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$checks = New-Object System.Collections.Generic.List[object]
$evidence = [ordered]@{
    StartedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    Scenario = $Scenario
    Result = 'FAIL'
    Rules = @()
    Counts = [ordered]@{}
}
$setDemoConnection = $false

function Write-SafeLine {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host $Message
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'WARN', 'FAIL', 'SKIP')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    $script:checks.Add([ordered]@{
        Name = $Name
        Status = $Status
        Detail = $Detail
    }) | Out-Null
}

function Get-RepositoryRoot {
    $current = Get-Location
    while ($null -ne $current) {
        if (Test-Path (Join-Path $current.Path 'ConShield.sln')) {
            return $current.Path
        }

        $current = $current.Parent
    }

    throw 'Repository root not found. Run this script from the ConShield repository.'
}

function Test-WebRoute {
    param(
        [Parameter(Mandatory = $true)][string]$Route,
        [Parameter(Mandatory = $true)][int[]]$ExpectedStatusCodes,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $uri = '{0}{1}' -f $BaseUrl.TrimEnd('/'), $Route
    try {
        $routeErrors = $null
        $response = Invoke-WebRequest -Uri $uri -MaximumRedirection 0 -SkipHttpErrorCheck -TimeoutSec 8 -ErrorAction SilentlyContinue -ErrorVariable routeErrors
        if ($null -eq $response) {
            throw ($routeErrors | Select-Object -First 1)
        }

        $statusCode = [int]$response.StatusCode
        if ($ExpectedStatusCodes -contains $statusCode) {
            Add-Check -Name $Name -Status 'OK' -Detail ("HTTP {0}" -f $statusCode)
            return $true
        }

        Add-Check -Name $Name -Status 'FAIL' -Detail ("unexpected HTTP {0}" -f $statusCode)
        return $false
    }
    catch {
        Add-Check -Name $Name -Status 'FAIL' -Detail 'not reachable'
        return $false
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Port,
        [switch]$WarnOnly
    )

    $connection = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $connection) {
        Add-Check -Name $Name -Status 'OK' -Detail ("listening on 127.0.0.1:{0}" -f $Port)
        return $true
    }

    Add-Check -Name $Name -Status ($WarnOnly ? 'WARN' : 'FAIL') -Detail ("not listening on local port {0}" -f $Port)
    return $false
}

function Get-LocalEnvValues {
    $path = Join-Path (Get-Location) '.conshield.local.env'
    $values = @{}
    if (-not (Test-Path $path)) {
        return $values
    }

    Get-Content $path | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            $name = $Matches[1]
            $value = $Matches[2]
            if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
                ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                $value = $value.Substring(1, $value.Length - 2)
            }

            $values[$name] = $value
        }
    }

    return $values
}

function Ensure-DemoConnection {
    $existing = Get-Item Env:CONSHIELD_DEMO_CONNECTION_STRING -ErrorAction SilentlyContinue
    if ($null -ne $existing -and -not [string]::IsNullOrWhiteSpace($existing.Value)) {
        Add-Check -Name 'PostgreSQL' -Status 'OK' -Detail 'demo connection configured'
        return
    }

    $local = Get-LocalEnvValues
    $postgresPassword = $local['CONSHIELD_POSTGRES_PASSWORD']
    if ([string]::IsNullOrWhiteSpace($postgresPassword)) {
        Add-Check -Name 'PostgreSQL' -Status 'FAIL' -Detail 'local demo connection unavailable'
        throw 'Local PostgreSQL demo connection is unavailable. Run Start-ConShield.ps1 setup first; secrets were not printed.'
    }

    $env:CONSHIELD_DEMO_CONNECTION_STRING = "Host=127.0.0.1;Port=5432;Database=conshield;Username=conshield;Password=$postgresPassword"
    $script:setDemoConnection = $true
    Add-Check -Name 'PostgreSQL' -Status 'OK' -Detail 'local demo connection prepared'

    $postgresPassword = $null
    $local.Clear()
}

function Get-CliScenario {
    if ($Scenario -eq 'Healthy') {
        return 'healthy'
    }

    if ($Scenario -eq 'FullDemo') {
        return 'full-demo'
    }

    return 'defense-demo'
}

function Invoke-DemoScenario {
    $cliScenario = Get-CliScenario
    $arguments = @('run', '--project', 'tools/ConShield.DemoScenario', '--configuration', 'Release', '--no-restore', '--', '--scenario', $cliScenario, '--yes')
    if ($SkipImageScan -or $SkipPolicyGate -or $SkipRuntimeDemo -or $SkipLifecycleDemo -or $SkipCorrelation) {
        Add-Check -Name 'Scenario switches' -Status 'WARN' -Detail 'skip switches recorded; the bundled defense-demo uses synthetic safe coverage as a unit'
    }

    Write-SafeLine ("Scenario: {0}" -f $Scenario)
    Write-SafeLine 'Scenario steps: image scan, policy gate, synthetic runtime, demo lifecycle, SIEM correlation, reports/evidence'
    Write-SafeLine 'No secrets, raw JSON, connection strings, API keys, tokens, cookies, verifier values, or env values are printed.'

    $output = & dotnet @arguments 2>&1
    $exitCode = $LASTEXITCODE
    $safeOutput = @($output | ForEach-Object { [string]$_ })

    if ($exitCode -ne 0) {
        Add-Check -Name 'Demo scenario CLI' -Status 'FAIL' -Detail ("exit_code={0}" -f $exitCode)
        throw 'Demo scenario CLI failed. Output was not expanded to avoid exposing local details.'
    }

    Add-Check -Name 'Demo scenario CLI' -Status 'OK' -Detail ("scenario={0}" -f $cliScenario)

    foreach ($line in $safeOutput) {
        if ($line -match '^\s*actual_([a-z_]+)=(.*)$') {
            $evidence.Counts[$Matches[1]] = $Matches[2].Trim()
            if ($Matches[1] -eq 'rules') {
                $actualRules = $Matches[2].Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
                $evidence.Rules = @($evidence.Rules + $actualRules | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
            }
        }
        elseif ($line -match '^SIEM correlation:\s+alerts_created=(\d+)\s+incidents_created=(\d+)\s+rules=(.*)$') {
            $evidence.Counts['alerts_created'] = $Matches[1]
            $evidence.Counts['incidents_created'] = $Matches[2]
            $rules = $Matches[3].Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
            $evidence.Rules = @($rules | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
    }

    $expectedRules = @('IMG-001', 'POL-001', 'RTE-001', 'LIFE-001', 'LIFE-002')
    if ((Get-CliScenario) -eq 'healthy') {
        $expectedRules = @()
    }

    foreach ($rule in $expectedRules) {
        if ($evidence.Rules -contains $rule) {
            Add-Check -Name ("SIEM {0}" -f $rule) -Status 'OK' -Detail 'alert demonstrated'
        }
        else {
            Add-Check -Name ("SIEM {0}" -f $rule) -Status 'FAIL' -Detail 'expected rule not demonstrated'
        }
    }
}

function Write-MarkdownEvidence {
    if ([string]::IsNullOrWhiteSpace($OutputMarkdownPath)) {
        return
    }

    $target = $OutputMarkdownPath
    if (-not [System.IO.Path]::IsPathRooted($target)) {
        $target = Join-Path (Get-Location) $target
    }

    $directory = Split-Path -Parent $target
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# ConShield defense scenario evidence') | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add(('- Started UTC: {0}' -f $evidence.StartedAtUtc)) | Out-Null
    $lines.Add(('- Scenario: {0}' -f $evidence.Scenario)) | Out-Null
    $lines.Add(('- Result: {0}' -f $evidence.Result)) | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('## Checks') | Out-Null
    foreach ($check in $checks) {
        $lines.Add(('- {0}: {1} ({2})' -f $check.Name, $check.Status, $check.Detail)) | Out-Null
    }

    $lines.Add('') | Out-Null
    $lines.Add('## Counts') | Out-Null
    foreach ($key in $evidence.Counts.Keys) {
        $lines.Add(('- {0}: {1}' -f $key, $evidence.Counts[$key])) | Out-Null
    }

    $lines.Add('') | Out-Null
    $lines.Add('## UI pages to open') | Out-Null
    foreach ($route in @('/Operations/Health', '/SecurityEvents', '/Sensors', '/SiemAlerts', '/Incidents', '/Reports/SecuritySummary')) {
        $lines.Add(('- {0}{1}' -f $BaseUrl.TrimEnd('/'), $route)) | Out-Null
    }

    $lines.Add('') | Out-Null
    $lines.Add('Secrets, raw event JSON, AdditionalDataJson, connection strings, API keys, tokens, cookies, credentials, and verifier values are intentionally excluded.') | Out-Null
    Set-Content -Path $target -Value $lines -Encoding UTF8
    Add-Check -Name 'Markdown evidence' -Status 'OK' -Detail ("written to {0}" -f $target)
}

function Complete-Run {
    $failed = @($checks | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warned = @($checks | Where-Object { $_.Status -eq 'WARN' }).Count
    if ($failed -gt 0) {
        $evidence.Result = 'FAIL'
        return 1
    }

    if ($warned -gt 0) {
        $evidence.Result = 'WARN'
        return 2
    }

    $evidence.Result = 'PASS'
    return 0
}

try {
    $repoRoot = Get-RepositoryRoot
    Set-Location $repoRoot
    Add-Check -Name 'Repository' -Status 'OK' -Detail 'ConShield root detected'

    Write-SafeLine 'ConShield defense scenario'

    $webOk = Test-WebRoute -Route '/' -ExpectedStatusCodes @(200, 302) -Name 'Web'
    if (-not $webOk) {
        Write-SafeLine 'Web is not running. Start it with:'
        Write-SafeLine 'pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit'
        $exitCode = Complete-Run
        Write-SafeLine ("Result: {0}" -f $evidence.Result)
        exit $exitCode
    }

    [void](Test-WebRoute -Route '/Account/Login' -ExpectedStatusCodes @(200) -Name 'Login page')
    [void](Test-WebRoute -Route '/Operations/Health' -ExpectedStatusCodes @(200, 302, 401, 403) -Name 'Operations health route')
    [void](Test-WebRoute -Route '/SecurityEvents' -ExpectedStatusCodes @(200, 302, 401, 403) -Name 'Security events route')
    [void](Test-WebRoute -Route '/Reports/SecuritySummary' -ExpectedStatusCodes @(200, 302, 401, 403) -Name 'Reports route')

    [void](Test-TcpPort -Name 'RabbitMQ' -Port 5672 -WarnOnly)
    [void](Test-TcpPort -Name 'Mongo projection' -Port 27017 -WarnOnly)

    $consumerProcess = Get-CimInstance Win32_Process -Filter "Name = 'dotnet.exe' OR Name = 'ConShield.EventConsumer.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*ConShield.EventConsumer*' -or $_.Name -eq 'ConShield.EventConsumer.exe' } |
        Select-Object -First 1
    if ($null -ne $consumerProcess) {
        Add-Check -Name 'EventConsumer' -Status 'OK' -Detail 'process detected'
    }
    else {
        Add-Check -Name 'EventConsumer' -Status 'WARN' -Detail 'process not detected; synthetic inbox evidence will still be generated'
    }

    Ensure-DemoConnection
    Invoke-DemoScenario

    $outboxPending = [int]($evidence.Counts['outbox_pending'] ?? '0')
    $outboxProcessing = [int]($evidence.Counts['outbox_processing'] ?? '0')
    $outboxDeadLetter = [int]($evidence.Counts['outbox_deadletter'] ?? '0')
    if ($outboxPending -eq 0 -and $outboxProcessing -eq 0 -and $outboxDeadLetter -eq 0) {
        Add-Check -Name 'Outbox backlog' -Status 'OK' -Detail 'no demo backlog'
    }
    else {
        Add-Check -Name 'Outbox backlog' -Status 'WARN' -Detail ("pending={0} processing={1} deadletter={2}" -f $outboxPending, $outboxProcessing, $outboxDeadLetter)
    }

    Add-Check -Name 'Reports' -Status 'OK' -Detail '/Reports/SecuritySummary available for review'

    $exitCode = Complete-Run
    Write-MarkdownEvidence
    $exitCode = Complete-Run

    Write-SafeLine ("Web: {0}" -f (($checks | Where-Object Name -eq 'Web' | Select-Object -First 1).Status))
    Write-SafeLine ("EventConsumer: {0}" -f (($checks | Where-Object Name -eq 'EventConsumer' | Select-Object -First 1).Status))
    Write-SafeLine ("PostgreSQL: {0}" -f (($checks | Where-Object Name -eq 'PostgreSQL' | Select-Object -First 1).Status))
    Write-SafeLine ("RabbitMQ: {0}" -f (($checks | Where-Object Name -eq 'RabbitMQ' | Select-Object -First 1).Status))
    Write-SafeLine ("Mongo projection: {0}" -f (($checks | Where-Object Name -eq 'Mongo projection' | Select-Object -First 1).Status))
    Write-SafeLine ("Events created: {0}" -f ($evidence.Counts['security_events'] ?? '0'))
    Write-SafeLine ("Outbox delivered: {0}" -f (($evidence.Counts['outbox_messages'] ?? '0') -as [string]))
    Write-SafeLine ("Inbox receipts: {0}" -f ($evidence.Counts['inbox_receipts'] ?? '0'))
    Write-SafeLine ("SIEM alerts: {0}" -f ($evidence.Counts['siem_alerts'] ?? '0'))
    Write-SafeLine ("Incidents: {0}" -f ($evidence.Counts['incidents'] ?? '0'))
    Write-SafeLine ("Rules: {0}" -f (($evidence.Rules -join ',') ?? ''))
    Write-SafeLine 'Reports: /Reports/SecuritySummary'
    Write-SafeLine ("Result: {0}" -f $evidence.Result)
    exit $exitCode
}
catch {
    Add-Check -Name 'Runner' -Status 'FAIL' -Detail $_.Exception.Message
    $exitCode = Complete-Run
    Write-SafeLine ("Result: {0}" -f $evidence.Result)
    Write-SafeLine $_.Exception.Message
    exit $exitCode
}
finally {
    if ($setDemoConnection) {
        Remove-Item Env:CONSHIELD_DEMO_CONNECTION_STRING -ErrorAction SilentlyContinue
    }
}
