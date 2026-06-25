[CmdletBinding()]
param(
    [ValidateSet('healthy', 'full-demo', 'lifecycle-alerts', 'runtime-incident', 'outbox-backlog')]
    [string]$Scenario = 'full-demo',

    [switch]$DryRun,

    [switch]$Apply,

    [switch]$ResetDemoData,

    [switch]$Yes,

    [string]$BaseUrl = 'http://127.0.0.1:5080',

    [switch]$SkipWebChecks
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-SafeInfo {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host $Message
}

function Test-DemoConnectionConfigured {
    $item = Get-Item Env:CONSHIELD_DEMO_CONNECTION_STRING -ErrorAction SilentlyContinue
    return $null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.Value)
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    $executable = $Command[0]
    $arguments = @($Command | Select-Object -Skip 1)
    Write-SafeInfo ("Running: {0}" -f ($Command -join ' '))
    & $executable @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE."
    }
}

function Test-WebRoute {
    param(
        [Parameter(Mandatory = $true)][string]$Route,
        [Parameter(Mandatory = $true)][int[]]$ExpectedStatusCodes
    )

    $uri = '{0}{1}' -f $BaseUrl.TrimEnd('/'), $Route
    try {
        $response = Invoke-WebRequest -Uri $uri -MaximumRedirection 0 -SkipHttpErrorCheck -TimeoutSec 5
        $statusCode = [int]$response.StatusCode
        if ($ExpectedStatusCodes -notcontains $statusCode) {
            throw "Unexpected HTTP status $statusCode for $Route."
        }

        Write-SafeInfo ("web_check route={0} status={1}" -f $Route, $statusCode)
    }
    catch {
        Write-Warning ("Web check skipped/failed for {0}. Start the app first using your local startup workflow. Details are intentionally non-secret: {1}" -f $Route, $_.Exception.Message)
    }
}

if ($Apply -and $DryRun) {
    throw '-Apply and -DryRun are mutually exclusive.'
}

$effectiveDryRun = -not $Apply

Write-SafeInfo 'ConShield demo scenario validation'
Write-SafeInfo ("scenario={0} reset_demo_data={1} dry_run={2} apply={3}" -f $Scenario, [bool]$ResetDemoData, $effectiveDryRun, [bool]$Apply)
Write-SafeInfo 'Connection string values, API keys, tokens, passwords, cookies, and env values are never printed.'

if ($Apply -and -not (Test-DemoConnectionConfigured)) {
    throw 'CONSHIELD_DEMO_CONNECTION_STRING must be set for -Apply. The value is intentionally not printed.'
}

if ($ResetDemoData -and -not $effectiveDryRun -and -not $Yes) {
    throw 'Reset apply requires -Yes. No data was deleted.'
}

if ($ResetDemoData -and $effectiveDryRun -and -not (Test-DemoConnectionConfigured)) {
    throw 'CONSHIELD_DEMO_CONNECTION_STRING must be set to preview reset counts. The value is intentionally not printed.'
}

$runnerArgs = @('run', '--project', 'tools/ConShield.DemoScenario', '--')

if ($ResetDemoData) {
    $runnerArgs += '--reset-demo-data'
}
else {
    $runnerArgs += @('--scenario', $Scenario)
}

if ($effectiveDryRun) {
    $runnerArgs += '--dry-run'
}

if ($ResetDemoData -and -not $effectiveDryRun -and $Yes) {
    $runnerArgs += '--yes'
}

Invoke-CheckedCommand -Command (@('dotnet') + $runnerArgs)

if (-not $SkipWebChecks) {
    Write-SafeInfo 'Checking unauthenticated web route behavior. If the app is not running, start it first using your local startup workflow.'
    Test-WebRoute -Route '/' -ExpectedStatusCodes @(200, 302)
    Test-WebRoute -Route '/Account/Login' -ExpectedStatusCodes @(200)
    Test-WebRoute -Route '/Operations/Health' -ExpectedStatusCodes @(302, 401, 403)
    Test-WebRoute -Route '/SecurityEvents' -ExpectedStatusCodes @(302, 401, 403)
    Test-WebRoute -Route '/Reports/SecuritySummary' -ExpectedStatusCodes @(302, 401, 403)
}
else {
    Write-SafeInfo 'Web checks skipped by -SkipWebChecks.'
}

Write-SafeInfo 'After successful local seeding, open these pages:'
Write-SafeInfo '  /Operations/Health'
Write-SafeInfo '  /SecurityEvents'
Write-SafeInfo '  /Sensors'
Write-SafeInfo '  /Reports/SecuritySummary'
Write-SafeInfo '  /Siem'
Write-SafeInfo '  /Incidents'
Write-SafeInfo 'Do not run -Apply against a production database.'
