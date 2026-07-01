[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:5080',
    [switch]$ResetFirst,
    [switch]$SkipEvidenceExport,
    [string]$OutputEvidencePath = '.\artifacts\local\defense-evidence-guided-demo.md',
    [switch]$ContinueOnExpectedFindings,
    [ValidateRange(30, 1800)]
    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$results = @()
$hints = @()

function Resolve-RepositoryRoot {
    $directory = Get-Item -LiteralPath $PSScriptRoot
    while ($null -ne $directory -and -not (Test-Path -LiteralPath (Join-Path $directory.FullName 'ConShield.sln'))) {
        $directory = $directory.Parent
    }

    if ($null -eq $directory) {
        throw 'Repository root was not found. Run this script from the ConShield repository.'
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

function Add-SeedResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'FAIL', 'SKIP')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Detail,
        [string]$Hint
    )

    $script:results += [pscustomobject][ordered]@{
        Name = $Name
        Status = $Status
        Detail = $Detail
    }

    if (-not [string]::IsNullOrWhiteSpace($Hint)) {
        $script:hints += ('{0}: {1}' -f $Name, $Hint)
    }
}

function Get-SeedResultValue {
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Result) {
        return ''
    }

    $property = $Result.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return [string]$property.Value
    }

    if ($Result -is [System.Collections.IDictionary] -and $Result.Contains($Name)) {
        return [string]$Result[$Name]
    }

    return ''
}

function Test-WebApiAvailable {
    param([Parameter(Mandatory = $true)][string]$RootUrl)

    try {
        $response = Invoke-WebRequest -Uri ($RootUrl.TrimEnd('/') + '/Operations/Health') -UseBasicParsing -MaximumRedirection 1 -SkipHttpErrorCheck -TimeoutSec 10
        return [int]$response.StatusCode -in @(200, 302, 401, 403)
    }
    catch {
        return $false
    }
}

function Test-WebRouteAvailable {
    param(
        [Parameter(Mandatory = $true)][string]$RootUrl,
        [Parameter(Mandatory = $true)][string]$Route
    )

    try {
        $response = Invoke-WebRequest -Uri ($RootUrl.TrimEnd('/') + $Route) -UseBasicParsing -MaximumRedirection 1 -SkipHttpErrorCheck -TimeoutSec 10
        return [int]$response.StatusCode -in @(200, 302, 401, 403)
    }
    catch {
        return $false
    }
}

function Invoke-SeedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [string[]]$RequiredMarkers = @(),
        [string]$Hint = ''
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    $process = $null
    try {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $FileName
        $startInfo.WorkingDirectory = $WorkingDirectory
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in $Arguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        $completed = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $completed) {
            try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
            Add-SeedResult -Name $Name -Status 'FAIL' -Detail 'timed out' -Hint $Hint
            return [pscustomobject]@{ Ok = $false; Output = '' }
        }

        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $output = (@($stdout, $stderr) -join "`n")

        if ([int]$process.ExitCode -ne 0) {
            Add-SeedResult -Name $Name -Status 'FAIL' -Detail ('exit_code={0}' -f $process.ExitCode) -Hint $Hint
            return [pscustomobject]@{ Ok = $false; Output = $output }
        }

        foreach ($marker in $RequiredMarkers) {
            if ($output.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                Add-SeedResult -Name $Name -Status 'FAIL' -Detail ('missing marker: {0}' -f $marker) -Hint $Hint
                return [pscustomobject]@{ Ok = $false; Output = $output }
            }
        }

        Add-SeedResult -Name $Name -Status 'OK' -Detail 'idempotent OK'
        return [pscustomobject]@{ Ok = $true; Output = $output }
    }
    catch {
        Add-SeedResult -Name $Name -Status 'FAIL' -Detail 'process failed' -Hint $Hint
        return [pscustomobject]@{ Ok = $false; Output = '' }
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Invoke-PowerShellScript {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string[]]$RequiredMarkers = @(),
        [string]$Hint = ''
    )

    $scriptArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath) + $Arguments
    return Invoke-SeedProcess -Name $Name -FileName 'pwsh' -Arguments $scriptArguments -WorkingDirectory $RepoRoot -RequiredMarkers $RequiredMarkers -Hint $Hint
}

function Stop-OnFailureIfNeeded {
    param([Parameter(Mandatory = $true)][string]$StepName)

    if ($ContinueOnExpectedFindings) {
        return
    }

    $failed = @($results) | Where-Object { (Get-SeedResultValue -Result $_ -Name 'Name') -eq $StepName -and (Get-SeedResultValue -Result $_ -Name 'Status') -eq 'FAIL' } | Select-Object -First 1
    if ($null -ne $failed) {
        throw ('Step failed: {0}' -f $StepName)
    }
}

function Write-SeedSummary {
    param([Parameter(Mandatory = $true)][string]$FinalResult)

    Write-Host 'ConShield demo data seed'
    foreach ($entry in @($results)) {
        Write-Host ('{0}: {1}' -f (Get-SeedResultValue -Result $entry -Name 'Name'), (Get-SeedResultValue -Result $entry -Name 'Status'))
    }

    $failed = @($results) | Where-Object { (Get-SeedResultValue -Result $_ -Name 'Status') -eq 'FAIL' } | Select-Object -First 1
    if ($null -ne $failed) {
        Write-Host ('Failed step: {0}' -f (Get-SeedResultValue -Result $failed -Name 'Name'))
        Write-Host ('Failure detail: {0}' -f (Get-SeedResultValue -Result $failed -Name 'Detail'))
    }

    foreach ($hint in $hints) {
        Write-Host ('Hint: {0}' -f $hint)
    }

    Write-Host ('Result: {0}' -f $FinalResult)
}

$repoRoot = Resolve-RepositoryRoot
$baseUrlNormalized = $BaseUrl.TrimEnd('/')
$resolvedEvidencePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $OutputEvidencePath

Push-Location $repoRoot
try {
    $requiredFiles = @(
        'scripts\Run-ConShieldDefenseScenario.ps1',
        'scripts\Replay-ConShieldFalcoRuntimeEvent.ps1',
        'scripts\Reset-ConShieldLocalDemoData.ps1',
        'scripts\Export-ConShieldDefenseEvidence.ps1',
        'tests\TestData\Falco\terminal-shell-container.json',
        'tests\TestData\Trivy\sample-image-scan.json',
        'tests\TestData\DockerEvents\container-lifecycle-events.json'
    )

    $missing = @($requiredFiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $repoRoot $_) -PathType Leaf) })
    if ($missing.Count -gt 0) {
        Add-SeedResult -Name 'Prerequisites' -Status 'FAIL' -Detail 'required repo files missing' -Hint 'Restore committed scripts and deterministic fixtures.'
        throw 'Prerequisites failed.'
    }

    if (-not (Test-WebApiAvailable -RootUrl $baseUrlNormalized)) {
        Add-SeedResult -Name 'Prerequisites' -Status 'FAIL' -Detail 'Web/API unavailable' -Hint 'Start local services with: pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit'
        throw 'Prerequisites failed.'
    }

    Add-SeedResult -Name 'Prerequisites' -Status 'OK' -Detail 'Web/API reachable and fixtures present'

    if ($ResetFirst) {
        [void](Invoke-PowerShellScript `
            -Name 'Optional reset' `
            -ScriptPath (Join-Path $repoRoot 'scripts\Reset-ConShieldLocalDemoData.ps1') `
            -Arguments @('-ConfirmReset') `
            -RepoRoot $repoRoot `
            -RequiredMarkers @('Result: PASS') `
            -Hint 'Reset is optional. Rerun without -ResetFirst to preserve current local demo data.')
        Stop-OnFailureIfNeeded -StepName 'Optional reset'
    }
    else {
        Add-SeedResult -Name 'Optional reset' -Status 'SKIP' -Detail 'not requested; pass -ResetFirst for confirmed reset'
    }

    [void](Invoke-PowerShellScript `
        -Name 'Runtime/Falco replay' `
        -ScriptPath (Join-Path $repoRoot 'scripts\Replay-ConShieldFalcoRuntimeEvent.ps1') `
        -Arguments @('-BaseUrl', $baseUrlNormalized, '-DemoSignature') `
        -RepoRoot $repoRoot `
        -RequiredMarkers @('Result: PASS', 'RTE-001') `
        -Hint 'Run scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -DemoSignature after Start-ConShield.ps1.')
    Stop-OnFailureIfNeeded -StepName 'Runtime/Falco replay'

    [void](Invoke-PowerShellScript `
        -Name 'Sensor trust unknown' `
        -ScriptPath (Join-Path $repoRoot 'scripts\Replay-ConShieldFalcoRuntimeEvent.ps1') `
        -Arguments @('-BaseUrl', $baseUrlNormalized, '-SimulateUnknownSensor') `
        -RepoRoot $repoRoot `
        -RequiredMarkers @('Result: PASS', 'SENSOR-001') `
        -Hint 'Run scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -SimulateUnknownSensor after Start-ConShield.ps1.')
    Stop-OnFailureIfNeeded -StepName 'Sensor trust unknown'

    [void](Invoke-PowerShellScript `
        -Name 'Sensor trust revoked' `
        -ScriptPath (Join-Path $repoRoot 'scripts\Replay-ConShieldFalcoRuntimeEvent.ps1') `
        -Arguments @('-BaseUrl', $baseUrlNormalized, '-SimulateRevokedSensor') `
        -RepoRoot $repoRoot `
        -RequiredMarkers @('Result: PASS', 'SENSOR-002') `
        -Hint 'Run scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -SimulateRevokedSensor after Start-ConShield.ps1.')
    Stop-OnFailureIfNeeded -StepName 'Sensor trust revoked'

    [void](Invoke-PowerShellScript `
        -Name 'Signed sensor missing' `
        -ScriptPath (Join-Path $repoRoot 'scripts\Replay-ConShieldFalcoRuntimeEvent.ps1') `
        -Arguments @('-BaseUrl', $baseUrlNormalized, '-SimulateMissingSignature') `
        -RepoRoot $repoRoot `
        -RequiredMarkers @('Result: PASS', 'SIGN-001') `
        -Hint 'Run scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -SimulateMissingSignature after Start-ConShield.ps1.')
    Stop-OnFailureIfNeeded -StepName 'Signed sensor missing'

    [void](Invoke-PowerShellScript `
        -Name 'Signed sensor invalid' `
        -ScriptPath (Join-Path $repoRoot 'scripts\Replay-ConShieldFalcoRuntimeEvent.ps1') `
        -Arguments @('-BaseUrl', $baseUrlNormalized, '-SimulateInvalidSignature') `
        -RepoRoot $repoRoot `
        -RequiredMarkers @('Result: PASS', 'SIGN-002') `
        -Hint 'Run scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -SimulateInvalidSignature after Start-ConShield.ps1.')
    Stop-OnFailureIfNeeded -StepName 'Signed sensor invalid'

    [void](Invoke-PowerShellScript `
        -Name 'Signed sensor stale' `
        -ScriptPath (Join-Path $repoRoot 'scripts\Replay-ConShieldFalcoRuntimeEvent.ps1') `
        -Arguments @('-BaseUrl', $baseUrlNormalized, '-SimulateStaleSignature') `
        -RepoRoot $repoRoot `
        -RequiredMarkers @('Result: PASS', 'SIGN-003') `
        -Hint 'Run scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -SimulateStaleSignature after Start-ConShield.ps1.')
    Stop-OnFailureIfNeeded -StepName 'Signed sensor stale'

    $scenario = Invoke-PowerShellScript `
        -Name 'Defense scenario correlation' `
        -ScriptPath (Join-Path $repoRoot 'scripts\Run-ConShieldDefenseScenario.ps1') `
        -Arguments @('-BaseUrl', $baseUrlNormalized, '-NoOpenBrowser') `
        -RepoRoot $repoRoot `
        -RequiredMarkers @('Result: PASS', 'IMG-001', 'POL-001', 'LIFE-001', 'LIFE-002', 'RTE-001') `
        -Hint 'Run scripts\Run-ConShieldDefenseScenario.ps1 after local services are started.'
    Stop-OnFailureIfNeeded -StepName 'Defense scenario correlation'

    if ($scenario.Ok) {
        Add-SeedResult -Name 'Image scan' -Status 'OK' -Detail 'IMG-001 demonstrated'
        Add-SeedResult -Name 'CI/CD gate finding' -Status 'OK' -Detail 'IMG-001/POL-001 demonstrated'
        Add-SeedResult -Name 'Protected run decision' -Status 'OK' -Detail 'POL-001 demonstrated'
        Add-SeedResult -Name 'Docker lifecycle replay' -Status 'OK' -Detail 'LIFE-001/LIFE-002 demonstrated'
    }

    if (-not $SkipEvidenceExport) {
        [void](Invoke-PowerShellScript `
            -Name 'Evidence-ready data' `
            -ScriptPath (Join-Path $repoRoot 'scripts\Export-ConShieldDefenseEvidence.ps1') `
            -Arguments @('-BaseUrl', $baseUrlNormalized, '-OutputMarkdownPath', $resolvedEvidencePath) `
            -RepoRoot $repoRoot `
            -RequiredMarkers @('Result: PASS') `
            -Hint 'Run scripts\Export-ConShieldDefenseEvidence.ps1 after seed completes.')
        Stop-OnFailureIfNeeded -StepName 'Evidence-ready data'
    }
    else {
        Add-SeedResult -Name 'Evidence-ready data' -Status 'SKIP' -Detail 'evidence export skipped'
    }

    if (Test-WebRouteAvailable -RootUrl $baseUrlNormalized -Route '/Dashboard') {
        Add-SeedResult -Name 'Dashboard-ready data' -Status 'OK' -Detail 'dashboard route reachable after seed'
    }
    else {
        Add-SeedResult -Name 'Dashboard-ready data' -Status 'FAIL' -Detail 'dashboard route not reachable' -Hint 'Open http://127.0.0.1:5080/Dashboard after login.'
    }

    $hasFailures = @(@($results) | Where-Object { (Get-SeedResultValue -Result $_ -Name 'Status') -eq 'FAIL' }).Count -gt 0
    $finalResult = if ($hasFailures) { 'FAIL' } else { 'PASS' }
    Write-SeedSummary -FinalResult $finalResult
    exit $(if ($hasFailures) { 1 } else { 0 })
}
catch {
    if (@(@($results) | Where-Object { (Get-SeedResultValue -Result $_ -Name 'Name') -eq 'Runner' }).Count -eq 0) {
        Add-SeedResult -Name 'Runner' -Status 'FAIL' -Detail $_.Exception.Message
    }

    Write-SeedSummary -FinalResult 'FAIL'
    exit 1
}
finally {
    Pop-Location
}
