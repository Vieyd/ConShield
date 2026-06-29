[CmdletBinding()]
param(
    [switch]$SkipStartApps,
    [switch]$SkipScenario,
    [switch]$SkipImageScan,
    [switch]$SkipProtectedRun,
    [switch]$SkipFalcoReplay,
    [string]$BaseUrl = 'http://127.0.0.1:5080',
    [string]$OutputMarkdownPath = '.\artifacts\local\demo-readiness-evidence.md'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$checks = New-Object System.Collections.Generic.List[object]
$safeHints = New-Object System.Collections.Generic.List[string]

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

function Add-ReadinessCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'WARN', 'FAIL', 'SKIP', 'PASS')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Detail,
        [string]$Hint
    )

    $script:checks.Add([ordered]@{
        Name = $Name
        Status = $Status
        Detail = $Detail
    }) | Out-Null

    if (-not [string]::IsNullOrWhiteSpace($Hint)) {
        $script:safeHints.Add(('{0}: {1}' -f $Name, $Hint)) | Out-Null
    }
}

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [ValidateRange(5, 1800)]
        [int]$TimeoutSeconds = 300
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    $process = $null
    try {
        $escapedArguments = foreach ($argument in $Arguments) {
            $value = [string]$argument
            if ($value -notmatch '[\s"]') {
                $value
                continue
            }

            ('"{0}"' -f ($value -replace '"', '\"'))
        }

        $argumentText = $escapedArguments -join ' '

        $process = Start-Process `
            -FilePath $FilePath `
            -ArgumentList $argumentText `
            -WorkingDirectory $WorkingDirectory `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -WindowStyle Hidden `
            -PassThru
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $completed) {
            try {
                $process.Kill($true)
            }
            catch {
                try { $process.Kill() } catch { }
            }

            return [pscustomobject]@{
                ExitCode = 124
                Output = @('command timed out')
            }
        }

        $output = @()
        if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
            $output += @(Get-Content -LiteralPath $stdoutPath -ErrorAction SilentlyContinue | ForEach-Object { [string]$_ })
        }

        if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            $output += @(Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue | ForEach-Object { [string]$_ })
        }

        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            Output = @($output)
        }
    }
    catch {
        return [pscustomobject]@{
            ExitCode = 1
            Output = @($_.Exception.Message)
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Test-WebRoute {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [int[]]$ExpectedStatusCodes = @(200, 302, 401, 403)
    )

    try {
        $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -MaximumRedirection 5 -SkipHttpErrorCheck -TimeoutSec 10
        return [pscustomobject]@{
            Ok = ([int]$response.StatusCode -in $ExpectedStatusCodes)
            StatusCode = [int]$response.StatusCode
        }
    }
    catch {
        return [pscustomobject]@{
            Ok = $false
            StatusCode = 0
        }
    }
}

function Get-DockerContainerHealth {
    param([Parameter(Mandatory = $true)][string]$ContainerName)

    $inspect = Invoke-CapturedCommand -FilePath 'docker' -Arguments @(
        'inspect',
        '--format',
        '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}',
        $ContainerName
    ) -WorkingDirectory (Get-Location).Path

    if ($inspect.ExitCode -ne 0 -or $inspect.Output.Count -eq 0) {
        return [pscustomobject]@{ Exists = $false; Running = $false; Healthy = $false; Detail = 'container not found' }
    }

    $parts = ([string]$inspect.Output[0]).Split('|')
    $status = if ($parts.Count -gt 0) { $parts[0] } else { 'unknown' }
    $health = if ($parts.Count -gt 1) { $parts[1] } else { 'none' }

    return [pscustomobject]@{
        Exists = $true
        Running = ($status -eq 'running')
        Healthy = ($status -eq 'running' -and ($health -eq 'healthy' -or $health -eq 'none'))
        Detail = ('status={0}, health={1}' -f $status, $health)
    }
}

function Test-DockerService {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ContainerName
    )

    $health = Get-DockerContainerHealth -ContainerName $ContainerName
    if ($health.Healthy) {
        Add-ReadinessCheck -Name $Name -Status 'OK' -Detail $health.Detail
        return $true
    }

    Add-ReadinessCheck `
        -Name $Name `
        -Status 'FAIL' `
        -Detail $health.Detail `
        -Hint 'Start local services with: pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps'
    return $false
}

function Test-ProcessByCommandLine {
    param([Parameter(Mandatory = $true)][string]$Pattern)

    $process = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -match $Pattern } |
        Select-Object -First 1

    return $null -ne $process
}

function Test-DemoUsers {
    param([Parameter(Mandatory = $true)][string]$DiagnosticsUrl)

    try {
        $diagnostics = Invoke-RestMethod -Uri $DiagnosticsUrl -TimeoutSec 10
        $users = @($diagnostics.users)
        $admin = $users | Where-Object { $_.userName -eq 'adminib' } | Select-Object -First 1
        $operator = $users | Where-Object { $_.userName -eq 'operator' } | Select-Object -First 1
        if ($diagnostics.configuredDemoUserCount -ge 2 -and
            $null -ne $admin -and $admin.hasPassword -eq $true -and
            $null -ne $operator -and $operator.hasPassword -eq $true) {
            Add-ReadinessCheck -Name 'Demo users' -Status 'OK' -Detail 'adminib/operator configured with passwords present'
            return $true
        }

        Add-ReadinessCheck `
            -Name 'Demo users' `
            -Status 'FAIL' `
            -Detail 'adminib/operator configuration incomplete' `
            -Hint 'Run: pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-LocalDemoUsers.ps1'
        return $false
    }
    catch {
        Add-ReadinessCheck `
            -Name 'Demo users' `
            -Status 'FAIL' `
            -Detail 'diagnostics endpoint unavailable' `
            -Hint 'Start Web in Development with Start-ConShield.ps1; secrets were not printed.'
        return $false
    }
}

function Test-GeneratedEvidenceSafety {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-ReadinessCheck -Name 'Evidence export' -Status 'FAIL' -Detail 'generated evidence file missing'
        return $false
    }

    $content = Get-Content -LiteralPath $Path -Raw
    $forbiddenPatterns = @(
        'AdditionalDataJson',
        'PayloadJson',
        'SourceEventIdsJson',
        'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY',
        'CONSHIELD_[A-Z0-9_]+\s*=',
        '(?i)(password|api[_ -]?key|token|cookie|connection string)\s*[:=]\s*[^`\r\n\[]'
    )

    foreach ($pattern in $forbiddenPatterns) {
        if ($content -match $pattern) {
            Add-ReadinessCheck -Name 'Evidence safety' -Status 'FAIL' -Detail ('forbidden marker detected: {0}' -f $pattern)
            return $false
        }
    }

    Add-ReadinessCheck -Name 'Evidence safety' -Status 'OK' -Detail 'generated evidence passed marker scan'
    return $true
}

function Write-ReadinessSummary {
    param(
        [Parameter(Mandatory = $true)][string]$ResolvedEvidencePath,
        [Parameter(Mandatory = $true)][string]$Result
    )

    Write-Host 'ConShield demo readiness check'
    foreach ($check in $checks) {
        Write-Host ('{0}: {1}' -f $check.Name, $check.Status)
    }

    $failedCheck = $checks | Where-Object { $_.Status -eq 'FAIL' } | Select-Object -First 1
    if ($null -ne $failedCheck) {
        Write-Host ('Failed step: {0}' -f $failedCheck.Name)
        if (-not [string]::IsNullOrWhiteSpace($failedCheck.Detail)) {
            Write-Host ('Failure detail: {0}' -f $failedCheck.Detail)
        }
    }

    if (Test-Path -LiteralPath $ResolvedEvidencePath -PathType Leaf) {
        Write-Host ('Generated evidence: {0}' -f (Resolve-Path -LiteralPath $ResolvedEvidencePath -Relative))
    }

    foreach ($hint in $safeHints) {
        Write-Host ('Hint: {0}' -f $hint)
    }

    Write-Host ('Result: {0}' -f $Result)
}

$repoRoot = Resolve-RepositoryRoot
$resolvedEvidencePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $OutputMarkdownPath
$normalizedBaseUrl = $BaseUrl.TrimEnd('/')

Push-Location $repoRoot
try {
    $gitRoot = (Invoke-CapturedCommand -FilePath 'git' -Arguments @('rev-parse', '--show-toplevel') -WorkingDirectory $repoRoot)
    if ($gitRoot.ExitCode -eq 0) {
        $branch = (Invoke-CapturedCommand -FilePath 'git' -Arguments @('branch', '--show-current') -WorkingDirectory $repoRoot).Output | Select-Object -First 1
        $commit = (Invoke-CapturedCommand -FilePath 'git' -Arguments @('rev-parse', '--short', 'HEAD') -WorkingDirectory $repoRoot).Output | Select-Object -First 1
        Add-ReadinessCheck -Name 'Git' -Status 'OK' -Detail ('branch={0}, commit={1}' -f $branch, $commit)

        $trackedChanges = @(Invoke-CapturedCommand -FilePath 'git' -Arguments @('status', '--porcelain', '--untracked-files=no') -WorkingDirectory $repoRoot).Output
        if ($trackedChanges.Count -gt 0) {
            Add-ReadinessCheck -Name 'Git working tree' -Status 'WARN' -Detail 'tracked files have local changes'
        }
    }
    else {
        Add-ReadinessCheck -Name 'Git' -Status 'FAIL' -Detail 'not a git repository'
    }

    $dockerVersion = Invoke-CapturedCommand -FilePath 'docker' -Arguments @('version', '--format', '{{.Server.Version}}') -WorkingDirectory $repoRoot
    if ($dockerVersion.ExitCode -eq 0 -and $dockerVersion.Output.Count -gt 0) {
        Add-ReadinessCheck -Name 'Docker' -Status 'OK' -Detail 'daemon reachable'
    }
    else {
        Add-ReadinessCheck -Name 'Docker' -Status 'FAIL' -Detail 'daemon unavailable' -Hint 'Start Docker Desktop and rerun the readiness check.'
    }

    if (-not $SkipStartApps) {
        $start = Invoke-CapturedCommand `
            -FilePath 'pwsh' `
            -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\Start-ConShield.ps1', '-StartApps') `
            -WorkingDirectory $repoRoot
        if ($start.ExitCode -eq 0) {
            Add-ReadinessCheck -Name 'Start apps' -Status 'OK' -Detail 'Start-ConShield.ps1 completed'
        }
        else {
            Add-ReadinessCheck -Name 'Start apps' -Status 'FAIL' -Detail 'Start-ConShield.ps1 failed' -Hint 'Run Start-ConShield.ps1 manually and inspect local logs; secrets are not printed by this readiness check.'
        }
    }
    else {
        Add-ReadinessCheck -Name 'Start apps' -Status 'SKIP' -Detail 'requested by -SkipStartApps'
    }

    [void](Test-DockerService -Name 'PostgreSQL' -ContainerName 'conshield-postgres')
    [void](Test-DockerService -Name 'RabbitMQ' -ContainerName 'conshield-rabbitmq')
    [void](Test-DockerService -Name 'MongoDB' -ContainerName 'conshield-mongo')

    $web = Test-WebRoute -Uri $normalizedBaseUrl -ExpectedStatusCodes @(200, 302)
    if ($web.Ok) {
        Add-ReadinessCheck -Name 'Web' -Status 'OK' -Detail ('HTTP {0}' -f $web.StatusCode)
    }
    else {
        Add-ReadinessCheck -Name 'Web' -Status 'FAIL' -Detail 'not reachable' -Hint 'Start Web with Start-ConShield.ps1 -StartApps.'
    }

    [void](Test-DemoUsers -DiagnosticsUrl ($normalizedBaseUrl + '/Account/DemoUserDiagnostics'))

    if (Test-ProcessByCommandLine -Pattern 'ConShield\.EventConsumer') {
        Add-ReadinessCheck -Name 'EventConsumer' -Status 'OK' -Detail 'process detected'
    }
    else {
        Add-ReadinessCheck -Name 'EventConsumer' -Status 'FAIL' -Detail 'process not detected' -Hint 'Start apps with Start-ConShield.ps1 -StartApps.'
    }

    $siemRules = Invoke-CapturedCommand `
        -FilePath 'pwsh' `
        -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\scripts\Test-ConShieldSiemRules.ps1') `
        -WorkingDirectory $repoRoot
    $siemRulesResult = ($siemRules.Output | Where-Object { $_ -match '^Result:\s+' } | Select-Object -Last 1)
    if ($siemRules.ExitCode -eq 0 -and $siemRulesResult -match 'PASS') {
        Add-ReadinessCheck -Name 'SIEM rules validation' -Status 'PASS' -Detail 'Result: PASS'
    }
    else {
        Add-ReadinessCheck -Name 'SIEM rules validation' -Status 'FAIL' -Detail 'default SIEM rules config did not validate' -Hint 'Run scripts\Test-ConShieldSiemRules.ps1 directly for safe detailed output.'
    }

    $containerPolicy = Invoke-CapturedCommand `
        -FilePath 'pwsh' `
        -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\scripts\Test-ConShieldContainerPolicy.ps1') `
        -WorkingDirectory $repoRoot
    $containerPolicyResult = ($containerPolicy.Output | Where-Object { $_ -match '^Result:\s+' } | Select-Object -Last 1)
    if ($containerPolicy.ExitCode -eq 0 -and $containerPolicyResult -match 'PASS') {
        Add-ReadinessCheck -Name 'Container policy validation' -Status 'PASS' -Detail 'Result: PASS'
    }
    else {
        Add-ReadinessCheck -Name 'Container policy validation' -Status 'FAIL' -Detail 'default container policy config did not validate' -Hint 'Run scripts\Test-ConShieldContainerPolicy.ps1 directly for safe detailed output.'
    }

    $sensorRegistry = Invoke-CapturedCommand `
        -FilePath 'pwsh' `
        -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\scripts\Test-ConShieldSensorRegistry.ps1') `
        -WorkingDirectory $repoRoot
    $sensorRegistryResult = ($sensorRegistry.Output | Where-Object { $_ -match '^Result:\s+' } | Select-Object -Last 1)
    if ($sensorRegistry.ExitCode -eq 0 -and $sensorRegistryResult -match 'PASS') {
        Add-ReadinessCheck -Name 'Sensor registry validation' -Status 'PASS' -Detail 'Result: PASS'
    }
    else {
        Add-ReadinessCheck -Name 'Sensor registry validation' -Status 'FAIL' -Detail 'default sensor registry config did not validate' -Hint 'Run scripts\Test-ConShieldSensorRegistry.ps1 directly for safe detailed output.'
    }

    if ($SkipScenario) {
        Add-ReadinessCheck -Name 'Defense scenario' -Status 'SKIP' -Detail 'requested by -SkipScenario'
    }
    else {
        $scenario = Invoke-CapturedCommand `
            -FilePath 'pwsh' `
            -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\scripts\Run-ConShieldDefenseScenario.ps1') `
            -WorkingDirectory $repoRoot
        $scenarioResult = ($scenario.Output | Where-Object { $_ -match '^Result:\s+' } | Select-Object -Last 1)
        if ($scenario.ExitCode -eq 0 -and $scenarioResult -match 'PASS') {
            Add-ReadinessCheck -Name 'Defense scenario' -Status 'PASS' -Detail 'Result: PASS'
        }
        else {
            Add-ReadinessCheck -Name 'Defense scenario' -Status 'FAIL' -Detail 'scenario did not return PASS' -Hint 'Run scripts\Run-ConShieldDefenseScenario.ps1 directly for safe detailed output.'
        }
    }

    if ($SkipImageScan) {
        Add-ReadinessCheck -Name 'Image scan fixture' -Status 'SKIP' -Detail 'requested by -SkipImageScan'
    }
    else {
        $imageScan = Invoke-CapturedCommand `
            -FilePath 'pwsh' `
            -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\scripts\Invoke-ConShieldImageScan.ps1', '-FromTrivyJson', '.\tests\TestData\Trivy\sample-image-scan.json', '-NoSubmit') `
            -WorkingDirectory $repoRoot
        $imageScanResult = ($imageScan.Output | Where-Object { $_ -match '^Result:\s+' } | Select-Object -Last 1)
        if ($imageScan.ExitCode -eq 0 -and $imageScanResult -match 'PASS') {
            Add-ReadinessCheck -Name 'Image scan fixture' -Status 'PASS' -Detail 'Result: PASS'
        }
        else {
            Add-ReadinessCheck -Name 'Image scan fixture' -Status 'FAIL' -Detail 'fixture scan did not return PASS' -Hint 'Run scripts\Invoke-ConShieldImageScan.ps1 with -FromTrivyJson and -NoSubmit for safe detailed output.'
        }
    }

    if ($SkipProtectedRun) {
        Add-ReadinessCheck -Name 'Protected run fixture' -Status 'SKIP' -Detail 'requested by -SkipProtectedRun'
    }
    else {
        $protectedRun = Invoke-CapturedCommand `
            -FilePath 'pwsh' `
            -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\scripts\Invoke-ConShieldProtectedRun.ps1', '-Image', 'demo/insecure-api:latest', '-ContainerName', 'conshield-demo-insecure', '-FromTrivyJson', '.\tests\TestData\Trivy\sample-image-scan.json', '-NoRun', '-NoSubmit') `
            -WorkingDirectory $repoRoot
        $protectedRunResult = ($protectedRun.Output | Where-Object { $_ -match '^Result:\s+' } | Select-Object -Last 1)
        if ($protectedRun.ExitCode -eq 0 -and $protectedRunResult -match 'PASS') {
            Add-ReadinessCheck -Name 'Protected run fixture' -Status 'PASS' -Detail 'Result: PASS'
        }
        else {
            Add-ReadinessCheck -Name 'Protected run fixture' -Status 'FAIL' -Detail 'protected run fixture did not return PASS' -Hint 'Run scripts\Invoke-ConShieldProtectedRun.ps1 with -FromTrivyJson -NoRun -NoSubmit for safe detailed output.'
        }
    }

    if ($SkipFalcoReplay) {
        Add-ReadinessCheck -Name 'Falco replay' -Status 'SKIP' -Detail 'requested by -SkipFalcoReplay'
    }
    else {
        $falco = Invoke-CapturedCommand `
            -FilePath 'pwsh' `
            -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1') `
            -WorkingDirectory $repoRoot
        $falcoResult = ($falco.Output | Where-Object { $_ -match '^Result:\s+' } | Select-Object -Last 1)
        if ($falco.ExitCode -eq 0 -and $falcoResult -match 'PASS') {
            Add-ReadinessCheck -Name 'Falco replay' -Status 'PASS' -Detail 'Result: PASS'
        }
        else {
            Add-ReadinessCheck -Name 'Falco replay' -Status 'FAIL' -Detail 'replay did not return PASS' -Hint 'Run scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 directly; real Fedora/Falco is not required.'
        }
    }

    $runtimeRoute = Test-WebRoute -Uri ($normalizedBaseUrl + '/RuntimeSensors') -ExpectedStatusCodes @(200, 302, 401, 403)
    if ($runtimeRoute.Ok) {
        Add-ReadinessCheck -Name 'Runtime Sensor Health' -Status 'OK' -Detail ('HTTP {0}' -f $runtimeRoute.StatusCode)
    }
    else {
        Add-ReadinessCheck -Name 'Runtime Sensor Health' -Status 'FAIL' -Detail 'route unavailable'
    }

    $evidenceDirectory = Split-Path -Parent $resolvedEvidencePath
    if (-not [string]::IsNullOrWhiteSpace($evidenceDirectory)) {
        New-Item -ItemType Directory -Force -Path $evidenceDirectory | Out-Null
    }

    $export = Invoke-CapturedCommand `
        -FilePath 'pwsh' `
        -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\scripts\Export-ConShieldDefenseEvidence.ps1', '-OutputMarkdownPath', $OutputMarkdownPath) `
        -WorkingDirectory $repoRoot
    if ($export.ExitCode -eq 0 -and (Test-Path -LiteralPath $resolvedEvidencePath -PathType Leaf)) {
        Add-ReadinessCheck -Name 'Evidence export' -Status 'PASS' -Detail 'generated readiness evidence'
        [void](Test-GeneratedEvidenceSafety -Path $resolvedEvidencePath)
    }
    else {
        Add-ReadinessCheck -Name 'Evidence export' -Status 'FAIL' -Detail 'export failed' -Hint 'Run Export-ConShieldDefenseEvidence.ps1 directly for safe diagnostics.'
    }

    $hasFailures = @($checks | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0
    $result = if ($hasFailures) { 'FAIL' } else { 'PASS' }
    Write-ReadinessSummary -ResolvedEvidencePath $resolvedEvidencePath -Result $result
    if ($hasFailures) {
        exit 1
    }

    exit 0
}
catch {
    Add-ReadinessCheck `
        -Name 'Readiness runner' `
        -Status 'FAIL' `
        -Detail $_.Exception.Message `
        -Hint 'Rerun: pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1'
    Write-ReadinessSummary -ResolvedEvidencePath $resolvedEvidencePath -Result 'FAIL'
    exit 1
}
finally {
    Pop-Location
}
