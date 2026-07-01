param(
    [switch]$IncludeWeb
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepositoryRoot {
    $directory = Get-Item -LiteralPath $PSScriptRoot
    while ($null -ne $directory -and -not (Test-Path -LiteralPath (Join-Path $directory.FullName 'ConShield.sln'))) {
        $directory = $directory.Parent
    }

    if ($null -eq $directory) {
        throw "Repository root was not found."
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

function New-StepResult {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Detail,
        [string]$Hint
    )

    return [pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = ConvertTo-SafeText -Value $Detail
        Hint = ConvertTo-SafeText -Value $Hint
    }
}

function Invoke-Process {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

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
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    return [pscustomobject]@{
        ExitCode = [int]$process.ExitCode
        Output = @($stdout, $stderr) -join "`n"
    }
}

function Invoke-ValidationCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string[]]$RequiredMarkers = @(),
        [string]$Hint = ''
    )

    $result = Invoke-Process -FileName $FileName -Arguments $Arguments -WorkingDirectory $RepoRoot
    if ($result.ExitCode -ne 0) {
        return New-StepResult -Name $Name -Passed $false -Detail ("exit={0}; {1}" -f $result.ExitCode, $result.Output) -Hint $Hint
    }

    foreach ($marker in $RequiredMarkers) {
        if ($result.Output.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return New-StepResult -Name $Name -Passed $false -Detail ("missing marker: {0}" -f $marker) -Hint $Hint
        }
    }

    return New-StepResult -Name $Name -Passed $true -Detail 'OK' -Hint $Hint
}

function Test-RequiredFiles {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string[]]$RelativePaths
    )

    foreach ($relativePath in $RelativePaths) {
        $path = Join-Path $RepoRoot $relativePath
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return "Missing file: $relativePath"
        }
    }

    return $null
}

function Test-PowerShellSyntax {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $scriptPaths = @()
    $scriptPaths += Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'scripts') -Filter '*.ps1' -File -ErrorAction SilentlyContinue
    $startScript = Join-Path $RepoRoot 'Start-ConShield.ps1'
    if (Test-Path -LiteralPath $startScript -PathType Leaf) {
        $scriptPaths += Get-Item -LiteralPath $startScript
    }

    foreach ($path in $scriptPaths) {
        $parseErrors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath $path.FullName -Raw), [ref]$parseErrors)
        if ($parseErrors) {
            return "PowerShell parse failed: $($path.FullName)"
        }
    }

    return $null
}

function Test-FileContainsAll {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Markers
    )

    $content = Get-Content -LiteralPath $Path -Raw
    foreach ($marker in $Markers) {
        if ($content.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return "Missing marker in $([System.IO.Path]::GetFileName($Path)): $marker"
        }
    }

    return $null
}

function Test-Repository {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $required = @(
        'ConShield.sln',
        'src\ConShield.Cli\ConShield.Cli.csproj',
        'docs\GUIDED_DEMO_SCENARIO.md',
        'scripts\Export-ConShieldDefenseEvidence.ps1',
        'scripts\Seed-ConShieldDemoData.ps1',
        'scripts\Test-ConShieldDemoReadiness.ps1',
        'README.md',
        '.github\workflows\dotnet.yml'
    )

    $missing = Test-RequiredFiles -RepoRoot $RepoRoot -RelativePaths $required
    if ($missing) {
        return New-StepResult -Name 'Repository' -Passed $false -Detail $missing -Hint 'Run from the ConShield repository root.'
    }

    return New-StepResult -Name 'Repository' -Passed $true -Detail 'OK' -Hint ''
}

function Test-Configuration {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $required = @(
        'config\siem-rules.default.json',
        'config\container-policy.default.json',
        'config\sensor-registry.default.json'
    )

    $missing = Test-RequiredFiles -RepoRoot $RepoRoot -RelativePaths $required
    if ($missing) {
        return New-StepResult -Name 'Configuration' -Passed $false -Detail $missing -Hint 'Restore committed config defaults.'
    }

    foreach ($relativePath in $required) {
        try {
            $null = Get-Content -LiteralPath (Join-Path $RepoRoot $relativePath) -Raw | ConvertFrom-Json -Depth 32
        }
        catch {
            return New-StepResult -Name 'Configuration' -Passed $false -Detail ("Invalid JSON: {0}" -f $relativePath) -Hint 'Run the specific Test-ConShield* config script.'
        }
    }

    foreach ($script in @('Test-ConShieldSiemRules.ps1', 'Test-ConShieldContainerPolicy.ps1', 'Test-ConShieldSensorRegistry.ps1')) {
        $result = Invoke-ValidationCommand `
            -Name "Configuration/$script" `
            -FileName 'pwsh' `
            -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $RepoRoot "scripts\$script")) `
            -RepoRoot $RepoRoot `
            -RequiredMarkers @('Result: PASS') `
            -Hint "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\$script"
        if (-not $result.Passed) {
            return New-StepResult -Name 'Configuration' -Passed $false -Detail $result.Detail -Hint $result.Hint
        }
    }

    return New-StepResult -Name 'Configuration' -Passed $true -Detail 'OK' -Hint ''
}

function Test-Cli {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $project = Join-Path $RepoRoot 'src\ConShield.Cli'
    $help = Invoke-ValidationCommand `
        -Name 'CLI/help' `
        -FileName 'dotnet' `
        -Arguments @('run', '--project', $project, '--', '--help') `
        -RepoRoot $RepoRoot `
        -RequiredMarkers @('validate', 'demo readiness', 'demo seed', 'demo reset', 'scan image', 'run protected', 'sensor replay', 'lifecycle replay', 'lifecycle watch', 'gate image', 'evidence export') `
        -Hint 'dotnet run --project .\src\ConShield.Cli -- --help'
    if (-not $help.Passed) {
        return New-StepResult -Name 'CLI' -Passed $false -Detail $help.Detail -Hint $help.Hint
    }

    $validate = Invoke-ValidationCommand `
        -Name 'CLI/validate' `
        -FileName 'dotnet' `
        -Arguments @('run', '--project', $project, '--', 'validate') `
        -RepoRoot $RepoRoot `
        -RequiredMarkers @('Result: PASS') `
        -Hint 'dotnet run --project .\src\ConShield.Cli -- validate'
    if (-not $validate.Passed) {
        return New-StepResult -Name 'CLI' -Passed $false -Detail $validate.Detail -Hint $validate.Hint
    }

    return New-StepResult -Name 'CLI' -Passed $true -Detail 'OK' -Hint ''
}

function Test-Scripts {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $syntaxError = Test-PowerShellSyntax -RepoRoot $RepoRoot
    if ($syntaxError) {
        return New-StepResult -Name 'Scripts' -Passed $false -Detail $syntaxError -Hint 'Parse scripts/*.ps1 and Start-ConShield.ps1.'
    }

    $required = @(
        'scripts\Run-ConShieldDefenseScenario.ps1',
        'scripts\Replay-ConShieldFalcoRuntimeEvent.ps1',
        'scripts\Invoke-ConShieldImageScan.ps1',
        'scripts\Invoke-ConShieldProtectedRun.ps1',
        'scripts\Export-ConShieldDefenseEvidence.ps1',
        'scripts\Seed-ConShieldDemoData.ps1',
        'scripts\Test-ConShieldDemoReadiness.ps1',
        'scripts\Reset-ConShieldLocalDemoData.ps1'
    )

    $missing = Test-RequiredFiles -RepoRoot $RepoRoot -RelativePaths $required
    if ($missing) {
        return New-StepResult -Name 'Scripts' -Passed $false -Detail $missing -Hint 'Restore the missing workflow script.'
    }

    return New-StepResult -Name 'Scripts' -Passed $true -Detail 'OK' -Hint ''
}

function Test-Fixtures {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $required = @(
        'tests\TestData\Trivy\sample-image-scan.json',
        'tests\TestData\Trivy\warn-image-scan.json',
        'tests\TestData\Trivy\clean-image-scan.json',
        'tests\TestData\DockerEvents\container-lifecycle-events.json',
        'tests\TestData\Falco\terminal-shell-container.json'
    )

    $missing = Test-RequiredFiles -RepoRoot $RepoRoot -RelativePaths $required
    if ($missing) {
        return New-StepResult -Name 'Fixtures' -Passed $false -Detail $missing -Hint 'Restore deterministic fixtures under tests/TestData.'
    }

    $project = Join-Path $RepoRoot 'src\ConShield.Cli'
    $commands = @(
        @{
            Name = 'scan image'
            Args = @('run', '--project', $project, '--', 'scan', 'image', '--from-trivy-json', (Join-Path $RepoRoot 'tests\TestData\Trivy\sample-image-scan.json'), '--no-submit')
            Markers = @('Expected rule: IMG-001', 'Result: PASS')
        },
        @{
            Name = 'run protected'
            Args = @('run', '--project', $project, '--', 'run', 'protected', '--image', 'demo/insecure-api:latest', '--container-name', 'conshield-demo-insecure', '--from-trivy-json', (Join-Path $RepoRoot 'tests\TestData\Trivy\sample-image-scan.json'), '--no-run', '--no-submit')
            Markers = @('Policy: Block', 'Result: PASS')
        },
        @{
            Name = 'sensor replay'
            Args = @('run', '--project', $project, '--', 'sensor', 'replay', '--demo-signature', '--no-submit')
            Markers = @('Signature: Valid', 'Result: PASS')
        },
        @{
            Name = 'sensor collect'
            Args = @('run', '--project', $project, '--', 'sensor', 'collect', '--from-json-lines', (Join-Path $RepoRoot 'tests\TestData\Falco\falco-runtime-stream.jsonl'), '--demo-signature', '--no-submit')
            Markers = @('ConShield runtime sensor stream collector', 'Events skipped: 1', 'Result: PASS')
        },
        @{
            Name = 'lifecycle replay'
            Args = @('run', '--project', $project, '--', 'lifecycle', 'replay', '--from-docker-events-json', (Join-Path $RepoRoot 'tests\TestData\DockerEvents\container-lifecycle-events.json'), '--no-submit')
            Markers = @('SourceSystem: conshield.docker-lifecycle-collector', 'Result: PASS')
        },
        @{
            Name = 'gate image'
            Args = @('run', '--project', $project, '--', 'gate', 'image', '--image', 'demo/clean-api:latest', '--from-trivy-json', (Join-Path $RepoRoot 'tests\TestData\Trivy\clean-image-scan.json'), '--fail-on', 'block', '--no-submit')
            Markers = @('Policy: Allow', 'Result: PASS')
        }
    )

    foreach ($command in $commands) {
        $result = Invoke-ValidationCommand `
            -Name ("Fixtures/{0}" -f $command.Name) `
            -FileName 'dotnet' `
            -Arguments $command.Args `
            -RepoRoot $RepoRoot `
            -RequiredMarkers $command.Markers `
            -Hint ("dotnet run --project .\src\ConShield.Cli -- {0}" -f $command.Name)
        if (-not $result.Passed) {
            return New-StepResult -Name 'Fixtures' -Passed $false -Detail $result.Detail -Hint $result.Hint
        }
    }

    return New-StepResult -Name 'Fixtures' -Passed $true -Detail 'OK' -Hint ''
}

function Test-DemoContract {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $combined = @(
        (Get-Content -LiteralPath (Join-Path $RepoRoot 'src\ConShield.Web\Controllers\DemoController.cs') -Raw),
        (Get-Content -LiteralPath (Join-Path $RepoRoot 'src\ConShield.Web\Views\Demo\Index.cshtml') -Raw)
    ) -join "`n"

    foreach ($marker in @(
        'Test-ConShieldDemoReadiness.ps1',
        'Seed-ConShieldDemoData.ps1',
        'demo seed',
        'Reset-ConShieldLocalDemoData.ps1',
        'scan image',
        'run protected',
        'gate image',
        'lifecycle replay',
        'sensor replay',
        'sensor collect',
        'Export-ConShieldDefenseEvidence.ps1',
        '/Reports/SecuritySummary',
        '/SecurityEvents',
        '/Siem',
        '/Incidents',
        '/RuntimeSensors'
    )) {
        if ($combined.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return New-StepResult -Name 'Demo contract' -Passed $false -Detail "Missing Demo marker: $marker" -Hint 'Review /Demo commands and links.'
        }
    }

    return New-StepResult -Name 'Demo contract' -Passed $true -Detail 'OK' -Hint ''
}

function Test-EvidenceContract {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $script = Join-Path $RepoRoot 'scripts\Export-ConShieldDefenseEvidence.ps1'
    $missing = Test-FileContainsAll -Path $script -Markers @(
        'ConShield Defense Evidence Pack',
        'Image Scan Evidence',
        'Protected Run Evidence',
        'Container Policy Evidence',
        'SIEM Rules Evidence',
        'Sensor Trust Evidence',
        'Sensor Trust Enforcement Evidence',
        'Signed Sensor Event Evidence',
        'Docker Lifecycle Collector Evidence',
        'Runtime Sensor Health',
        'Operator Workflow'
    )

    if ($missing) {
        return New-StepResult -Name 'Evidence contract' -Passed $false -Detail $missing -Hint 'Update Export-ConShieldDefenseEvidence.ps1 sections.'
    }

    return New-StepResult -Name 'Evidence contract' -Passed $true -Detail 'OK' -Hint ''
}

function Test-SecurityGuardrails {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $gitignore = Get-Content -LiteralPath (Join-Path $RepoRoot '.gitignore') -Raw
    foreach ($marker in @('artifacts/local/', '*.env', 'src/**/appsettings.Development.json', '*.log', '*.jsonl', 'TestResults/')) {
        if ($gitignore.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return New-StepResult -Name 'Security guardrails' -Passed $false -Detail "Missing .gitignore marker: $marker" -Hint 'Update .gitignore for generated/local artifacts.'
        }
    }

    $trackedArtifacts = Invoke-Process -FileName 'git' -Arguments @('ls-files', 'artifacts/local') -WorkingDirectory $RepoRoot
    if (-not [string]::IsNullOrWhiteSpace($trackedArtifacts.Output)) {
        return New-StepResult -Name 'Security guardrails' -Passed $false -Detail 'Tracked generated artifacts under artifacts/local.' -Hint 'Remove generated artifacts from git.'
    }

    $sensitiveMarkers = @(
        ('-----BEGIN ' + 'PRIVATE KEY-----'),
        ('-----BEGIN ' + 'CERTIFICATE-----'),
        ('Docker logs' + ' |')
    )

    $safeFiles = @(
        'README.md',
        'docs\CONSHIELD_CLI.md',
        'docs\GUIDED_DEMO_SCENARIO.md',
        'docs\CICD_CONTAINER_GATE.md',
        'docs\OPERATIONS_AND_SIEM_RUNBOOK.md',
        'scripts\Seed-ConShieldDemoData.ps1',
        'scripts\Test-ConShieldDemoReadiness.ps1',
        'scripts\Export-ConShieldDefenseEvidence.ps1'
    )

    foreach ($relativePath in $safeFiles) {
        $content = Get-Content -LiteralPath (Join-Path $RepoRoot $relativePath) -Raw
        foreach ($marker in $sensitiveMarkers) {
            if ($content.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return New-StepResult -Name 'Security guardrails' -Passed $false -Detail "Unsafe marker in $relativePath" -Hint 'Keep docs/scripts sanitized and rely on fixture summaries.'
            }
        }
    }

    return New-StepResult -Name 'Security guardrails' -Passed $true -Detail 'OK' -Hint ''
}

function Test-OptionalWeb {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $project = Join-Path $RepoRoot 'src\ConShield.Cli'
    $readiness = Invoke-ValidationCommand `
        -Name 'Optional Web/readiness' `
        -FileName 'dotnet' `
        -Arguments @('run', '--project', $project, '--', 'demo', 'readiness') `
        -RepoRoot $RepoRoot `
        -RequiredMarkers @('Result: PASS') `
        -Hint 'Start local services first: pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit'
    if (-not $readiness.Passed) {
        return New-StepResult -Name 'Optional Web' -Passed $false -Detail $readiness.Detail -Hint $readiness.Hint
    }

    $evidencePath = Join-Path $RepoRoot 'artifacts\local\defense-evidence-full-validation.md'
    $evidence = Invoke-ValidationCommand `
        -Name 'Optional Web/evidence' `
        -FileName 'dotnet' `
        -Arguments @('run', '--project', $project, '--', 'evidence', 'export', '--output', $evidencePath) `
        -RepoRoot $RepoRoot `
        -RequiredMarkers @('Result: PASS') `
        -Hint 'Run evidence export after local Web/API services are available.'
    if (-not $evidence.Passed) {
        return New-StepResult -Name 'Optional Web' -Passed $false -Detail $evidence.Detail -Hint $evidence.Hint
    }

    return New-StepResult -Name 'Optional Web' -Passed $true -Detail 'OK' -Hint ''
}

$repoRoot = Resolve-RepositoryRoot
$results = [System.Collections.Generic.List[object]]::new()

Write-Host 'ConShield full validation'

$steps = @(
    { Test-Repository -RepoRoot $repoRoot },
    { Test-Configuration -RepoRoot $repoRoot },
    { Test-Cli -RepoRoot $repoRoot },
    { Test-Scripts -RepoRoot $repoRoot },
    { Test-Fixtures -RepoRoot $repoRoot },
    { Test-DemoContract -RepoRoot $repoRoot },
    { Test-EvidenceContract -RepoRoot $repoRoot },
    { Test-SecurityGuardrails -RepoRoot $repoRoot }
)

foreach ($step in $steps) {
    $result = & $step
    $results.Add($result) | Out-Null
    Write-Host ("{0}: {1}" -f $result.Name, $(if ($result.Passed) { 'OK' } else { 'FAIL' }))
    if (-not $result.Passed) {
        Write-Host ("Failed step: {0}" -f $result.Name)
        Write-Host ("Failure detail: {0}" -f $result.Detail)
        if (-not [string]::IsNullOrWhiteSpace($result.Hint)) {
            Write-Host ("Hint: {0}" -f $result.Hint)
        }

        Write-Host 'Result: FAIL'
        exit 1
    }
}

if ($IncludeWeb) {
    $web = Test-OptionalWeb -RepoRoot $repoRoot
    $results.Add($web) | Out-Null
    Write-Host ("{0}: {1}" -f $web.Name, $(if ($web.Passed) { 'OK' } else { 'FAIL' }))
    if (-not $web.Passed) {
        Write-Host ("Failed step: {0}" -f $web.Name)
        Write-Host ("Failure detail: {0}" -f $web.Detail)
        if (-not [string]::IsNullOrWhiteSpace($web.Hint)) {
            Write-Host ("Hint: {0}" -f $web.Hint)
        }

        Write-Host 'Result: FAIL'
        exit 1
    }
}

Write-Host 'Result: PASS'
exit 0
