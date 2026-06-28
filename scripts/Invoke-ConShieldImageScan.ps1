[CmdletBinding()]
param(
    [string]$Image,
    [string]$TrivyPath = 'trivy',
    [string]$WebBaseUrl = 'http://127.0.0.1:5080',
    [string]$FromTrivyJson,
    [switch]$NoSubmit,
    [string]$OutputMarkdownPath,
    [ValidateRange(15, 900)]
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sourceSystem = 'conshield.image-scanner'
$eventType = 'container.image.scan.completed'
$expectedRule = 'IMG-001'
$transientEnvironment = [System.Collections.Generic.List[string]]::new()

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

function Get-LocalEnvMap {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $path = Join-Path $RepoRoot '.conshield.local.env'
    $values = @{}
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $values
    }

    Get-Content -LiteralPath $path -Encoding UTF8 | ForEach-Object {
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

function Get-SafeImageReference {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'unknown-image'
    }

    $safe = ([string]$Value).Trim()
    $safe = -join ($safe.ToCharArray() | Where-Object { -not [char]::IsControl($_) })
    if ($safe -match '^[^/@:]+:[^/@]+@(.+)$') {
        $safe = '***:***@' + $Matches[1]
    }

    return $(if ($safe.Length -le 512) { $safe } else { $safe.Substring(0, 512) })
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Value)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($hash).ToLowerInvariant()
}

function New-DeterministicGuid {
    param([Parameter(Mandatory = $true)][string]$Seed)

    $bytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Seed))[0..15]
    $bytes[6] = ($bytes[6] -band 0x0f) -bor 0x50
    $bytes[8] = ($bytes[8] -band 0x3f) -bor 0x80
    return [Guid]::new([byte[]]$bytes).ToString('D')
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Trivy JSON fixture was not found.'
    }

    $item = Get-Item -LiteralPath $Path
    if ($item.Length -gt 4MB) {
        throw 'Trivy JSON report exceeded the maximum allowed size.'
    }

    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8
}

function Invoke-TrivyImageScan {
    param(
        [Parameter(Mandatory = $true)][string]$TrivyExecutable,
        [Parameter(Mandatory = $true)][string]$ImageReference,
        [Parameter(Mandatory = $true)][int]$Timeout
    )

    $resolved = Get-Command $TrivyExecutable -ErrorAction SilentlyContinue
    if ($null -eq $resolved) {
        throw 'Trivy executable was not found. Install Trivy or use -FromTrivyJson for deterministic offline validation.'
    }

    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    try {
        $versionProcess = Start-Process -FilePath $resolved.Source -ArgumentList '--version' -RedirectStandardOutput $stdout -RedirectStandardError $stderr -NoNewWindow -PassThru
        if (-not $versionProcess.WaitForExit(30000) -or $versionProcess.ExitCode -ne 0) {
            throw 'Trivy did not start. Verify Trivy is installed and available on PATH.'
        }

        $versionText = (Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ([string]::IsNullOrWhiteSpace($versionText)) {
            $versionText = 'trivy'
        }

        Clear-Content -LiteralPath $stdout, $stderr -ErrorAction SilentlyContinue
        $args = @('image', '--format', 'json', '--quiet', '--scanners', 'vuln,secret,misconfig', $ImageReference)
        $scanProcess = Start-Process -FilePath $resolved.Source -ArgumentList $args -RedirectStandardOutput $stdout -RedirectStandardError $stderr -NoNewWindow -PassThru
        if (-not $scanProcess.WaitForExit($Timeout * 1000)) {
            try { $scanProcess.Kill($true) } catch { try { $scanProcess.Kill() } catch { } }
            throw 'Trivy scan timed out. Use -FromTrivyJson for deterministic offline validation.'
        }

        if ((Get-Item -LiteralPath $stdout).Length -gt 4MB) {
            throw 'Trivy JSON report exceeded the maximum allowed size.'
        }

        if ($scanProcess.ExitCode -ne 0) {
            throw 'Trivy scan failed. Verify Trivy is installed and its vulnerability database is available. For deterministic local validation use -FromTrivyJson with -NoSubmit.'
        }

        return [pscustomobject]@{
            ScannerVersion = [string]$versionText
            Json = Get-Content -LiteralPath $stdout -Raw -Encoding UTF8
        }
    }
    finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Get-SeverityName {
    param([AllowNull()][string]$Severity)

    switch (($Severity ?? '').Trim().ToUpperInvariant()) {
        'LOW' { 'LOW'; break }
        'MEDIUM' { 'MEDIUM'; break }
        'HIGH' { 'HIGH'; break }
        'CRITICAL' { 'CRITICAL'; break }
        default { 'UNKNOWN' }
    }
}

function Get-OptionalPropertyValue {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-OptionalPropertyItems {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $value = Get-OptionalPropertyValue -InputObject $InputObject -Name $Name
    if ($null -eq $value) {
        return @()
    }

    return @($value)
}

function Convert-TrivyJsonToSummary {
    param(
        [Parameter(Mandatory = $true)][string]$ReportJson,
        [Parameter(Mandatory = $true)][string]$RequestedImage,
        [Parameter(Mandatory = $true)][string]$ScannerVersion
    )

    try {
        $report = $ReportJson | ConvertFrom-Json -Depth 100
    }
    catch {
        throw 'Malformed Trivy JSON report.'
    }

    $findings = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $targets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $counts = [ordered]@{
        UNKNOWN = 0
        LOW = 0
        MEDIUM = 0
        HIGH = 0
        CRITICAL = 0
    }
    $fixAvailable = 0
    $secretCount = 0
    $criticalSecretCount = 0
    $misconfigurationCount = 0

    foreach ($result in (Get-OptionalPropertyItems -InputObject $report -Name 'Results')) {
        $target = Get-SafeImageReference ([string](Get-OptionalPropertyValue -InputObject $result -Name 'Target'))
        $targetHasFinding = $false

        foreach ($vulnerability in (Get-OptionalPropertyItems -InputObject $result -Name 'Vulnerabilities')) {
            $severity = Get-SeverityName ([string](Get-OptionalPropertyValue -InputObject $vulnerability -Name 'Severity'))
            $identity = '{0}|{1}|{2}|{3}' -f $target, ([string](Get-OptionalPropertyValue -InputObject $vulnerability -Name 'VulnerabilityID')), ([string](Get-OptionalPropertyValue -InputObject $vulnerability -Name 'PkgName')), ([string](Get-OptionalPropertyValue -InputObject $vulnerability -Name 'InstalledVersion'))
            if ($findings.Add($identity)) {
                $counts[$severity]++
                if (-not [string]::IsNullOrWhiteSpace([string](Get-OptionalPropertyValue -InputObject $vulnerability -Name 'FixedVersion'))) {
                    $fixAvailable++
                }
                $targetHasFinding = $true
            }
        }

        foreach ($secret in (Get-OptionalPropertyItems -InputObject $result -Name 'Secrets')) {
            $secretCount++
            if ((Get-SeverityName ([string](Get-OptionalPropertyValue -InputObject $secret -Name 'Severity'))) -eq 'CRITICAL') {
                $criticalSecretCount++
            }
            $targetHasFinding = $true
        }

        foreach ($misconfiguration in (Get-OptionalPropertyItems -InputObject $result -Name 'Misconfigurations')) {
            $misconfigurationCount++
            $targetHasFinding = $true
        }

        if ($targetHasFinding -and -not [string]::IsNullOrWhiteSpace($target)) {
            [void]$targets.Add($target)
        }
    }

    $imageReference = $RequestedImage
    $metadata = Get-OptionalPropertyValue -InputObject $report -Name 'Metadata'
    $repoTags = Get-OptionalPropertyValue -InputObject $metadata -Name 'RepoTags'
    if ($repoTags) {
        $firstTag = @($repoTags | Select-Object -First 1)[0]
        if (-not [string]::IsNullOrWhiteSpace([string]$firstTag)) {
            $imageReference = [string]$firstTag
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string](Get-OptionalPropertyValue -InputObject $report -Name 'ArtifactName'))) {
        $imageReference = [string](Get-OptionalPropertyValue -InputObject $report -Name 'ArtifactName')
    }

    $imageDigest = $null
    foreach ($digest in (Get-OptionalPropertyItems -InputObject $metadata -Name 'RepoDigests')) {
        $text = [string]$digest
        if ($text -match '@sha256:') {
            $imageDigest = Get-SafeImageReference $text
            break
        }
    }

    $reportSha = Get-Sha256Hex -Value $ReportJson
    $totalCount = [int]($counts.UNKNOWN + $counts.LOW + $counts.MEDIUM + $counts.HIGH + $counts.CRITICAL)
    $severity = if ($counts.CRITICAL -gt 0 -or $criticalSecretCount -gt 0) {
        'Critical'
    }
    elseif ($counts.HIGH -gt 0) {
        'High'
    }
    elseif ($counts.MEDIUM -gt 0) {
        'Warning'
    }
    else {
        'Info'
    }

    $safeImage = Get-SafeImageReference $imageReference
    return [pscustomobject]@{
        Scanner = 'trivy'
        ScannerVersion = Get-SafeImageReference $ScannerVersion
        ImageReference = $safeImage
        ImageDigest = $imageDigest
        ArtifactType = Get-SafeImageReference ([string](Get-OptionalPropertyValue -InputObject $report -Name 'ArtifactType'))
        UnknownCount = [int]$counts.UNKNOWN
        LowCount = [int]$counts.LOW
        MediumCount = [int]$counts.MEDIUM
        HighCount = [int]$counts.HIGH
        CriticalCount = [int]$counts.CRITICAL
        TotalCount = $totalCount
        FixAvailableCount = $fixAvailable
        AffectedTargetCount = $targets.Count
        SecretCount = $secretCount
        CriticalSecretCount = $criticalSecretCount
        MisconfigurationCount = $misconfigurationCount
        ReportSha256 = $reportSha
        Severity = $severity
        ExternalEventId = New-DeterministicGuid -Seed ('{0}|{1}|{2}|{3}|{4}' -f $sourceSystem, $eventType, $safeImage, $imageDigest, $reportSha)
    }
}

function New-IngestPayload {
    param([Parameter(Mandatory = $true)]$Summary)

    return [ordered]@{
        externalEventId = $Summary.ExternalEventId
        occurredAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        sourceSystem = $sourceSystem
        eventType = $eventType
        severity = $Summary.Severity
        userName = $null
        sourceHost = 'local-image-scan-cli'
        description = ('Trivy image scan completed for {0}: critical={1}, high={2}, total={3}.' -f $Summary.ImageReference, $Summary.CriticalCount, $Summary.HighCount, $Summary.TotalCount)
        additionalData = [ordered]@{
            schemaVersion = 1
            scanner = $Summary.Scanner
            scannerVersion = $Summary.ScannerVersion
            imageReference = $Summary.ImageReference
            imageDigest = $Summary.ImageDigest
            artifactType = $Summary.ArtifactType
            scanStatus = 'completed'
            unknownCount = $Summary.UnknownCount
            lowCount = $Summary.LowCount
            mediumCount = $Summary.MediumCount
            highCount = $Summary.HighCount
            criticalCount = $Summary.CriticalCount
            totalCount = $Summary.TotalCount
            fixAvailableCount = $Summary.FixAvailableCount
            affectedTargetCount = $Summary.AffectedTargetCount
            secretCount = $Summary.SecretCount
            misconfigurationCount = $Summary.MisconfigurationCount
            reportSha256 = $Summary.ReportSha256
            durationMs = 0
        }
    }
}

function Test-Web {
    param([Parameter(Mandatory = $true)][string]$BaseUrl)

    try {
        $response = Invoke-WebRequest -Uri ($BaseUrl.TrimEnd('/') + '/Operations/Health') -UseBasicParsing -MaximumRedirection 5 -SkipHttpErrorCheck -TimeoutSec 8
        return [int]$response.StatusCode -in @(200, 302, 401, 403)
    }
    catch {
        return $false
    }
}

function Submit-ImageScanEvent {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $true)]$Payload
    )

    $json = $Payload | ConvertTo-Json -Depth 20 -Compress
    try {
        $response = Invoke-RestMethod `
            -Uri ($BaseUrl.TrimEnd('/') + '/api/v1/security-events') `
            -Method Post `
            -Headers @{ 'X-ConShield-Api-Key' = $ApiKey } `
            -Body $json `
            -ContentType 'application/json' `
            -TimeoutSec 30
        return [pscustomobject]@{
            Ok = $true
            Created = [bool]$response.created
            SecurityEventId = [string]$response.securityEventId
            Error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Ok = $false
            Created = $false
            SecurityEventId = $null
            Error = 'external ingestion request failed'
        }
    }
}

function Write-SafeMarkdown {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)][string]$IngestionStatus
    )

    $resolved = Resolve-RepoPath -RepoRoot $RepoRoot -Path $Path
    $expectedRoot = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot 'artifacts\local'))
    if (-not $resolved.StartsWith($expectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutputMarkdownPath must be under artifacts/local.'
    }

    $directory = Split-Path -Parent $resolved
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }

    $lines = @(
        '# ConShield Image Scan Evidence',
        '',
        ('- Image: {0}' -f $Summary.ImageReference),
        ('- Scanner: {0}' -f $Summary.Scanner),
        ('- SourceSystem: {0}' -f $sourceSystem),
        ('- ExternalEventId: {0}' -f $Summary.ExternalEventId),
        ('- Severity: {0}' -f $Summary.Severity),
        ('- Critical vulnerabilities: {0}' -f $Summary.CriticalCount),
        ('- High vulnerabilities: {0}' -f $Summary.HighCount),
        ('- Medium vulnerabilities: {0}' -f $Summary.MediumCount),
        ('- Low vulnerabilities: {0}' -f $Summary.LowCount),
        ('- Secrets: {0}' -f $Summary.SecretCount),
        ('- Misconfigurations: {0}' -f $Summary.MisconfigurationCount),
        ('- Ingestion: {0}' -f $IngestionStatus),
        ('- Expected rule: {0}' -f $expectedRule),
        '',
        'Raw Trivy JSON, raw payload JSON, AdditionalDataJson, secrets, connection strings, API keys, env values, logs, screenshots, and generated local artifacts are intentionally excluded.'
    )
    Set-Content -LiteralPath $resolved -Value $lines -Encoding UTF8
}

function Write-Summary {
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)][string]$WebStatus,
        [Parameter(Mandatory = $true)][string]$TrivyStatus,
        [Parameter(Mandatory = $true)][string]$ScanStatus,
        [Parameter(Mandatory = $true)][string]$IngestionStatus,
        [Parameter(Mandatory = $true)][string]$Result
    )

    Write-Output 'ConShield image scan'
    Write-Output ('Image: {0}' -f $Summary.ImageReference)
    Write-Output 'Scanner: Trivy'
    Write-Output ('Web: {0}' -f $WebStatus)
    Write-Output ('Trivy: {0}' -f $TrivyStatus)
    Write-Output ('Scan: {0}' -f $ScanStatus)
    Write-Output ('Critical vulnerabilities: {0}' -f $Summary.CriticalCount)
    Write-Output ('High vulnerabilities: {0}' -f $Summary.HighCount)
    Write-Output ('Medium vulnerabilities: {0}' -f $Summary.MediumCount)
    Write-Output ('Low vulnerabilities: {0}' -f $Summary.LowCount)
    Write-Output ('Secrets: {0}' -f $Summary.SecretCount)
    Write-Output ('Misconfigurations: {0}' -f $Summary.MisconfigurationCount)
    Write-Output 'Policy outcome: Not evaluated'
    Write-Output ('SourceSystem: {0}' -f $sourceSystem)
    Write-Output ('ExternalEventId: {0}' -f $Summary.ExternalEventId)
    Write-Output ('Ingestion: {0}' -f $IngestionStatus)
    Write-Output ('Expected rule: {0}' -f $expectedRule)
    if ($IngestionStatus -eq 'OK') {
        Write-Output 'Run SIEM correlation from the local UI if IMG-001 is not already present.'
    }
    Write-Output ('Result: {0}' -f $Result)
}

$repoRoot = Resolve-RepositoryRoot
Push-Location $repoRoot
try {
    if ([string]::IsNullOrWhiteSpace($Image) -and [string]::IsNullOrWhiteSpace($FromTrivyJson)) {
        Write-Output 'ConShield image scan'
        Write-Output 'Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldImageScan.ps1 -Image alpine:3.18'
        Write-Output 'Offline validation: pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldImageScan.ps1 -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json -NoSubmit'
        Write-Output 'Result: FAIL'
        exit 1
    }

    if (-not [string]::IsNullOrWhiteSpace($Image) -and -not [string]::IsNullOrWhiteSpace($FromTrivyJson)) {
        throw 'Use either -Image or -FromTrivyJson, not both.'
    }

    $trivyStatus = 'OK'
    $requestedImage = $Image
    if (-not [string]::IsNullOrWhiteSpace($FromTrivyJson)) {
        $resolvedFixture = Resolve-RepoPath -RepoRoot $repoRoot -Path $FromTrivyJson
        $reportJson = Read-JsonFile -Path $resolvedFixture
        $scannerVersion = 'fixture'
        if ([string]::IsNullOrWhiteSpace($requestedImage)) {
            $requestedImage = Split-Path -Leaf $resolvedFixture
        }
        $trivyStatus = 'SKIP (fixture)'
    }
    else {
        $trivy = Invoke-TrivyImageScan -TrivyExecutable $TrivyPath -ImageReference $Image -Timeout $TimeoutSeconds
        $reportJson = $trivy.Json
        $scannerVersion = $trivy.ScannerVersion
    }

    $summary = Convert-TrivyJsonToSummary -ReportJson $reportJson -RequestedImage $requestedImage -ScannerVersion $scannerVersion
    $payload = New-IngestPayload -Summary $summary

    $webStatus = if ($NoSubmit) { 'SKIP' } else { if (Test-Web -BaseUrl $WebBaseUrl) { 'OK' } else { 'FAIL' } }
    $ingestionStatus = if ($NoSubmit) { 'SKIP' } else { 'FAIL' }
    $result = 'PASS'

    if (-not $NoSubmit) {
        if ($webStatus -ne 'OK') {
            Write-Summary -Summary $summary -WebStatus $webStatus -TrivyStatus $trivyStatus -ScanStatus 'OK' -IngestionStatus $ingestionStatus -Result 'FAIL'
            Write-Output 'Start local services first:'
            Write-Output 'pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit'
            exit 1
        }

        $localEnv = Get-LocalEnvMap -RepoRoot $repoRoot
        Set-TransientEnvironmentValue -Name 'CONSHIELD_EXTERNAL_EVENT_API_KEY' -Value $localEnv['CONSHIELD_EXTERNAL_EVENT_API_KEY']
        Set-TransientEnvironmentValue -Name 'CONSHIELD_API_KEY' -Value $localEnv['CONSHIELD_API_KEY']
        $apiKey = if (-not [string]::IsNullOrWhiteSpace($env:CONSHIELD_EXTERNAL_EVENT_API_KEY)) {
            $env:CONSHIELD_EXTERNAL_EVENT_API_KEY
        }
        else {
            $env:CONSHIELD_API_KEY
        }

        if ([string]::IsNullOrWhiteSpace($apiKey)) {
            Write-Summary -Summary $summary -WebStatus $webStatus -TrivyStatus $trivyStatus -ScanStatus 'OK' -IngestionStatus $ingestionStatus -Result 'FAIL'
            Write-Output 'Configure the local external ingestion key or rerun with -NoSubmit for offline validation.'
            exit 1
        }

        $submit = Submit-ImageScanEvent -BaseUrl $WebBaseUrl -ApiKey $apiKey -Payload $payload
        if (-not $submit.Ok) {
            Write-Summary -Summary $summary -WebStatus $webStatus -TrivyStatus $trivyStatus -ScanStatus 'OK' -IngestionStatus $ingestionStatus -Result 'FAIL'
            Write-Output 'External ingestion failed. Check Web status and local ingestion configuration; secret values were not printed.'
            exit 1
        }

        $ingestionStatus = 'OK'
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputMarkdownPath)) {
        Write-SafeMarkdown -RepoRoot $repoRoot -Path $OutputMarkdownPath -Summary $summary -IngestionStatus $ingestionStatus
    }

    Write-Summary -Summary $summary -WebStatus $webStatus -TrivyStatus $trivyStatus -ScanStatus 'OK' -IngestionStatus $ingestionStatus -Result $result
    exit 0
}
catch {
    Write-Output 'ConShield image scan'
    Write-Output ('Scan: FAIL ({0})' -f $_.Exception.Message)
    Write-Output 'For deterministic local validation use:'
    Write-Output 'pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldImageScan.ps1 -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json -NoSubmit'
    Write-Output 'Result: FAIL'
    exit 1
}
finally {
    foreach ($name in $transientEnvironment) {
        Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    }

    Pop-Location
}
