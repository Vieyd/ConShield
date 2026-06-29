[CmdletBinding()]
param(
    [string]$Image,
    [string]$ContainerName,
    [string]$Command,
    [string]$FromTrivyJson,
    [string]$WebBaseUrl = 'http://127.0.0.1:5080',
    [string]$PolicyPath = '.\config\container-policy.default.json',
    [string]$TrivyPath = 'trivy',
    [string]$DockerPath = 'docker',
    [switch]$NoSubmit,
    [switch]$NoRun,
    [switch]$Execute,
    [switch]$AcceptWarning,
    [switch]$RemoveExistingDemoContainer,
    [string]$OutputMarkdownPath,
    [ValidateRange(5, 120)]
    [int]$RunTimeoutSeconds = 30,
    [ValidateRange(15, 900)]
    [int]$ScanTimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$imageSourceSystem = 'conshield.image-scanner'
$imageEventType = 'container.image.scan.completed'
$policySourceSystem = 'conshield.container-guard'
$policyEventType = 'container.image.policy.evaluated'
$lifeSourceSystem = 'conshield.container-runtime'
$lifeEventType = 'container.image.launch.result'
$runtimeProfile = 'docker-hardened-v1'
$expectedRules = 'IMG-001,POL-001,LIFE-001'
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

function Get-SafeText {
    param(
        [AllowNull()][string]$Value,
        [int]$MaxLength = 512
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    $safe = ([string]$Value).Trim()
    $safe = -join ($safe.ToCharArray() | Where-Object { -not [char]::IsControl($_) })
    $safe = $safe -replace '(?i)(password|secret|token|api[_ -]?key|authorization|bearer|cookie|credential)\s*[:=]\s*[^;\s,]+', '$1=[redacted]'
    return $(if ($safe.Length -le $MaxLength) { $safe } else { $safe.Substring(0, $MaxLength) })
}

function Get-SafeImageReference {
    param([AllowNull()][string]$Value)

    $safe = Get-SafeText -Value $Value -MaxLength 512
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return 'unknown-image'
    }

    if ($safe -match '^[^/@:]+:[^/@]+@(.+)$') {
        $safe = '***:***@' + $Matches[1]
    }

    return $safe
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
        throw 'JSON report exceeded the maximum allowed size.'
    }

    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8
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
            throw 'Trivy scan failed. Verify Trivy is installed and its vulnerability database is available. For deterministic local validation use -FromTrivyJson with -NoRun -NoSubmit.'
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
    }
}

function Get-NormalizedIdentity {
    param([AllowNull()][string]$Value)

    $safe = Get-SafeImageReference $Value
    return $safe.ToLowerInvariant()
}

function Read-ContainerPolicy {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $selectedPath = $Path
    if ($Path -eq '.\config\container-policy.default.json' -or $Path -eq './config/container-policy.default.json') {
        $localPolicy = Join-Path $RepoRoot 'config\container-policy.local.json'
        if (Test-Path -LiteralPath $localPolicy -PathType Leaf) {
            $selectedPath = $localPolicy
        }
    }

    $resolved = Resolve-RepoPath -RepoRoot $RepoRoot -Path $selectedPath
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw 'Container policy file was not found.'
    }

    $item = Get-Item -LiteralPath $resolved
    if ($item.Length -le 0 -or $item.Length -gt 65536) {
        throw 'Container policy file size is invalid.'
    }

    $json = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8
    try {
        $policy = $json | ConvertFrom-Json -Depth 20
    }
    catch {
        throw 'Container policy JSON is invalid.'
    }

    $displayPath = [System.IO.Path]::GetRelativePath($RepoRoot, $resolved).Replace('\', '/')

    $schemaVersion = Get-OptionalPropertyValue -InputObject $policy -Name 'schemaVersion'
    if ($null -ne $schemaVersion) {
        if ([int]$schemaVersion -ne 1) {
            throw 'Only container policy schemaVersion 1 is supported.'
        }

        $policyId = Get-SafeText -Value ([string]$policy.policyId) -MaxLength 128
        $policyVersion = Get-SafeText -Value ([string]$policy.version) -MaxLength 128
        if ([string]::IsNullOrWhiteSpace($policyId) -or [string]::IsNullOrWhiteSpace($policyVersion)) {
            throw 'Container policy id/version is invalid.'
        }

        return [pscustomobject]@{
            PolicyId = $policyId
            Version = $policyVersion
            PolicySha256 = Get-Sha256Hex -Value $json
            ConfigSource = $displayPath
            DefaultDecision = 'Allow'
            Rules = @(
                [pscustomobject]@{ Id = 'LEGACY-IMAGE-DENIED-BLOCK'; Enabled = $true; Decision = 'Block'; Reason = 'Image is denied by policy.'; Match = [pscustomobject]@{ deniedImages = @($policy.deniedImages) } },
                [pscustomobject]@{ Id = 'LEGACY-CRITICAL-VULN-BLOCK'; Enabled = $true; Decision = 'Block'; Reason = 'Image contains critical vulnerabilities.'; Match = [pscustomobject]@{ criticalVulnerabilitiesAtLeast = $policy.thresholds.criticalBlock } },
                [pscustomobject]@{ Id = 'LEGACY-HIGH-VULN-BLOCK'; Enabled = $true; Decision = 'Block'; Reason = 'Image contains too many high vulnerabilities.'; Match = [pscustomobject]@{ highVulnerabilitiesAtLeast = $policy.thresholds.highBlock } },
                [pscustomobject]@{ Id = 'LEGACY-TOTAL-FINDINGS-BLOCK'; Enabled = $true; Decision = 'Block'; Reason = 'Image contains too many findings.'; Match = [pscustomobject]@{ totalFindingsAtLeast = $policy.thresholds.totalBlock } },
                [pscustomobject]@{ Id = 'LEGACY-HIGH-VULN-WARN'; Enabled = $true; Decision = 'Warn'; Reason = 'Image contains high vulnerabilities.'; Match = [pscustomobject]@{ highVulnerabilitiesAtLeast = $policy.thresholds.highWarn } },
                [pscustomobject]@{ Id = 'LEGACY-MEDIUM-VULN-WARN'; Enabled = $true; Decision = 'Warn'; Reason = 'Image contains medium vulnerabilities.'; Match = [pscustomobject]@{ mediumVulnerabilitiesAtLeast = $policy.thresholds.mediumWarn } },
                [pscustomobject]@{ Id = 'LEGACY-UNKNOWN-VULN-WARN'; Enabled = $true; Decision = 'Warn'; Reason = 'Image contains unknown-severity vulnerabilities.'; Match = [pscustomobject]@{ unknownVulnerabilitiesAtLeast = $policy.thresholds.unknownWarn } }
            )
        }
    }

    if ([int](Get-OptionalPropertyValue -InputObject $policy -Name 'version') -ne 1) {
        throw 'Only container policy-as-code version 1 is supported.'
    }

    $policyId = Get-SafeText -Value ([string]$policy.policyId) -MaxLength 128
    $policyVersion = Get-SafeText -Value ([string]$policy.policyVersion) -MaxLength 128
    if ([string]::IsNullOrWhiteSpace($policyId) -or [string]::IsNullOrWhiteSpace($policyVersion)) {
        throw 'Container policy id/version is invalid.'
    }

    $defaultDecision = Get-SafeText -Value ([string]$policy.defaultDecision) -MaxLength 16
    if ($defaultDecision -notin @('Allow', 'Warn', 'Block')) {
        throw 'Container policy defaultDecision is invalid.'
    }

    $rules = @($policy.rules)
    if ($rules.Count -eq 0) {
        throw 'Container policy must contain at least one rule.'
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($rule in $rules) {
        $ruleId = Get-SafeText -Value ([string]$rule.id) -MaxLength 128
        if ([string]::IsNullOrWhiteSpace($ruleId) -or -not $seen.Add($ruleId)) {
            throw 'Container policy rule ids are required and unique.'
        }

        $decision = Get-SafeText -Value ([string]$rule.decision) -MaxLength 16
        if ($decision -notin @('Allow', 'Warn', 'Block')) {
            throw 'Container policy rule decision is invalid.'
        }

        if (($decision -in @('Warn', 'Block')) -and [string]::IsNullOrWhiteSpace([string]$rule.reason)) {
            throw 'Container policy Warn/Block rules require a reason.'
        }

        if ($null -eq $rule.match) {
            throw 'Container policy rule match is required.'
        }
    }

    return [pscustomobject]@{
        PolicyId = $policyId
        Version = $policyVersion
        PolicySha256 = Get-Sha256Hex -Value $json
        ConfigSource = $displayPath
        DefaultDecision = $defaultDecision
        Rules = $rules
    }
}

function Test-PolicyThreshold {
    param(
        [int]$Actual,
        [AllowNull()]$Threshold
    )

    return ($null -ne $Threshold -and [int]$Threshold -ge 0 -and $Actual -ge [int]$Threshold)
}

function Test-PolicyRuleMatch {
    param(
        [Parameter(Mandatory = $true)]$Rule,
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)][string]$TriggerIdentity,
        [Parameter(Mandatory = $true)][string]$ImageReference
    )

    $match = $Rule.Match
    $matchedAny = $false
    foreach ($image in @(Get-OptionalPropertyValue -InputObject $match -Name 'deniedImages')) {
        $normalized = Get-NormalizedIdentity ([string]$image)
        if ($normalized -eq $TriggerIdentity -or $normalized -eq $ImageReference) {
            return $true
        }
    }

    foreach ($pair in @(
        @{ Name = 'criticalVulnerabilitiesAtLeast'; Actual = $Summary.CriticalCount },
        @{ Name = 'highVulnerabilitiesAtLeast'; Actual = $Summary.HighCount },
        @{ Name = 'mediumVulnerabilitiesAtLeast'; Actual = $Summary.MediumCount },
        @{ Name = 'lowVulnerabilitiesAtLeast'; Actual = $Summary.LowCount },
        @{ Name = 'unknownVulnerabilitiesAtLeast'; Actual = $Summary.UnknownCount },
        @{ Name = 'totalFindingsAtLeast'; Actual = $Summary.TotalCount },
        @{ Name = 'secretsAtLeast'; Actual = $Summary.SecretCount },
        @{ Name = 'misconfigurationsAtLeast'; Actual = $Summary.MisconfigurationCount }
    )) {
        $threshold = Get-OptionalPropertyValue -InputObject $match -Name $pair.Name
        if ($null -ne $threshold) {
            $matchedAny = $true
            if (-not (Test-PolicyThreshold -Actual ([int]$pair.Actual) -Threshold $threshold)) {
                return $false
            }
        }
    }

    return $matchedAny
}

function Invoke-PolicyEvaluation {
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [Parameter(Mandatory = $true)]$Summary
    )

    $imageReference = Get-NormalizedIdentity $Summary.ImageReference
    $imageDigest = if ([string]::IsNullOrWhiteSpace($Summary.ImageDigest)) { $null } else { Get-NormalizedIdentity $Summary.ImageDigest }
    $triggerIdentity = if ($imageDigest) { $imageDigest } else { $imageReference }
    $matches = @($Policy.Rules | Where-Object {
        ($null -eq $_.enabled -or $_.enabled -eq $true) -and
        (Test-PolicyRuleMatch -Rule $_ -Summary $Summary -TriggerIdentity $triggerIdentity -ImageReference $imageReference)
    })

    $selectedDecision = if (($matches | Where-Object { $_.decision -eq 'Block' } | Select-Object -First 1)) {
        'Block'
    }
    elseif (($matches | Where-Object { $_.decision -eq 'Warn' } | Select-Object -First 1)) {
        'Warn'
    }
    elseif (($matches | Where-Object { $_.decision -eq 'Allow' } | Select-Object -First 1)) {
        'Allow'
    }
    else {
        $Policy.DefaultDecision
    }

    $selectedRules = @($matches | Where-Object { $_.decision -eq $selectedDecision })
    $matchedIds = @($selectedRules | ForEach-Object { Get-SafeText -Value ([string]$_.id) -MaxLength 128 })
    $reasonCodes = if ($matchedIds.Count -gt 0) { $matchedIds } else { @('WITHIN_POLICY') }
    $reasonSummary = if ($selectedRules.Count -gt 0) {
        (($selectedRules | ForEach-Object { Get-SafeText -Value ([string]$_.reason) -MaxLength 160 }) -join '; ')
    }
    else {
        'No policy rule matched.'
    }

    return [pscustomobject]@{
        Decision = $selectedDecision
        ReasonCodes = @($reasonCodes)
        MatchedRuleIds = @($matchedIds)
        ReasonSummary = $reasonSummary
        PolicyConfigSource = $Policy.ConfigSource
        PolicyConfigSha256 = $Policy.PolicySha256
        PolicyConfigVersion = $Policy.Version
        TriggerIdentity = $triggerIdentity
    }
}

function Test-ContainerName {
    param([AllowNull()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    return $Name -match '^conshield-demo-[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$'
}

function Convert-CommandToDockerArgs {
    param([AllowNull()][string]$CommandText)

    if ([string]::IsNullOrWhiteSpace($CommandText)) {
        return @()
    }

    $safe = Get-SafeText -Value $CommandText -MaxLength 256
    if ($safe -match '[;&|<>`$\\]') {
        throw 'Command contains unsupported characters for the safe v1 runner.'
    }

    return @($safe -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
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

function New-IngestPayload {
    param(
        [Parameter(Mandatory = $true)][string]$ExternalEventId,
        [Parameter(Mandatory = $true)][string]$SourceSystem,
        [Parameter(Mandatory = $true)][string]$EventType,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)]$AdditionalData
    )

    return [ordered]@{
        externalEventId = $ExternalEventId
        occurredAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        sourceSystem = $SourceSystem
        eventType = $EventType
        severity = $Severity
        userName = $null
        sourceHost = 'local-protected-runner'
        description = $Description
        additionalData = $AdditionalData
    }
}

function New-ImageEventPayload {
    param(
        [Parameter(Mandatory = $true)][string]$ExternalEventId,
        [Parameter(Mandatory = $true)]$Summary
    )

    New-IngestPayload `
        -ExternalEventId $ExternalEventId `
        -SourceSystem $imageSourceSystem `
        -EventType $imageEventType `
        -Severity $Summary.Severity `
        -Description ('Trivy image scan completed for {0}: critical={1}, high={2}, total={3}.' -f $Summary.ImageReference, $Summary.CriticalCount, $Summary.HighCount, $Summary.TotalCount) `
        -AdditionalData ([ordered]@{
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
        })
}

function New-PolicyEventPayload {
    param(
        [Parameter(Mandatory = $true)][string]$ExternalEventId,
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)]$Policy,
        [Parameter(Mandatory = $true)]$Evaluation
    )

    $severity = switch ($Evaluation.Decision) {
        'Block' { 'High'; break }
        'Warn' { 'Warning'; break }
        default { 'Info' }
    }

    New-IngestPayload `
        -ExternalEventId $ExternalEventId `
        -SourceSystem $policySourceSystem `
        -EventType $policyEventType `
        -Severity $severity `
        -Description ('Container policy {0}/{1} evaluated {2} for {3}.' -f $Policy.PolicyId, $Policy.Version, $Evaluation.Decision, $Summary.ImageReference) `
        -AdditionalData ([ordered]@{
            schemaVersion = 1
            decision = $Evaluation.Decision
            policyId = $Policy.PolicyId
            policyVersion = $Policy.Version
            policySha256 = $Policy.PolicySha256
            policyConfigSource = $Policy.ConfigSource
            policyConfigVersion = $Policy.Version
            policyConfigSha256 = $Policy.PolicySha256
            matchedPolicyRuleIds = @($Evaluation.MatchedRuleIds)
            reasonSummary = $Evaluation.ReasonSummary
            imageReference = $Summary.ImageReference
            imageDigest = $Summary.ImageDigest
            reportSha256 = $Summary.ReportSha256
            unknownCount = $Summary.UnknownCount
            lowCount = $Summary.LowCount
            mediumCount = $Summary.MediumCount
            highCount = $Summary.HighCount
            criticalCount = $Summary.CriticalCount
            totalCount = $Summary.TotalCount
            reasonCodes = @($Evaluation.ReasonCodes)
            executionRequested = [bool]$Execute
            warningAccepted = [bool]$AcceptWarning
            containerName = $ContainerName
        })
}

function New-LifeEventPayload {
    param(
        [Parameter(Mandatory = $true)][string]$ExternalEventId,
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)]$Evaluation,
        [Parameter(Mandatory = $true)]$Launch
    )

    $severity = switch ($Launch.Outcome) {
        'Succeeded' { 'Info'; break }
        'SkippedNoExecute' { 'Info'; break }
        'SkippedNoRun' { 'Info'; break }
        'WarnRequiresAcceptance' { 'Warning'; break }
        default { 'High' }
    }

    New-IngestPayload `
        -ExternalEventId $ExternalEventId `
        -SourceSystem $lifeSourceSystem `
        -EventType $lifeEventType `
        -Severity $severity `
        -Description ('Protected run launch outcome {0} for image {1}, container {2}, policy {3}.' -f $Launch.Outcome, $Summary.ImageReference, $ContainerName, $Evaluation.Decision) `
        -AdditionalData ([ordered]@{
            schemaVersion = 1
            runtime = 'docker'
            runtimeProfile = $runtimeProfile
            outcome = $Launch.Outcome
            dockerRunInvoked = [bool]$Launch.DockerRunInvoked
            processExitCode = $Launch.ProcessExitCode
            durationMs = $Launch.DurationMs
            runtimeVersion = $Launch.RuntimeVersion
            launchReference = $Summary.ImageReference
            imageReference = $Summary.ImageReference
            imageDigest = $Summary.ImageDigest
            reportSha256 = $Summary.ReportSha256
            containerName = $ContainerName
            policyOutcome = $Evaluation.Decision
            reasonSummary = $Launch.Reason
            commandHash = $Launch.CommandHash
            safeErrorCategory = $Launch.SafeErrorCategory
        })
}

function Submit-ExternalEvent {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $true)]$Payload
    )

    $json = $Payload | ConvertTo-Json -Depth 24 -Compress
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
        }
    }
    catch {
        return [pscustomobject]@{
            Ok = $false
            Created = $false
            SecurityEventId = $null
        }
    }
}

function Invoke-CapturedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 30
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    $process = $null
    $startedAt = Get-Date
    try {
        $process = Start-Process `
            -FilePath $FilePath `
            -ArgumentList $Arguments `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -NoNewWindow `
            -PassThru
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
            return [pscustomobject]@{
                Started = $true
                TimedOut = $true
                ExitCode = $null
                DurationMs = [long]((Get-Date) - $startedAt).TotalMilliseconds
            }
        }

        return [pscustomobject]@{
            Started = $true
            TimedOut = $false
            ExitCode = [int]$process.ExitCode
            DurationMs = [long]((Get-Date) - $startedAt).TotalMilliseconds
        }
    }
    catch {
        return [pscustomobject]@{
            Started = $false
            TimedOut = $false
            ExitCode = $null
            DurationMs = [long]((Get-Date) - $startedAt).TotalMilliseconds
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Invoke-ProtectedDockerRun {
    param(
        [Parameter(Mandatory = $true)][string]$DockerExecutable,
        [Parameter(Mandatory = $true)][string]$ImageReference,
        [Parameter(Mandatory = $true)][string]$SafeContainerName,
        [string[]]$CommandArguments,
        [int]$TimeoutSeconds,
        [switch]$RemoveExisting
    )

    $resolved = Get-Command $DockerExecutable -ErrorAction SilentlyContinue
    if ($null -eq $resolved) {
        return [pscustomobject]@{
            Outcome = 'Unavailable'
            Reason = 'Docker executable was not found.'
            DockerRunInvoked = $false
            ProcessExitCode = $null
            DurationMs = 0
            RuntimeVersion = $null
            SafeErrorCategory = 'runtime_unavailable'
        }
    }

    $version = Invoke-CapturedProcess -FilePath $resolved.Source -Arguments @('version', '--format', '{{.Server.Version}}') -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 15))
    if ($version.TimedOut -or -not $version.Started -or $version.ExitCode -ne 0) {
        return [pscustomobject]@{
            Outcome = 'Unavailable'
            Reason = 'Docker daemon unavailable.'
            DockerRunInvoked = $false
            ProcessExitCode = $version.ExitCode
            DurationMs = $version.DurationMs
            RuntimeVersion = $null
            SafeErrorCategory = 'runtime_unavailable'
        }
    }

    $exists = Invoke-CapturedProcess -FilePath $resolved.Source -Arguments @('container', 'inspect', $SafeContainerName) -TimeoutSeconds 10
    if ($exists.Started -and $exists.ExitCode -eq 0) {
        if (-not $RemoveExisting) {
            return [pscustomobject]@{
                Outcome = 'Unavailable'
                Reason = 'Container already exists; pass -RemoveExistingDemoContainer to remove only this exact demo container.'
                DockerRunInvoked = $false
                ProcessExitCode = $null
                DurationMs = 0
                RuntimeVersion = 'docker'
                SafeErrorCategory = 'container_exists'
            }
        }

        $remove = Invoke-CapturedProcess -FilePath $resolved.Source -Arguments @('rm', '-f', $SafeContainerName) -TimeoutSeconds 15
        if (-not $remove.Started -or $remove.ExitCode -ne 0) {
            return [pscustomobject]@{
                Outcome = 'Unavailable'
                Reason = 'Existing demo container could not be removed safely.'
                DockerRunInvoked = $false
                ProcessExitCode = $remove.ExitCode
                DurationMs = $remove.DurationMs
                RuntimeVersion = 'docker'
                SafeErrorCategory = 'container_remove_failed'
            }
        }
    }

    $args = @(
        'run',
        '--rm',
        '--name',
        $SafeContainerName,
        '--pull=never',
        '--network=none',
        '--read-only',
        '--cap-drop=ALL',
        '--security-opt=no-new-privileges',
        '--pids-limit=128',
        '--memory=256m',
        '--cpus=0.5',
        '--tmpfs=/tmp:rw,noexec,nosuid,size=64m',
        $ImageReference
    ) + @($CommandArguments)

    $run = Invoke-CapturedProcess -FilePath $resolved.Source -Arguments $args -TimeoutSeconds $TimeoutSeconds
    if ($run.TimedOut) {
        return [pscustomobject]@{
            Outcome = 'Failed'
            Reason = 'Docker run timed out.'
            DockerRunInvoked = $true
            ProcessExitCode = $null
            DurationMs = $run.DurationMs
            RuntimeVersion = 'docker'
            SafeErrorCategory = 'timeout'
        }
    }

    if (-not $run.Started -or $run.ExitCode -ne 0) {
        return [pscustomobject]@{
            Outcome = 'Failed'
            Reason = 'Docker run failed.'
            DockerRunInvoked = $true
            ProcessExitCode = $run.ExitCode
            DurationMs = $run.DurationMs
            RuntimeVersion = 'docker'
            SafeErrorCategory = 'non_zero_exit'
        }
    }

    return [pscustomobject]@{
        Outcome = 'Succeeded'
        Reason = 'Docker run completed.'
        DockerRunInvoked = $true
        ProcessExitCode = $run.ExitCode
        DurationMs = $run.DurationMs
        RuntimeVersion = 'docker'
        SafeErrorCategory = $null
    }
}

function Get-PlannedLaunch {
    param(
        [Parameter(Mandatory = $true)][string]$Decision,
        [Parameter(Mandatory = $true)][string]$CommandHash
    )

    if ($Decision -eq 'Block') {
        return [pscustomobject]@{
            Outcome = 'BlockedByPolicy'
            Reason = 'blocked by policy'
            DockerRunInvoked = $false
            ProcessExitCode = $null
            DurationMs = 0
            RuntimeVersion = $null
            SafeErrorCategory = 'blocked_by_policy'
            CommandHash = $CommandHash
        }
    }

    if ($NoRun) {
        return [pscustomobject]@{
            Outcome = 'SkippedNoRun'
            Reason = 'NoRun requested'
            DockerRunInvoked = $false
            ProcessExitCode = $null
            DurationMs = 0
            RuntimeVersion = $null
            SafeErrorCategory = $null
            CommandHash = $CommandHash
        }
    }

    if ($Decision -eq 'Warn' -and (-not $AcceptWarning -or -not $Execute)) {
        return [pscustomobject]@{
            Outcome = 'WarnRequiresAcceptance'
            Reason = 'requires -AcceptWarning and -Execute'
            DockerRunInvoked = $false
            ProcessExitCode = $null
            DurationMs = 0
            RuntimeVersion = $null
            SafeErrorCategory = 'warning_not_accepted'
            CommandHash = $CommandHash
        }
    }

    if (-not $Execute) {
        return [pscustomobject]@{
            Outcome = 'SkippedNoExecute'
            Reason = 'requires -Execute'
            DockerRunInvoked = $false
            ProcessExitCode = $null
            DurationMs = 0
            RuntimeVersion = $null
            SafeErrorCategory = $null
            CommandHash = $CommandHash
        }
    }

    return $null
}

function Write-SafeMarkdown {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)]$Evaluation,
        [Parameter(Mandatory = $true)]$Launch,
        [Parameter(Mandatory = $true)][string]$ImgStatus,
        [Parameter(Mandatory = $true)][string]$PolStatus,
        [Parameter(Mandatory = $true)][string]$LifeStatus
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
        '# ConShield Protected Run Evidence',
        '',
        ('- Image: {0}' -f $Summary.ImageReference),
        ('- ContainerName: {0}' -f $ContainerName),
        ('- PolicyOutcome: {0}' -f $Evaluation.Decision),
        ('- PolicyConfig: {0}' -f $Evaluation.PolicyConfigSource),
        ('- MatchedPolicyRules: {0}' -f (($Evaluation.MatchedRuleIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ', ')),
        ('- LaunchOutcome: {0}' -f $Launch.Outcome),
        ('- IMG event: {0}' -f $ImgStatus),
        ('- POL event: {0}' -f $PolStatus),
        ('- LIFE event: {0}' -f $LifeStatus),
        ('- Expected rules: {0}' -f $expectedRules),
        '',
        'Raw Trivy JSON, raw payload JSON, raw AdditionalDataJson, Docker logs, secrets, connection strings, API keys, env values, screenshots, and generated local artifacts are intentionally excluded.'
    )
    Set-Content -LiteralPath $resolved -Value $lines -Encoding UTF8
}

function Write-ProtectedRunSummary {
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)]$Evaluation,
        [Parameter(Mandatory = $true)]$Launch,
        [Parameter(Mandatory = $true)][string]$ScanStatus,
        [Parameter(Mandatory = $true)][string]$ImgStatus,
        [Parameter(Mandatory = $true)][string]$PolStatus,
        [Parameter(Mandatory = $true)][string]$LifeStatus,
        [Parameter(Mandatory = $true)][string]$Result
    )

    $launchText = switch ($Launch.Outcome) {
        'BlockedByPolicy' { 'Skipped (blocked by policy)'; break }
        'WarnRequiresAcceptance' { 'Skipped (requires -AcceptWarning and -Execute)'; break }
        'SkippedNoExecute' { 'Skipped (requires -Execute)'; break }
        'SkippedNoRun' { 'Skipped (NoRun requested)'; break }
        default { $Launch.Outcome }
    }

    Write-Output 'ConShield protected container run'
    Write-Output ('Image: {0}' -f $Summary.ImageReference)
    Write-Output ('Container: {0}' -f $ContainerName)
    Write-Output ('Scan: {0}' -f $ScanStatus)
    Write-Output ('Policy: {0}' -f $Evaluation.Decision)
    Write-Output ('Matched policy rules: {0}' -f $(if (@($Evaluation.MatchedRuleIds).Count -gt 0) { @($Evaluation.MatchedRuleIds) -join ',' } else { '-' }))
    Write-Output ('Policy config: {0}' -f $Evaluation.PolicyConfigSource)
    Write-Output ('Launch: {0}' -f $launchText)
    Write-Output ('IMG event: {0}' -f $ImgStatus)
    Write-Output ('POL event: {0}' -f $PolStatus)
    Write-Output ('LIFE event: {0}' -f $LifeStatus)
    Write-Output ('ExternalEventId: {0}' -f $script:externalEventId)
    Write-Output ('Expected rules: {0}' -f $expectedRules)
    Write-Output ('Result: {0}' -f $Result)
}

$repoRoot = Resolve-RepositoryRoot
Push-Location $repoRoot
try {
    if ([string]::IsNullOrWhiteSpace($Image) -or [string]::IsNullOrWhiteSpace($ContainerName)) {
        Write-Output 'ConShield protected container run'
        Write-Output 'Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldProtectedRun.ps1 -Image demo/insecure-api:latest -ContainerName conshield-demo-insecure -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json -NoRun -NoSubmit'
        Write-Output 'Result: FAIL'
        exit 1
    }

    if (-not (Test-ContainerName -Name $ContainerName)) {
        throw 'ContainerName must start with conshield-demo- and contain only letters, digits, dot, underscore, or dash.'
    }

    if (-not [string]::IsNullOrWhiteSpace($FromTrivyJson)) {
        $resolvedFixture = Resolve-RepoPath -RepoRoot $repoRoot -Path $FromTrivyJson
        $reportJson = Read-JsonFile -Path $resolvedFixture
        $scannerVersion = 'fixture'
    }
    else {
        $trivy = Invoke-TrivyImageScan -TrivyExecutable $TrivyPath -ImageReference $Image -Timeout $ScanTimeoutSeconds
        $reportJson = $trivy.Json
        $scannerVersion = $trivy.ScannerVersion
    }

    $summary = Convert-TrivyJsonToSummary -ReportJson $reportJson -RequestedImage $Image -ScannerVersion $scannerVersion
    $policy = Read-ContainerPolicy -RepoRoot $repoRoot -Path $PolicyPath
    $evaluation = Invoke-PolicyEvaluation -Policy $policy -Summary $summary
    $commandArgs = Convert-CommandToDockerArgs -CommandText $Command
    $commandHash = Get-Sha256Hex -Value (($commandArgs -join "`n") + '|' + $ContainerName)

    $plannedLaunch = Get-PlannedLaunch -Decision $evaluation.Decision -CommandHash $commandHash
    if ($null -ne $plannedLaunch) {
        $launch = $plannedLaunch
    }
    else {
        $dockerLaunch = Invoke-ProtectedDockerRun `
            -DockerExecutable $DockerPath `
            -ImageReference $Image `
            -SafeContainerName $ContainerName `
            -CommandArguments $commandArgs `
            -TimeoutSeconds $RunTimeoutSeconds `
            -RemoveExisting:$RemoveExistingDemoContainer
        $launch = [pscustomobject]@{
            Outcome = $dockerLaunch.Outcome
            Reason = $dockerLaunch.Reason
            DockerRunInvoked = $dockerLaunch.DockerRunInvoked
            ProcessExitCode = $dockerLaunch.ProcessExitCode
            DurationMs = $dockerLaunch.DurationMs
            RuntimeVersion = $dockerLaunch.RuntimeVersion
            SafeErrorCategory = $dockerLaunch.SafeErrorCategory
            CommandHash = $commandHash
        }
    }

    $script:externalEventId = New-DeterministicGuid -Seed ('{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $summary.ImageReference, $ContainerName, $policy.PolicyId, $evaluation.Decision, $summary.ReportSha256, $launch.Outcome, $commandHash)
    $imagePayload = New-ImageEventPayload -ExternalEventId $script:externalEventId -Summary $summary
    $policyPayload = New-PolicyEventPayload -ExternalEventId $script:externalEventId -Summary $summary -Policy $policy -Evaluation $evaluation
    $lifePayload = New-LifeEventPayload -ExternalEventId $script:externalEventId -Summary $summary -Evaluation $evaluation -Launch $launch

    $imgStatus = if ($NoSubmit) { 'SKIP' } else { 'FAIL' }
    $polStatus = if ($NoSubmit) { 'SKIP' } else { 'FAIL' }
    $lifeStatus = if ($NoSubmit) { 'SKIP' } else { 'FAIL' }

    if (-not $NoSubmit) {
        if (-not (Test-Web -BaseUrl $WebBaseUrl)) {
            Write-ProtectedRunSummary -Summary $summary -Evaluation $evaluation -Launch $launch -ScanStatus 'OK' -ImgStatus $imgStatus -PolStatus $polStatus -LifeStatus $lifeStatus -Result 'FAIL'
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
            Write-ProtectedRunSummary -Summary $summary -Evaluation $evaluation -Launch $launch -ScanStatus 'OK' -ImgStatus $imgStatus -PolStatus $polStatus -LifeStatus $lifeStatus -Result 'FAIL'
            Write-Output 'Configure the local external ingestion key or rerun with -NoSubmit for offline validation.'
            exit 1
        }

        $imageSubmit = Submit-ExternalEvent -BaseUrl $WebBaseUrl -ApiKey $apiKey -Payload $imagePayload
        if ($imageSubmit.Ok) { $imgStatus = 'OK' }
        $policySubmit = Submit-ExternalEvent -BaseUrl $WebBaseUrl -ApiKey $apiKey -Payload $policyPayload
        if ($policySubmit.Ok) { $polStatus = 'OK' }
        $lifeSubmit = Submit-ExternalEvent -BaseUrl $WebBaseUrl -ApiKey $apiKey -Payload $lifePayload
        if ($lifeSubmit.Ok) { $lifeStatus = 'OK' }

        if ($imgStatus -ne 'OK' -or $polStatus -ne 'OK' -or $lifeStatus -ne 'OK') {
            Write-ProtectedRunSummary -Summary $summary -Evaluation $evaluation -Launch $launch -ScanStatus 'OK' -ImgStatus $imgStatus -PolStatus $polStatus -LifeStatus $lifeStatus -Result 'FAIL'
            Write-Output 'External ingestion failed. Check Web status and local ingestion configuration; secret values were not printed.'
            exit 1
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputMarkdownPath)) {
        Write-SafeMarkdown -RepoRoot $repoRoot -Path $OutputMarkdownPath -Summary $summary -Evaluation $evaluation -Launch $launch -ImgStatus $imgStatus -PolStatus $polStatus -LifeStatus $lifeStatus
    }

    $result = if ($launch.Outcome -eq 'Failed' -or $launch.Outcome -eq 'Unavailable') { 'FAIL' } else { 'PASS' }
    Write-ProtectedRunSummary -Summary $summary -Evaluation $evaluation -Launch $launch -ScanStatus 'OK' -ImgStatus $imgStatus -PolStatus $polStatus -LifeStatus $lifeStatus -Result $result
    if ($result -eq 'FAIL') { exit 1 }
    exit 0
}
catch {
    Write-Output 'ConShield protected container run'
    Write-Output ('Run: FAIL ({0})' -f $_.Exception.Message)
    Write-Output 'For deterministic local validation use:'
    Write-Output 'pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldProtectedRun.ps1 -Image demo/insecure-api:latest -ContainerName conshield-demo-insecure -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json -NoRun -NoSubmit'
    Write-Output 'Result: FAIL'
    exit 1
}
finally {
    foreach ($name in $transientEnvironment) {
        Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    }

    Pop-Location
}
