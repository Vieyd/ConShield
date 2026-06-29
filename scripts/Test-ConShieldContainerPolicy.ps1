param(
    [string]$ConfigPath = '.\config\container-policy.default.json'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

function Get-PropertyNames {
    param([Parameter(Mandatory = $true)]$InputObject)

    @($InputObject.PSObject.Properties | ForEach-Object { $_.Name })
}

function Add-Error {
    param(
        [System.Collections.Generic.List[string]]$Errors,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $Errors.Add($Message) | Out-Null
}

function Test-AllowedProperties {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Allowed,
        [Parameter(Mandatory = $true)][string]$Label,
        [System.Collections.Generic.List[string]]$Errors
    )

    foreach ($name in Get-PropertyNames -InputObject $InputObject) {
        if ($Allowed -notcontains $name) {
            Add-Error -Errors $Errors -Message ('{0}: unknown field {1}' -f $Label, $name)
        }
    }
}

function Test-Decision {
    param(
        [AllowNull()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [System.Collections.Generic.List[string]]$Errors
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or @('Allow', 'Warn', 'Block') -notcontains $Value) {
        Add-Error -Errors $Errors -Message ('{0}: decision must be Allow, Warn, or Block' -f $Label)
    }
}

function Test-Threshold {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [System.Collections.Generic.List[string]]$Errors,
        [ref]$HasCondition
    )

    if ($null -eq $Value) {
        return
    }

    $HasCondition.Value = $true
    $number = 0
    if (-not [int]::TryParse([string]$Value, [ref]$number) -or $number -lt 0) {
        Add-Error -Errors $Errors -Message ('{0}: threshold must be non-negative' -f $Label)
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

$repoRoot = Resolve-RepositoryRoot
$resolvedConfigPath = Resolve-RepoPath -RepoRoot $repoRoot -Path $ConfigPath
$displayPath = [System.IO.Path]::GetRelativePath($repoRoot, $resolvedConfigPath).Replace('\', '/')
$errors = [System.Collections.Generic.List[string]]::new()

Write-Host 'ConShield container policy validation'
Write-Host ('Config: {0}' -f $displayPath)

try {
    if (-not (Test-Path -LiteralPath $resolvedConfigPath -PathType Leaf)) {
        throw 'Config file was not found.'
    }

    $config = Get-Content -LiteralPath $resolvedConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 20
    Test-AllowedProperties -InputObject $config -Allowed @('version', 'policyId', 'policyVersion', 'defaultDecision', 'rules') -Label 'root' -Errors $errors

    if ([int]$config.version -ne 1) {
        Add-Error -Errors $errors -Message 'root: version must be 1'
    }

    if ([string]::IsNullOrWhiteSpace([string]$config.policyId)) {
        Add-Error -Errors $errors -Message 'root: policyId is required'
    }

    if ([string]::IsNullOrWhiteSpace([string]$config.policyVersion)) {
        Add-Error -Errors $errors -Message 'root: policyVersion is required'
    }

    Test-Decision -Value ([string]$config.defaultDecision) -Label 'root.defaultDecision' -Errors $errors

    $rules = @($config.rules)
    if ($rules.Count -eq 0) {
        Add-Error -Errors $errors -Message 'root: at least one rule is required'
    }

    $ids = @()
    foreach ($rule in $rules) {
        $label = if ([string]::IsNullOrWhiteSpace([string]$rule.id)) { 'index {0}' -f $ids.Count } else { [string]$rule.id }
        $ids += [string]$rule.id
        Test-AllowedProperties -InputObject $rule -Allowed @('id', 'enabled', 'name', 'match', 'decision', 'reason') -Label $label -Errors $errors

        if ([string]::IsNullOrWhiteSpace([string]$rule.id)) {
            Add-Error -Errors $errors -Message ('{0}: id is required' -f $label)
        }

        if ([string]::IsNullOrWhiteSpace([string]$rule.name)) {
            Add-Error -Errors $errors -Message ('{0}: name is required' -f $label)
        }

        Test-Decision -Value ([string]$rule.decision) -Label ('{0}.decision' -f $label) -Errors $errors
        if ([string]$rule.decision -in @('Warn', 'Block') -and [string]::IsNullOrWhiteSpace([string]$rule.reason)) {
            Add-Error -Errors $errors -Message ('{0}: reason is required for Warn/Block' -f $label)
        }

        if ($null -eq $rule.match) {
            Add-Error -Errors $errors -Message ('{0}: match is required' -f $label)
            continue
        }

        Test-AllowedProperties -InputObject $rule.match -Allowed @('criticalVulnerabilitiesAtLeast', 'highVulnerabilitiesAtLeast', 'mediumVulnerabilitiesAtLeast', 'lowVulnerabilitiesAtLeast', 'unknownVulnerabilitiesAtLeast', 'totalFindingsAtLeast', 'secretsAtLeast', 'misconfigurationsAtLeast', 'deniedImages') -Label ('{0}.match' -f $label) -Errors $errors
        $hasCondition = $false
        foreach ($name in @('criticalVulnerabilitiesAtLeast', 'highVulnerabilitiesAtLeast', 'mediumVulnerabilitiesAtLeast', 'lowVulnerabilitiesAtLeast', 'unknownVulnerabilitiesAtLeast', 'totalFindingsAtLeast', 'secretsAtLeast', 'misconfigurationsAtLeast')) {
            Test-Threshold -Value (Get-OptionalPropertyValue -InputObject $rule.match -Name $name) -Label ('{0}.match.{1}' -f $label, $name) -Errors $errors -HasCondition ([ref]$hasCondition)
        }

        $deniedImages = Get-OptionalPropertyValue -InputObject $rule.match -Name 'deniedImages'
        if ($null -ne $deniedImages -and @($deniedImages).Count -gt 0) {
            $hasCondition = $true
        }

        if (-not $hasCondition) {
            Add-Error -Errors $errors -Message ('{0}: rule must have at least one meaningful match condition' -f $label)
        }
    }

    foreach ($duplicate in @($ids | Group-Object | Where-Object { $_.Name -and $_.Count -gt 1 })) {
        Add-Error -Errors $errors -Message ('{0}: id must be unique' -f $duplicate.Name)
    }

    Write-Host ('Rules: {0}' -f $rules.Count)
    Write-Host ('Enabled: {0}' -f @($rules | Where-Object { $null -eq $_.enabled -or $_.enabled -eq $true }).Count)
    Write-Host ('Disabled: {0}' -f @($rules | Where-Object { $_.enabled -eq $false }).Count)
    Write-Host ('Default decision: {0}' -f $config.defaultDecision)

    foreach ($rule in $rules) {
        $ruleErrors = @($errors | Where-Object { $_ -like ('{0}:*' -f $rule.id) -or $_ -like ('{0}.*' -f $rule.id) })
        Write-Host ('{0}: {1}' -f $rule.id, $(if ($ruleErrors.Count -eq 0) { 'OK' } else { 'FAIL' }))
    }

    if ($errors.Count -gt 0) {
        Write-Host ('Failed rule: {0}' -f (($errors[0] -split ':', 2)[0]))
        Write-Host ('Reason: {0}' -f $errors[0])
        Write-Host 'Result: FAIL'
        exit 1
    }

    Write-Host 'Result: PASS'
}
catch {
    Write-Host 'Failed rule: config'
    Write-Host ('Reason: {0}' -f $_.Exception.Message)
    Write-Host 'Result: FAIL'
    exit 1
}
