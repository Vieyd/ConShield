param(
    [string]$ConfigPath = '.\config\siem-rules.default.json'
)

$ErrorActionPreference = 'Stop'

function Resolve-RepositoryRoot {
    $current = Get-Location
    while ($null -ne $current) {
        if (Test-Path -LiteralPath (Join-Path $current.Path 'ConShield.sln') -PathType Leaf) {
            return $current.Path
        }

        $current = $current.Parent
    }

    throw 'Repository root was not found.'
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

function Get-ObjectPropertyNames {
    param([Parameter(Mandatory = $true)]$InputObject)

    return @($InputObject.PSObject.Properties | ForEach-Object { $_.Name })
}

function Add-ValidationError {
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

    foreach ($name in Get-ObjectPropertyNames -InputObject $InputObject) {
        if ($Allowed -notcontains $name) {
            Add-ValidationError -Errors $Errors -Message ('{0}: unknown field {1}' -f $Label, $name)
        }
    }
}

function Test-Severity {
    param(
        [string]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [System.Collections.Generic.List[string]]$Errors
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or @('Info', 'Warning', 'High', 'Critical') -notcontains $Value) {
        Add-ValidationError -Errors $Errors -Message ('{0}: severity must be Info, Warning, High, or Critical' -f $Label)
    }
}

function Get-StringArray {
    param(
        [object]$Single,
        [object]$Many
    )

    $values = @()
    if ($null -ne $Single -and -not [string]::IsNullOrWhiteSpace([string]$Single)) {
        $values += [string]$Single
    }

    if ($null -ne $Many) {
        foreach ($item in @($Many)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$item)) {
                $values += [string]$item
            }
        }
    }

    return @($values | Select-Object -Unique)
}

$repoRoot = Resolve-RepositoryRoot
$resolvedConfigPath = Resolve-RepoPath -RepoRoot $repoRoot -Path $ConfigPath
$displayPath = [System.IO.Path]::GetRelativePath($repoRoot, $resolvedConfigPath).Replace('\', '/')
$errors = [System.Collections.Generic.List[string]]::new()
$requiredRuleIds = @('IMG-001', 'POL-001', 'RTE-001', 'LIFE-001', 'LIFE-002', 'SENSOR-001', 'SENSOR-002', 'SIGN-001', 'SIGN-002', 'SIGN-003')
$supportedRuleIds = $requiredRuleIds

Write-Host 'ConShield SIEM rules validation'
Write-Host ('Config: {0}' -f $displayPath)

try {
    if (-not (Test-Path -LiteralPath $resolvedConfigPath -PathType Leaf)) {
        throw 'Config file was not found.'
    }

    $json = Get-Content -LiteralPath $resolvedConfigPath -Raw
    $config = $json | ConvertFrom-Json -Depth 12

    Test-AllowedProperties `
        -InputObject $config `
        -Allowed @('version', 'rules') `
        -Label 'root' `
        -Errors $errors

    if ($config.version -ne 1) {
        Add-ValidationError -Errors $errors -Message 'root: version must be 1'
    }

    $rules = @($config.rules)
    if ($rules.Count -eq 0) {
        Add-ValidationError -Errors $errors -Message 'root: at least one rule is required'
    }

    $ids = @()
    foreach ($rule in $rules) {
        $label = if ([string]::IsNullOrWhiteSpace([string]$rule.id)) { 'index {0}' -f $ids.Count } else { [string]$rule.id }
        $ids += [string]$rule.id

        Test-AllowedProperties `
            -InputObject $rule `
            -Allowed @('id', 'name', 'description', 'enabled', 'sourceSystem', 'sourceSystems', 'eventType', 'eventTypes', 'severity', 'minimumSeverity', 'threshold', 'timeWindowMinutes', 'groupingKey', 'alertSeverity', 'incident') `
            -Label $label `
            -Errors $errors

        if ($null -ne $rule.incident) {
            Test-AllowedProperties `
                -InputObject $rule.incident `
                -Allowed @('create', 'severity') `
                -Label ('{0}.incident' -f $label) `
                -Errors $errors
        }

        if ([string]::IsNullOrWhiteSpace([string]$rule.id)) {
            Add-ValidationError -Errors $errors -Message ('{0}: id is required' -f $label)
        }
        elseif ($supportedRuleIds -notcontains [string]$rule.id) {
            Add-ValidationError -Errors $errors -Message ('{0}: rule id is not supported by configurable SIEM rules v1' -f $label)
        }

        if ([string]::IsNullOrWhiteSpace([string]$rule.name)) {
            Add-ValidationError -Errors $errors -Message ('{0}: name is required' -f $label)
        }

        if ([int]$rule.threshold -le 0) {
            Add-ValidationError -Errors $errors -Message ('{0}: threshold must be positive' -f $label)
        }

        if ([int]$rule.timeWindowMinutes -le 0) {
            Add-ValidationError -Errors $errors -Message ('{0}: timeWindowMinutes must be positive' -f $label)
        }

        if ([string]::IsNullOrWhiteSpace([string]$rule.groupingKey)) {
            Add-ValidationError -Errors $errors -Message ('{0}: groupingKey is required' -f $label)
        }

        $sourceSystems = Get-StringArray -Single $rule.sourceSystem -Many $rule.sourceSystems
        $eventTypes = Get-StringArray -Single $rule.eventType -Many $rule.eventTypes
        if ($sourceSystems.Count -eq 0) {
            Add-ValidationError -Errors $errors -Message ('{0}: at least one exact source system is required' -f $label)
        }

        if ($eventTypes.Count -eq 0) {
            Add-ValidationError -Errors $errors -Message ('{0}: at least one exact event type is required' -f $label)
        }

        foreach ($value in @($sourceSystems + $eventTypes)) {
            if ($value -eq '*' -or $value -eq 'all' -or $value.Contains('*')) {
                Add-ValidationError -Errors $errors -Message ('{0}: wildcard source/event matching is not allowed' -f $label)
            }
        }

        $minimumSeverity = if ($null -ne $rule.minimumSeverity) { [string]$rule.minimumSeverity } elseif ($null -ne $rule.severity) { [string]$rule.severity } else { 'Info' }
        Test-Severity -Value $minimumSeverity -Label ('{0}.minimumSeverity' -f $label) -Errors $errors
        Test-Severity -Value ([string]$rule.alertSeverity) -Label ('{0}.alertSeverity' -f $label) -Errors $errors
        if ($null -ne $rule.incident -and $null -ne $rule.incident.severity) {
            Test-Severity -Value ([string]$rule.incident.severity) -Label ('{0}.incident.severity' -f $label) -Errors $errors
        }
    }

    foreach ($duplicate in @($ids | Group-Object | Where-Object { $_.Name -and $_.Count -gt 1 })) {
        Add-ValidationError -Errors $errors -Message ('{0}: id must be unique' -f $duplicate.Name)
    }

    foreach ($required in $requiredRuleIds) {
        if ($ids -notcontains $required) {
            Add-ValidationError -Errors $errors -Message ('{0}: required rule is missing' -f $required)
        }
    }

    Write-Host ('Rules: {0}' -f $rules.Count)
    Write-Host ('Enabled: {0}' -f @($rules | Where-Object { $null -eq $_.enabled -or $_.enabled -eq $true }).Count)
    Write-Host ('Disabled: {0}' -f @($rules | Where-Object { $_.enabled -eq $false }).Count)

    foreach ($rule in $rules) {
        $ruleErrors = @($errors | Where-Object { $_ -like ('{0}:*' -f $rule.id) -or $_ -like ('{0}.*' -f $rule.id) })
        $status = if ($ruleErrors.Count -eq 0) { 'OK' } else { 'FAIL' }
        Write-Host ('{0}: {1}' -f $rule.id, $status)
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
