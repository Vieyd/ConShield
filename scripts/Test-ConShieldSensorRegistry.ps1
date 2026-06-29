param(
    [string]$ConfigPath = '.\config\sensor-registry.default.json'
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

function Test-SafeText {
    param(
        [AllowNull()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [System.Collections.Generic.List[string]]$Errors,
        [switch]$Required
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        if ($Required) {
            Add-Error -Errors $Errors -Message ('{0}: value is required' -f $Label)
        }

        return
    }

    if ($Value -match '[\x00-\x1F\x7F]') {
        Add-Error -Errors $Errors -Message ('{0}: control characters are not allowed' -f $Label)
    }
}

function Test-NoCertificateMaterial {
    param(
        [AllowNull()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [System.Collections.Generic.List[string]]$Errors
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }

    if ($Value -match '-----BEGIN|PRIVATE KEY|CERTIFICATE') {
        Add-Error -Errors $Errors -Message ('{0}: certificate or private key material is not allowed' -f $Label)
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
$allowedStatuses = @('Trusted', 'Unknown', 'Revoked', 'Disabled')

Write-Host 'ConShield sensor registry validation'
Write-Host ('Config: {0}' -f $displayPath)

try {
    if (-not (Test-Path -LiteralPath $resolvedConfigPath -PathType Leaf)) {
        throw 'Config file was not found.'
    }

    $config = Get-Content -LiteralPath $resolvedConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 20
    Test-AllowedProperties -InputObject $config -Allowed @('version', 'sensors') -Label 'root' -Errors $errors

    if ([int]$config.version -ne 1) {
        Add-Error -Errors $errors -Message 'root: version must be 1'
    }

    $sensors = @($config.sensors)
    if ($sensors.Count -eq 0) {
        Add-Error -Errors $errors -Message 'root: at least one sensor is required'
    }

    $ids = @()
    foreach ($sensor in $sensors) {
        $sensorId = [string](Get-OptionalPropertyValue -InputObject $sensor -Name 'sensorId')
        $label = if ([string]::IsNullOrWhiteSpace($sensorId)) { 'index {0}' -f $ids.Count } else { $sensorId }
        $ids += $sensorId

        Test-AllowedProperties `
            -InputObject $sensor `
            -Allowed @('sensorId', 'displayName', 'sourceSystem', 'environment', 'status', 'expectedEventTypes', 'fingerprintSha256', 'notes') `
            -Label $label `
            -Errors $errors

        $status = [string](Get-OptionalPropertyValue -InputObject $sensor -Name 'status')
        Test-SafeText -Value $sensorId -Label ('{0}.sensorId' -f $label) -Errors $errors -Required
        Test-SafeText -Value ([string](Get-OptionalPropertyValue -InputObject $sensor -Name 'displayName')) -Label ('{0}.displayName' -f $label) -Errors $errors -Required
        Test-SafeText -Value ([string](Get-OptionalPropertyValue -InputObject $sensor -Name 'sourceSystem')) -Label ('{0}.sourceSystem' -f $label) -Errors $errors -Required
        Test-SafeText -Value ([string](Get-OptionalPropertyValue -InputObject $sensor -Name 'environment')) -Label ('{0}.environment' -f $label) -Errors $errors
        Test-SafeText -Value $status -Label ('{0}.status' -f $label) -Errors $errors -Required

        if ($allowedStatuses -notcontains $status) {
            Add-Error -Errors $errors -Message ('{0}: status must be Trusted, Unknown, Revoked, or Disabled' -f $label)
        }

        foreach ($eventType in @(Get-OptionalPropertyValue -InputObject $sensor -Name 'expectedEventTypes')) {
            Test-SafeText -Value ([string]$eventType) -Label ('{0}.expectedEventTypes' -f $label) -Errors $errors -Required
        }

        Test-NoCertificateMaterial -Value ([string](Get-OptionalPropertyValue -InputObject $sensor -Name 'fingerprintSha256')) -Label ('{0}.fingerprintSha256' -f $label) -Errors $errors
    }

    foreach ($duplicate in @($ids | Group-Object | Where-Object { $_.Name -and $_.Count -gt 1 })) {
        Add-Error -Errors $errors -Message ('{0}: sensorId must be unique' -f $duplicate.Name)
    }

    Write-Host ('Sensors: {0}' -f $sensors.Count)
    Write-Host ('Trusted: {0}' -f @($sensors | Where-Object { (Get-OptionalPropertyValue -InputObject $_ -Name 'status') -eq 'Trusted' }).Count)
    Write-Host ('Revoked: {0}' -f @($sensors | Where-Object { (Get-OptionalPropertyValue -InputObject $_ -Name 'status') -eq 'Revoked' }).Count)
    Write-Host ('Disabled: {0}' -f @($sensors | Where-Object { (Get-OptionalPropertyValue -InputObject $_ -Name 'status') -eq 'Disabled' }).Count)
    Write-Host ('Unknown: {0}' -f @($sensors | Where-Object { (Get-OptionalPropertyValue -InputObject $_ -Name 'status') -eq 'Unknown' }).Count)

    foreach ($sensor in $sensors) {
        $sensorId = [string](Get-OptionalPropertyValue -InputObject $sensor -Name 'sensorId')
        $sensorErrors = @($errors | Where-Object { $_ -like ('{0}:*' -f $sensorId) -or $_ -like ('{0}.*' -f $sensorId) })
        Write-Host ('{0}: {1}' -f $sensorId, $(if ($sensorErrors.Count -eq 0) { 'OK' } else { 'FAIL' }))
    }

    if ($errors.Count -gt 0) {
        Write-Host ('Failed sensor: {0}' -f (($errors[0] -split ':', 2)[0]))
        Write-Host ('Reason: {0}' -f $errors[0])
        Write-Host 'Result: FAIL'
        exit 1
    }

    Write-Host 'Result: PASS'
}
catch {
    Write-Host 'Failed sensor: config'
    Write-Host ('Reason: {0}' -f $_.Exception.Message)
    Write-Host 'Result: FAIL'
    exit 1
}
