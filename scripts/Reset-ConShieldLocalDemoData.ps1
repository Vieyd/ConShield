[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$ConfirmReset,
    [switch]$AllowNonLocal,
    [switch]$CleanLocalArtifacts,
    [string]$OutputArtifactRoot = '.\artifacts\local'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$results = New-Object System.Collections.Generic.List[object]
$hints = New-Object System.Collections.Generic.List[string]

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

function Add-ResetResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'WARN', 'FAIL', 'SKIP')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Detail,
        [string]$Hint
    )

    $script:results.Add([ordered]@{
        Name = $Name
        Status = $Status
        Detail = $Detail
    }) | Out-Null

    if (-not [string]::IsNullOrWhiteSpace($Hint)) {
        $script:hints.Add(('{0}: {1}' -f $Name, $Hint)) | Out-Null
    }
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

function Get-DemoDatabaseLink {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    if (-not [string]::IsNullOrWhiteSpace($env:CONSHIELD_DEMO_CONNECTION_STRING)) {
        return $env:CONSHIELD_DEMO_CONNECTION_STRING
    }

    $localValues = Get-LocalEnvMap -RepoRoot $RepoRoot
    $postgresPassword = $localValues['CONSHIELD_POSTGRES_PASSWORD']
    if ([string]::IsNullOrWhiteSpace($postgresPassword)) {
        return $null
    }

    return "Host=127.0.0.1;Port=5432;Database=conshield;Username=conshield;Password=$postgresPassword"
}

function Import-NpgsqlClient {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $candidatePaths = @(
        (Join-Path $RepoRoot 'tools\ConShield.DemoScenario\bin\Release\net8.0\Npgsql.dll'),
        (Join-Path $RepoRoot 'src\ConShield.Web\bin\Release\net8.0\Npgsql.dll'),
        (Join-Path $RepoRoot 'tools\ConShield.DemoScenario\bin\Debug\net8.0\Npgsql.dll'),
        (Join-Path $RepoRoot 'src\ConShield.Web\bin\Debug\net8.0\Npgsql.dll')
    )

    foreach ($path in $candidatePaths) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            [System.Reflection.Assembly]::LoadFrom($path) | Out-Null
            return $true
        }
    }

    return $false
}

function Test-LocalDatabaseLink {
    param([Parameter(Mandatory = $true)][string]$DatabaseLink)

    try {
        $builder = [Npgsql.NpgsqlConnectionStringBuilder]::new($DatabaseLink)
        $hosts = @(([string]$builder.Host).Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim().ToLowerInvariant() })
        if ($hosts.Count -eq 0) {
            return $false
        }

        $localHosts = @('localhost', '127.0.0.1', '::1')
        return @($hosts | Where-Object { $localHosts -notcontains $_ }).Count -eq 0
    }
    catch {
        return $false
    }
}

function Invoke-Scalar {
    param(
        [Parameter(Mandatory = $true)][Npgsql.NpgsqlConnection]$Connection,
        [Parameter(Mandatory = $true)][string]$Sql,
        [Npgsql.NpgsqlTransaction]$Transaction
    )

    $command = $Connection.CreateCommand()
    $command.CommandText = $Sql
    if ($null -ne $Transaction) {
        $command.Transaction = $Transaction
    }

    try {
        return $command.ExecuteScalar()
    }
    finally {
        $command.Dispose()
    }
}

function Invoke-NonQuery {
    param(
        [Parameter(Mandatory = $true)][Npgsql.NpgsqlConnection]$Connection,
        [Parameter(Mandatory = $true)][string]$Sql,
        [Npgsql.NpgsqlTransaction]$Transaction
    )

    $command = $Connection.CreateCommand()
    $command.CommandText = $Sql
    if ($null -ne $Transaction) {
        $command.Transaction = $Transaction
    }

    try {
        return [int]$command.ExecuteNonQuery()
    }
    finally {
        $command.Dispose()
    }
}

function Get-PostgresCounts {
    param([Parameter(Mandatory = $true)][Npgsql.NpgsqlConnection]$Connection)

    return [ordered]@{
        'DeadLetter replay requests' = [int64](Invoke-Scalar -Connection $Connection -Sql 'select count(*) from "DeadLetterReplayRequests"')
        'DeadLetter quarantine messages' = [int64](Invoke-Scalar -Connection $Connection -Sql 'select count(*) from "DeadLetterQuarantineMessages"')
        'Outbox messages' = [int64](Invoke-Scalar -Connection $Connection -Sql 'select count(*) from "SecurityEventOutbox"')
        'Inbox receipts' = [int64](Invoke-Scalar -Connection $Connection -Sql 'select count(*) from "SecurityEventInboxReceipts"')
        'SIEM alerts' = [int64](Invoke-Scalar -Connection $Connection -Sql 'select count(*) from "SiemAlerts"')
        'Incidents' = [int64](Invoke-Scalar -Connection $Connection -Sql 'select count(*) from "Incidents"')
        'Security events' = [int64](Invoke-Scalar -Connection $Connection -Sql 'select count(*) from "SecurityEvents"')
        'Demo sensors' = [int64](Invoke-Scalar -Connection $Connection -Sql 'select count(*) from "Sensors" where "DisplayName" like ''demo-%'' or "SourceSystem" like ''conshield.demo%''')
    }
}

function Reset-PostgresOperationalData {
    param(
        [Parameter(Mandatory = $true)][Npgsql.NpgsqlConnection]$Connection,
        [Parameter(Mandatory = $true)][bool]$Apply
    )

    $before = Get-PostgresCounts -Connection $Connection
    foreach ($name in $before.Keys) {
        $suffix = if ($Apply) { 'removed' } else { 'would be removed' }
        Add-ResetResult -Name $name -Status 'OK' -Detail ('{0} {1}' -f $before[$name], $suffix)
    }

    if (-not $Apply) {
        return
    }

    $transaction = $Connection.BeginTransaction()
    try {
        [void](Invoke-NonQuery -Connection $Connection -Transaction $transaction -Sql 'delete from "DeadLetterReplayRequests"')
        [void](Invoke-NonQuery -Connection $Connection -Transaction $transaction -Sql 'delete from "DeadLetterQuarantineMessages"')
        [void](Invoke-NonQuery -Connection $Connection -Transaction $transaction -Sql 'delete from "SecurityEventOutbox"')
        [void](Invoke-NonQuery -Connection $Connection -Transaction $transaction -Sql 'delete from "SecurityEventInboxReceipts"')
        [void](Invoke-NonQuery -Connection $Connection -Transaction $transaction -Sql 'delete from "SiemAlerts"')
        [void](Invoke-NonQuery -Connection $Connection -Transaction $transaction -Sql 'delete from "Incidents"')
        [void](Invoke-NonQuery -Connection $Connection -Transaction $transaction -Sql 'delete from "SecurityEvents"')
        [void](Invoke-NonQuery -Connection $Connection -Transaction $transaction -Sql 'delete from "Sensors" where "DisplayName" like ''demo-%'' or "SourceSystem" like ''conshield.demo%''')
        $transaction.Commit()
    }
    catch {
        $transaction.Rollback()
        throw
    }
    finally {
        $transaction.Dispose()
    }
}

function Invoke-DockerCommand {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $output = & docker @Arguments 2>$null
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output = @($output | ForEach-Object { [string]$_ })
    }
}

function ConvertTo-ShSingleQuoted {
    param([Parameter(Mandatory = $true)][string]$Value)

    return "'" + ($Value -replace "'", "'\''") + "'"
}

function Test-LocalMongoContainer {
    $inspect = Invoke-DockerCommand -Arguments @('inspect', '--format', '{{.State.Status}}', 'conshield-mongo')
    return $inspect.ExitCode -eq 0 -and ($inspect.Output | Select-Object -First 1) -eq 'running'
}

function Invoke-MongoCount {
    $script = 'const c=db.getSiblingDB("conshield_events").getCollection("security_event_raw_v1"); print(c.countDocuments({}));'
    $quotedScript = ConvertTo-ShSingleQuoted -Value $script
    $result = Invoke-DockerCommand -Arguments @(
        'exec',
        'conshield-mongo',
        'sh',
        '-lc',
        ('mongosh --quiet -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --eval {0}' -f $quotedScript)
    )

    if ($result.ExitCode -ne 0 -or $result.Output.Count -eq 0) {
        return $null
    }

    $text = $result.Output | Select-Object -Last 1
    $count = 0
    if ([int]::TryParse($text, [ref]$count)) {
        return $count
    }

    return $null
}

function Invoke-MongoReset {
    $script = 'const c=db.getSiblingDB("conshield_events").getCollection("security_event_raw_v1"); const r=c.deleteMany({}); print(r.deletedCount);'
    $quotedScript = ConvertTo-ShSingleQuoted -Value $script
    $result = Invoke-DockerCommand -Arguments @(
        'exec',
        'conshield-mongo',
        'sh',
        '-lc',
        ('mongosh --quiet -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --eval {0}' -f $quotedScript)
    )

    if ($result.ExitCode -ne 0) {
        return $null
    }

    $text = $result.Output | Select-Object -Last 1
    $count = 0
    if ([int]::TryParse($text, [ref]$count)) {
        return $count
    }

    return $null
}

function Reset-MongoProjection {
    param([Parameter(Mandatory = $true)][bool]$Apply)

    if (-not (Test-LocalMongoContainer)) {
        Add-ResetResult -Name 'Mongo projections' -Status 'WARN' -Detail 'local conshield-mongo container not running' -Hint 'Start local apps if Mongo projection cleanup is needed.'
        return
    }

    $count = Invoke-MongoCount
    if ($null -eq $count) {
        Add-ResetResult -Name 'Mongo projections' -Status 'WARN' -Detail 'count unavailable'
        return
    }

    if (-not $Apply) {
        Add-ResetResult -Name 'Mongo projections' -Status 'OK' -Detail ('{0} would be removed' -f $count)
        return
    }

    $removed = Invoke-MongoReset
    if ($null -eq $removed) {
        Add-ResetResult -Name 'Mongo projections' -Status 'FAIL' -Detail 'reset failed'
        return
    }

    Add-ResetResult -Name 'Mongo projections' -Status 'OK' -Detail ('{0} removed' -f $removed)
}

function Clear-LocalArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ArtifactRoot,
        [Parameter(Mandatory = $true)][bool]$Apply
    )

    if (-not $CleanLocalArtifacts) {
        Add-ResetResult -Name 'Local artifacts' -Status 'SKIP' -Detail 'skipped'
        return
    }

    $resolvedRoot = Resolve-RepoPath -RepoRoot $RepoRoot -Path $ArtifactRoot
    $expectedRoot = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot 'artifacts\local'))
    if (-not $resolvedRoot.StartsWith($expectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Add-ResetResult -Name 'Local artifacts' -Status 'FAIL' -Detail 'refusing to clean outside artifacts/local'
        return
    }

    if (-not (Test-Path -LiteralPath $resolvedRoot)) {
        Add-ResetResult -Name 'Local artifacts' -Status 'OK' -Detail 'nothing to clean'
        return
    }

    $files = @(Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse -ErrorAction SilentlyContinue)
    if (-not $Apply) {
        Add-ResetResult -Name 'Local artifacts' -Status 'OK' -Detail ('{0} files would be removed under artifacts/local' -f $files.Count)
        return
    }

    foreach ($file in $files) {
        Remove-Item -LiteralPath $file.FullName -Force
    }

    Add-ResetResult -Name 'Local artifacts' -Status 'OK' -Detail ('{0} files removed under artifacts/local' -f $files.Count)
}

function Write-Summary {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$Environment,
        [Parameter(Mandatory = $true)][string]$Result
    )

    Write-Host 'ConShield local demo data reset'
    Write-Host ('Mode: {0}' -f $Mode)
    Write-Host ('Environment: {0}' -f $Environment)
    Write-Host 'Local demo reset only. This is intended for local development/demo data.'
    Write-Host 'No secrets are printed.'
    Write-Host 'No repository files are deleted.'
    Write-Host 'Docker volumes are not removed.'
    foreach ($item in $results) {
        Write-Host ('{0}: {1} ({2})' -f $item.Name, $item.Status, $item.Detail)
    }

    foreach ($hint in $hints) {
        Write-Host ('Hint: {0}' -f $hint)
    }

    Write-Host ('Result: {0}' -f $Result)
}

$repoRoot = Resolve-RepositoryRoot
$applyReset = $ConfirmReset.IsPresent -and -not $WhatIfPreference
$mode = if ($applyReset) { 'Confirmed' } else { 'WhatIf' }
$environment = 'Unknown'

Push-Location $repoRoot
try {
    if (-not (Import-NpgsqlClient -RepoRoot $repoRoot)) {
        throw 'Npgsql client was not found. Build the solution first.'
    }

    $databaseLink = Get-DemoDatabaseLink -RepoRoot $repoRoot
    if ([string]::IsNullOrWhiteSpace($databaseLink)) {
        throw 'Local demo database connection is unavailable. Run Start-ConShield.ps1 setup first; secrets were not printed.'
    }

    $isLocal = Test-LocalDatabaseLink -DatabaseLink $databaseLink
    if (-not $isLocal -and -not $AllowNonLocal) {
        throw 'Database host is not provably local. Refusing reset without -AllowNonLocal.'
    }

    $environment = if ($isLocal) { 'Local' } else { 'NonLocalAllowed' }
    Add-ResetResult -Name 'PostgreSQL' -Status 'OK' -Detail 'connection target accepted'

    if (-not $ConfirmReset -or $WhatIfPreference) {
        Add-ResetResult -Name 'Confirmation' -Status 'WARN' -Detail 'dry-run only; pass -ConfirmReset for actual reset'
    }

    $connection = [Npgsql.NpgsqlConnection]::new($databaseLink)
    $connection.Open()
    try {
        Reset-PostgresOperationalData -Connection $connection -Apply $applyReset
    }
    finally {
        $connection.Dispose()
    }

    Reset-MongoProjection -Apply $applyReset
    Clear-LocalArtifacts -RepoRoot $repoRoot -ArtifactRoot $OutputArtifactRoot -Apply $applyReset

    $hasFailures = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0
    $result = if ($hasFailures) { 'FAIL' } elseif ($applyReset) { 'PASS' } else { 'DRY-RUN' }
    Write-Summary -Mode $mode -Environment $environment -Result $result

    if ($hasFailures) {
        exit 1
    }

    exit 0
}
catch {
    Add-ResetResult -Name 'Reset runner' -Status 'FAIL' -Detail $_.Exception.Message
    Write-Summary -Mode $mode -Environment $environment -Result 'FAIL'
    exit 1
}
finally {
    Pop-Location
}
