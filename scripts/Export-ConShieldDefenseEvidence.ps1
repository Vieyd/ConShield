param(
    [switch]$RunScenario,
    [string]$OutputMarkdownPath = ".\artifacts\local\defense-evidence.md",
    [string]$BaseUrl = "http://127.0.0.1:5080"
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

function Get-LocalEnvMap {
    param([string]$RepoRoot)

    $path = Join-Path $RepoRoot '.conshield.local.env'
    $values = @{}
    if (-not (Test-Path -LiteralPath $path)) {
        return $values
    }

    Get-Content -LiteralPath $path | ForEach-Object {
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
    param([string]$RepoRoot)

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

function ConvertTo-SafeCell {
    param(
        [AllowNull()][object]$Value,
        [int]$MaxLength = 120
    )

    if ($null -eq $Value -or [System.DBNull]::Value.Equals($Value)) {
        return '-'
    }

    $text = [string]$Value
    $text = $text -replace '[\r\n\t]+', ' '
    $text = $text -replace '\|', '\|'
    $text = $text -replace '(?i)(password|secret|token|api[_ -]?key|authorization|bearer|cookie|credential)\s*[:=]\s*[^;\s,]+', '$1=[redacted]'
    $text = $text.Trim()
    if ($text.Length -gt $MaxLength) {
        return $text.Substring(0, $MaxLength - 3) + '...'
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
        return '-'
    }

    return $text
}

function Test-HttpRoute {
    param(
        [string]$Url,
        [int[]]$AllowedStatusCodes = @(200, 302)
    )

    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0 -ErrorAction Stop
        return $AllowedStatusCodes -contains [int]$response.StatusCode
    }
    catch {
        if ($_.Exception.Response -and ($AllowedStatusCodes -contains [int]$_.Exception.Response.StatusCode)) {
            return $true
        }

        return $false
    }
}

function Test-PortOpen {
    param(
        [string]$HostName,
        [int]$Port
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne(1500)) {
            return $false
        }

        $client.EndConnect($connect)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Import-NpgsqlClient {
    param([string]$RepoRoot)

    $candidatePaths = @(
        (Join-Path $RepoRoot 'tools\ConShield.DemoScenario\bin\Release\net8.0\Npgsql.dll'),
        (Join-Path $RepoRoot 'src\ConShield.Web\bin\Release\net8.0\Npgsql.dll'),
        (Join-Path $RepoRoot 'tools\ConShield.DemoScenario\bin\Debug\net8.0\Npgsql.dll'),
        (Join-Path $RepoRoot 'src\ConShield.Web\bin\Debug\net8.0\Npgsql.dll')
    )

    foreach ($path in $candidatePaths) {
        if (Test-Path -LiteralPath $path) {
            [System.Reflection.Assembly]::LoadFrom($path) | Out-Null
            return $true
        }
    }

    return $false
}

function Invoke-SafeQuery {
    param(
        [string]$DatabaseLink,
        [string]$Sql
    )

    $connection = [Npgsql.NpgsqlConnection]::new($DatabaseLink)
    $connection.Open()
    try {
        $command = $connection.CreateCommand()
        $command.CommandText = $Sql
        $reader = $command.ExecuteReader()
        try {
            $rows = @()
            while ($reader.Read()) {
                $row = [ordered]@{}
                for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                    $row[$reader.GetName($i)] = $reader.GetValue($i)
                }

                $rows += [pscustomobject]$row
            }

            return $rows
        }
        finally {
            $reader.Dispose()
            $command.Dispose()
        }
    }
    finally {
        $connection.Dispose()
    }
}

function Get-CountValue {
    param([AllowNull()][object]$Rows)

    if ($null -eq $Rows) {
        return 0
    }

    $items = @($Rows)
    if ($items.Count -eq 0) {
        return 0
    }

    return [int]$items[0].Count
}

function Add-MarkdownTable {
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [string[]]$Headers,
        [object[]]$Rows
    )

    $Lines.Add('| ' + ($Headers -join ' | ') + ' |') | Out-Null
    $Lines.Add('| ' + (($Headers | ForEach-Object { '---' }) -join ' | ') + ' |') | Out-Null

    if ($Rows.Count -eq 0) {
        $Lines.Add('| ' + ((@('-') * $Headers.Count) -join ' | ') + ' |') | Out-Null
        return
    }

    foreach ($row in $Rows) {
        $cells = foreach ($header in $Headers) {
            ConvertTo-SafeCell -Value $row.$header
        }

        $Lines.Add('| ' + ($cells -join ' | ') + ' |') | Out-Null
    }
}

function Invoke-DefenseScenario {
    param([string]$RepoRoot)

    $runner = Join-Path $RepoRoot 'scripts\Run-ConShieldDefenseScenario.ps1'
    if (-not (Test-Path -LiteralPath $runner)) {
        return [pscustomobject]@{
            Result = 'FAIL'
            Lines = @('Scenario runner was not found.')
            Counts = @{}
        }
    }

    Push-Location $RepoRoot
    try {
        $output = & pwsh -NoProfile -ExecutionPolicy Bypass -File $runner 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    $counts = @{}
    foreach ($line in @($output)) {
        $text = [string]$line
        if ($text -match '^(actual_[A-Za-z0-9_]+)=(.+)$') {
            $counts[$Matches[1]] = ConvertTo-SafeCell -Value $Matches[2] -MaxLength 80
        }
    }

    $result = if ($exitCode -eq 0) { 'PASS' } elseif ($exitCode -eq 2) { 'UNKNOWN' } else { 'FAIL' }
    return [pscustomobject]@{
        Result = $result
        Lines = @($output | ForEach-Object { ConvertTo-SafeCell -Value $_ -MaxLength 160 })
        Counts = $counts
    }
}

$repoRoot = Resolve-RepositoryRoot
$resolvedOutputPath = if ([System.IO.Path]::IsPathRooted($OutputMarkdownPath)) {
    $OutputMarkdownPath
}
else {
    Join-Path $repoRoot $OutputMarkdownPath
}

$scenario = $null
if ($RunScenario) {
    $scenario = Invoke-DefenseScenario -RepoRoot $repoRoot
}

$databaseLink = Get-DemoDatabaseLink -RepoRoot $repoRoot
$health = [ordered]@{
    Web = Test-HttpRoute -Url ($BaseUrl.TrimEnd('/') + '/Operations/Health')
    PostgreSQL = $false
    RabbitMQ = Test-PortOpen -HostName '127.0.0.1' -Port 5672
    MongoProjection = Test-PortOpen -HostName '127.0.0.1' -Port 27017
}

$queryError = $null
$tables = @{
    Counts = @{}
    SiemAlerts = @()
    Incidents = @()
    SecurityEvents = @()
    Outbox = @()
    Inbox = @()
    Rules = @()
    OperatorIncidentCounts = @()
    OperatorAcknowledgedAlerts = @()
    OperatorClosedIncidents = @()
}

if (-not [string]::IsNullOrWhiteSpace($databaseLink)) {
    try {
        if (-not (Import-NpgsqlClient -RepoRoot $repoRoot)) {
            throw "Npgsql client is unavailable. Run dotnet build -c Release before exporting live database evidence."
        }

        [void](Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select 1 as "Count";')
        $health.PostgreSQL = $true

        $tables.Counts.SecurityEvents = Get-CountValue (Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select count(*)::int as "Count" from "SecurityEvents";')
        $tables.Counts.SiemAlerts = Get-CountValue (Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select count(*)::int as "Count" from "SiemAlerts";')
        $tables.Counts.Incidents = Get-CountValue (Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select count(*)::int as "Count" from "Incidents";')
        $tables.Counts.Outbox = Get-CountValue (Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select count(*)::int as "Count" from "SecurityEventOutbox";')
        $tables.Counts.Inbox = Get-CountValue (Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select count(*)::int as "Count" from "SecurityEventInboxReceipts";')

        $tables.SiemAlerts = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Id", "CreatedAtUtc", "RuleCode", "Severity", "Status", coalesce("IncidentId", 0) as "IncidentId", "Description" from "SiemAlerts" order by "CreatedAtUtc" desc limit 10;')
        $tables.Incidents = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Id", "CreatedAtUtc", "Name", "Severity", "Status", coalesce("SourceEventId", 0) as "SourceEventId" from "Incidents" order by "CreatedAtUtc" desc limit 10;')
        $tables.SecurityEvents = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Id", "OccurredAtUtc", "EventType", "Severity", coalesce("SourceSystem", '''') as "SourceSystem", coalesce("ExternalEventType", '''') as "ExternalEventType", "Description" from "SecurityEvents" order by "OccurredAtUtc" desc limit 10;')
        $tables.Outbox = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Status", count(*)::int as "Count" from "SecurityEventOutbox" group by "Status" order by "Status";')
        $tables.Inbox = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select count(*)::int as "Count", max("ProcessedAtUtc") as "LastProcessedAtUtc" from "SecurityEventInboxReceipts";')
        $tables.Rules = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "RuleCode", count(*)::int as "Count" from "SiemAlerts" group by "RuleCode" order by "RuleCode";')
        $tables.OperatorIncidentCounts = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Status", count(*)::int as "Count" from "Incidents" group by "Status" order by "Status";')
        $tables.OperatorAcknowledgedAlerts = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Id", "RuleCode", "Status", "AcknowledgedAtUtc", coalesce("AcknowledgedBy", '''') as "AcknowledgedBy", coalesce("IncidentId", 0) as "IncidentId" from "SiemAlerts" where "Status" = ''Acknowledged'' or "AcknowledgedAtUtc" is not null order by coalesce("AcknowledgedAtUtc", "CreatedAtUtc") desc limit 10;')
        $tables.OperatorClosedIncidents = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Id", "Status", "ClosedAtUtc", coalesce("SourceEventId", 0) as "SourceEventId", "Conclusion" from "Incidents" where "Status" = ''Closed'' order by coalesce("ClosedAtUtc", "CreatedAtUtc") desc limit 10;')
    }
    catch {
        $queryError = ConvertTo-SafeCell -Value $_.Exception.Message -MaxLength 180
    }
}
else {
    $queryError = "Local database configuration was not found. Run Start-ConShield.ps1 after preparing .conshield.local.env."
}

$result = 'PASS'
if (-not $health.Web -or -not $health.PostgreSQL) {
    $result = 'FAIL'
}
elseif (($tables.Counts.SiemAlerts -eq 0) -or ($tables.Counts.Incidents -eq 0)) {
    $result = 'UNKNOWN'
}

if ($RunScenario -and $scenario -and $scenario.Result -eq 'FAIL') {
    $result = 'FAIL'
}
elseif ($RunScenario -and $scenario -and $scenario.Result -eq 'UNKNOWN' -and $result -eq 'PASS') {
    $result = 'UNKNOWN'
}

$lines = [System.Collections.Generic.List[string]]::new()
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$lines.Add('# ConShield Defense Evidence Pack v1') | Out-Null
$lines.Add('') | Out-Null
$lines.Add("- Generated UTC: $timestamp") | Out-Null
$lines.Add("- Repository: ConShield") | Out-Null
$lines.Add("- Scenario mode: " + $(if ($RunScenario) { 'RunScenario enabled' } else { 'Snapshot only' })) | Out-Null
$lines.Add("- Result: $result") | Out-Null
$lines.Add("- Sensitive configuration values, raw event bodies, and local logs are intentionally excluded.") | Out-Null
$lines.Add('') | Out-Null

$lines.Add('## Health and availability') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Component', 'Status', 'Evidence') -Rows @(
    [pscustomobject]@{ Component = 'Web /Operations/Health'; Status = if ($health.Web) { 'OK' } else { 'FAIL' }; Evidence = $BaseUrl.TrimEnd('/') + '/Operations/Health' },
    [pscustomobject]@{ Component = 'PostgreSQL'; Status = if ($health.PostgreSQL) { 'OK' } else { 'FAIL' }; Evidence = if ($health.PostgreSQL) { 'safe aggregate query succeeded' } else { 'start local stack first' } },
    [pscustomobject]@{ Component = 'RabbitMQ'; Status = if ($health.RabbitMQ) { 'OK' } else { 'UNKNOWN' }; Evidence = '127.0.0.1:5672 connectivity' },
    [pscustomobject]@{ Component = 'Mongo projection'; Status = if ($health.MongoProjection) { 'OK' } else { 'UNKNOWN' }; Evidence = '127.0.0.1:27017 connectivity' }
)
if ($queryError) {
    $lines.Add('') | Out-Null
    $lines.Add("> Query note: $queryError") | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('Start local services with: `pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit`') | Out-Null
}
$lines.Add('') | Out-Null

$lines.Add('## Scenario summary') | Out-Null
$lines.Add('') | Out-Null
if ($scenario) {
    $scenarioRows = @(
        [pscustomobject]@{ Metric = 'Scenario result'; Value = $scenario.Result },
        [pscustomobject]@{ Metric = 'Security events'; Value = $scenario.Counts['actual_security_events'] },
        [pscustomobject]@{ Metric = 'Inbox receipts'; Value = $scenario.Counts['actual_inbox_receipts'] },
        [pscustomobject]@{ Metric = 'Outbox messages'; Value = $scenario.Counts['actual_outbox_messages'] },
        [pscustomobject]@{ Metric = 'SIEM alerts'; Value = $scenario.Counts['actual_siem_alerts'] },
        [pscustomobject]@{ Metric = 'Incidents'; Value = $scenario.Counts['actual_incidents'] },
        [pscustomobject]@{ Metric = 'Rules'; Value = $scenario.Counts['actual_rules'] }
    )
    Add-MarkdownTable -Lines $lines -Headers @('Metric', 'Value') -Rows $scenarioRows
}
else {
    Add-MarkdownTable -Lines $lines -Headers @('Metric', 'Value') -Rows @(
        [pscustomobject]@{ Metric = 'Mode'; Value = 'Snapshot only; pass -RunScenario for a fresh synthetic walkthrough.' },
        [pscustomobject]@{ Metric = 'Security events'; Value = $tables.Counts.SecurityEvents },
        [pscustomobject]@{ Metric = 'SIEM alerts'; Value = $tables.Counts.SiemAlerts },
        [pscustomobject]@{ Metric = 'Incidents'; Value = $tables.Counts.Incidents },
        [pscustomobject]@{ Metric = 'Outbox messages'; Value = $tables.Counts.Outbox },
        [pscustomobject]@{ Metric = 'Inbox receipts'; Value = $tables.Counts.Inbox }
    )
}
$lines.Add('') | Out-Null

$lines.Add('## SIEM alerts') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Id', 'CreatedAtUtc', 'RuleCode', 'Severity', 'Status', 'IncidentId', 'Description') -Rows $tables.SiemAlerts
$lines.Add('') | Out-Null

$lines.Add('## Incidents') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Id', 'CreatedAtUtc', 'Name', 'Severity', 'Status', 'SourceEventId') -Rows $tables.Incidents
$lines.Add('') | Out-Null

$lines.Add('## Security events') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Id', 'OccurredAtUtc', 'EventType', 'Severity', 'SourceSystem', 'ExternalEventType', 'Description') -Rows $tables.SecurityEvents
$lines.Add('') | Out-Null

$lines.Add('## Outbox and inbox summary') | Out-Null
$lines.Add('') | Out-Null
$lines.Add('### Outbox') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Status', 'Count') -Rows $tables.Outbox
$lines.Add('') | Out-Null
$lines.Add('### Inbox') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Count', 'LastProcessedAtUtc') -Rows $tables.Inbox
$lines.Add('') | Out-Null

$lines.Add('## Correlation rules demonstrated') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('RuleCode', 'Count') -Rows $tables.Rules
$lines.Add('') | Out-Null

$lines.Add('## Operator Workflow') | Out-Null
$lines.Add('') | Out-Null
$lines.Add('### Incident status counts') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Status', 'Count') -Rows $tables.OperatorIncidentCounts
$lines.Add('') | Out-Null
$lines.Add('### Recently acknowledged or reviewed SIEM alerts') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Id', 'RuleCode', 'Status', 'AcknowledgedAtUtc', 'AcknowledgedBy', 'IncidentId') -Rows $tables.OperatorAcknowledgedAlerts
$lines.Add('') | Out-Null
$lines.Add('### Recently closed incidents') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Id', 'Status', 'ClosedAtUtc', 'SourceEventId', 'Conclusion') -Rows $tables.OperatorClosedIncidents
$lines.Add('') | Out-Null
$lines.Add('### Operator workflow checklist') | Out-Null
$lines.Add('') | Out-Null
$lines.Add('- [ ] Open Security Summary and follow the SIEM alerts link.') | Out-Null
$lines.Add('- [ ] Open a SIEM alert and confirm the linked incident and source Security Event metadata.') | Out-Null
$lines.Add('- [ ] Acknowledge or review the SIEM alert.') | Out-Null
$lines.Add('- [ ] Move the linked incident to In Progress.') | Out-Null
$lines.Add('- [ ] Close the incident with a non-empty operator conclusion.') | Out-Null
$lines.Add('- [ ] Re-run this evidence export and confirm the Operator Workflow section reflects the actions.') | Out-Null
$lines.Add('') | Out-Null

$lines.Add('## Demo navigation checklist') | Out-Null
$lines.Add('') | Out-Null
foreach ($route in @('/Operations/Health', '/SecurityEvents', '/Sensors', '/Siem', '/Incidents', '/Reports/SecuritySummary', '/Outbox')) {
    $lines.Add(("- [ ] Open `{0}{1}` and confirm the screen matches the counts above." -f $BaseUrl.TrimEnd('/'), $route)) | Out-Null
}
$lines.Add('') | Out-Null

$lines.Add('## Defense talking points') | Out-Null
$lines.Add('') | Out-Null
$lines.Add('- Event ingestion is shown through safe aggregate counts and recent event metadata.') | Out-Null
$lines.Add('- SIEM rules link security events to alerts and incidents without exposing raw local data.') | Out-Null
$lines.Add('- Outbox/inbox evidence demonstrates reliable delivery and deduplication signals.') | Out-Null
$lines.Add('- Operator-ready screens are covered by the navigation checklist.') | Out-Null
$lines.Add('') | Out-Null

$lines.Add('## Operator checklist') | Out-Null
$lines.Add('') | Out-Null
$lines.Add('- [ ] Start local stack with `Start-ConShield.ps1 -StartApps -OpenRabbit`.') | Out-Null
$lines.Add('- [ ] Run `Export-ConShieldDefenseEvidence.ps1 -RunScenario` before the defense walkthrough.') | Out-Null
$lines.Add('- [ ] Confirm generated evidence remains under `artifacts/local/` or another ignored path.') | Out-Null
$lines.Add('- [ ] Do not commit generated markdown, local config, screenshots, or logs.') | Out-Null
$lines.Add('- [ ] If result is FAIL, resolve health notes and regenerate the pack.') | Out-Null

$outputDirectory = Split-Path -Parent $resolvedOutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Set-Content -LiteralPath $resolvedOutputPath -Value $lines -Encoding UTF8

Write-Output 'ConShield defense evidence export'
Write-Output ("Web: {0}" -f $(if ($health.Web) { 'OK' } else { 'FAIL' }))
Write-Output ("PostgreSQL: {0}" -f $(if ($health.PostgreSQL) { 'OK' } else { 'FAIL' }))
Write-Output ("RabbitMQ: {0}" -f $(if ($health.RabbitMQ) { 'OK' } else { 'UNKNOWN' }))
Write-Output ("Mongo projection: {0}" -f $(if ($health.MongoProjection) { 'OK' } else { 'UNKNOWN' }))
Write-Output ("SIEM alerts: {0}" -f $tables.Counts.SiemAlerts)
Write-Output ("Incidents: {0}" -f $tables.Counts.Incidents)
Write-Output ("Evidence: {0}" -f $resolvedOutputPath)
Write-Output ("Result: {0}" -f $result)

if ($result -eq 'FAIL') {
    exit 1
}

exit 0
