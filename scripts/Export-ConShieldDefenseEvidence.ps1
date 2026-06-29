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

function Get-SiemRulesEvidence {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $path = Join-Path $RepoRoot 'config\siem-rules.default.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{
            Summary = @([pscustomobject]@{
                ConfigSource = 'config/siem-rules.default.json'
                RulesLoaded = 0
                EnabledRules = 0
                DisabledRules = 0
                RuleIds = '-'
                Status = 'Missing'
            })
            Rules = @()
        }
    }

    try {
        $config = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 12
        $rules = @($config.rules)
        return [pscustomobject]@{
            Summary = @([pscustomobject]@{
                ConfigSource = 'config/siem-rules.default.json'
                RulesLoaded = $rules.Count
                EnabledRules = @($rules | Where-Object { $null -eq $_.enabled -or $_.enabled -eq $true }).Count
                DisabledRules = @($rules | Where-Object { $_.enabled -eq $false }).Count
                RuleIds = (($rules | ForEach-Object { [string]$_.id }) -join ', ')
                Status = 'Loaded'
            })
            Rules = @($rules | ForEach-Object {
                [pscustomobject]@{
                    RuleId = ConvertTo-SafeCell -Value $_.id -MaxLength 32
                    Enabled = if ($null -eq $_.enabled -or $_.enabled -eq $true) { 'true' } else { 'false' }
                    SourceSystems = ConvertTo-SafeCell -Value (@($_.sourceSystems) -join ', ') -MaxLength 160
                    EventTypes = ConvertTo-SafeCell -Value (@($_.eventTypes) -join ', ') -MaxLength 180
                    MinimumSeverity = ConvertTo-SafeCell -Value $_.minimumSeverity -MaxLength 32
                    AlertSeverity = ConvertTo-SafeCell -Value $_.alertSeverity -MaxLength 32
                    Threshold = ConvertTo-SafeCell -Value $_.threshold -MaxLength 16
                    TimeWindowMinutes = ConvertTo-SafeCell -Value $_.timeWindowMinutes -MaxLength 16
                }
            })
        }
    }
    catch {
        return [pscustomobject]@{
            Summary = @([pscustomobject]@{
                ConfigSource = 'config/siem-rules.default.json'
                RulesLoaded = 0
                EnabledRules = 0
                DisabledRules = 0
                RuleIds = '-'
                Status = 'Invalid'
            })
            Rules = @()
        }
    }
}

function Get-ContainerPolicyEvidence {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $path = Join-Path $RepoRoot 'config\container-policy.default.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{
            Summary = @([pscustomobject]@{
                ConfigSource = 'config/container-policy.default.json'
                DefaultDecision = '-'
                RulesLoaded = 0
                EnabledRules = 0
                DisabledRules = 0
                PolicyVersion = '-'
                Status = 'Missing'
            })
            Rules = @()
        }
    }

    try {
        $config = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 20
        $rules = @($config.rules)
        return [pscustomobject]@{
            Summary = @([pscustomobject]@{
                ConfigSource = 'config/container-policy.default.json'
                DefaultDecision = ConvertTo-SafeCell -Value $config.defaultDecision -MaxLength 32
                RulesLoaded = $rules.Count
                EnabledRules = @($rules | Where-Object { $null -eq $_.enabled -or $_.enabled -eq $true }).Count
                DisabledRules = @($rules | Where-Object { $_.enabled -eq $false }).Count
                PolicyVersion = ConvertTo-SafeCell -Value $config.policyVersion -MaxLength 64
                Status = 'Loaded'
            })
            Rules = @($rules | ForEach-Object {
                [pscustomobject]@{
                    RuleId = ConvertTo-SafeCell -Value $_.id -MaxLength 64
                    Enabled = if ($null -eq $_.enabled -or $_.enabled -eq $true) { 'true' } else { 'false' }
                    Decision = ConvertTo-SafeCell -Value $_.decision -MaxLength 32
                    Reason = ConvertTo-SafeCell -Value $_.reason -MaxLength 120
                }
            })
        }
    }
    catch {
        return [pscustomobject]@{
            Summary = @([pscustomobject]@{
                ConfigSource = 'config/container-policy.default.json'
                DefaultDecision = '-'
                RulesLoaded = 0
                EnabledRules = 0
                DisabledRules = 0
                PolicyVersion = '-'
                Status = 'Invalid'
            })
            Rules = @()
        }
    }
}

function Get-SensorTrustEvidence {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $path = Join-Path $RepoRoot 'config\sensor-registry.default.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{
            Summary = @([pscustomobject]@{
                ConfigSource = 'config/sensor-registry.default.json'
                SensorsLoaded = 0
                Trusted = 0
                Unknown = 0
                Revoked = 0
                Disabled = 0
                Status = 'Missing'
            })
            Sensors = @()
        }
    }

    try {
        $config = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 20
        $sensors = @($config.sensors)
        return [pscustomobject]@{
            Summary = @([pscustomobject]@{
                ConfigSource = 'config/sensor-registry.default.json'
                SensorsLoaded = $sensors.Count
                Trusted = @($sensors | Where-Object { $_.status -eq 'Trusted' }).Count
                Unknown = @($sensors | Where-Object { $_.status -eq 'Unknown' }).Count
                Revoked = @($sensors | Where-Object { $_.status -eq 'Revoked' }).Count
                Disabled = @($sensors | Where-Object { $_.status -eq 'Disabled' }).Count
                Status = 'Loaded'
            })
            Sensors = @($sensors | ForEach-Object {
                [pscustomobject]@{
                    SensorId = ConvertTo-SafeCell -Value $_.sensorId -MaxLength 80
                    DisplayName = ConvertTo-SafeCell -Value $_.displayName -MaxLength 120
                    SourceSystem = ConvertTo-SafeCell -Value $_.sourceSystem -MaxLength 120
                    Environment = ConvertTo-SafeCell -Value $_.environment -MaxLength 80
                    TrustStatus = ConvertTo-SafeCell -Value $_.status -MaxLength 32
                    ExpectedEventTypes = ConvertTo-SafeCell -Value (@($_.expectedEventTypes) -join ', ') -MaxLength 180
                }
            })
        }
    }
    catch {
        return [pscustomobject]@{
            Summary = @([pscustomobject]@{
                ConfigSource = 'config/sensor-registry.default.json'
                SensorsLoaded = 0
                Trusted = 0
                Unknown = 0
                Revoked = 0
                Disabled = 0
                Status = 'Invalid'
            })
            Sensors = @()
        }
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
$siemRulesEvidence = Get-SiemRulesEvidence -RepoRoot $repoRoot
$containerPolicyEvidence = Get-ContainerPolicyEvidence -RepoRoot $repoRoot
$sensorTrustEvidence = Get-SensorTrustEvidence -RepoRoot $repoRoot
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
    RuntimeSensorSummary = @()
    RuntimeSensorRules = @()
    RuntimeSensorHealth = @()
    ImageScanEvidence = @()
    ImageScanRules = @()
    ImageScanIncidents = @()
    ProtectedRunLaunches = @()
    ProtectedRunPolicies = @()
    ProtectedRunRules = @()
    ContainerPolicyDecisions = @()
    ContainerPolicyPolAlerts = @()
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
        $tables.RuntimeSensorSummary = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select coalesce("SourceSystem", '''') as "SourceSystem", coalesce("ExternalEventType", '''') as "ExternalEventType", count(*)::int as "Count", max("OccurredAtUtc") as "LatestOccurredAtUtc" from "SecurityEvents" where coalesce("SourceSystem", '''') in (''conshield.falco-linux-sensor'', ''conshield.falco-runtime-collector'', ''conshield.container-runtime'') or coalesce("ExternalEventType", '''') like ''container.runtime.%'' group by coalesce("SourceSystem", ''''), coalesce("ExternalEventType", '''') order by max("OccurredAtUtc") desc limit 10;')
        $tables.RuntimeSensorRules = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select case when position(''rule='' in "Description") > 0 then split_part(split_part("Description", ''rule='', 2), '','', 1) else ''-'' end as "FalcoRule", count(*)::int as "Count", max("OccurredAtUtc") as "LatestOccurredAtUtc" from "SecurityEvents" where (coalesce("SourceSystem", '''') in (''conshield.falco-linux-sensor'', ''conshield.falco-runtime-collector'', ''conshield.container-runtime'') or coalesce("ExternalEventType", '''') like ''container.runtime.%'') group by case when position(''rule='' in "Description") > 0 then split_part(split_part("Description", ''rule='', 2), '','', 1) else ''-'' end order by max("OccurredAtUtc") desc limit 10;')
        $tables.RuntimeSensorHealth = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'with runtime_sources("SourceSystem") as (values (''conshield.falco-linux-sensor''), (''conshield.falco-runtime-collector''), (''conshield.container-runtime'') union select distinct coalesce("SourceSystem", ''unknown-runtime-source'') from "SecurityEvents" where coalesce("SourceSystem", '''') ilike ''%runtime%'' or coalesce("SourceSystem", '''') ilike ''%falco%'' or coalesce("ExternalEventType", '''') ilike ''%runtime%'' or coalesce("ExternalEventType", '''') ilike ''%falco%''), runtime_events as (select se.* from "SecurityEvents" se join runtime_sources rs on coalesce(se."SourceSystem", ''unknown-runtime-source'') = rs."SourceSystem" where coalesce(se."SourceSystem", '''') ilike ''%runtime%'' or coalesce(se."SourceSystem", '''') ilike ''%falco%'' or coalesce(se."ExternalEventType", '''') ilike ''%runtime%'' or coalesce(se."ExternalEventType", '''') ilike ''%falco%''), latest as (select distinct on (coalesce("SourceSystem", ''unknown-runtime-source'')) coalesce("SourceSystem", ''unknown-runtime-source'') as "SourceSystem", "OccurredAtUtc" as "LastSeenUtc", "Id" as "LatestEventId", coalesce("ExternalEventType", '''') as "LatestEventType", "Severity"::text as "LatestSeverity" from runtime_events order by coalesce("SourceSystem", ''unknown-runtime-source''), "OccurredAtUtc" desc, "Id" desc), grouped as (select coalesce("SourceSystem", ''unknown-runtime-source'') as "SourceSystem", count(*)::int as "EventCount" from runtime_events group by coalesce("SourceSystem", ''unknown-runtime-source'')) select rs."SourceSystem", case when latest."LastSeenUtc" is null then ''NoData'' when latest."LastSeenUtc" >= ((now() at time zone ''utc'') - interval ''24 hours'') then ''Active'' else ''Stale'' end as "Status", latest."LastSeenUtc", coalesce(grouped."EventCount", 0)::int as "EventCount", latest."LatestEventType", (select count(distinct alert."Id")::int from "SiemAlerts" alert where alert."RuleCode" = ''RTE-001'' and exists (select 1 from runtime_events se where coalesce(se."SourceSystem", ''unknown-runtime-source'') = rs."SourceSystem" and position(''Source event #'' || se."Id"::text in alert."Description") > 0)) as "RelatedRteAlertCount", (select count(distinct incident."Id")::int from "Incidents" incident join runtime_events se on incident."SourceEventId" = se."Id" where coalesce(se."SourceSystem", ''unknown-runtime-source'') = rs."SourceSystem") as "RelatedIncidentCount" from runtime_sources rs left join grouped on grouped."SourceSystem" = rs."SourceSystem" left join latest on latest."SourceSystem" = rs."SourceSystem" order by case when latest."LastSeenUtc" is null then 1 else 0 end, latest."LastSeenUtc" desc nulls last, rs."SourceSystem";')
        $tables.ImageScanEvidence = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Id", "OccurredAtUtc", "Severity"::text as "Severity", coalesce("SourceSystem", '''') as "SourceSystem", coalesce("ExternalEventType", '''') as "ExternalEventType", "Description" from "SecurityEvents" where coalesce("SourceSystem", '''') = ''conshield.image-scanner'' and coalesce("ExternalEventType", '''') = ''container.image.scan.completed'' order by "OccurredAtUtc" desc limit 10;')
        $tables.ImageScanRules = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "RuleCode", count(*)::int as "Count", max("CreatedAtUtc") as "LatestCreatedAtUtc" from "SiemAlerts" where "RuleCode" = ''IMG-001'' group by "RuleCode";')
        $tables.ImageScanIncidents = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select count(*)::int as "Count" from "Incidents" incident join "SecurityEvents" se on incident."SourceEventId" = se."Id" where coalesce(se."SourceSystem", '''') = ''conshield.image-scanner'' and coalesce(se."ExternalEventType", '''') = ''container.image.scan.completed'';')
        $tables.ProtectedRunLaunches = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Id", "OccurredAtUtc", "Severity"::text as "Severity", coalesce("SourceSystem", '''') as "SourceSystem", coalesce("ExternalEventType", '''') as "ExternalEventType", "Description" from "SecurityEvents" where coalesce("SourceSystem", '''') = ''conshield.container-runtime'' and coalesce("ExternalEventType", '''') = ''container.image.launch.result'' order by "OccurredAtUtc" desc limit 10;')
        $tables.ProtectedRunPolicies = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Id", "OccurredAtUtc", "Severity"::text as "Severity", coalesce("SourceSystem", '''') as "SourceSystem", coalesce("ExternalEventType", '''') as "ExternalEventType", "Description" from "SecurityEvents" where coalesce("SourceSystem", '''') = ''conshield.container-guard'' and coalesce("ExternalEventType", '''') = ''container.image.policy.evaluated'' order by "OccurredAtUtc" desc limit 10;')
        $tables.ProtectedRunRules = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "RuleCode", count(*)::int as "Count", max("CreatedAtUtc") as "LatestCreatedAtUtc" from "SiemAlerts" where "RuleCode" in (''IMG-001'', ''POL-001'', ''LIFE-001'') group by "RuleCode" order by "RuleCode";')
        $tables.ContainerPolicyDecisions = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "Id", "OccurredAtUtc", "Severity"::text as "Severity", coalesce("SourceSystem", '''') as "SourceSystem", coalesce("ExternalEventType", '''') as "ExternalEventType", "Description" from "SecurityEvents" where coalesce("SourceSystem", '''') = ''conshield.container-guard'' and coalesce("ExternalEventType", '''') = ''container.image.policy.evaluated'' order by "OccurredAtUtc" desc limit 10;')
        $tables.ContainerPolicyPolAlerts = @(Invoke-SafeQuery -DatabaseLink $databaseLink -Sql 'select "RuleCode", count(*)::int as "Count", max("CreatedAtUtc") as "LatestCreatedAtUtc" from "SiemAlerts" where "RuleCode" = ''POL-001'' group by "RuleCode";')
    }
    catch {
        $queryError = ConvertTo-SafeCell -Value $_.Exception.Message -MaxLength 180
    }
}
else {
    $queryError = "Local database configuration was not found. Run Start-ConShield.ps1 after preparing .conshield.local.env."
}

$registryBySource = @{}
foreach ($sensor in @($sensorTrustEvidence.Sensors)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$sensor.SourceSystem)) {
        $registryBySource[[string]$sensor.SourceSystem] = $sensor
    }
}

$tables.RuntimeSensorHealth = @($tables.RuntimeSensorHealth | ForEach-Object {
    $sourceSystem = [string]$_.SourceSystem
    $sensor = if ($registryBySource.ContainsKey($sourceSystem)) { $registryBySource[$sourceSystem] } else { $null }
    [pscustomobject]@{
        SensorId = if ($null -ne $sensor) { $sensor.SensorId } else { '-' }
        SourceSystem = $_.SourceSystem
        DisplayName = if ($null -ne $sensor) { $sensor.DisplayName } else { $_.SourceSystem }
        Environment = if ($null -ne $sensor) { $sensor.Environment } else { '-' }
        TrustStatus = if ($null -ne $sensor) { $sensor.TrustStatus } else { 'Unknown' }
        Status = $_.Status
        LastSeenUtc = $_.LastSeenUtc
        EventCount = $_.EventCount
        LatestEventType = $_.LatestEventType
        RelatedRteAlertCount = $_.RelatedRteAlertCount
        RelatedIncidentCount = $_.RelatedIncidentCount
    }
})

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

$lines.Add('## Image Scan Evidence') | Out-Null
$lines.Add('') | Out-Null
if (@($tables.ImageScanEvidence).Count -eq 0) {
    $lines.Add('No ConShield image scan events were found in the current evidence window.') | Out-Null
}
else {
    Add-MarkdownTable -Lines $lines -Headers @('Id', 'OccurredAtUtc', 'Severity', 'SourceSystem', 'ExternalEventType', 'Description') -Rows $tables.ImageScanEvidence
    $lines.Add('') | Out-Null
    $lines.Add('### Related IMG-001 alerts') | Out-Null
    $lines.Add('') | Out-Null
    Add-MarkdownTable -Lines $lines -Headers @('RuleCode', 'Count', 'LatestCreatedAtUtc') -Rows $tables.ImageScanRules
    $lines.Add('') | Out-Null
    $lines.Add('### Related image-scan incidents') | Out-Null
    $lines.Add('') | Out-Null
    Add-MarkdownTable -Lines $lines -Headers @('Count') -Rows $tables.ImageScanIncidents
    $lines.Add('') | Out-Null
    $lines.Add('- Related SIEM rule: `IMG-001` Critical container image risk.') | Out-Null
    $lines.Add('- Review linked pages: `/SecurityEvents`, `/Siem`, `/Incidents`, and `/Demo`.') | Out-Null
}
$lines.Add('') | Out-Null

$lines.Add('## Protected Run Evidence') | Out-Null
$lines.Add('') | Out-Null
if (@($tables.ProtectedRunLaunches).Count -eq 0 -and @($tables.ProtectedRunPolicies).Count -eq 0) {
    $lines.Add('No protected container run events were found in the current evidence window.') | Out-Null
}
else {
    $lines.Add('### Launch lifecycle events') | Out-Null
    $lines.Add('') | Out-Null
    Add-MarkdownTable -Lines $lines -Headers @('Id', 'OccurredAtUtc', 'Severity', 'SourceSystem', 'ExternalEventType', 'Description') -Rows $tables.ProtectedRunLaunches
    $lines.Add('') | Out-Null
    $lines.Add('### Policy decision events') | Out-Null
    $lines.Add('') | Out-Null
    Add-MarkdownTable -Lines $lines -Headers @('Id', 'OccurredAtUtc', 'Severity', 'SourceSystem', 'ExternalEventType', 'Description') -Rows $tables.ProtectedRunPolicies
    $lines.Add('') | Out-Null
    $lines.Add('### Related rules') | Out-Null
    $lines.Add('') | Out-Null
    Add-MarkdownTable -Lines $lines -Headers @('RuleCode', 'Count', 'LatestCreatedAtUtc') -Rows $tables.ProtectedRunRules
    $lines.Add('') | Out-Null
    $lines.Add('- Protected run path: image scan → policy decision → launch lifecycle result.') | Out-Null
    $lines.Add('- Related evidence uses safe descriptions only; raw Trivy JSON, raw payloads, raw Docker logs, and local artifacts are excluded.') | Out-Null
}
$lines.Add('') | Out-Null

$lines.Add('## Container Policy Evidence') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('ConfigSource', 'DefaultDecision', 'RulesLoaded', 'EnabledRules', 'DisabledRules', 'PolicyVersion', 'Status') -Rows $containerPolicyEvidence.Summary
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('RuleId', 'Enabled', 'Decision', 'Reason') -Rows $containerPolicyEvidence.Rules
$lines.Add('') | Out-Null
$lines.Add('### Latest policy decisions') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('Id', 'OccurredAtUtc', 'Severity', 'SourceSystem', 'ExternalEventType', 'Description') -Rows $tables.ContainerPolicyDecisions
$lines.Add('') | Out-Null
$lines.Add('### Related POL-001 alerts') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('RuleCode', 'Count', 'LatestCreatedAtUtc') -Rows $tables.ContainerPolicyPolAlerts
$lines.Add('') | Out-Null
$lines.Add('- Container policy evidence is summarized from `config/container-policy.default.json`; raw Trivy JSON, raw event payloads, raw additional data, Docker logs, and local secrets are excluded.') | Out-Null
$lines.Add('') | Out-Null

$lines.Add('## Sensor Trust Evidence') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('ConfigSource', 'SensorsLoaded', 'Trusted', 'Unknown', 'Revoked', 'Disabled', 'Status') -Rows $sensorTrustEvidence.Summary
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('SensorId', 'DisplayName', 'SourceSystem', 'Environment', 'TrustStatus', 'ExpectedEventTypes') -Rows $sensorTrustEvidence.Sensors
$lines.Add('') | Out-Null
$lines.Add('- Sensor trust evidence is summarized from `config/sensor-registry.default.json`; runtime payloads, local secrets, certificates, private keys, and logs are excluded.') | Out-Null
$lines.Add('') | Out-Null

$lines.Add('## Runtime Sensor Evidence') | Out-Null
$lines.Add('') | Out-Null
if (@($tables.RuntimeSensorSummary).Count -eq 0) {
    $lines.Add('No Falco-compatible runtime events were found in the current evidence window.') | Out-Null
}
else {
    $lines.Add('### Runtime event summary') | Out-Null
    $lines.Add('') | Out-Null
    Add-MarkdownTable -Lines $lines -Headers @('SourceSystem', 'ExternalEventType', 'Count', 'LatestOccurredAtUtc') -Rows $tables.RuntimeSensorSummary
    $lines.Add('') | Out-Null
    $lines.Add('### Latest Falco-compatible rule names') | Out-Null
    $lines.Add('') | Out-Null
    Add-MarkdownTable -Lines $lines -Headers @('FalcoRule', 'Count', 'LatestOccurredAtUtc') -Rows $tables.RuntimeSensorRules
    $lines.Add('') | Out-Null
    $lines.Add('- Related SIEM rule: `RTE-001` Container runtime threat detected.') | Out-Null
    $lines.Add('- Review linked pages: `/SecurityEvents`, `/SiemAlerts`, `/Incidents`, and `/Reports/SecuritySummary`.') | Out-Null
}
$lines.Add('') | Out-Null

$lines.Add('## Runtime Sensor Health') | Out-Null
$lines.Add('') | Out-Null
if (@($tables.RuntimeSensorHealth).Count -eq 0 -or @($tables.RuntimeSensorHealth | Where-Object { [int]$_.EventCount -gt 0 }).Count -eq 0) {
    $lines.Add('No runtime sensor activity was found in the current evidence window.') | Out-Null
}
else {
    Add-MarkdownTable -Lines $lines -Headers @('SensorId', 'SourceSystem', 'DisplayName', 'Environment', 'TrustStatus', 'Status', 'LastSeenUtc', 'EventCount', 'LatestEventType', 'RelatedRteAlertCount', 'RelatedIncidentCount') -Rows $tables.RuntimeSensorHealth
}
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

$lines.Add('## SIEM Rules Evidence') | Out-Null
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('ConfigSource', 'RulesLoaded', 'EnabledRules', 'DisabledRules', 'RuleIds', 'Status') -Rows $siemRulesEvidence.Summary
$lines.Add('') | Out-Null
Add-MarkdownTable -Lines $lines -Headers @('RuleId', 'Enabled', 'SourceSystems', 'EventTypes', 'MinimumSeverity', 'AlertSeverity', 'Threshold', 'TimeWindowMinutes') -Rows $siemRulesEvidence.Rules
$lines.Add('') | Out-Null
$lines.Add('- SIEM rule evidence is summarized from `config/siem-rules.default.json`; raw event payloads and local secrets are excluded.') | Out-Null
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
foreach ($route in @('/Operations/Health', '/SecurityEvents', '/Sensors', '/RuntimeSensors', '/Siem', '/Incidents', '/Reports/SecuritySummary', '/Outbox')) {
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
