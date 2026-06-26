param(
    [switch]$RunTests,
    [switch]$StartApps,
    [switch]$OpenRabbit,
    [switch]$Status,
    [switch]$Stop,
    [switch]$StopApps,
    [switch]$ForceStopPortOwners
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeFile = Join-Path $ProjectRoot "infra\docker-compose.yml"
$EnvFile = Join-Path $ProjectRoot ".conshield.local.env"
$RuntimeDir = Join-Path $ProjectRoot ".conshield-local"
$WebPidFile = Join-Path $RuntimeDir "web.pid"
$ConsumerPidFile = Join-Path $RuntimeDir "consumer.pid"
$WebLog = Join-Path $RuntimeDir "web.log"
$WebErrorLog = Join-Path $RuntimeDir "web.error.log"
$ConsumerLog = Join-Path $RuntimeDir "consumer.log"
$ConsumerErrorLog = Join-Path $RuntimeDir "consumer.error.log"
$TestResultFile = Join-Path $RuntimeDir "last-test-result.txt"
$NuGetConfig = Join-Path $RuntimeDir "NuGet.Config"
$WebUrl = "http://127.0.0.1:5080"
$ComposeArgs = @("-f", $ComposeFile, "--profile", "messaging", "--profile", "projection")
$RequiredVariables = @(
    "CONSHIELD_POSTGRES_PASSWORD", "CONSHIELD_RABBITMQ_USER",
    "CONSHIELD_RABBITMQ_PASSWORD", "CONSHIELD_MONGO_ROOT_USERNAME",
    "CONSHIELD_MONGO_ROOT_PASSWORD", "CONSHIELD_MONGO_APP_USERNAME",
    "CONSHIELD_MONGO_APP_PASSWORD", "CONSHIELD_EXTERNAL_EVENT_API_KEY",
    "ExternalEventIngestion__Enabled", "ExternalEventIngestion__ApiKey"
)
$DemoUserVariables = @(
    "DemoUsers__0__UserName", "DemoUsers__0__Password", "DemoUsers__0__DisplayName",
    "DemoUsers__0__Role", "DemoUsers__1__UserName", "DemoUsers__1__Password",
    "DemoUsers__1__DisplayName", "DemoUsers__1__Role"
)

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function ConvertFrom-SecureStringForProcess {
    param([Parameter(Mandatory = $true)][securestring]$SecureValue)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Get-EffectiveEnvValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    $processValue = [Environment]::GetEnvironmentVariable($Name, "Process")
    if (-not [string]::IsNullOrWhiteSpace($processValue)) {
        return $processValue
    }

    $userValue = [Environment]::GetEnvironmentVariable($Name, "User")
    if (-not [string]::IsNullOrWhiteSpace($userValue)) {
        return $userValue
    }

    return $null
}

function Set-ProcessEnvIfMissing {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name, "Process"))) {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

function Import-LocalEnv {
    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
        throw "Missing local environment file: $EnvFile"
    }

    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $EnvFile -Encoding UTF8) {
        $lineNumber++
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith("#")) { continue }
        if ($trimmed -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            throw "Invalid NAME=VALUE syntax in ${EnvFile} at line $lineNumber."
        }

        $name = $Matches[1]
        $value = $Matches[2]
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        Set-ProcessEnvIfMissing -Name $name -Value $value
    }

    $missing = @($RequiredVariables | Where-Object {
        [string]::IsNullOrWhiteSpace((Get-EffectiveEnvValue -Name $_))
    })
    if ($missing.Count -gt 0) {
        throw "Local environment is missing required variable names: $($missing -join ', ')"
    }

    foreach ($demoVariable in $DemoUserVariables) {
        $demoValue = Get-EffectiveEnvValue -Name $demoVariable
        if (-not [string]::IsNullOrWhiteSpace($demoValue)) {
            [Environment]::SetEnvironmentVariable($demoVariable, $demoValue, "Process")
        }
    }

    $allowLegacyText = [Environment]::GetEnvironmentVariable(
        "ExternalEventIngestion__AllowLegacyRuntimeCollectorCredential",
        "Process")
    if ([string]::IsNullOrWhiteSpace($allowLegacyText)) {
        $allowLegacyText = [Environment]::GetEnvironmentVariable(
            "ExternalEventIngestion__AllowLegacyRuntimeCollectorCredential",
            "User")
    }
    $allowLegacy = $true
    if (-not [string]::IsNullOrWhiteSpace($allowLegacyText) -and
        -not [bool]::TryParse($allowLegacyText, [ref]$allowLegacy)) {
        throw "ExternalEventIngestion__AllowLegacyRuntimeCollectorCredential must be true or false."
    }
    if ($allowLegacy -and
        [string]::IsNullOrWhiteSpace($env:CONSHIELD_RUNTIME_COLLECTOR_API_KEY)) {
        throw "Local environment requires CONSHIELD_RUNTIME_COLLECTOR_API_KEY while legacy runtime fallback is enabled."
    }
    $script:AllowLegacyRuntimeCollectorCredential = $allowLegacy
}

function Set-DerivedEnvironment {
    $postgresPassword = Get-EffectiveEnvValue -Name "CONSHIELD_POSTGRES_PASSWORD"
    if ([string]::IsNullOrWhiteSpace($postgresPassword)) {
        $securePostgresPassword = Read-Host -Prompt "Local PostgreSQL password" -AsSecureString
        try {
            $postgresPassword = ConvertFrom-SecureStringForProcess -SecureValue $securePostgresPassword
        }
        finally {
            $securePostgresPassword.Dispose()
        }
    }

    if ([string]::IsNullOrWhiteSpace($postgresPassword)) {
        throw "Local PostgreSQL password is missing. Set CONSHIELD_POSTGRES_PASSWORD in process/User env or .conshield.local.env."
    }

    [Environment]::SetEnvironmentVariable("CONSHIELD_POSTGRES_PASSWORD", $postgresPassword, "Process")

    $postgresHost = Get-EffectiveEnvValue -Name "CONSHIELD_POSTGRES_HOST"
    if ([string]::IsNullOrWhiteSpace($postgresHost)) { $postgresHost = "127.0.0.1" }
    $postgresPort = Get-EffectiveEnvValue -Name "CONSHIELD_POSTGRES_PORT"
    if ([string]::IsNullOrWhiteSpace($postgresPort)) { $postgresPort = "5432" }
    $postgresDatabase = Get-EffectiveEnvValue -Name "CONSHIELD_POSTGRES_DATABASE"
    if ([string]::IsNullOrWhiteSpace($postgresDatabase)) { $postgresDatabase = "conshield" }
    $postgresUser = Get-EffectiveEnvValue -Name "CONSHIELD_POSTGRES_USER"
    if ([string]::IsNullOrWhiteSpace($postgresUser)) { $postgresUser = "conshield" }

    $mongoAppPassword = Get-EffectiveEnvValue -Name "CONSHIELD_MONGO_APP_PASSWORD"
    $mongoAppUser = Get-EffectiveEnvValue -Name "CONSHIELD_MONGO_APP_USERNAME"
    $mongoPassword = [Uri]::EscapeDataString($mongoAppPassword)
    $mongoConnection = "mongodb://${mongoAppUser}:${mongoPassword}@127.0.0.1:27017/conshield_events?authSource=conshield_events"

    if ([string]::IsNullOrWhiteSpace($env:ConnectionStrings__DefaultConnection)) {
        $env:ConnectionStrings__DefaultConnection = "Host=${postgresHost};Port=${postgresPort};Database=${postgresDatabase};Username=${postgresUser};Password=${postgresPassword}"
    }
    $env:ASPNETCORE_ENVIRONMENT = "Development"
    $env:ASPNETCORE_URLS = $WebUrl
    if (-not $script:AllowLegacyRuntimeCollectorCredential) {
        Remove-Item Env:CONSHIELD_RUNTIME_COLLECTOR_API_KEY -ErrorAction SilentlyContinue
        Remove-Item Env:ExternalEventIngestion__RuntimeCollectorApiKey -ErrorAction SilentlyContinue
    } else {
        $env:ExternalEventIngestion__RuntimeCollectorApiKey = $env:CONSHIELD_RUNTIME_COLLECTOR_API_KEY
    }
    $env:SecurityEventOutbox__Enabled = "true"
    $env:SecurityEventOutbox__Transport = "RabbitMq"
    $env:RabbitMq__Enabled = "true"
    $env:RabbitMq__HostName = "127.0.0.1"
    $env:RabbitMq__Port = "5672"
    $env:RabbitMq__VirtualHost = "/conshield"
    $env:RabbitMq__UserName = $env:CONSHIELD_RABBITMQ_USER
    $env:RabbitMq__Password = $env:CONSHIELD_RABBITMQ_PASSWORD
    $env:MongoProjection__Enabled = "true"
    $env:MongoProjection__ConnectionString = $mongoConnection
    $env:MongoProjection__DatabaseName = "conshield_events"
    $env:MongoProjection__CollectionName = "security_event_raw_v1"

    $env:CONSHIELD_TEST_POSTGRES_CONNECTION = "Host=127.0.0.1;Port=5432;Database=conshield_tests;Username=conshield;Password=$($env:CONSHIELD_POSTGRES_PASSWORD)"
    $env:CONSHIELD_TEST_RABBITMQ_HOST = "127.0.0.1"
    $env:CONSHIELD_TEST_RABBITMQ_PORT = "5672"
    $env:CONSHIELD_TEST_RABBITMQ_VHOST = "/conshield"
    $env:CONSHIELD_TEST_RABBITMQ_USERNAME = $env:CONSHIELD_RABBITMQ_USER
    $env:CONSHIELD_TEST_RABBITMQ_PASSWORD = $env:CONSHIELD_RABBITMQ_PASSWORD
    $env:CONSHIELD_TEST_MONGODB_CONNECTION = $mongoConnection
    $env:CONSHIELD_TEST_MONGODB_DATABASE = "conshield_events"
}

function Test-DockerServer {
    & docker version --format '{{.Server.Version}}' *> $null
    return $LASTEXITCODE -eq 0
}

function Ensure-Docker {
    if (Test-DockerServer) { return }
    Write-Step "Starting Docker Desktop"
    try { & docker desktop start | Out-Null } catch { }
    if (-not (Test-DockerServer)) {
        $desktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
        if (Test-Path -LiteralPath $desktop) {
            Start-Process -FilePath $desktop -WindowStyle Hidden | Out-Null
        }
    }
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        if (Test-DockerServer) { return }
    }
    throw "Docker Server did not become available within 120 seconds."
}

function Invoke-Compose([string[]]$Arguments) {
    & docker compose @ComposeArgs @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed (exit $LASTEXITCODE)." }
}

function Wait-Healthy([string[]]$Containers, [int]$TimeoutSeconds = 180) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $states = foreach ($container in $Containers) {
            $text = (& docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $container 2>$null | Out-String).Trim()
            [pscustomobject]@{ Container = $container; State = $text; ExitCode = $LASTEXITCODE }
        }
        if (@($states | Where-Object { $_.ExitCode -ne 0 -or $_.State -ne "healthy" }).Count -eq 0) { return }
        Start-Sleep -Seconds 3
    }
    & docker compose @ComposeArgs ps -a
    throw "PostgreSQL, RabbitMQ, or MongoDB did not become healthy within $TimeoutSeconds seconds."
}

function Ensure-TestDatabase {
    $exists = & docker exec conshield-postgres psql -U conshield -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='conshield_tests';"
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect PostgreSQL test database." }
    $existsText = ($exists | Out-String).Trim()
    if ($existsText -ne "1") {
        Write-Step "Creating conshield_tests database"
        & docker exec conshield-postgres createdb -U conshield conshield_tests
        if ($LASTEXITCODE -ne 0) { throw "Could not create conshield_tests database." }
    }
}

function Get-CommandLine([int]$ProcessId) {
    try { return (Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop).CommandLine } catch { return $null }
}

function Get-ProcessInfo([int]$ProcessId) {
    try {
        return Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Test-ConShieldProcess {
    param(
        [Parameter(Mandatory = $true)]$ProcessInfo,
        [Parameter(Mandatory = $true)][string]$IdentityText
    )

    if ($null -eq $ProcessInfo) { return $false }
    if ($ProcessInfo.Name -eq "${IdentityText}.exe") { return $true }
    if ($ProcessInfo.CommandLine -like "*$IdentityText*") { return $true }
    return $false
}

function Get-ConShieldProcesses([string]$IdentityText) {
    @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { Test-ConShieldProcess -ProcessInfo $_ -IdentityText $IdentityText })
}

function Get-WebPortOwner {
    Get-NetTCPConnection -LocalPort 5080 -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

function Stop-ConShieldProcess {
    param(
        [Parameter(Mandatory = $true)]$ProcessInfo,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $processId = [int]$ProcessInfo.ProcessId
    $processName = [string]$ProcessInfo.Name
    Write-Host ("Stopping {0} process PID {1} ({2})." -f $Name, $processId, $processName)
    Stop-Process -Id $processId -ErrorAction Stop
    try { Wait-Process -Id $processId -Timeout 15 -ErrorAction SilentlyContinue } catch { }
}

function Stop-ManagedProcess([string]$Name, [string]$PidFile, [string]$IdentityText) {
    if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) { return }
    $pidText = (Get-Content -Raw -LiteralPath $PidFile).Trim()
    $processId = 0
    if (-not [int]::TryParse($pidText, [ref]$processId)) {
        Remove-Item -LiteralPath $PidFile -Force
        return
    }
    $processInfo = Get-ProcessInfo -ProcessId $processId
    if ($null -eq $processInfo) {
        Remove-Item -LiteralPath $PidFile -Force
        return
    }
    if (-not (Test-ConShieldProcess -ProcessInfo $processInfo -IdentityText $IdentityText)) {
        throw "Refusing to stop PID ${processId}: it is not the helper-managed $Name process."
    }
    Stop-ConShieldProcess -ProcessInfo $processInfo -Name $Name
    Remove-Item -LiteralPath $PidFile -Force
    Write-Host "$Name stopped (PID $processId)."
}

function Stop-ManagedApps {
    Stop-ManagedProcess "Web" $WebPidFile "ConShield.Web"
    Stop-ManagedProcess "EventConsumer" $ConsumerPidFile "ConShield.EventConsumer"

    foreach ($webProcess in Get-ConShieldProcesses "ConShield.Web") {
        Stop-ConShieldProcess -ProcessInfo $webProcess -Name "Web"
    }
    foreach ($consumerProcess in Get-ConShieldProcesses "ConShield.EventConsumer") {
        Stop-ConShieldProcess -ProcessInfo $consumerProcess -Name "EventConsumer"
    }

    $listener = Get-WebPortOwner
    if ($null -ne $listener) {
        $ownerInfo = Get-ProcessInfo -ProcessId ([int]$listener.OwningProcess)
        if (Test-ConShieldProcess -ProcessInfo $ownerInfo -IdentityText "ConShield.Web") {
            Stop-ConShieldProcess -ProcessInfo $ownerInfo -Name "Web port owner"
        }
        elseif ($ForceStopPortOwners) {
            $ownerName = if ($ownerInfo) { $ownerInfo.Name } else { "unknown" }
            Write-Warning ("Force stopping TCP 5080 owner PID {0} ({1})." -f $listener.OwningProcess, $ownerName)
            Stop-Process -Id $listener.OwningProcess -ErrorAction Stop
        }
        else {
            $ownerName = if ($ownerInfo) { $ownerInfo.Name } else { "unknown" }
            Write-Warning ("TCP 5080 is owned by PID {0} ({1}) and does not clearly look like ConShield.Web; not stopping it without -ForceStopPortOwners." -f $listener.OwningProcess, $ownerName)
        }
    }

    Remove-Item -LiteralPath $WebPidFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ConsumerPidFile -Force -ErrorAction SilentlyContinue
}

function Test-Web([string]$Url = "http://127.0.0.1:5080/Account/Login") {
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 5 -ErrorAction Stop
        return $response.StatusCode -in @(200, 302)
    } catch {
        $errorResponse = $_.Exception.PSObject.Properties['Response']?.Value
        if ($errorResponse -and [int]$errorResponse.StatusCode -eq 302) { return $true }
        return $false
    }
}

function Get-ConsumerProcess {
    @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { Test-ConShieldProcess -ProcessInfo $_ -IdentityText "ConShield.EventConsumer" }) | Select-Object -First 1
}

function New-AppEnvironment {
    $environment = @{
        "ASPNETCORE_ENVIRONMENT" = "Development"
        "ASPNETCORE_URLS" = $WebUrl
        "ConnectionStrings__DefaultConnection" = $env:ConnectionStrings__DefaultConnection
        "SecurityEventOutbox__Enabled" = $env:SecurityEventOutbox__Enabled
        "SecurityEventOutbox__Transport" = $env:SecurityEventOutbox__Transport
        "RabbitMq__Enabled" = $env:RabbitMq__Enabled
        "RabbitMq__HostName" = $env:RabbitMq__HostName
        "RabbitMq__Port" = $env:RabbitMq__Port
        "RabbitMq__VirtualHost" = $env:RabbitMq__VirtualHost
        "RabbitMq__UserName" = $env:RabbitMq__UserName
        "RabbitMq__Password" = $env:RabbitMq__Password
        "MongoProjection__Enabled" = $env:MongoProjection__Enabled
        "MongoProjection__ConnectionString" = $env:MongoProjection__ConnectionString
        "MongoProjection__DatabaseName" = $env:MongoProjection__DatabaseName
        "MongoProjection__CollectionName" = $env:MongoProjection__CollectionName
        "ExternalEventIngestion__Enabled" = $env:ExternalEventIngestion__Enabled
        "ExternalEventIngestion__ApiKey" = $env:ExternalEventIngestion__ApiKey
    }

    foreach ($demoVariable in $DemoUserVariables) {
        $demoValue = Get-EffectiveEnvValue -Name $demoVariable
        if (-not [string]::IsNullOrWhiteSpace($demoValue)) {
            $environment[$demoVariable] = $demoValue
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($env:ExternalEventIngestion__RuntimeCollectorApiKey)) {
        $environment["ExternalEventIngestion__RuntimeCollectorApiKey"] = $env:ExternalEventIngestion__RuntimeCollectorApiKey
    }

    return $environment
}

function Show-DemoUserEnvironmentSummary {
    for ($index = 0; $index -le 1; $index++) {
        $userName = Get-EffectiveEnvValue -Name "DemoUsers__${index}__UserName"
        $password = Get-EffectiveEnvValue -Name "DemoUsers__${index}__Password"
        Write-Host ("DemoUsers__{0} configured: {1}" -f $index, (-not [string]::IsNullOrWhiteSpace($userName)).ToString().ToLowerInvariant())
        Write-Host ("DemoUsers__{0} password present: {1}" -f $index, (-not [string]::IsNullOrWhiteSpace($password)).ToString().ToLowerInvariant())
    }
}

function Test-ParentChildProcess {
    param(
        [Parameter(Mandatory = $true)][int]$ParentProcessId,
        [Parameter(Mandatory = $true)][int]$ChildProcessId
    )

    $child = Get-ProcessInfo -ProcessId $ChildProcessId
    return $null -ne $child -and [int]$child.ParentProcessId -eq $ParentProcessId
}

function Assert-WebPortOwner {
    param([int]$LauncherProcessId = 0)

    $listener = Get-WebPortOwner
    if ($null -eq $listener) {
        throw "ConShield.Web did not open TCP 5080."
    }

    $ownerProcessId = [int]$listener.OwningProcess
    $ownerInfo = Get-ProcessInfo -ProcessId $ownerProcessId
    $isWebOwner = Test-ConShieldProcess -ProcessInfo $ownerInfo -IdentityText "ConShield.Web"
    if (-not $isWebOwner) {
        $ownerName = if ($ownerInfo) { $ownerInfo.Name } else { "unknown" }
        throw "TCP 5080 owner PID $ownerProcessId ($ownerName) is not ConShield.Web."
    }

    if ($LauncherProcessId -gt 0) {
        $matchesLauncher = $ownerProcessId -eq $LauncherProcessId
        $isChild = Test-ParentChildProcess -ParentProcessId $LauncherProcessId -ChildProcessId $ownerProcessId
        Write-Host ("Web launcher PID: {0}; Web port owner PID: {1}; matches launcher: {2}; child process: {3}" -f $LauncherProcessId, $ownerProcessId, $matchesLauncher.ToString().ToLowerInvariant(), $isChild.ToString().ToLowerInvariant())
        if (-not $matchesLauncher -and -not $isChild) {
            Write-Warning "Web launcher PID and port owner PID differ; this can be expected when dotnet run starts a child process, but the port owner was verified as ConShield.Web."
        }
    }
    else {
        Write-Host ("Web port owner PID: {0}; verified ConShield.Web." -f $ownerProcessId)
    }
}

function Start-ConShieldApps {
    New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
    $appEnvironment = New-AppEnvironment
    Show-DemoUserEnvironmentSummary

    $listener = Get-WebPortOwner
    if ($null -ne $listener) {
        if (Test-Web) {
            Assert-WebPortOwner
            Write-Host "Web already running (PID $($listener.OwningProcess))."
        } else {
            $owner = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            $ownerName = if ($owner) { $owner.ProcessName } else { "unknown" }
            throw "TCP 5080 is occupied by non-responsive PID $($listener.OwningProcess) ($ownerName). Stop it explicitly and retry."
        }
    } else {
        Write-Step "Starting ConShield.Web"
        $web = Start-Process -FilePath "dotnet" -WorkingDirectory $ProjectRoot -ArgumentList @(
            "run", "--project", ".\src\ConShield.Web\ConShield.Web.csproj",
            "--no-launch-profile", "--urls", $WebUrl
        ) -Environment $appEnvironment -RedirectStandardOutput $WebLog -RedirectStandardError $WebErrorLog -PassThru -WindowStyle Hidden
        Set-Content -LiteralPath $WebPidFile -Value $web.Id -Encoding ASCII
        $deadline = (Get-Date).AddSeconds(90)
        while ((Get-Date) -lt $deadline -and -not (Test-Web)) {
            if ($web.HasExited) { throw "ConShield.Web exited during startup. See $WebErrorLog" }
            Start-Sleep -Seconds 2
            $web.Refresh()
        }
        if (-not (Test-Web)) { throw "ConShield.Web did not respond within 90 seconds. See $WebErrorLog" }
        Write-Host "Web launcher started (PID $($web.Id))."
        Assert-WebPortOwner -LauncherProcessId $web.Id
    }

    $consumer = Get-ConsumerProcess
    if ($null -ne $consumer) {
        Write-Host "EventConsumer already running (PID $($consumer.ProcessId))."
    } else {
        Write-Step "Starting ConShield.EventConsumer"
        $consumerDll = Join-Path $ProjectRoot "src\ConShield.EventConsumer\bin\Release\net8.0\ConShield.EventConsumer.dll"
        if (-not (Test-Path -LiteralPath $consumerDll)) {
            & dotnet build (Join-Path $ProjectRoot "src\ConShield.EventConsumer\ConShield.EventConsumer.csproj") --configuration Release
            if ($LASTEXITCODE -ne 0) { throw "ConShield.EventConsumer build failed." }
        }
        $consumerProcess = Start-Process -FilePath "dotnet" -WorkingDirectory $ProjectRoot -ArgumentList @(
            $consumerDll
        ) -Environment $appEnvironment -RedirectStandardOutput $ConsumerLog -RedirectStandardError $ConsumerErrorLog -PassThru -WindowStyle Hidden
        Set-Content -LiteralPath $ConsumerPidFile -Value $consumerProcess.Id -Encoding ASCII
        Start-Sleep -Seconds 5
        $consumerProcess.Refresh()
        if ($consumerProcess.HasExited) { throw "ConShield.EventConsumer exited during startup. See $ConsumerErrorLog" }
        Write-Host "EventConsumer started (PID $($consumerProcess.Id))."
    }
}

function Invoke-FullTests {
    Write-Step "Restoring tools and solution"
    & dotnet tool restore --configfile $NuGetConfig
    if ($LASTEXITCODE -ne 0) { throw "dotnet tool restore failed." }
    & dotnet restore (Join-Path $ProjectRoot "ConShield.sln") --configfile $NuGetConfig
    if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed." }
    & dotnet build (Join-Path $ProjectRoot "ConShield.sln") --configuration Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw "dotnet build failed." }

    Write-Step "Running the full test suite"
    $testOutput = @(& dotnet test (Join-Path $ProjectRoot "ConShield.sln") --configuration Release --no-build 2>&1)
    $testOutput | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "dotnet test failed." }
    $summaries = @($testOutput | ForEach-Object {
        if ($_ -match 'Failed:\s*(\d+).*Passed:\s*(\d+).*Skipped:\s*(\d+).*Total:\s*(\d+)') {
            [pscustomobject]@{ Failed=[int]$Matches[1]; Passed=[int]$Matches[2]; Skipped=[int]$Matches[3]; Total=[int]$Matches[4] }
        }
    })
    if ($summaries.Count -eq 0) { throw "Could not verify the dotnet test summary." }
    $failed = ($summaries | Measure-Object Failed -Sum).Sum
    $passed = ($summaries | Measure-Object Passed -Sum).Sum
    $skipped = ($summaries | Measure-Object Skipped -Sum).Sum
    $total = ($summaries | Measure-Object Total -Sum).Sum
    "Passed=$passed`nFailed=$failed`nSkipped=$skipped`nTotal=$total" | Set-Content -LiteralPath $TestResultFile -Encoding ASCII
    if ($failed -ne 0 -or $skipped -ne 0) { throw "Full-suite requirement failed: Failed=$failed, Skipped=$skipped." }
}

function Show-Status {
    & docker compose @ComposeArgs ps -a
    $listener = Get-NetTCPConnection -LocalPort 5080 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listener -and (Test-Web)) { Write-Host "Web: running, PID $($listener.OwningProcess), http://127.0.0.1:5080" } else { Write-Host "Web: not running" }
    $consumer = Get-ConsumerProcess
    if ($consumer) { Write-Host "EventConsumer: running, PID $($consumer.ProcessId)" } else { Write-Host "EventConsumer: not running" }
    if (Test-Path -LiteralPath $TestResultFile) { Get-Content -LiteralPath $TestResultFile }
    $vmnet = Get-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet1" -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($vmnet) { Write-Host "Windows VMnet1: $($vmnet.IPAddress)/$($vmnet.PrefixLength)" }
    Write-Host "RabbitMQ: http://localhost:15672"
}

if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "ConShield.sln"))) { throw "Start-ConShield.ps1 must be in the repository root." }
New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
Import-LocalEnv
Set-DerivedEnvironment

if ($StopApps) { Stop-ManagedApps; if (-not $Stop) { Show-Status; exit 0 } }
if ($Stop) {
    Stop-ManagedApps
    Ensure-Docker
    Write-Step "Stopping ConShield containers without removing volumes"
    Invoke-Compose @("stop")
    Show-Status
    exit 0
}
if ($Status) { Show-Status; exit 0 }

Ensure-Docker
Write-Step "Starting PostgreSQL, RabbitMQ, and MongoDB"
Invoke-Compose @("up", "-d", "postgres", "rabbitmq", "mongo")
Wait-Healthy @("conshield-postgres", "conshield-rabbitmq", "conshield-mongo")
Ensure-TestDatabase
Write-Host "Docker services healthy."

if ($RunTests) { Invoke-FullTests }
if ($StartApps) { Start-ConShieldApps }
if ($OpenRabbit) { Start-Process "http://localhost:15672" | Out-Null }
Show-Status
