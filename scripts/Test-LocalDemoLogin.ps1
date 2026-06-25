[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [string]$BaseUrl = 'http://127.0.0.1:5080',

    [switch]$SkipDiagnostics
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-SafeInfo {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host $Message
}

function ConvertFrom-SecureStringForRequest {
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

function Get-AntiforgeryToken {
    param([Parameter(Mandatory = $true)][string]$Html)

    $match = [regex]::Match(
        $Html,
        '<input[^>]+name="__RequestVerificationToken"[^>]+value="([^"]+)"',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if (-not $match.Success) {
        $match = [regex]::Match(
            $Html,
            '<input[^>]+value="([^"]+)"[^>]+name="__RequestVerificationToken"',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }

    if (-not $match.Success) {
        throw 'Could not find login form antiforgery token. Token value was not printed.'
    }

    return [System.Net.WebUtility]::HtmlDecode($match.Groups[1].Value)
}

function Get-SafeHeaderValue {
    param(
        [Parameter(Mandatory = $false)]$Headers,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Headers) {
        return $null
    }

    try {
        $keys = @($Headers.Keys)
    }
    catch {
        $keys = @()
    }

    foreach ($key in $keys) {
        if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            try {
                return $Headers[$key]
            }
            catch {
                return $null
            }
        }
    }

    try {
        return $Headers[$Name]
    }
    catch {
        return $null
    }
}

function Invoke-WebRequestNoRedirect {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $false)][string]$Method = 'Get',
        [Parameter(Mandatory = $false)]$Body,
        [Parameter(Mandatory = $true)]$WebSession,
        [Parameter(Mandatory = $false)][int]$TimeoutSec = 10
    )

    $requestErrors = $null
    $request = @{
        Uri                  = $Uri
        WebSession           = $WebSession
        MaximumRedirection   = 0
        SkipHttpErrorCheck   = $true
        TimeoutSec           = $TimeoutSec
        ErrorAction          = 'SilentlyContinue'
        ErrorVariable        = 'requestErrors'
    }

    if ($Method -ne 'Get') {
        $request.Method = $Method
    }

    if ($null -ne $Body) {
        $request.Body = $Body
    }

    $response = Invoke-WebRequest @request
    if ($null -eq $response -and $requestErrors) {
        throw $requestErrors[0]
    }

    return $response
}

$normalizedBaseUrl = $BaseUrl.TrimEnd('/')
$session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()

Write-SafeInfo ("base_url={0}" -f $normalizedBaseUrl)
Write-SafeInfo ("user_name={0}" -f $UserName)
Write-SafeInfo 'Passwords, cookies, antiforgery tokens, and response bodies are not printed.'

if (-not $SkipDiagnostics) {
    try {
        $diagnostics = Invoke-RestMethod `
            -Uri "$normalizedBaseUrl/Account/DemoUserDiagnostics" `
            -WebSession $session `
            -TimeoutSec 5

        Write-SafeInfo ("diagnostics_environment={0}" -f $diagnostics.environment)
        Write-SafeInfo ("diagnostics_configured_demo_user_count={0}" -f $diagnostics.configuredDemoUserCount)
        foreach ($user in @($diagnostics.users)) {
            Write-SafeInfo ("diagnostics_user userName={0} role={1} has_password={2}" -f $user.userName, $user.role, $user.hasPassword)
        }
        foreach ($warning in @($diagnostics.warnings)) {
            Write-Warning ("diagnostics_warning={0}" -f $warning)
        }
    }
    catch {
        Write-Warning ("Diagnostics endpoint unavailable or not Development-only enabled. Details are intentionally non-secret: {0}" -f $_.Exception.Message)
    }
}

$securePassword = Read-Host -Prompt 'Password' -AsSecureString
$plainPassword = ConvertFrom-SecureStringForRequest -SecureValue $securePassword

try {
    $loginGet = Invoke-WebRequest `
        -Uri "$normalizedBaseUrl/Account/Login" `
        -WebSession $session `
        -TimeoutSec 10
    $loginGetStatus = [int]$loginGet.StatusCode
    $token = Get-AntiforgeryToken -Html $loginGet.Content

    $form = @{
        UserName                       = $UserName
        Password                       = $plainPassword
        RememberMe                     = 'false'
        __RequestVerificationToken     = $token
    }

    $loginPost = Invoke-WebRequestNoRedirect `
        -Uri "$normalizedBaseUrl/Account/Login" `
        -Method Post `
        -Body $form `
        -WebSession $session `
        -TimeoutSec 10
    $loginPostStatus = [int]$loginPost.StatusCode
    $loginLocation = Get-SafeHeaderValue -Headers $loginPost.Headers -Name 'Location'

    $authenticatedProbe = Invoke-WebRequestNoRedirect `
        -Uri "$normalizedBaseUrl/Operations/Health" `
        -WebSession $session `
        -TimeoutSec 10
    $probeStatus = [int]$authenticatedProbe.StatusCode
    $probeLocation = Get-SafeHeaderValue -Headers $authenticatedProbe.Headers -Name 'Location'

    $failedByLoginPage = $loginPostStatus -eq 200 -and $loginPost.Content -match 'Неверный логин или пароль'
    $successByRedirect = $loginPostStatus -in @(301, 302, 303, 307, 308) -and ($null -eq $loginLocation -or $loginLocation.ToString() -notmatch '/Account/Login')
    $successByProbe = $probeStatus -eq 200
    $failedByProbeRedirect = $probeStatus -in @(301, 302, 303, 307, 308) -and $null -ne $probeLocation -and $probeLocation.ToString() -match '/Account/Login'

    if ($successByRedirect -or $successByProbe) {
        Write-SafeInfo 'login_result=success'
    }
    elseif ($failedByLoginPage -or $failedByProbeRedirect) {
        Write-SafeInfo 'login_result=failed'
    }
    else {
        Write-SafeInfo 'login_result=unknown'
    }

    Write-SafeInfo ("login_get_status={0}" -f $loginGetStatus)
    Write-SafeInfo ("login_post_status={0}" -f $loginPostStatus)
    Write-SafeInfo ("authenticated_probe_status={0}" -f $probeStatus)

    if (-not ($successByRedirect -or $successByProbe)) {
        exit 1
    }
}
finally {
    $plainPassword = $null
    $securePassword.Dispose()
}
