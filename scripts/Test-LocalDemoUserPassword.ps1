[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [string]$BaseUrl = 'http://127.0.0.1:5080'
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

$normalizedBaseUrl = $BaseUrl.TrimEnd('/')

Write-SafeInfo ("base_url={0}" -f $normalizedBaseUrl)
Write-SafeInfo ("user_name={0}" -f $UserName)
Write-SafeInfo 'Passwords and response bodies are not printed.'

$securePassword = Read-Host -Prompt 'Password' -AsSecureString
$plainPassword = ConvertFrom-SecureStringForRequest -SecureValue $securePassword

try {
    $body = @{
        userName = $UserName
        password = $plainPassword
    } | ConvertTo-Json -Compress

    $verify = Invoke-RestMethod `
        -Uri "$normalizedBaseUrl/Account/DemoUserDiagnostics/VerifyPassword" `
        -Method Post `
        -ContentType 'application/json' `
        -Body $body `
        -TimeoutSec 10

    Write-SafeInfo ("verify_environment={0}" -f $verify.environment)
    Write-SafeInfo ("verify_user_found={0}" -f $verify.userFound)
    Write-SafeInfo ("verify_has_configured_password={0}" -f $verify.hasConfiguredPassword)
    Write-SafeInfo ("verify_role={0}" -f $verify.role)
    Write-SafeInfo ("password_match={0}" -f $verify.passwordMatches)

    if ($verify.passwordMatches -ne $true) {
        exit 1
    }
}
catch {
    Write-Warning ("Password verification endpoint unavailable or failed. Details are intentionally non-secret: {0}" -f $_.Exception.Message)
    exit 1
}
finally {
    $body = $null
    $plainPassword = $null
    $securePassword.Dispose()
}
