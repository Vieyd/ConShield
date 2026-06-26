[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$UserName = 'adminib',

    [ValidateNotNullOrEmpty()]
    [string]$OperatorUserName = 'operator',

    [ValidateNotNullOrEmpty()]
    [string]$AdminDisplayName = 'Администратор ИБ',

    [ValidateNotNullOrEmpty()]
    [string]$OperatorDisplayName = 'Оператор',

    [switch]$UseSamePasswordForLocalDemo
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-SafeInfo {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host $Message
}

function ConvertFrom-SecureStringForEnvironment {
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

function Set-DemoUserEnvironmentValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    [Environment]::SetEnvironmentVariable($Name, $Value, 'User')
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
    Write-SafeInfo ("configured_env={0}" -f $Name)
}

Write-SafeInfo 'Configuring local demo users in Windows User environment.'
Write-SafeInfo 'Password values are not printed. No repository files are written.'

$adminSecurePassword = Read-Host -Prompt 'AdminIB demo password' -AsSecureString
$operatorSecurePassword = $null

try {
    if ($UseSamePasswordForLocalDemo) {
        $operatorSecurePassword = $adminSecurePassword.Copy()
    }
    else {
        $operatorSecurePassword = Read-Host -Prompt 'Operator demo password' -AsSecureString
    }

    $adminPassword = ConvertFrom-SecureStringForEnvironment -SecureValue $adminSecurePassword
    $operatorPassword = ConvertFrom-SecureStringForEnvironment -SecureValue $operatorSecurePassword

    if ([string]::IsNullOrWhiteSpace($adminPassword) -or [string]::IsNullOrWhiteSpace($operatorPassword)) {
        throw 'Demo user passwords must not be empty.'
    }

    Set-DemoUserEnvironmentValue -Name 'DemoUsers__0__UserName' -Value $UserName
    Set-DemoUserEnvironmentValue -Name 'DemoUsers__0__Password' -Value $adminPassword
    Set-DemoUserEnvironmentValue -Name 'DemoUsers__0__DisplayName' -Value $AdminDisplayName
    Set-DemoUserEnvironmentValue -Name 'DemoUsers__0__Role' -Value 'AdminIB'

    Set-DemoUserEnvironmentValue -Name 'DemoUsers__1__UserName' -Value $OperatorUserName
    Set-DemoUserEnvironmentValue -Name 'DemoUsers__1__Password' -Value $operatorPassword
    Set-DemoUserEnvironmentValue -Name 'DemoUsers__1__DisplayName' -Value $OperatorDisplayName
    Set-DemoUserEnvironmentValue -Name 'DemoUsers__1__Role' -Value 'Operator'

    Write-SafeInfo ("DemoUsers__0 configured: {0}" -f (-not [string]::IsNullOrWhiteSpace($UserName)).ToString().ToLowerInvariant())
    Write-SafeInfo ("DemoUsers__0 password present: {0}" -f (-not [string]::IsNullOrWhiteSpace($adminPassword)).ToString().ToLowerInvariant())
    Write-SafeInfo ("DemoUsers__1 configured: {0}" -f (-not [string]::IsNullOrWhiteSpace($OperatorUserName)).ToString().ToLowerInvariant())
    Write-SafeInfo ("DemoUsers__1 password present: {0}" -f (-not [string]::IsNullOrWhiteSpace($operatorPassword)).ToString().ToLowerInvariant())
    Write-SafeInfo 'Restart Web after changing demo-user environment variables.'
    Write-SafeInfo 'Verification command: pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoUserPassword.ps1 -UserName adminib'
}
finally {
    $adminPassword = $null
    $operatorPassword = $null
    if ($null -ne $operatorSecurePassword) { $operatorSecurePassword.Dispose() }
    $adminSecurePassword.Dispose()
}
