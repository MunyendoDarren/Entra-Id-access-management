# Shared helpers - dot-source with:  . (Join-Path $PSScriptRoot '../lib/Common.ps1')
$script:RepoRoot = Split-Path $PSScriptRoot -Parent

function Connect-EntraLab {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Scopes)

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph SDK missing. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
    }
    # Delegated, least-privilege scopes: you consent only to what each script needs.
    Connect-MgGraph -Scopes $Scopes -NoWelcome
    $ctx = Get-MgContext
    Write-Host "Connected to tenant $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Green
}

function Get-ReportPath {
    param([Parameter(Mandatory)][string]$Name)
    $dir = Join-Path $script:RepoRoot 'reports'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    Join-Path $dir ("{0}-{1:yyyyMMdd-HHmm}.csv" -f $Name, (Get-Date))
}

function New-RandomPassword {
    param([int]$Length = 20)
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+'.ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    do {
        $bytes = New-Object byte[] $Length
        $rng.GetBytes($bytes)
        $pw = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    } until ($pw -cmatch '[a-z]' -and $pw -cmatch '[A-Z]' -and $pw -match '\d' -and $pw -match '[^a-zA-Z0-9]')
    $pw
}
