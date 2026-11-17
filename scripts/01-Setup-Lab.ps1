<#
.SYNOPSIS
  Builds the RBAC lab: security groups + users from data/users.csv.
.DESCRIPTION
  Idempotent - safe to re-run. Users get a random one-time password and must
  change it at first sign-in. Passwords are printed to the console only (never saved to disk).
.EXAMPLE
  ./01-Setup-Lab.ps1 -Domain contoso.onmicrosoft.com -WhatIf
  ./01-Setup-Lab.ps1 -Domain contoso.onmicrosoft.com
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Domain,
    [string]$CsvPath = (Join-Path $PSScriptRoot '../data/users.csv'),
    [string]$UsageLocation = 'KE'
)

. (Join-Path $PSScriptRoot '../lib/Common.ps1')
Connect-EntraLab -Scopes 'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All'

function Get-OrCreateGroup {
    param([string]$Name)
    $g = Get-MgGroup -Filter "displayName eq '$Name'" | Select-Object -First 1
    if ($g) { return $g }
    if ($PSCmdlet.ShouldProcess($Name, 'Create security group')) {
        Write-Host "  + group $Name" -ForegroundColor Cyan
        New-MgGroup -DisplayName $Name `
            -MailEnabled:$false -MailNickname ($Name -replace '[^a-zA-Z0-9]', '') `
            -SecurityEnabled:$true -Description 'Access-management lab: RBAC group'
    }
}

$rows = Import-Csv $CsvPath

# Groups (plus the emergency-access group used by the Conditional Access baseline)
$groupNames = @($rows.Groups -split ';' | Where-Object { $_ } | Sort-Object -Unique) + 'SG-BreakGlass'
$groups = @{}
foreach ($n in $groupNames) { $groups[$n] = Get-OrCreateGroup -Name $n }

# Users
foreach ($row in $rows) {
    $upn = "$($row.Alias)@$Domain"
    $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" | Select-Object -First 1

    if (-not $user) {
        $pw = New-RandomPassword
        $body = @{
            accountEnabled    = $true
            displayName       = $row.DisplayName
            mailNickname      = $row.Alias
            userPrincipalName = $upn
            department        = $row.Department
            jobTitle          = $row.JobTitle
            usageLocation     = $UsageLocation
            passwordProfile   = @{ forceChangePasswordNextSignIn = $true; password = $pw }
        }
        if ($PSCmdlet.ShouldProcess($upn, 'Create user')) {
            $user = New-MgUser -BodyParameter $body
            Write-Host "  + user $upn  (temp password: $pw)" -ForegroundColor Yellow
        }
    }
    else { Write-Host "  = user $upn already exists" }

    if (-not $user) { continue }
    foreach ($gn in ($row.Groups -split ';' | Where-Object { $_ })) {
        $g = $groups[$gn]
        if (-not $g) { continue }
        $already = Get-MgGroupMember -GroupId $g.Id -All | Where-Object Id -eq $user.Id
        if (-not $already -and $PSCmdlet.ShouldProcess("$upn -> $gn", 'Add to group')) {
            New-MgGroupMember -GroupId $g.Id -DirectoryObjectId $user.Id
            Write-Host "    -> added to $gn" -ForegroundColor Cyan
        }
    }
}
Write-Host "`nDone. Create your 2 emergency-access accounts manually and add them to SG-BreakGlass." -ForegroundColor Green
