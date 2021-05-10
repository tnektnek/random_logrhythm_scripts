 <#
    .SYNOPSIS
        Take any availabile C2 Feed to auto-import IPv4 addresses into LogRhythm as a List through its Admin API.
    .DESCRIPTION
        Creates a new LogRhythm List using New-LrList called NCI : C2 IOC IP Addresses if not found. 
        Add-LrListItem adds the supplied object to the specified list.
        Having LogRhythm.Tools setup with the LogRHythm API key and network connectivity to the PM is a hard requirement.
    .EXAMPLE
        PS C:\> ImportIPv4_IOCs.ps1 -uri 'https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt'
#>

[CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $uri
    )
# $uri = 'https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt'
try {
    $Response = Invoke-RestMethod $uri -Method 'Get' -SkipCertificateCheck
}
catch {
    $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
    Write-Verbose "Exception Message: $ExceptionMessage"
    return $ExceptionMessage
}
$IPv4Regex = '(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)'
$iocs = (irm $uri).Split(",")
$iocs = [regex]::Matches($iocs, $IPv4Regex) | %{ $_.Groups[1].Value} | Select-Object -Unique

try {
    Write-Host "----- Importing LogRhythm Tools Module -----" -ForegroundColor Green
    Import-Module LogRhythm.Tools
    $lrlistname = 'NCI : C2 IOC IP Addresses'
    if ((Get-LrList -Name $lrlistname) -eq $null) { 
        New-LrList -Name $lrlistname -ListType 'ip'
    }
    ForEach ($ioc in $iocs) {
        Write-Host "----- Adding new IOC Entry ($ioc) into $lrlistname -----"
        Add-LrListItem -Name $lrlistname -Value $ioc
    }
catch { 
    Write-Host "----- Failed to Import LogRhythm Tools Module to Import -----" -ForegroundColor Red
}
