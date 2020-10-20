# Requires -Version 3.0
# Point is that it functions as a slightly more in-depth notification that provides CC addresses when a SmartResponse notification for approval is required. 
# Takes alarm information from the DB and adds it in the body for the SMTP notification. 
#
# Usage: 
# Generally run from an agent or ARM with access to DB

[CmdLetBinding()]
param( 
    [switch]$sendEmail = $false,
    [string]$smtpServer,
    [string]$emailFrom,
    [string]$emailTo,
    [string]$ccAddress,
    [string]$alarmID
)

try
{
    $EMDBServer = "localhost"
    $DB = "master"
    $Security = "Integrated Security=sspi"

    $ConnectionString = "server=" + $EMDBServer + ";database=" + $DB + ";" + $Security
    $CommandText = "Retrieve alarm information"

    # Prepared SQL statements
    $alarmname = "select a2.Name from LogRhythm_Alarms.dbo.alarm as a left join logrhythmemdb.dbo.aierule as a2 on a2.AlarmRuleID = a.AlarmRuleID where a.AlarmID = " + $alarm + ";"
    $smartresponsename = "SELECT Name FROM [LogRhythm_Alarms].[dbo].[AutoRmdnAction] where AlarmID = " + $alarm + ";"
    Invoke-Sqlcmd -ConnectionString $ConnectionString -Query $alarmname
    Invoke-Sqlcmd -ConnectionString $ConnectionString -Query $smartresponsename
}

catch{
    write-error "Error : Incorrect Alarm ID"
    throw "ExecutionFailure"
}

if ( $smtpServer ) {
    function sendEmail {
        $msg = New-Object System.Net.Mail.MailMessage
        $smtp = New-Object System.Net.Mail.SMTPClient($smtpServer)
        $msg.From = $emailFrom
        $msg.To.Add($emailTo)
        $msg.cc.Add($ccAddress)
        $msg.Subject = "LogRhythm Smart Response Pending Approval (AlarmID: $alarmID)"
        $msg.Body = @"
<html><head></head><body>
<center><br />
<p style='font:16px Lucida Console,Monaco,monospace;'>
Please reply to this email with "APPROVE" or "DENY" to proceed with SmartResponse workflow for actioning. `n 
AlarmID: $alarm `n
Alarm Rule: $alarmrulename `n

</center>
</p>
</body></html>
"@
        $msg.IsBodyHTML = $true
        $smtp.Send($msg)
    }
    Write-Host ""
    Write-Host "     Sending email using SMTP Server: $smtpServer"
    sendEmail
    Write-Host "     Message From : $emailFrom"
    Write-Host "     Message To : $emailTo"
    Write-Host "     Ccing To : $ccAddress"
    Write-Host "     Subject : LogRhythm Smart Response Pending Approval (AlarmID: $alarmID)"
    Write-Host ""
}
