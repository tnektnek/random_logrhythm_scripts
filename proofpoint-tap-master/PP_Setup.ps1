# If your LogRhythm Agent runs as a user other than NT AUTHORITY\SYSTEM, put that in the variable below:
# EG MYDOMAIN\LogRhythm
$agent_user = ''

#Requires -RunAsAdministrator

$path       = 'C:\Proofpoint_TAP\'

If(!(Test-Path $path))
{ New-Item -ItemType Directory -Force -Path $path
}

$date = (Get-Date)
##### Create our scheduled task #####
$executable = "$path\PP_TAP.ps1"
$conf_script = "$path\PP_CONF.ps1"
$taskName   = 'Download Proofpoint TAP logs for LogRhythm'
$taskConfName = 'Creating PP TAP credentials under Local System'

$action   = New-ScheduledTaskAction -Execute "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoLogo -NonInteractive -ExecutionPolicy Bypass -NoProfile -File $path\PP_Tap.ps1"
$action2   = New-ScheduledTaskAction -Execute "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoLogo -NonInteractive -ExecutionPolicy Bypass -NoProfile -File $path\PP_Conf.ps1"
$trigger  = New-ScheduledTaskTrigger -At $date -Once -RepetitionInterval (New-TimeSpan -Minutes 10) 
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 4)

If($agent_user -eq "") {
    try {
      Write-Host "Creating scheduled task as local SYSTEM user."
      Register-ScheduledTask -ErrorAction Stop -TaskName $taskName -Trigger $trigger -Action $action -Setting $settings -User "NT AUTHORITY\SYSTEM" -RunLevel 1
      Register-ScheduledTask -ErrorAction Stop -TaskName $taskConfName -Trigger $trigger -Action $action2 -Setting $settings -User "NT AUTHORITY\SYSTEM" -RunLevel 1
    } catch {
      Write-Host $_.Exception
      Write-Host "Scheduled task already exists, skipping."
    }
    Set-ScheduledTask -TaskName $taskName -Trigger $trigger
    Set-ScheduledTask -TaskName $taskConfName -Trigger $trigger
}
else {
      try {
      Write-Host "Creating scheduled task as specified service account user."
      Register-ScheduledTask -ErrorAction Stop -TaskName $taskName -Trigger $trigger -Action $action -Setting $settings -User $agent_user -RunLevel 1
      Register-ScheduledTask -ErrorAction Stop -TaskName $taskConfName -Trigger $trigger -Action $action2 -Setting $settings -User $agent_user -RunLevel 1
    } catch {
      Write-Host $_.Exception
      Write-Host "Scheduled task already exists, skipping."
    }
    Set-ScheduledTask $taskName -Trigger $trigger  
    Set-ScheduledTask -TaskName $taskConfName -Trigger $trigger
}

