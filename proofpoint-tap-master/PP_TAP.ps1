# PP_TAP Powershell Script to Query PP TAP API
# Last updated 10/20/2020 by Kent Mei kmei@novacoast.com
# First use PP_Conf.ps1 to initialize a hashtable for PP TAP credentials and using securestring to encrypt
# ################################
# Define Parameters for the script
# ################################
[CmdletBinding()]
param(
    $MaxLogFileSizeBytes = 10 * 1000 * 1000,
    [switch]$DebugOutput             
)

# File directories
$global:installpath = "C:\Proofpoint_TAP"

$statepath = "$installpath\State"
If(!(Test-Path $Statepath))
{ New-Item -ItemType Directory -Force -Path $statepath
}
$eventpath = "$installpath\Events"
If(!(Test-Path $eventpath))
{ New-Item -ItemType Directory -Force -Path $eventpath
}
$logpath = "$installpath\Log"
If(!(Test-Path $logpath))
{ New-Item -ItemType Directory -Force -Path $logpath
New-Item -Path $logpath -Name "PP_TAP.log" -ItemType File
}

$stateFile = "$statepath\PP_TAP.pos"
$eventsFile = "$eventpath\PP_TAP.txt"
$logFile = "$logpath\PP_TAP.log"
$global:xmlconfiguration = "$installpath\PP_TAP_CONFIG.xml"


# Datetime format for the state file
$StateFileFormat = "yyyy-MM-ddTHH:mm:ss"
# Proofpoint TAP SIEM API 
$APIendpoint = "https://tap-api-v2.proofpoint.com"
$ALLEVENTS = "/v2/siem/all?format=syslog&sinceSeconds="
$sinceSeconds = "600"
$Uri = ($APIendpoint + $ALLEVENTS + $sinceSeconds)

# If we're in debug mode, tell Powershell to write output to console
if ($DebugOutput) {
    $DebugPreference = "Continue"
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Information',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    [pscustomobject]@{
        Time     = (Get-Date -Format "dd-MMM-yyyy HH:mm:ss.fff")
        Severity = $Severity
        Message  = $Message
    } | Export-Csv -Path $logfile -Append -NoTypeInformation
}

function Get-ConfigFileData
{
	try{
		if (!(Test-Path -Path $xmlconfiguration))
		{
            write-host "No Config File Found."
            Write-Log -Message ("No config file found.") -Severity Information
			throw "ExecutionFailure"
		}
		else
		{
            Write-Log -Message ("Config file found. Attempting to access credentials.") -Severity Information
            $ConfigFileContent = Import-Clixml -Path $global:xmlconfiguration
            $EncryptedServiceprincipal = $ConfigFileContent.Serviceprincipal
            $EncryptedSecret = $ConfigFileContent.Secret
            $global:PlainServiceprincipal = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($EncryptedServiceprincipal))))
            $global:PlainSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($EncryptedSecret))))
        }
	}
	catch{
		$message = $_.Exception.message
		if($message -eq "ExecutionFailure"){
			throw "ExecutionFailure"
		}
		else{
            Write-Log -Message ("Error: User or script running does not have access to configuration file for credentials.") -Severity Information
            Write-Log -Message ($message) -Severity Information
            write-host "Error: User does not have access to Config File."
			throw "ExecutionFailure"
		}
    }
}

# Check if log file exists
if (Test-Path $logfile) {

    # Check if the log file is larger than the Max allowable log file size
    if ((Get-Item $logfile).Length -ge $MaxLogFileSizeBytes) {

        # If so, clear the log file to start fresh
        Clear-Content $logfile
        Write-Debug ("Log File " + $logfile + " exceeded " + $MaxLogFileSizeBytes.ToString() + " bytes; truncating.")
        Write-Log -Message ("Log File " + $logfile + " exceeded " + $MaxLogFileSizeBytes.ToString() + " bytes; truncating.") -Severity Information
    }
}

# Check if the state file exists
if (Test-Path $StateFile) {
    Write-Debug ("State file " + $StateFile + " exists.")
    Write-Log -Message ("State file " + $StateFile + " exists.") -Severity Information

    try {
        $StateContent = Get-Content $StateFile
 
        # Attempt to parse the state file
        $StartTime = [datetime]::ParseExact($StateContent, $StateFileFormat, $null).ToUniversalTime()
    }
    catch {
 
        # If the state file doesn't contain a valid date, use the default
        $StartTime = $DefaultStartTime
        Write-Debug "Failed to parse date from the state file"
        Write-Debug $_.Exception

        Write-Log -Message "Failed to parse date from the state file" -Severity Error
        Write-Log -Message $_.Exception -Severity Error
    }
}
else {
    Write-Debug "State file did not exist, using default start time"
    Write-Log -Message "State file did not exist, using default start time" -Severity Information
}

Write-Log -Message ("Requesting PP_TAP logs from " + ($sinceSeconds) + " seconds ago") -Severity Information

# Declaring header variables
Write-Log -Message ("Accessing Config File Data for Credentials") -Severity Information
Get-ConfigFileData

$Serviceprincipal = $global:PlainServiceprincipal
$Secret = $global:PlainSecret
$credentialpair = "$($Serviceprincipal):$($Secret)"
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credentialpair))
$basicAuthValue = "Basic $encodedCreds"
$Headers = @{
    Authorization = $basicAuthValue
}
# Using TLS 1.2 and other TLS bypass for .X509 certificates
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback=@"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore();



# Invoking-web request 
Write-Log -Message ("Calling Proofpoint TAP API: " + $Uri) -Severity Information

try{ 
    Write-Host "Calling Proofpoint TAP API"
    $Response = (Invoke-Webrequest -Uri $Uri -Headers $Headers -UseBasicParsing)
    Write-Log -Message ("Proofpoint TAP API Returned " + $Response.statusdescription + ".") -Severity Information
    Write-Host Proofpoint TAP API returned $Response.statusdescription $Response.Statuscode
    $Output = $Response.content
    $Statuscode = $Response.StatusCode
    $desc = $Response.statusdescription
}
catch [System.Net.WebException] {   
    $reader = $_.Exception.Response.GetResponseStream()
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $errmsg = $reader.ReadToEnd() | ConvertFrom-Json
    Write-Host "API webrequest outbound failed."
    Write-Host $errmsg
    Write-Log -Message "$errmsg"
    throw "ExecutionFailure"
}

# 200 Response (Content Found)
if ($Statuscode -eq 200) {
    Write-Host "HTTP $Statuscode Found logs and now writing content to $eventsfile"
    Write-Log -Message ("HTTP " + $Statuscode +" Found logs and now writing to " + $eventsfile) -Severity Information
    
    # If number of received events is greater than 0
    if ((@($Response.Content).Length.ToString()) -gt 0) {
        try {
            # Get the last date entry in the response
            $EndTime = ($Response.content -split '\s')[1].Trim()
        }
        catch {
            Write-Error "Could not get last date entry from received events"
            Write-Debug $_.Exception

            Write-Log -Message "Could not get last date entry from received events" -Severity Warning
            Write-Log -Message $_.Exception -Severity Error
        }
        try {
            # Add the last date entry to the StateFile
            [datetime]::parseexact($EndTime, 'yyyy-MM-ddTHH:mm:ssZ', $null).ToString('yyyy-MM-ddTHH:mm:ss') | Out-File $StateFile
        }   
        catch {
            Write-Error ("Could not write timestamp to state file: " + $StateFile + ". This may result in duplicate logs")
            Write-Debug $_.Exception

            Write-Log -Message ("Could not write timestamp to state file: " + $StateFile + ". This may result in duplicate logs") -Severity Warning
            Write-Log -Message $_.Exception -Severity Error
        }
    }

    # Check if events file exists
    if (Test-Path $eventsfile) {
        Write-Log -Message ("Found $eventsfile") -Severity Information
        # Check if the events file is larger than the Max allowable log file size
        Write-Log -Message ("Checking if length of Event file is greater than or equal to $MaxLogFileSizeBytes") -Severity Information
        if ((Get-Item $eventsfile).Length -ge $MaxLogFileSizeBytes) {
            # If so, clear the log file to start fresh
            Clear-Content $eventsfile
            Write-Debug ("Events File " + $eventsfile + " exceeded " + $MaxLogFileSizeBytes.ToString() + " bytes; truncating.")
            Write-Log -Message ("Events File " + $eventsfile + " exceeded " + $MaxLogFileSizeBytes.ToString() + " bytes; truncating.") -Severity Information
        }
        else {
            Write-Log -Message ("No need to rotate file, appending output") -Severity Information
            try {
                # Export the logs, appending to the log file
                $Output + "`n" | Out-File $EventsFile -Append -Encoding UTF8

                Write-Debug ("Wrote " + (@($Response.Content).Length.ToString()) + " logs to file " + $EventsFile)
                Write-Log -Message ("Wrote " + (@($Response.Content).Length.ToString()) + " logs to file " + $EventsFile) -Severity Information
            }
            catch {
                Write-Error ("Could not write logs to the file " + $EventsFile)
                Write-Debug $_.Exception

                Write-Log -Message ("Could not write logs to the events file: " + $EventsFile) -Severity Warning
                Write-Log -Message $_.Exception -Severity Error
                exit
            }
        } 
    }
    else {
        Write-Log -Message ("No Events file found, creating $EventsFile") -Severity Information
        New-Item -Path $Eventpath -Name "PP_TAP.txt" -ItemType File
        try {
            # Export the logs, appending to the log file
            $Output + "`n" | Out-File $EventsFile -Append -Encoding UTF8

            Write-Debug ("Wrote " + (@($Response.Content).Length.ToString()) + " logs to file " + $EventsFile)
            Write-Log -Message ("Wrote " + (@($Response.Content).Length.ToString()) + " logs to file " + $EventsFile) -Severity Information
        }
        catch {
            Write-Error ("Could not write logs to the file " + $EventsFile)
            Write-Debug $_.Exception

            Write-Log -Message ("Could not write logs to the events file: " + $EventsFile) -Severity Warning
            Write-Log -Message $_.Exception -Severity Error
            exit
        }
    }  
}
# 204 Response (No Content)
elseif ($Statuscode -eq 204) {
    Write-Host "HTTP 204. No available content to return at the moment."
    Write-Log -Message ("Returned $Statuscode" ) -Severity Information
    Write-Log -Message ("No available content within " + $sinceSeconds + "seconds" ) -Severity Information
}

# 400 Response (invalid credentials)
elseif ($Statuscode -eq 400) {
    Write-Host "HTTP 400. Service credentials incorrect."
    Write-Log ("Service Credentials incorrect. $Statuscode Error")
} 
else {
    Write-Host "Either no new events or error retrieving events from TAP API. Returned raw message:" $response.RawContent
    Write-Log -Message ("Either no new events or error retrieving events from TAP API. Returned " + $desc) -Severity Information
}

