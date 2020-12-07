[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Serviceprincipal,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Secret
)
$global:xmlconfiguration = "C:\Proofpoint_TAP\PP_TAP_CONFIG.xml"

# Function to Create Hashtable for the parameters

function Create-Hashtable
{
	$global:HashTable = [PSCustomObject]@{ "Serviceprincipal" = $SecureSP
										"Secret" = $SecureSecret
						}
}

function Create-ConfigFile
{
	$global:HashTable | Export-Clixml -Path $xmlconfiguration
	write-host "Configuration Parameters saved"
	
}

$SecureSP = $Serviceprincipal | ConvertTo-SecureString -AsPlainText -Force
$SecureSecret  = $Secret | ConvertTo-SecureString -AsPlainText -Force

Create-Hashtable
Create-ConfigFile