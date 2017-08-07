<#
.SYNOPSIS
    Deploys enterprise registry configurations for Blue Team
    Operations.

.DESCRIPTION
	Designed to be used with Deploy-Blue.ps1 script.

	# Enter the FQDN of the Windows Event Collector Server
	$collectorServer = "dc01.zulu8.info"

	# Enter the path to store all original system configurations
	$backupDirectory = "C:\Backups"

	# Enter the path to store all transcripts.
	$transcriptDirectory = "\\DC01\Transcripts"

	# Create Group for Special Logon Auditing (Event ID 4964). Add Suspects to Group.
	$specialAuditGroup = 'SpecialAudit'
	$specialGroupString = "S-1-5-113;$((get-adgroup $specialAuditGroup).sid.Value);$((get-adgroup 'domain admins').sid.Value);$((get-adgroup 'enterprise admins').sid.Value)"

	.\Deploy-BlueRegistry.ps1 -ArgumentList $collectorServer,$transcriptDirectory,$specialGroupString

.EXAMPLE
	$collectorServer = "dc01.zulu8.info"
	$backupDirectory = "C:\Backups"
	$transcriptDirectory = "\\DC01\Transcripts"
	$specialAuditGroup = 'SpecialAudit'
	$specialGroupString = "S-1-5-113;$((get-adgroup $specialAuditGroup).sid.Value);$((get-adgroup 'domain admins').sid.Value);$((get-adgroup 'enterprise admins').sid.Value)"

	.\Deploy-BlueRegistry.ps1 -ArgumentList $collectorServer,$transcriptDirectory,$specialGroupString

.NOTES
  Author:
 Version: 1.0
 Updated: 3.Aug.2017
   LEGAL: PUBLIC DOMAIN.  SCRIPT PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF
          ANY KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR
          A PARTICULAR PURPOSE.  ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF
          THE AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF
          ANY SUCH DAMAGE.  IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
          LIABILITY, THEN DELETE THIS FILE SINCE YOU ARE NOW PROHIBITED TO HAVE IT.
#>

[CmdletBinding()]
param
(
	[Parameter(Mandatory=$True,
	HelpMessage='WEC Server')]
	[string]$collectorServer,
	[Parameter(Mandatory=$True,
	HelpMessage='Directory (share) to store transcripts')]
	[string]$transcriptDirectory,
	[Parameter(Mandatory=$True,
	HelpMessage='String of Group SIDs for Special Logon Auditing')]
	[string]$specialGroupString
)

# Step : Set Desired Modifications to Registry
$desiredConfig = @"
regKey,name,value,type
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit","ProcessCreationIncludeCmdLine_Enabled",1,"DWord"
"HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System\Audit","ProcessCreationIncludeCmdLine_Enabled",1,"DWord"
"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa","scenoapplylegacyauditpolicy",1,"DWord"
"HKLM:\System\CurrentControlSet\Control\Lsa\Audit","SpecialGroups",$specialGroupString,"String"
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager",1,"Server=http://$collectorServer`:5985/wsman/SubscriptionManager/WEC,Refresh=10","String"
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager",1,"Server=http://$collectorServer`:5985/wsman/SubscriptionManager/WEC,Refresh=10","String"
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription","EnableTranscripting",1,"DWord"
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription","OutputDirectory",$transcriptDirectory,"String"
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription","EnableTranscripting",1,"DWord"
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription","OutputDirectory",$transcriptDirectory,"String"
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging","EnableScriptBlockLogging",1,"DWord"
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging","EnableScriptBlockLogging",1,"DWord"
"@ | ConvertFrom-Csv


$backupConfig = @()

# Iterate over array of objects containing desired registry configurations, document original config, change target
$backupConfig = $desiredConfig | ForEach-Object {
	if (-Not (Test-Path $_.regKey)) {
		# Registry path does not exist -> create and document DNE
		Write-Warning "Path $($_.regKey) does not exist"
		$null = New-Item $_.regKey -Force
		New-Object PSObject -Property @{regKey = $_.regKey; name = "DNE"; value = "DNE"; type = "DNE"}
	}
	else {
		if ( (Get-ItemProperty $_.regKey | Select-Object -Property $_.name) ) {
			# Registry key exists. Document value
			Write-Warning "Property $($_.name) exists. Documenting Value"
			New-Object PSObject -Property @{regKey = $_.regKey; name = $_.name; value = $(Get-ItemProperty $_.regKey | Select-Object -ExpandProperty $_.name); type = $_.type}
		}
		else {
			# Registry key does not exist. Document DNE
			Write-Warning "Property $($_.name) DNE. Documenting Null"
			New-Object PSObject -Property @{regKey = $_.regKey; name = $_.name; value = "DNE"; type = "DNE"}
		}
	}
	# Set Registry Key to Desired Value
	Set-ItemProperty $_.regKey -Name $_.name -Value $_.value -Type $_.type
} | ConvertTo-Csv -NoTypeInformation

$backupConfig | Out-File C:\$(hostname).reg.orig.csv

