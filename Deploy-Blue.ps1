<#
.SYNOPSIS
    Remotely configures auditing and logging for Blue Team Operations wihtout
    reliance on Active Directory or Group Policy.

.DESCRIPTION
	Given:
		1) a list of hostnames as scope
		2) a FQDN of the designated Windows Event Collector Server
		3) a directory for backing up current configs
		4) an smb share for remotely saving transcripts
	The following script will remotely set advanced audit levels, enable
	command line process auditing, enable powershell transcription, enable
	powershell script block logging, configure Windows Event Forwarding,
	install and configure Sysmon.

	Configure-Sensors
	 	configures the above listed settings
	Restore-Sensors
		returns systems to their original configuration

	Tested on:
		Windows Server 2012R2 (PS Version 5.1)
		Windows 10 (PS Version 5.0)

.EXAMPLE
	./Deploy-Blue.ps1
	Configure-Sensors
	Restore-Sensors

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

# Enter the FQDN of the Windows Event Collector Server
$collectorServer = "dc01.zulu8.info"

# Enter the path to store all original system configurations
$backupDirectory = "C:\Backups"

# Enter the path to store all powershell transcripts
$transcriptDirectory = "\\DC01\Transcripts"

# Sysmon Configuration File
$sysmonConfigFile = "C:\exampleSysmonConf.xml"

# Define all target systems in scope. Use Hostname.
$targetSystems = @(
    'pc02win10'
)

# Setup Windows Event Collector Server
Invoke-Command -ComputerName $collectorServer -ScriptBlock {wecutil qc /quiet}

# Create Group for Special Logon Auditing (Event ID 4964). Add Suspects to Group.
$specialAuditGroup = 'SpecialAudit'
New-ADGroup $specialAuditGroup -GroupScope "Global"
$specialGroupString = "S-1-5-113;$((get-adgroup $specialAuditGroup).sid.Value);$((get-adgroup 'domain admins').sid.Value);$((get-adgroup 'enterprise admins').sid.Value)"

# Define Desired State for Registry Entries
$regConfig = @"
regKey,name,value,type
"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa","scenoapplylegacyauditpolicy",1,"DWord"
"HKLM:\System\CurrentControlSet\Control\Lsa\Audit","SpecialGroups",$specialGroupString,"String"
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit","ProcessCreationIncludeCmdLine_Enabled",1,"DWord"
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription","EnableTranscripting",1,"DWord"
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription","OutputDirectory",$transcriptDirectory,"String"
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging","EnableScriptBlockLogging",1,"DWord"
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager",1,"Server=http://$collectorServer`:5985/wsman/SubscriptionManager/WEC,Refresh=10","String"
"HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System\Audit","ProcessCreationIncludeCmdLine_Enabled",1,"DWord"
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription","EnableTranscripting",1,"DWord"
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription","OutputDirectory",$transcriptDirectory,"String"
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging","EnableScriptBlockLogging",1,"DWord"
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager",1,"Server=http://$collectorServer`:5985/wsman/SubscriptionManager/WEC,Refresh=10","String"
"@


$sysmonConfig = Get-Content $sysmonConfigFile


function Configure-Sensors
{

	foreach ($i in $targetSystems)
	{
		$s = New-PSSession -ComputerName $i
	# Audit Config
		# Backup Current Audit Config to C:\<hostname>.auditpolicy.orig.csv
		# Set New Audit Policy
		Invoke-Command -Session $s -ScriptBlock {
			&auditpol.exe /backup /file:C:\$(hostname).audit.orig.csv
			&auditpol.exe /set /subcategory:"Special Logon","Logon","Directory Service Access","Directory Service Changes","Credential Validation","Kerberos Service Ticket Operations","Kerberos Authentication Service","Computer Account Management","Other Account Management Events","Security Group Management","User Account Management","DPAPI Activity","Process Creation","IPsec Driver","Security State Change","Security System Extension","System Integrity","Removable Storage" /success:enable /failure:enable
			&auditpol.exe /set /subcategory:"Logoff","Account Lockout" /success:enable
		}

		# Get Auditpol Config Backup and Store to Backup Folder
		$auditBackup = Invoke-Command -Session $s -ScriptBlock {
			Get-Content "C:\$(hostname).audit.orig.csv"
			Remove-Item "C:\$(hostname).audit.orig.csv"
		}

	# PowerShell and WEF Config
		$regBackup = @()

		# Iterate over array of objects containing desired registry configurations, document original config
		$regBackup = Invoke-Command -Session $s -Script {
			param([string[]]$regConfig)
			$regConfig | ConvertFrom-Csv | ForEach-Object {
				if (-Not (Test-Path $_.regKey)) {
					# Registry path does not exist -> create and document DNE
					Write-Warning "Path $($_.regKey) does not exist"
					$null = New-Item $_.regKey -Force
					New-Object PSObject -Property @{regKey = $_.regKey; name = "DNE"; value = "DNE"; type = "DNE"}
				}
				else {
					if (Get-ItemProperty $_.regKey | Select-Object -Property $_.name) {
						# Registry key exists. Document value
						Write-Warning "Key $($_.regKey) if $(Get-ItemProperty $_.regKey | Select-Object -Property $_.name)"
						Write-Warning "Property $($_.name) exists. Documenting Value: $(Get-ItemProperty $_.regKey | Select-Object -ExpandProperty $_.name)"
						# Handle Cases where SubscriptionManager value already exists.
						if ($_.regKey -like "*SubscriptionManager*") {
							Write-Warning "RegKey is Like SubscriptionManager"
							Write-Warning "Property = $($_.name)"
							$wecNum = 1
							# Backup each currently configured SubscriptionManager values.
							while ( (Get-ItemProperty $_.regKey | Select-Object -ExpandProperty $([string]$wecNum) -ErrorAction SilentlyContinue) ) {
								Write-Warning "RegKey with property = $wecNum exists"
								New-Object PSObject -Property @{regKey = $_.regKey; name = $wecNum; value = $(Get-ItemProperty $_.regKey | Select-Object -ExpandProperty $([string]$wecNum)); type = $_.type}
								Write-Warning "Incrementing wecNum"
								$wecNum++
							}
						}
						# Backup all non-SubscriptionManager values to array.
						else {
							New-Object PSObject -Property @{regKey = $_.regKey; name = $_.name; value = $(Get-ItemProperty $_.regKey | Select-Object -ExpandProperty $_.name); type = $_.type}
						}
					}
					else {
						# Registry key does not exist. Document DNE
						Write-Warning "Property $($_.name) DNE. Documenting Null"
						New-Object PSObject -Property @{regKey = $_.regKey; name = $_.name; value = "DNE"; type = "DNE"}
					}
				}
			} | ConvertTo-Csv -NoTypeInformation
			Write-Warning "wecNum = $wecNum"
			# Set Registry Key to Desired Value
			$regConfig | ConvertFrom-Csv | ForEach-Object {
				if ($_.regKey -like "*SubscriptionManager*") {
					# Add our configuration for WEC SubscriptionManager to the list instead of overwrite
					Set-ItemProperty $_.regKey -Name $wecNum -Value $_.value -Type $_.type
				}
				else {
					Set-ItemProperty $_.regKey -Name $_.name -Value $_.value -Type $_.type
				}
			}
		} -Args (,$regConfig)

		# Pull wecNum value from remote system
		$wecNum = Invoke-Command -Session $s -Script {$wecNum}
		Write-Warning "wecNum = $wecNum"

	# Install Sysmon
		Copy-Item "C:\Sysmon64.exe" -Destination "C:\Sysmon64.exe" -ToSession $s

		$sysmonBackup = Invoke-Command -Session $s -ScriptBlock {
			param([string[]]$sysmonConfig)
			if ((Get-Service Sysmon) -ne $null) {
				Write-Warning "Sysmon service present. Documenting Config."
				$sysmonBackup = $(&sysmon -c)
				$sysmonBackup #| select -Skip 5
				Remove-Item "C:\Sysmon64.exe"
			}
			else {
				Write-Warning "Sysmon DNE. Installing"
				&C:\Sysmon64.exe -i -accepteula > null 2>&1
				Write-Warning "Changing config to desired state."
				$sysmonConfig | Out-File "C:\sysmonConfig.xml"
				&C:\Sysmon64.exe -c "C:\sysmonConfig.xml" > null 2>&1
				Remove-Item "C:\Sysmon64.exe"
				Remove-Item "C:\sysmonConfig.xml"
				$sysmonBackup = "DNE"
				$sysmonBackup
			}
		} -Args (,$sysmonConfig)


	# Backup all configs to single .ps1 file named <hostname>.config.ps1
		# Backup original audit configuration
		Write-Output "`$auditBackup `= `@`"" | Out-File "$backupDirectory\$i.config.ps1" -Force
		$auditBackup | Add-Content "$backupDirectory\$i.config.ps1"
		Write-Output "`"`@" | Add-Content "$backupDirectory\$i.config.ps1"
		Write-Output "" | Add-Content "$backupDirectory\$i.config.ps1"
		# Backup Registry values before PS script block logging, transcription, and WEF
		Write-Output "`$regBackup `= `@`"" | Add-Content "$backupDirectory\$i.config.ps1"
		$regBackup | Add-Content "$backupDirectory\$i.config.ps1"
		Write-Output "`"`@" | Add-Content "$backupDirectory\$i.config.ps1"
		Write-Output "" | Add-Content "$backupDirectory\$i.config.ps1"
		# Backup number of SubscriptionManagers configured before adding ours
		Write-Output "`$wecNum `= $wecNum" | Add-Content "$backupDirectory\$i.config.ps1"
		Write-Output "" | Add-Content "$backupDirectory\$i.config.ps1"
		# Backup sysmon schema configuration
		Write-Output "`$sysmonBackup `= `@`"" | Add-Content "$backupDirectory\$i.config.ps1"
		$sysmonBackup | Add-Content "$backupDirectory\$i.config.ps1"
		Write-Output "`"`@" | Add-Content "$backupDirectory\$i.config.ps1"

	# Cleanup Session
		Remove-PSSession $s
	}
}


function Restore-Sensors
{
	foreach ($i in $targetSystems)
	{
		$s = New-PSSession -ComputerName $i

		# Read in backup configuration
		. "$backupDirectory\$i.config.ps1"

	# Audit Cleanup
		# Restore original config
		Invoke-Command -Session $s -Script {
			param([string[]]$auditBackup)
			$auditBackup | Out-File "C:\$(hostname).audit.orig.csv" -Force
			&auditpol.exe /restore /file:C:\$(hostname).audit.orig.csv
			Remove-Item "C:\$(hostname).audit.orig.csv"
		} -Args (,$auditBackup)

	# PowerShell and WEF Config
		# Configure Registry
		Write-Warning "wecNum = $wecNum"

		# Restore original registry config
		Invoke-Command -Session $s -Script {
			param([string[]]$regBackup)
			$regBackup | ConvertFrom-Csv | ForEach-Object {
				if ($_.name -eq "DNE") {
					Write-Warning "Removing Path: $($_.regKey)"
					Remove-Item $_.regKey -ErrorAction SilentlyContinue
				}
				elseif ($_.value -eq "DNE") {
					Write-Warning "Removing Key: $($_.name) with Value: $($_.value)"
					Remove-ItemProperty $_.regKey -Name $_.name -ErrorAction SilentlyContinue
				}
				else {
					Write-Warning "On $(hostname) name: $($_.name) value: $($_.value) type: $($_.type)"
					Set-ItemProperty $_.regKey -Name $_.name -Value $_.value -Type $_.type
					if ($_.regKey -like "*SubscriptionManager*") {
						Write-Warning "RegKey is Like SubscriptionManager"
						Write-Warning "Property = $($_.name)"
						# Add our configuration for WEC SubscriptionManager to the list instead of overwrite
						Write-Warning "wecNum = $Using:wecNum"
						Remove-ItemProperty $_.regKey -Name $Using:wecNum  -ErrorAction SilentlyContinue
					}
				}
			}
		} -Args (,$regBackup)

	# Sysmon
		#Uninstall:  Sysmon.exe –u
		if ($sysmonBackup -contains "DNE") {
			Write-Warning "Sysmon not present on deployment. Uninstall."
			Invoke-Command -Session $s -ScriptBlock {
				&sysmon -u
			}
		}
		else {
			Write-Warning "Sysmon present before deployment. Do nothing."
		}


	# Cleanup Session
		Remove-PSSession $s
	}
}



