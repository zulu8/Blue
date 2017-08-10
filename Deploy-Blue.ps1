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

.EXAMPLE
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

# Enter the path to store all hashes of configs. This is required for monitoring deployed configs.
$transcriptDirectory = "\\DC01\Transcripts"

# Sysmon Configuration File
$symonConfigFile = "C:\example2.xml"

# Define all target systems in scope FQDN or Netbios name
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



$sysmonConfig = @"
<?xml version="1.0"?>
<Sysmon schemaversion="3.10">
  <!-- Capture SHA256 and IMPHASH Hashes -->
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <EventFiltering>
    <!-- Log all drivers loads except if the signature is Microsoft Windows -->
  	<DriverLoad onmatch="exclude">
          <Signature condition="is">Microsoft Windows</Signature>
    </DriverLoad>
	<!-- Log all images except if it's Microsoft or Windows signed -->
	<ImageLoad onmatch="exclude">
		<Signature condition="is">Microsoft Windows</Signature>
		<Signature condition="is">Microsoft Corporation</Signature>
	</ImageLoad>
	<!-- log only images loaded  from user profile directory, clear some noise and also monitor what is loaded  on lsass.exe> -->
	<ImageLoad onmatch="include">
		<Image condition="end with">lsass.exe</Image>
		<Image condition="contains">C:\Users</Image>
	</ImageLoad>
    <!-- Log all CreateRemoteThread, exclude CSRSS and Winlogon -->
	<CreateRemoteThread onmatch="exclude">
		<SourceImage condition="is">C:\Windows\System32\csrss.exe</SourceImage>
		<SourceImage condition="is">C:\Windows\System32\winlogon.exe</SourceImage>
	</CreateRemoteThread>
	<!-- Log all raw disk access if the Image is System or svchost  -->
	<RawAccessRead onmatch="include">
     <Image condition="contains">C:\Windows\System32\</Image>
    <Image condition="contains">C:\Users</Image>
    <Image condition="contains">C:\$recycle.bin</Image>
	</RawAccessRead>
	<!-- Log all file modified creation time -->
	<FileCreateTime onmatch="exclude"/>
	<!-- Log process access -->
	<!-- Only capture access to lsass and winlogon -->
	<ProcessAccess onmatch="include">
		<TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
		<TargetImage condition="is">C:\Windows\system32\winlogon.exe</TargetImage>
	</ProcessAccess>
	<ProcessAccess onmatch="exclude">
		<SourceImage condition="is">C:\WINDOWS\System32\Taskmgr.exe</SourceImage>
	</ProcessAccess>
	<!-- Log all initiated network connection -->
	<NetworkConnect onmatch="exclude">
       <Image condition="contains">chrome.exe</Image>
       <Image condition="contains">iexplore.exe</Image>
       <Image condition="contains">firefox.exe</Image>
       <Image condition="contains">outlook.exe</Image>
       <Image condition="contains">Skype.exe</Image>
       <Image condition="contains">lync.exe</Image>
       <Image condition="contains">GoogleUpdate.exe</Image>
	   <Image condition="contains">qbittorrent.exe</Image>
  </NetworkConnect>
	<!-- Log all process creation -->
	<ProcessCreate onmatch="exclude"/>
    <!-- Do not log process termination -->
	<ProcessTerminate onmatch="include"/>
  </EventFiltering>
</Sysmon>
"@




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
				#Copy-Item "C:\Sysmon64.exe" -Destination "C:\Sysmon64.exe" -ToSession $s
				&C:\Sysmon64.exe -i -accepteula > null 2>&1
				Write-Warning "Changing config to desired state."
				$sysmonConfig | Out-File "C:\sysmonConfig.xml"
				&C:\Sysmon64.exe -c "C:\sysmonConfig.xml" > null 2>&1
				Remove-Item "C:\Sysmon64.exe"
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
			#Invoke-Command -Session $s -ScriptBlock {
			#	param([string[]]$sysmonBackup)
			#	$sysmonBackup | Out-File "C:\$(hostname).sysmon.orig.xml" -Force
			#	#&sysmon -c "C:\$(hostname).sysmon.orig.xml"
			#} -Args (,$sysmonBackup)
		}


	# Cleanup Session
		Remove-PSSession $s
	}
}



