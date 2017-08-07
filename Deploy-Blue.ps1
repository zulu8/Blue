<#
.SYNOPSIS
    Deploys enterprise auditing and logging configurations for Blue Team
    Operations.

.DESCRIPTION

.EXAMPLE
	Configure-Sensors
	CleanUp-Sensors

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

# Hash directory for monitoring
#$hashDirectory = "\\DC01\Hashes"

# Define all target systems in scope FQDN or Netbios name
$targetSystems = @(
    'pc02win10'
)


function Configure-Sensors
{
	# Setup Windows Event Collector Server
	Invoke-Command -ComputerName $collectorServer -ScriptBlock {wecutil qc /quiet}

	# Create Group for Special Logon Auditing (Event ID 4964). Add Suspects to Group.
	$specialAuditGroup = 'SpecialAudit'
	New-ADGroup $specialAuditGroup -GroupScope "Global"
	$specialGroupString = "S-1-5-113;$((get-adgroup $specialAuditGroup).sid.Value);$((get-adgroup 'domain admins').sid.Value);$((get-adgroup 'enterprise admins').sid.Value)"

	foreach ($i in $targetSystems)
	{
		$s = New-PSSession -ComputerName $i
	# Audit Config
		# Backup Current Audit Config to C:\<hostname>.auditpolicy.orig.csv
		# Set New Audit Policy
		Invoke-Command -Session $s -ScriptBlock {
			auditpol.exe /backup /file:C:\$(hostname).audit.orig.csv;
			auditpol.exe /set /subcategory:"Special Logon","Logon","Directory Service Access","Directory Service Changes","Credential Validation","Kerberos Service Ticket Operations","Kerberos Authentication Service","Computer Account Management","Other Account Management Events","Security Group Management","User Account Management","DPAPI Activity","Process Creation","IPsec Driver","Security State Change","Security System Extension","System Integrity","Removable Storage" /success:enable /failure:enable;
			auditpol.exe /set /subcategory:"Logoff","Account Lockout" /success:enable;
		}

		# Get Auditpol Config Backup and Store to Backup Folder
		$auditBackup = Invoke-Command -Session $s -ScriptBlock {
			gc "C:\$(hostname).audit.orig.csv"
			Remove-Item "C:\$(hostname).audit.orig.csv"
		}
		$auditBackup | out-file "$backupDirectory\$i.audit.orig.csv"

	# PowerShell and WEF Config
		# Configure Registry
		Invoke-Command -Session $s -FilePath .\Deploy-BlueRegistry.ps1 -ArgumentList $collectorServer,$transcriptDirectory,$specialGroupString

		# Get Registry Config Backup and Store to Backup Folder
		$regBackup = Invoke-Command -Session $s -ScriptBlock {
			gc "C:\$(hostname).reg.orig.csv"
			Remove-Item "C:\$(hostname).reg.orig.csv"
		}
		$regBackup | out-file "$backupDirectory\$i.reg.orig.csv"

	# Cleanup Session
		Remove-PSSession $s
	}
}


function Cleanup-Sensors
{
	foreach ($i in $targetSystems)
	{
		$s = New-PSSession -ComputerName $i
	# Audit Cleanup
		# Read in original audit configuration
		$auditBackup = gc "$backupDirectory\$i.audit.orig.csv"

		# Restore original config
		Invoke-Command -Session $s -Script {
			param([string[]]$auditBackup)
			$auditBackup | Out-File "C:\$(hostname).audit.orig.csv"
			auditpol.exe /restore /file:C:\$(hostname).audit.orig.csv
			Remove-Item "C:\$(hostname).audit.orig.csv"
		} -Args (,$auditBackup)

	# PowerShell and WEF Config
		# Configure Registry
		$regBackup = gc "$backupDirectory\$i.reg.orig.csv"

		# Restore original registry config
		Invoke-Command -Session $s -Script {
			param([string[]]$regBackup)
			$regBackup | ConvertFrom-Csv | ForEach-Object {
				if ($_.name -eq "DNE") {
					Write-Warning "Removing Path: $($_.regKey)"
					Remove-Item $_.regKey
				}
				elseif ($_.value -eq "DNE") {
					Write-Warning "Removing Key: $($_.name) with Value: $($_.value)"
					Remove-ItemProperty $_.regKey -Name $_.name
				}
				else {
					Write-Warning "On $(hostname) name: $($_.name) value: $($_.value) type: $($_.type)"
					Set-ItemProperty $_.regKey -Name $_.name -Value $_.value -Type $_.type
				}
			}
		} -Args (,$regBackup)

	# System
		#Uninstall:  Sysmon.exe –u

	# Cleanup Session
		Remove-PSSession $s
	}
}



