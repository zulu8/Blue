
$theXmlVariable = [XML] "
<note>
<to>Tove</to>
<from>Jani</from>
<heading>Reminder</heading>
<body>Don't forget me this weekend!</body>
</note>
"

echo $theXmlVariable.note.to

echo $theXmlVariable.note.body

$Data = [Xml] (Get-Content Sample.xml)

Import-Clixml

# Sysmon Install and Configure
	# Install
	if ((Get-Service Sysmon) -ne $null) {
	  Write-Verbose "Sysmon Service exists"
	  return $true
	}
	Write-Verbose "Sysmon Service does not exist"
	return $false

	& "$SysmonpPath\sysmon64.exe" -i "$SysmonpPath\config.xml"
	Write-Verbose "Sysmon installed with expected configuration"

#Configure Sysmon
	# Check Config
	reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" `
	"$SysmonPath\temp.reg"
	$hash = Get-FileHash "$SysmonPath\temp.reg","$SysmonPath\config.reg"
	Remove-Item -Path "$SysmonPath\temp.reg"
	if ($hash[0].hash -eq $hash[1].hash) {
		Write-Verbose "Current Config Matches excpected config"
		return $true

	Write-Verbose "Current Config does not match expected config"
	return $false

	& "$SysmonPath\sysmon64.exe" -c "$SysmonPath\config.xml"
	Write-Verbose "Sysmon configured with expected configuration"











Proactive:
	Check Config vs Desired State
		If Different
			ALERT
			Doc change + forensic data
			Remediate
Passive:
	Alerts for config changes:
		(special group change Event 4908)




dir HKCU:\SOFTWARE\Microsoft\Office -Recurse |
Where-Object LastWriteTime -gt (Get-Date).AddDays(-1) |
Select-Object Name, LastWriteTime |
Sort LastWriteTime



"", "\Wow6432Node" |

    ForEach-Object { Get-ItemProperty "HKLM:\SOFTWARE$_\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue } |

    Where-Object DisplayName | # Some keys don't have display names

    Select-Object DisplayName, Publisher, DisplayVersion, InstallDate, @{Name="LastModified"; Expression={ (Add-RegKeyMember $_.PsPath).LastWriteTime }} |

    Sort-Object DisplayName



Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\* |

    Where-Object Service -eq USBSTOR |
Select-Object @{Name="DeviceDesc"; Expression={ $_.DeviceDesc -split ";" | select -last 1 }},
        @{Name="SerialNumber"; Expression={ $_.PsChildName }},
        @{Name="LastModified"; Expression={ (Add-RegKeyMember $_.PsPath).LastWriteTime }}







