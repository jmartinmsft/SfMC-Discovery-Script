<#
#################################################################################
#  DISCLAIMER: 									#
#										#
#  	THIS CODE IS SAMPLE CODE. THESE SAMPLES ARE PROVIDED "AS IS" WITHOUT	#
#  	WARRANTY OF ANY KIND. MICROSOFT FURTHER DISCLAIMS ALL IMPLIED		#
#	WARRANTIES INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OF 	#
#	MERCHANTABILITY OR OF FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE 	#
#	RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SAMPLES REMAINS 	#
#	WITH YOU. IN NO EVENT SHALL MICROSOFT OR ITS SUPPLIERS BE LIABLE FOR	#
#	ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR 	#
#	LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS 	#
#	INFORMATION, OR OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OF OR 	#
#	INABILITY TO USE THE SAMPLES, EVEN IF MICROSOFT HAS BEEN ADVISED OF 	#
#	THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME STATES DO NOT ALLOW THE 	#
#	EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL 	#
#	DAMAGES, THE ABOVE LIMITATION MAY NOT APPLY TO YOU.			#
#										#
#################################################################################
VERSION 2.0
#>
param( [Parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$creds)
function Write-Log {
    param( [string]$Message, [string]$Cmdlet )
    [pscustomobject]@{
        Time = (Get-Date -f o)
        Cmdlet = $Cmdlet
        Message = $Message
    } | Export-Csv -Path "$outputPath\$ServerName-LogFile.csv" -Append -NoTypeInformation
 }
 function Get-ServerData {
	param ([string]$strServer)
	foreach ($h in $hash.GetEnumerator()) {
		$Result = $null
        $CommandName = $h.Name 
		$Command = $h.Value
        $Error.Clear()
        Write-Log -Message $Command -Cmdlet $CommandName
        try{$Result = Invoke-Expression $h.Value}
        catch{Write-Log -Message $Error.Exception.ErrorRecord -Cmdlet $CommandName}
		if($Result -ne $null) {	$Result | Export-Csv $outputPath\$strServer-$CommandName.csv -NoTypeInformation -Force}
	}
}
function Zip-CsvResults {
	## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    try {[System.IO.Compression.ZipFile]::CreateFromDirectory($outputPath, $zipFolder)}
    catch {
        try{Remove-Item -Path $zipFolder -Force -ErrorAction Stop}
        catch{Write-Warning "Failed to remove file."}
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'update')
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        Get-ChildItem -Path $outputPath | Select FullName | ForEach-Object {
            try{[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipFile, $_.FullName, (Split-Path $_.FullName -Leaf), $compressionLevel) | Out-Null }
            catch {Write-Warning "failed to add"}
        }
        $zipFile.Dispose()
    }
}
$ServerName = $env:COMPUTERNAME
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings"
if(!(Test-Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory | Out-Null
}
else {Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force }
Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $env:COMPUTERNAME*.zip | Remove-Item -Confirm:$False -ErrorAction Ignore
## Data collection starts
## General information

$hash = @{
'ExchangeServer' = 'Get-ExchangeServer $strServer -Status -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName';
'ExchangeCertificate' = 'Get-ExchangeCertificate -Server $strServer -WarningAction Ignore -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'Partition' = 'Get-Disk | where {$_.Number -notlike $null} | ForEach-Object { Get-Partition -DiskNumber $_.Number | Select * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName }'
'Disk' = 'Get-Disk | where {$_.Number -notlike $null} | Select * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'EventLogLevel' = 'Get-EventLogLevel -WarningAction Ignore -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'HealthReport' ='Get-HealthReport * -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ServerComponentState' = 'Get-ServerComponentState $strServer -WarningAction Ignore -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ServerHealth' = 'Get-ServerHealth $strServer -WarningAction Ignore -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ServerMonitoringOverride' = 'Get-ServerMonitoringOverride $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Client access settings
'AutodiscoverVirtualDirectory' = 'Get-AutodiscoverVirtualDirectory -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ClientAccessServer' ='Get-ClientAccessServer $strServer -WarningAction Ignore -IncludeAlternateServiceAccountCredentialStatus -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'EcpVirtualDirectory' = 'Get-EcpVirtualDirectory -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'WebServicesVirtualDirectory' = 'Get-WebServicesVirtualDirectory  -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
#'SleepTime' = 'Start-Sleep -Seconds 60'
'MapiVirtualDirectory' = 'Get-MapiVirtualDirectory -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ActiveSyncVirtualDirectory' = 'Get-ActiveSyncVirtualDirectory -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'OabVirtualDirectory' = 'Get-OabVirtualDirectory -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'OwaVirtualDirectory' = 'Get-OwaVirtualDirectory -Server $strServer -WarningAction Ignore -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'OutlookAnywhere' = 'Get-OutlookAnywhere -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'PowerShellVirtualDirectory' = 'Get-PowerShellVirtualDirectory -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'RpcClientAccess' = 'Get-RpcClientAccess -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Transport settings
'ReceiveConnector' = 'Get-ReceiveConnector -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ImapSettings' = 'Get-ImapSettings -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'PopSettings' ='Get-PopSettings -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'TransportAgent' = 'Get-TransportAgent -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'TransportService' = 'Get-TransportService $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'MailboxTransportService' = 'Get-MailboxTransportService -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'FrontendTransportService' = 'Get-FrontendTransportService $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'TransportPipeline' = 'Get-TransportPipeline -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Mailbox settings
'DatabaseAvailabilityGroup' = 'Get-DatabaseAvailabilityGroup (Get-Cluster).Name -Status -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'DatabaseAvailabilityGroupNetwork' = 'Get-DatabaseAvailabilityGroupNetwork -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'DatabaseAvailabilityGroupConfiguration' = 'Get-DatabaseAvailabilityGroupConfiguration -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'MailboxDatabase' = 'Get-MailboxDatabase -Server $strServer -WarningAction Ignore -Status -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'MailboxServer' = 'Get-MailboxServer $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'PublicFolderDatabase' = 'Get-PublicFolderDatabase -Server $strServer -WarningAction Ignore -ErrorAction Stop  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'WindowsFeature'='Get-WindowsFeature -ErrorAction Stop  | Where {$_.Installed -eq $True} | Select-Object @{Name="ServerName"; Expression = {$strServer}},Name,DisplayName,Installed,InstallState,FeatureType';
'HotFix'='Get-HotFix -WarningAction Ignore -ErrorAction Stop  | Select-Object @{Name="ServerName"; Expression = {$strServer}},Description,HotFixID,InstalledBy,InstalledOn';
'Culture'='Get-Culture -ErrorAction Stop  | Select @{Name="ServerName"; Expression = {$strServer}},LCID,Name,DisplayName';
'NetAdapter'='Get-NetAdapter -ErrorAction Stop  | Select-Object SystemName,MacAddress,Status,LinkSpeed,MediaType,DriverFileName,InterfaceAlias,ifIndex,IfDesc,DriverVersion,Name,DeviceID';
'NetIPAddress'='Get-NetIPAddress -ErrorAction Stop  | Where {($_.IPv4Address -ne $null -or $_.IPv6Address -ne $null) -and ($_.IPv4Address -notlike "127*" -and $_.IPv4Address -notlike "169*")} | select @{Name="ServerName"; Expression = {$strServer}},InterfaceAlias,IPv4Address,IPv6Address,SuffixOrigin,PrefixLength | ? {$_.InterfaceAlias -notlike "*Loopback*"}';
'NetOffloadGlobalSetting'='Get-NetOffloadGlobalSetting -ErrorAction Stop  | select @{Name="ServerName"; Expression = {$strServer}},ReceiveSideScaling,ReceiveSegmentCoalescing,Chimney,TaskOffload,NetworkDirect,NetworkDirectAcrossIPSubnets,PacketCoalescingFilter';
'NetRoute'='Get-NetRoute  -ErrorAction Stop | select @{Name="ServerName"; Expression = {$strServer}},DestinationPrefix,NextHop,RouteMetric';
'ScheduledTask'='Get-ScheduledTask -ErrorAction Stop  | Where {$_.State -ne "Disabled"} | Select @{Name="ServerName"; Expression = {$strServer}},TaskPath,TaskName,State';
'Service'='Get-WmiObject -Query "select * from win32_service" -ErrorAction Stop  | Select @{Name="ServerName"; Expression = {$strServer}},Name,ProcessID,StartMode,State,Status';
'Processor'='Get-WmiObject -Query "select * from Win32_Processor" -ErrorAction Stop  | Select @{Name="ServerName"; Expression = {$strServer}},Caption,DeviceID, Manufacturer,Name,SocketDesignation,MaxClockSpeed,AddressWidth,NumberOfCores,NumberOfLogicalProcessors';
'Product'='Get-WmiObject -Query "select * from Win32_Product"  -ErrorAction Stop | Select @{Name="ServerName"; Expression = {$strServer}}, Name, Description, Vendor, Version, IdentifyingNumber, InstallDate, InstallLocation, PackageCode, PackageName, Language';
'LogicalDisk'='Get-WmiObject -Query "select * from Win32_LogicalDisk"  -ErrorAction Stop | Select @{Name="ServerName"; Expression = {$strServer}}, Name, Description, Size, FreeSpace, FileSystem, VolumeName';
'Bios'='Get-WmiObject -Query "select * from win32_BIOS" -ErrorAction Stop  | select @{Name="ServerName"; Expression = {$strServer}}, Name,SMBIOSBIOSVersion,Manufacturer,Version';
'OperatingSystem'='Get-WmiObject -Query "select * from Win32_OperatingSystem" -ErrorAction Stop  | select @{Name="ServerName"; Expression = {$strServer}}, BuildNumber,Version,WindowsDirectory,LastBootUpTime,ServicePackMajorVersion,ServicePackMinorVersion,TotalVirtualMemorySize,TotalVisibleMemorySize';
'ComputerSystem'='Get-WmiObject -Query "select * from Win32_Computersystem" -ErrorAction Stop  | select @{Name="ServerName"; Expression = {$strServer}}, Name,Domain,Manufacturer,Model';
'Memory'='Get-WmiObject -Query "select * from Win32_PhysicalMemory" -ErrorAction Stop  | Select @{Name="ServerName"; Expression = {$strServer}}, Capacity, DataWidth, Speed, DeviceLocator, Tag, TypeDetail, Manufacturer, PartNumber';
'PageFile'='Get-WmiObject -Query "select * from Win32_PageFile" -ErrorAction Stop  | select @{Name="ServerName"; Expression = {$strServer}},Compressed,Description,Drive,Encrypted,FileName,FileSize,FreeSpace,InitialSize,MaximumSize,System';
'CrashControl'='Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\crashcontrol -ErrorAction Stop  | select @{Name="ServerName"; Expression = {$strServer}},autoreboot,crashdumpenabled,DumpFile,LogEvent,MiniDumpDir,MiniDumpsCount,OverWrite,LastCrashTime'
}
Get-ServerData -strServer $ServerName
Write-Log -Message "Attempting to zip results" -Cmdlet "ZipCsvResults"
$ts = Get-Date -f yyyyMMddHHmmss
[string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$ServerName-Settings-$ts.zip"
$zipReady = $false
$zipAttempt = 0
while($zipReady -eq $false) {
    if(Get-Item -Path $zipFolder -ErrorAction Ignore) { $zipReady = $true }
    else {
        if($zipAttempt -eq 3) { $zipReady = $true }
        else {
            Zip-CsvResults
            $zipAttempt++
            Start-Sleep -Seconds 10
        }
    }
}
## Clean up
Remove-PSSession -Name SfMCSrvDis -ErrorAction Ignore | Out-Null