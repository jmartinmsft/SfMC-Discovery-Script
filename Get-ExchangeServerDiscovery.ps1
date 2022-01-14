<#//***********************************************************************
//
// Get-ExchangeServerDiscovery.ps1
// Modified 14 January 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v4.1
//
//***********************************************************************
//
// Copyright (c) 2018 Microsoft Corporation. All rights reserved.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//**********************************************************************​
#>

param( [Parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$creds)
Clear-Host
Write-Host -ForegroundColor Yellow '//***********************************************************************'
Write-Host -ForegroundColor Yellow '//'
Write-Host -ForegroundColor Yellow '// Copyright (c) 2018 Microsoft Corporation. All rights reserved.'
Write-Host -ForegroundColor Yellow '//'
Write-Host -ForegroundColor Yellow '// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR'
Write-Host -ForegroundColor Yellow '// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,'
Write-Host -ForegroundColor Yellow '// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE'
Write-Host -ForegroundColor Yellow '// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER'
Write-Host -ForegroundColor Yellow '// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,'
Write-Host -ForegroundColor Yellow '// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN'
Write-Host -ForegroundColor Yellow '// THE SOFTWARE.'
Write-Host -ForegroundColor Yellow '//'
Write-Host -ForegroundColor Yellow '//**********************************************************************​'
Start-Sleep -Seconds 2
function Write-Log {
    param( [string]$Message, [string]$Cmdlet )
    [pscustomobject]@{
        Time = (Get-Date -f o)
        Cmdlet = $Cmdlet
        Message = $Message
    } | Export-Csv -Path "$outputPath\$ServerName-LogFile.csv" -Append -NoTypeInformation
 }
 function Get-ServerData {
	param ([string]$ServerName)
	foreach ($h in $hash.GetEnumerator()) {
		$Result = $null
        $CommandName = $h.Name 
		$Command = $h.Value
        $Error.Clear()
        Write-Log -Message $Command -Cmdlet $CommandName
        try{$Result = Invoke-Expression $h.Value}
        catch{Write-Log -Message $Error.Exception.ErrorRecord -Cmdlet $CommandName}
		if($Result -ne $null) {	$Result | Export-Csv $outputPath\$ServerName-$CommandName.csv -NoTypeInformation -Force}
	}
}
function Zip-CsvResults {
	## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    try {[System.IO.Compression.ZipFile]::CreateFromDirectory($outputPath, $zipFolder)}
    catch {
        try{Remove-Item -Path $zipFolder -Force -ErrorAction SilentlyContinue}
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
Get-ExchangeServer $ServerName -Status -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName  | Export-Clixml $outputPath\$ServerName-ExchangeServer.xml
Get-ExchangeCertificate -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ExchangeCertificate.xml
Get-EventLogLevel -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-EventLogLevel.xml
Get-HealthReport * -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-HealthReport.xml
Get-ServerComponentState $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ServerComponentState.xml
Get-ServerHealth $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ServerHealth.xml
Get-ServerMonitoringOverride $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ServerMonitoringOverride.xml
## Client access settings
Get-AutodiscoverVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-AutodiscoverVirtualDirectory.xml
Get-ClientAccessServer $ServerName -WarningAction Ignore -IncludeAlternateServiceAccountCredentialStatus -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ClientAccessServer.xml
Get-EcpVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-EcpVirtualDirectory.xml
Get-WebServicesVirtualDirectory  -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-WebServicesVirtualDirectory.xml
Get-MapiVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MapiVirtualDirectory.xml
Get-ActiveSyncVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ActiveSyncVirtualDirectory.xml
Get-OabVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-OabVirtualDirectory.xml
Get-OwaVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-OwaVirtualDirectory.xml
Get-OutlookAnywhere -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-OutlookAnywhere.xml
Get-PowerShellVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-PowerShellVirtualDirectory.xml
Get-RpcClientAccess -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-RpcClientAccess.xml
## Transport settings
Get-ReceiveConnector -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ReceiveConnector.xml
Get-ImapSettings -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ImapSettings.xml
Get-PopSettings -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-PopSettings.xml
Get-TransportAgent -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-TransportAgent.xml
Get-TransportService $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-TransportService.xml
Get-MailboxTransportService -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MailboxTransportService.xml
Get-FrontendTransportService $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-FrontendTransportService.xml
Get-TransportPipeline -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-TransportPipeline.xml
## Mailbox settings
Get-DatabaseAvailabilityGroup (Get-Cluster).Name -Status -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-DatabaseAvailabilityGroup.xml
Get-DatabaseAvailabilityGroupNetwork (Get-Cluster).Name -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-DatabaseAvailabilityGroupNetwork.xml
Get-MailboxDatabase -Server $ServerName -WarningAction Ignore -Status -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MailboxDatabase.xml
Get-MailboxServer $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MailboxServer.xml
Get-PublicFolderDatabase -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-PublicFolderDatabase.xml
## Convert the XML into CSV files
Get-ChildItem $outputPath -Filter *.xml | ForEach-Object { Import-Clixml $_.FullName | Export-Csv $outputPath\$($_.BaseName).csv -NoTypeInformation -Force }
Get-ChildItem $outputPath -Filter *.xml | Remove-Item
$hash = @{
'Partition' = 'Get-Disk | where {$_.Number -notlike $null} | ForEach-Object { Get-Partition -DiskNumber $_.Number | Select * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName }'
'Disk' = 'Get-Disk | where {$_.Number -notlike $null} | Select * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'WindowsFeature'='Get-WindowsFeature -ErrorAction SilentlyContinue  | Where {$_.Installed -eq $True} | Select-Object @{Name="ServerName"; Expression = {$ServerName}},Name,DisplayName,Installed,InstallState,FeatureType';
'HotFix'='Get-HotFix -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object @{Name="ServerName"; Expression = {$ServerName}},Description,HotFixID,InstalledBy,InstalledOn';
'Culture'='Get-Culture -ErrorAction SilentlyContinue  | Select @{Name="ServerName"; Expression = {$ServerName}},LCID,Name,DisplayName';
'NetAdapter'='Get-NetAdapter -ErrorAction SilentlyContinue  | Select-Object SystemName,MacAddress,Status,LinkSpeed,MediaType,DriverFileName,InterfaceAlias,ifIndex,IfDesc,DriverVersion,Name,DeviceID';
'NetIPAddress'='Get-NetIPAddress -ErrorAction SilentlyContinue  | Where {($_.IPv4Address -ne $null -or $_.IPv6Address -ne $null) -and ($_.IPv4Address -notlike "127*" -and $_.IPv4Address -notlike "169*")} | select @{Name="ServerName"; Expression = {$ServerName}},InterfaceAlias,IPv4Address,IPv6Address,SuffixOrigin,PrefixLength | ? {$_.InterfaceAlias -notlike "*Loopback*"}';
'NetOffloadGlobalSetting'='Get-NetOffloadGlobalSetting -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}},ReceiveSideScaling,ReceiveSegmentCoalescing,Chimney,TaskOffload,NetworkDirect,NetworkDirectAcrossIPSubnets,PacketCoalescingFilter';
'NetRoute'='Get-NetRoute  -ErrorAction SilentlyContinue | select @{Name="ServerName"; Expression = {$ServerName}},DestinationPrefix,NextHop,RouteMetric';
'ScheduledTask'='Get-ScheduledTask -ErrorAction SilentlyContinue  | Where {$_.State -ne "Disabled"} | Select @{Name="ServerName"; Expression = {$ServerName}},TaskPath,TaskName,State';
'Service'='Get-WmiObject -Query "select * from win32_service" -ErrorAction SilentlyContinue  | Select @{Name="ServerName"; Expression = {$ServerName}},Name,ProcessID,StartMode,State,Status';
'Processor'='Get-WmiObject -Query "select * from Win32_Processor" -ErrorAction SilentlyContinue  | Select @{Name="ServerName"; Expression = {$ServerName}},Caption,DeviceID, Manufacturer,Name,SocketDesignation,MaxClockSpeed,AddressWidth,NumberOfCores,NumberOfLogicalProcessors';
'Product'='Get-WmiObject -Query "select * from Win32_Product"  -ErrorAction SilentlyContinue | Select @{Name="ServerName"; Expression = {$ServerName}}, Name, Description, Vendor, Version, IdentifyingNumber, InstallDate, InstallLocation, PackageCode, PackageName, Language';
'LogicalDisk'='Get-WmiObject -Query "select * from Win32_LogicalDisk"  -ErrorAction SilentlyContinue | Select @{Name="ServerName"; Expression = {$ServerName}}, Name, Description, Size, FreeSpace, FileSystem, VolumeName';
'Bios'='Get-WmiObject -Query "select * from win32_BIOS" -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}}, Name,SMBIOSBIOSVersion,Manufacturer,Version';
'OperatingSystem'='Get-WmiObject -Query "select * from Win32_OperatingSystem" -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}}, BuildNumber,Version,WindowsDirectory,LastBootUpTime,ServicePackMajorVersion,ServicePackMinorVersion,TotalVirtualMemorySize,TotalVisibleMemorySize';
'ComputerSystem'='Get-WmiObject -Query "select * from Win32_Computersystem" -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}}, Name,Domain,Manufacturer,Model';
'Memory'='Get-WmiObject -Query "select * from Win32_PhysicalMemory" -ErrorAction SilentlyContinue  | Select @{Name="ServerName"; Expression = {$ServerName}}, Capacity, DataWidth, Speed, DeviceLocator, Tag, TypeDetail, Manufacturer, PartNumber';
'PageFile'='Get-WmiObject -Query "select * from Win32_PageFile" -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}},Compressed,Description,Drive,Encrypted,FileName,FileSize,FreeSpace,InitialSize,MaximumSize,System';
'CrashControl'='Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\crashcontrol -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}},autoreboot,crashdumpenabled,DumpFile,LogEvent,MiniDumpDir,MiniDumpsCount,OverWrite,LastCrashTime'
}
Get-ServerData -ServerName $ServerName
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

# SIG # Begin signature block
# MIIDZgYJKoZIhvcNAQcCoIIDVzCCA1MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3a2fCv83gN6dG
# AzWdIpLu3C1e13BM5m0dR2fHufx/A6CCAZQwggGQMIIBFaADAgECAggmFxDWcEY7
# FTAKBggqhkjOPQQDAzAvMS0wKwYDVQQDEyQ3ZDMxYjI0NC05N2Y5LTQxZDAtYjQ5
# OS1mYzI0NjMxYmE1YTIwHhcNMjIwMTA0MDE1NjM2WhcNMjMwMTA0MTM1NjM2WjAv
# MS0wKwYDVQQDEyQ3ZDMxYjI0NC05N2Y5LTQxZDAtYjQ5OS1mYzI0NjMxYmE1YTIw
# djAQBgcqhkjOPQIBBgUrgQQAIgNiAASUaEmnP41/+lLXJYyUrAgHkTJAAh5eGabX
# yxoIVZ37/dE/Iyiy8rOraIaAkOEvswb4feDM96Chr0Dvd5DAVGWuxyVSh2xjFfyN
# P8jCulJgDFNospS9R5aX2h4y5WEn4XUwCgYIKoZIzj0EAwMDaQAwZgIxAJE52jMb
# c2lnsNMc5DrmsWk9mcWp2nR61oCAY+kBFkVXG229SrsU2QDG/4aCV3i74gIxAJ2p
# Ym1jSnD1MLCS6W4mpeHGgXoXbXOJ9jqRbWqc3g5ZdDxUXiUo66sVuT2YElKsgDGC
# ASgwggEkAgEBMDswLzEtMCsGA1UEAxMkN2QzMWIyNDQtOTdmOS00MWQwLWI0OTkt
# ZmMyNDYzMWJhNWEyAggmFxDWcEY7FTANBglghkgBZQMEAgEFAKBeMBAGCisGAQQB
# gjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMC8GCSqGSIb3DQEJ
# BDEiBCDvDgjILdkStyDznn+3nzRuAPMA+hC9cwC3cQNermrINjALBgcqhkjOPQIB
# BQAEZjBkAjBih7R+3a4OJ5fpRgZQEqqd3ulWazMT5SyuZepkgz1wdNjSCxfpSTHA
# LUAtnouetBACMGmFp1HTLMPWzkLSLv+va/lla87kLvSX5+QsM3J3tmwtSnYfwFlC
# 3n0XZCeRMh5EfA==
# SIG # End signature block
