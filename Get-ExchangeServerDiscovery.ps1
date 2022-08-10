<#//***********************************************************************
//
// Get-ExchangeServerDiscovery.ps1
// Modified 10 August 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v4.2
//
//.NOTES
// 4.2 Adds the HealthChecker script data collection
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
Set-Location $env:ExchangeInstallPath\Scripts
Unblock-File -Path .\HealthChecker.ps1 -Confirm:$False
.\HealthChecker.ps1 -OutputFilePath "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings" -SkipVersionCheck
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
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCpN05diNwWxoET
# +53VID84WBdaYfOdWFLMYbwdOFCA26CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJ5cGx5JVq/G35E6DCiGO0JT
# 5pUBkcnUC37rxSK5eUzHMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBVTfcz1xzZRt1WJsqATmibo/DM6RY5Pzwsxt7LQk3CFmF7DxLarGxL
# jZyNTLo9IFdSJ0kwjykDpXVte8PZf7pMHO+DRvloGQUOohujIi2j/yfyTWpTk2jY
# vLaT6cXEEGyM85Dvg6JOEGzIEyH0oVWSX20ftapXFJltgmuiLgBaWIXGytE7qkBi
# NqXZtJBcbuASgaw0so62CQvMq94UGOo9Z0YpwDXELtmYM8VVW5LA9d2ZyKnEOOkw
# PD5MhA8S5R+TQ4Hf+BpcvisOTH/9KqUBR0Q6PBdcOVD3QsM/A4HApZzmWG2eKpbt
# YgncyJWJkPxY45Jcix+9KK3L1UgdQzP1oYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBVjKRpmeMzavfzuCrphZMOKjtUqqvNdloApMuCRIRnRAgZi3nYF
# tW0YEzIwMjIwODEwMTgwNTA3LjYwMlowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046QTI0MC00QjgyLTEzMEUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY16VS54dJkqtwABAAABjTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDVaFw0yMzAxMjYxOTI3NDVaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkEyNDAt
# NEI4Mi0xMzBFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2jRILZg+O6U7dLcuwBPM
# B+0tJUz0wHLqJ5f7KJXQsTzWToADUMYV4xVZnp9mPTWojUJ/l3O4XqegLDNduFAO
# bcitrLyY5HDsxAfUG1/2YilcSkSP6CcMqWfsSwULGX5zlsVKHJ7tvwg26y6eLklU
# dFMpiq294T4uJQdXd5O7mFy0vVkaGPGxNWLbZxKNzqKtFnWQ7jMtZ05XvafkIWZr
# NTFv8GGpAlHtRsZ1A8KDo6IDSGVNZZXbQs+fOwMOGp/Bzod8f1YI8Gb2oN/mx2cc
# vdGr9la55QZeVsM7LfTaEPQxbgAcLgWDlIPcmTzcBksEzLOQsSpBzsqPaWI9ykVw
# 5ofmrkFKMbpQT5EMki2suJoVM5xGgdZWnt/tz00xubPSKFi4B4IMFUB9mcANUq9c
# HaLsHbDJ+AUsVO0qnVjwzXPYJeR7C/B8X0Ul6UkIdplZmncQZSBK3yZQy+oGsuJK
# XFAq3BlxT6kDuhYYvO7itLrPeY0knut1rKkxom+ui6vCdthCfnAiyknyRC2lknqz
# z8x1mDkQ5Q6Ox9p6/lduFupSJMtgsCPN9fIvrfppMDFIvRoULsHOdLJjrRli8co5
# M+vZmf20oTxYuXzM0tbRurEJycB5ZMbwznsFHymOkgyx8OeFnXV3car45uejI1B1
# iqUDbeSNxnvczuOhcpzwackCAwEAAaOCATYwggEyMB0GA1UdDgQWBBR4zJFuh59G
# wpTuSju4STcflihmkzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQA1r3Oz0lEq3VvpdFlh3YBxc4hnYkALyYPDa9FO
# 4XgqwkBm8Lsb+lK3tbGGgpi6QJbK3iM3BK0ObBcwRaJVCxGLGtr6Jz9hRumRyF8o
# 4n2y3YiKv4olBxNjFShSGc9E29JmVjBmLgmfjRqPc/2rD25q4ow4uA3rc9ekiauf
# gGhcSAdek/l+kASbzohOt/5z2+IlgT4e3auSUzt2GAKfKZB02ZDGWKKeCY3pELj1
# tuh6yfrOJPPInO4ZZLW3vgKavtL8e6FJZyJoDFMewJ59oEL+AK3e2M2I4IFE9n6L
# VS8bS9UbMUMvrAlXN5ZM2I8GdHB9TbfI17Wm/9Uf4qu588PJN7vCJj9s+KxZqXc5
# sGScLgqiPqIbbNTE+/AEZ/eTixc9YLgTyMqakZI59wGqjrONQSY7u0VEDkEE6ikz
# +FSFRKKzpySb0WTgMvWxsLvbnN8ACmISPnBHYZoGssPAL7foGGKFLdABTQC2PX19
# WjrfyrshHdiqSlCspqIGBTxRaHtyPMro3B/26gPfCl3MC3rC3NGq4xGnIHDZGSiz
# UmGg8TkQAloVdU5dJ1v910gjxaxaUraGhP8IttE0RWnU5XRp/sGaNmDcMwbyHuSp
# aFsn3Q21OzitP4BnN5tprHangAC7joe4zmLnmRnAiUc9sRqQ2bmsMAvUpsO8nlOF
# miM1LzCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046QTI0MC00QjgyLTEzMEUxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAIBzlZM9TRND4PgtpLWQZkSPYVcJoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmnguqMCIYDzIwMjIwODEw
# MTg0OTE0WhgPMjAyMjA4MTExODQ5MTRaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaeC6oCAQAwBwIBAAICHu0wBwIBAAICEU0wCgIFAOafXSoCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQBBa9s5bLkp6kF3bLR1uiWzfa/2wIzj/Iz+UUJBLrPm
# W4VhF7RyYhCguOeVoBBqC4+lAICOKxnmkmhVhnMBe/gyCiuf1MmZPUEfaV8cmcbW
# bwbPBpzFMdXufj4TVA0oBdz3e4L71YPHYwuzzJt3rJHvwgU8PIO4KrtmjJ27LKsA
# ZjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABjXpVLnh0mSq3AAEAAAGNMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIIjnRWA5FMmP6phVv6CX
# h8vwTANxi4Daid9Z+PM0RmJiMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# npYRM/odXkDAnzf2udL569W8cfGTgwVuenQ8ttIYzX8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY16VS54dJkqtwABAAABjTAiBCDO
# 2MA4MPi2qgFgVnEcgyWyJVrikjgys0pZwvA+BQuHmjANBgkqhkiG9w0BAQsFAASC
# AgAKcwZkqvSKtOw3a+3OOoC2mN+ixf8RTWH60DSBgBDnITU4StuOdO3YbF0yRuir
# tmAAxCRRvIeNgJI+FSj3Ijk8moc8vzAMlSOxR4yDcqB1jhxjjJuPT+DfCChg9eF7
# on/+dcI115ilU/IP3V1QOgfnM+IijkkGMhCU0QMyD8M1msj/HveUksZON1Bu1Bh+
# KYVYPWyIIDIdSd/uo4CynKb2TZjOF9LELEuF1aCYDR4/fS2J00Y8TeI5Ryf7TVeR
# LBPa2E/SmKYVVrkhYf/Ml4ruVh594rO4WHaMIXUGn1GlHzsmCCSHhsXz7Gov9lks
# exBt47i1wDArhQT8w5Rn8mvzx8oBrwQshyRs2t75cpx+YsZkHdzlvUqsc88eE7Ne
# +E6STdGBllgrKCJLuVTANfnO9D3/mSvZMQAeoRBSeCE3tKCc92aBoqW5z/RVnxfx
# VmUldBRjzK2aix89xD9a82nDmXVoaC2XEi447GslAwtJe5q/BoCQXvLfcmmI+NBX
# 50fTQzmMcJWuWgCjNa1At/jUZmAgDQ04ye98QuJ4txF2QwjLSAa35WDWgN0/gAxt
# Gd1XLGll/fPjGleSDJTe6+rFAZPHGQleCBhUR0W9N1zi/FYWNuWuk+MiO5J9CJ+1
# bgel14ZivfE1B2LYXWBjpGagCY2PxcS3xMhPI+PCB6Asyg==
# SIG # End signature block
