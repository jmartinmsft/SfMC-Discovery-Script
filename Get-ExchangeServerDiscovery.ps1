<#//***********************************************************************
//
// Get-ExchangeServerDiscovery.ps1
// Modified 21 September 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20230921.1931
//
//.NOTES
// 4.2 Adds the HealthChecker script data collection
// 20220823.1654 - Additional logging and option to run HealthChecker
// 20230421.1909 - Write event logs for start and finish
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

param(
    [Parameter(Mandatory=$true)] [bool]$HealthChecker,
    [Parameter(Mandatory=$false)] [string]$LogFile="$env:ExchangeInstallPath\Logging\SfMC Discovery\SfMC.log"
)

$script:ScriptVersion = "v20230921.1931"
if(!(Test-Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -ErrorAction Ignore)) {
    New-Item -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -ItemType Directory | Out-Null
}
if(Test-Path $LogFile -ErrorAction Ignore) {
    Remove-Item -Path $LogFile -Confirm:$false -Force
}


function LogToFile([string]$Details) {
	if ( [String]::IsNullOrEmpty($LogFile) ) { return }
	"$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToLongTimeString())   $Details" | Out-File $LogFile -Append
}

function Log([string]$Details, [ConsoleColor]$Colour) {
    if ($Colour -notlike $null)
    {
        $Colour = [ConsoleColor]::White
    }
    Write-Host $Details -ForegroundColor $Colour
    LogToFile $Details
}

function LogVerbose([string]$Details) {
    Write-Verbose $Details
    LogToFile $Details
}
LogVerbose "$($MyInvocation.MyCommand.Name) version $($script:ScriptVersion) starting"

function LogDebug([string]$Details) {
    Write-Debug $Details
    LogToFile $Details
}

$script:LastError = $Error[0]
function ErrorReported($Context) {
    # Check for any error, and return the result ($true means a new error has been detected)

    # We check for errors using $Error variable, as try...catch isn't reliable when remoting
    if ([String]::IsNullOrEmpty($Error[0])) { return } #$false }

    # We have an error, have we already reported it?
    if ($Error[0] -eq $script:LastError) { return  } #$false }

    # New error, so log it and return $true
    $script:LastError = $Error[0]
    if ($Context)
    {
        Log "Error ($Context): $($Error[0])" Red
    }
    else
    {
        Log "Error: $($Error[0])" Red
    }
    return #$true
}

function ReportError($Context) {
    # Reports error without returning the result
    ErrorReported $Context | Out-Null
}

function InvokeExchangeCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Cmdlet,
        [Parameter(Mandatory = $false)][bool]$ViewEntireForest,
        [string]$XmlOutputPath,
        [string]$Identity,
        [string]$Server,
        [switch]$Status,[scriptblock]$CatchActionFunction        
    )
    begin {
        Log([string]::Format("Calling: {0}", $MyInvocation.MyCommand)) Gray
        $returnValue = $null
    }
    process {
        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Log([string]::Format("Description: {0}", $ScriptBlockDescription)) Gray
        }

        try {
            $params = @{
                    ErrorAction  = "Stop"
                    WarningAction = "Ignore"
            }
            Log([string]::Format("Running the following Exchange cmdlet: {0}", $Cmdlet)) Gray
            if($Identity -notlike $null) {
                if($Status) {
                    $returnValue = & $Cmdlet -Identity $Identity -Status | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $XmlOutputPath
                }
                else{
                    $returnValue = & $Cmdlet -Identity $Identity | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $XmlOutputPath
                }
            }
            if($Server -notlike $null) {
                if($Status) {
                    $returnValue = & $Cmdlet -Server $Server -Status | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $XmlOutputPath
                }
                else {
                    $returnValue = & $Cmdlet -Server $Server | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $XmlOutputPath
                }
            }
            if($Identity -like $null -and $Server -like $null) {
                $returnValue = & $Cmdlet | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $XmlOutputPath
            }
        } catch {
            Log([string]::Format("Failed to run: {0}", $MyInvocation.MyCommand)) Gray
            InvokeCatchActionError $CatchActionFunction
        }
    }
    end {
        Log([string]::Format("Exiting: {0}", $MyInvocation.MyCommand)) Gray
        return $returnValue
    }
}

function InvokeCatchActionError {
    [CmdletBinding()]
    param(
        [scriptblock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}

function GetServerData {
	param ([string]$ServerName)
	foreach ($h in $hash.GetEnumerator()) {
		$Result = $null
        $CommandName = $h.Name 
		$Command = $h.Value
        $Error.Clear()
        Write-Verbose "Running the command: $Command"
        try{$Result = Invoke-Expression $h.Value}
        catch{
            Log([string]::Format("Error: {0} when running the cmdlet: {1}", $Error.Exception.ErrorRecord, $CommandName)) Gray
        }
		if($null -ne $Result) {	$Result | Export-Csv $outputPath\$ServerName-$CommandName.csv -NoTypeInformation -Force}
	}
}

function ZipCsvResults {
	## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    try {[System.IO.Compression.ZipFile]::CreateFromDirectory($outputPath, $zipFolder)}
    catch {
        try{Remove-Item -Path $zipFolder -Force -ErrorAction SilentlyContinue}
        catch{Write-Warning "Failed to remove file."}
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'update')
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        Get-ChildItem -Path $outputPath | Select-Object FullName | ForEach-Object {
            try{[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipFile, $_.FullName, (Split-Path $_.FullName -Leaf), $compressionLevel) | Out-Null }
            catch {Write-Warning "failed to add"}
        }
        $zipFile.Dispose()
    }
}

#region Dislaimer
$ScriptDisclaimer = @"
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
"@
Write-Host $ScriptDisclaimer -ForegroundColor Yellow
#Start-Sleep -Seconds 2
#endregion

Log([string]::Format("Writing event ID 1031 into the event log to notify the script has started.")) Gray
Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1031 -Message "The SfMC Exchange Server discovery script has started." -Category 1

## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings"
if(!(Test-Path $outputPath)) {
    Log([string]::Format("Creating logging directory for the discovery script results.")) Gray
    New-Item -Path $outputPath -ItemType Directory | Out-Null
}
else {
    Log([string]::Format("Removing any existing discovery script results.")) Gray
    Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force
}

Log([string]::Format("Adding Exchange Management snapin.")) Gray
$ServerName = $env:COMPUTERNAME
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

Log([string]::Format("Adding Exchange Management snapin.")) Gray
Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $env:COMPUTERNAME*.zip | Remove-Item -Confirm:$False -ErrorAction Ignore
InvokeExchangeCmdlet -Cmdlet "Set-ADServerSettings" -ViewEntireForest:$True

## Data collection starts
## General information
Log([string]::Format("Starting general server information data collection.")) Gray
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-ExchangeServer -Status -XmlOutputPath $outputPath\$ServerName-ExchangeServer.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-ExchangeCertificate -XmlOutputPath $outputPath\$ServerName-ExchangeCertificate.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-ServerComponentState -XmlOutputPath $outputPath\$ServerName-ServerComponentState.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-ServerHealth -XmlOutputPath $outputPath\$ServerName-ServerHealth.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-ServerMonitoringOverride -XmlOutputPath $outputPath\$ServerName-ServerMonitoringOverride.xml
InvokeExchangeCmdlet -Cmdlet Get-EventLogLevel -XmlOutputPath $outputPath\$ServerName-EventLogLevel.xml
InvokeExchangeCmdlet -Identity * -Cmdlet Get-HealthReport -XmlOutputPath $outputPath\$ServerName-HealthReport.xml

## Client access settings
Log([string]::Format("Starting client access server information data collection.")) Gray
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-AutodiscoverVirtualDirectory -XmlOutputPath $outputPath\$ServerName-AutodiscoverVirtualDirectory.xml
InvokeExchangeCmdlet -Cmdlet Get-ClientAccessServer -XmlOutputPath $outputPath\$ServerName-ClientAccessServer.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-EcpVirtualDirectory -XmlOutputPath $outputPath\$ServerName-EcpVirtualDirectory.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-WebServicesVirtualDirectory -XmlOutputPath $outputPath\$ServerName-WebServicesVirtualDirectory.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-MapiVirtualDirectory -XmlOutputPath $outputPath\$ServerName-MapiVirtualDirectory.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-ActiveSyncVirtualDirectory -XmlOutputPath $outputPath\$ServerName-ActiveSyncVirtualDirectory.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-OabVirtualDirectory -XmlOutputPath $outputPath\$ServerName-OabVirtualDirectory.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-OwaVirtualDirectory -XmlOutputPath $outputPath\$ServerName-OwaVirtualDirectory.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-OutlookAnywhere -XmlOutputPath $outputPath\$ServerName-OutlookAnywhere.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-PowerShellVirtualDirectory -XmlOutputPath $outputPath\$ServerName-PowerShellVirtualDirectory.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-RpcClientAccess -XmlOutputPath $outputPath\$ServerName-RpcClientAccess.xml

## Transport settings
Log([string]::Format("Starting transport server information data collection.")) Gray
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-ReceiveConnector -XmlOutputPath $outputPath\$ServerName-ReceiveConnector.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-ImapSettings -XmlOutputPath $outputPath\$ServerName-ImapSettings.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-PopSettings -XmlOutputPath $outputPath\$ServerName-PopSettings.xml
InvokeExchangeCmdlet -Cmdlet Get-TransportAgent -XmlOutputPath $outputPath\$ServerName-TransportAgent.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-TransportService -XmlOutputPath $outputPath\$ServerName-TransportService.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-MailboxTransportService -XmlOutputPath $outputPath\$ServerName-MailboxTransportService.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-FrontendTransportService -XmlOutputPath $outputPath\$ServerName-FrontendTransportService.xml

## Mailbox settings
Log([string]::Format("Starting mailbox server information data collection.")) Gray
$DagName = (Get-Cluster).Name
InvokeExchangeCmdlet -Identity $DagName -Cmdlet Get-DatabaseAvailabilityGroup -Status -XmlOutputPath $outputPath\$ServerName-DatabaseAvailabilityGroup.xml
InvokeExchangeCmdlet -Identity $DagName -Cmdlet Get-DatabaseAvailabilityGroupNetwork -XmlOutputPath $outputPath\$ServerName-DatabaseAvailabilityGroupNetwork.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-MailboxDatabase -Status -XmlOutputPath $outputPath\$ServerName-MailboxDatabase.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-MailboxServer -XmlOutputPath $outputPath\$ServerName-MailboxServer.xml

## Convert the XML into CSV files
Log([string]::Format("Converting the XML results into CSV files.")) Gray
Get-ChildItem $outputPath -Filter *.xml | ForEach-Object { Import-Clixml $_.FullName | Export-Csv $outputPath\$($_.BaseName).csv -NoTypeInformation -Force }
Get-ChildItem $outputPath -Filter *.xml | Remove-Item

Log([string]::Format("Starting server OS information data collection.")) Gray
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
GetServerData -ServerName $ServerName

#region HealthChecker
if($HealthChecker) {
    Log([string]::Format("Starting health checker data collection.")) Gray
    Set-Location $env:ExchangeInstallPath\Scripts
    Unblock-File -Path .\HealthChecker.ps1 -Confirm:$False
    .\HealthChecker.ps1 -OutputFilePath "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings" -SkipVersionCheck
}
#endregion

Log([string]::Format("Attempting to compress the results.")) Gray
$ts = Get-Date -f yyyyMMddHHmmss
[string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$ServerName-Settings-$ts.zip"
$zipReady = $false
$zipAttempt = 0
ZipCsvResults
while($zipReady -eq $false) {
    if(Get-Item -Path $zipFolder -ErrorAction Ignore) { 
        Log([string]::Format("Compression completed successfully.")) Gray
        Log([string]::Format("Writing event ID 1376 into the event log to notify the script has finished.")) Gray
        Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1376 -Message "The SfMC Exchange server discovery script has completed." -Category 1
        $zipReady = $true }
    else {
        Log([string]::Format("Compression attempt failed.")) Gray
        if($zipAttempt -eq 3) { $zipReady = $true }
        else {
            Log([string]::Format("Attempting to compress the results.")) Gray
            ZipCsvResults
            $zipAttempt++
            Start-Sleep -Seconds 10
        }
    }
}
