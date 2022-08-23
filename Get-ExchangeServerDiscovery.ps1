<#//***********************************************************************
//
// Get-ExchangeServerDiscovery.ps1
// Modified 23 August 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20220823.1654
//
//.NOTES
// 4.2 Adds the HealthChecker script data collection
// 20220823.1654 - Additional logging and option to run HealthChecker
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
    [Parameter(Mandatory=$true)] [bool]$HealthChecker
)

#region Disclaimer
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
#endregion

function Write-Verbose {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Verbose from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {
        #write to the debug log and call Write-Verbose normally
        Write-VerboseLog $Message
        Microsoft.PowerShell.Utility\Write-Verbose $Message
    }
}

function Write-VerboseLog ($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}

function Get-NewLoggerInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)] [string]$LogDirectory,
        [ValidateNotNullOrEmpty()][string]$LogName = "Script_Logging",
        [bool]$AppendDateTime = $true,
        [bool]$AppendDateTimeToFileName = $true,
        [int]$MaxFileSizeMB = 10,
        [int]$CheckSizeIntervalMinutes = 10,
        [int]$NumberOfLogsToKeep = 10
    )

    $fileName = if ($AppendDateTimeToFileName) { "{0}_{1}.txt" -f $LogName, ((Get-Date).ToString('yyyyMMddHHmmss')) } else { "$LogName.txt" }
    $fullFilePath = [System.IO.Path]::Combine($LogDirectory, $fileName)

    if (-not (Test-Path $LogDirectory)) {
        try {
            New-Item -ItemType Directory -Path $LogDirectory -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to create Log Directory: $LogDirectory"
        }
    }

    return [PSCustomObject]@{
        FullPath                 = $fullFilePath
        AppendDateTime           = $AppendDateTime
        MaxFileSizeMB            = $MaxFileSizeMB
        CheckSizeIntervalMinutes = $CheckSizeIntervalMinutes
        NumberOfLogsToKeep       = $NumberOfLogsToKeep
        BaseInstanceFileName     = $fileName.Replace(".txt", "")
        Instance                 = 1
        NextFileCheckTime        = ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
        PreventLogCleanup        = $false
        LoggerDisabled           = $false
    } | Write-LoggerInstance -Object "Starting Logger Instance $(Get-Date)"
}

function Write-LoggerInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance,

        [Parameter(Mandatory = $true, Position = 1)]
        [object]$Object
    )
    process {
        if ($LoggerInstance.LoggerDisabled) { return }

        if ($LoggerInstance.AppendDateTime -and
            $Object.GetType().Name -eq "string") {
            $Object = "[$([System.DateTime]::Now)] : $Object"
        }

        # Doing WhatIf:$false to support -WhatIf in main scripts but still log the information
        $Object | Out-File $LoggerInstance.FullPath -Append -WhatIf:$false

        #Upkeep of the logger information
        if ($LoggerInstance.NextFileCheckTime -gt [System.DateTime]::Now) {
            return
        }

        #Set next update time to avoid issues so we can log things
        $LoggerInstance.NextFileCheckTime = ([System.DateTime]::Now).AddMinutes($LoggerInstance.CheckSizeIntervalMinutes)
        $item = Get-ChildItem $LoggerInstance.FullPath

        if (($item.Length / 1MB) -gt $LoggerInstance.MaxFileSizeMB) {
            $LoggerInstance | Write-LoggerInstance -Object "Max file size reached rolling over" | Out-Null
            $directory = [System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)
            $fileName = "$($LoggerInstance.BaseInstanceFileName)-$($LoggerInstance.Instance).txt"
            $LoggerInstance.Instance++
            $LoggerInstance.FullPath = [System.IO.Path]::Combine($directory, $fileName)

            $items = Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*"

            if ($items.Count -gt $LoggerInstance.NumberOfLogsToKeep) {
                $item = $items | Sort-Object LastWriteTime | Select-Object -First 1
                $LoggerInstance | Write-LoggerInstance "Removing Log File $($item.FullName)" | Out-Null
                $item | Remove-Item -Force
            }
        }
    }
    end {
        return $LoggerInstance
    }
}

function Invoke-ExchangeCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Cmdlet,

        [Parameter(Mandatory = $false)]
        [bool]
        $ViewEntireForest,
        
        [string]
        $XmlOutputPath,

        [string]
        $Identity,

        [string]
        $Server,

        [switch]
        $Status,

        [scriptblock]
        $CatchActionFunction        
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $returnValue = $null
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Write-Verbose "Description: $ScriptBlockDescription"
        }

        try {
            $params = @{
                    ErrorAction  = "Stop"
                    WarningAction = "Ignore"
            }
            if($ViewEntireForest) {
                Write-Verbose "Running the following Exchange cmdlet: $Cmdlet"
                $returnValue = & $Cmdlet -ViewEntireForest:$True
            }
            else{
                Write-Verbose "Running the following Exchange cmdlet: $Cmdlet "
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
            }
            
        } catch {
            Write-Verbose "Failed to run $($MyInvocation.MyCommand)"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return $returnValue
    }
}

function Invoke-CatchActionError {
    [CmdletBinding()]
    param(
        [scriptblock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}

function Get-ServerData {
	param ([string]$ServerName)
	foreach ($h in $hash.GetEnumerator()) {
		$Result = $null
        $CommandName = $h.Name 
		$Command = $h.Value
        $Error.Clear()
        Write-Verbose "Running the command: $Command"
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

## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings"
if(!(Test-Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory | Out-Null
}
else {Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force }

$Script:Logger = Get-NewLoggerInstance -LogName "SfMCServerSettings-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue -LogDirectory $outputPath
Write-Verbose "Adding Exchange Management snapin."
$ServerName = $env:COMPUTERNAME
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

Write-Verbose "Removing any existing results."
Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $env:COMPUTERNAME*.zip | Remove-Item -Confirm:$False -ErrorAction Ignore
Invoke-ExchangeCmdlet -Cmdlet "Set-ADServerSettings" -ViewEntireForest:$True

## Data collection starts
## General information
Invoke-ExchangeCmdlet -Identity $ServerName -Cmdlet Get-ExchangeServer -Status -XmlOutputPath $outputPath\$ServerName-ExchangeServer.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-ExchangeCertificate -XmlOutputPath $outputPath\$ServerName-ExchangeCertificate.xml
Invoke-ExchangeCmdlet -Identity $ServerName -Cmdlet Get-ServerComponentState -XmlOutputPath $outputPath\$ServerName-ServerComponentState.xml
Invoke-ExchangeCmdlet -Identity $ServerName -Cmdlet Get-ServerHealth -XmlOutputPath $outputPath\$ServerName-ServerHealth.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-ServerMonitoringOverride -XmlOutputPath $outputPath\$ServerName-ServerMonitoringOverride.xml
Invoke-ExchangeCmdlet -Cmdlet Get-EventLogLevel -XmlOutputPath $outputPath\$ServerName-EventLogLevel.xml
Invoke-ExchangeCmdlet -Identity * -Cmdlet Get-HealthReport -XmlOutputPath $outputPath\$ServerName-HealthReport.xml
#Get-ExchangeServer $ServerName -Status -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName  | Export-Clixml $outputPath\$ServerName-ExchangeServer.xml
#Get-ExchangeCertificate -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ExchangeCertificate.xml
#Get-EventLogLevel -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-EventLogLevel.xml
#Get-HealthReport * -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-HealthReport.xml
#Get-ServerComponentState $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ServerComponentState.xml
#Get-ServerHealth $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ServerHealth.xml
#Get-ServerMonitoringOverride $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ServerMonitoringOverride.xml

## Client access settings
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-AutodiscoverVirtualDirectory -XmlOutputPath $outputPath\$ServerName-AutodiscoverVirtualDirectory.xml
Invoke-ExchangeCmdlet -Cmdlet Get-ClientAccessServer -XmlOutputPath $outputPath\$ServerName-ClientAccessServer.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-EcpVirtualDirectory -XmlOutputPath $outputPath\$ServerName-EcpVirtualDirectory.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-WebServicesVirtualDirectory -XmlOutputPath $outputPath\$ServerName-WebServicesVirtualDirectory.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-MapiVirtualDirectory -XmlOutputPath $outputPath\$ServerName-MapiVirtualDirectory.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-ActiveSyncVirtualDirectory -XmlOutputPath $outputPath\$ServerName-ActiveSyncVirtualDirectory.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-OabVirtualDirectory -XmlOutputPath $outputPath\$ServerName-OabVirtualDirectory.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-OwaVirtualDirectory -XmlOutputPath $outputPath\$ServerName-OwaVirtualDirectory.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-OutlookAnywhere -XmlOutputPath $outputPath\$ServerName-OutlookAnywhere.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-PowerShellVirtualDirectory -XmlOutputPath $outputPath\$ServerName-PowerShellVirtualDirectory.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-RpcClientAccess -XmlOutputPath $outputPath\$ServerName-RpcClientAccess.xml
#Get-AutodiscoverVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-AutodiscoverVirtualDirectory.xml
#Get-ClientAccessServer $ServerName -WarningAction Ignore -IncludeAlternateServiceAccountCredentialStatus -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ClientAccessServer.xml
#Get-EcpVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-EcpVirtualDirectory.xml
#Get-WebServicesVirtualDirectory  -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-WebServicesVirtualDirectory.xml
#Get-MapiVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MapiVirtualDirectory.xml
#Get-ActiveSyncVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ActiveSyncVirtualDirectory.xml
#Get-OabVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-OabVirtualDirectory.xml
#Get-OwaVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-OwaVirtualDirectory.xml
#Get-OutlookAnywhere -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-OutlookAnywhere.xml
#Get-PowerShellVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-PowerShellVirtualDirectory.xml
#Get-RpcClientAccess -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-RpcClientAccess.xml

## Transport settings
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-ReceiveConnector -XmlOutputPath $outputPath\$ServerName-ReceiveConnector.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-ImapSettings -XmlOutputPath $outputPath\$ServerName-ImapSettings.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-PopSettings -XmlOutputPath $outputPath\$ServerName-PopSettings.xml
Invoke-ExchangeCmdlet -Cmdlet Get-TransportAgent -XmlOutputPath $outputPath\$ServerName-TransportAgent.xml
Invoke-ExchangeCmdlet -Identity $ServerName -Cmdlet Get-TransportService -XmlOutputPath $outputPath\$ServerName-TransportService.xml
Invoke-ExchangeCmdlet -Identity $ServerName -Cmdlet Get-MailboxTransportService -XmlOutputPath $outputPath\$ServerName-MailboxTransportService.xml
Invoke-ExchangeCmdlet -Identity $ServerName -Cmdlet Get-FrontendTransportService -XmlOutputPath $outputPath\$ServerName-FrontendTransportService.xml
#Invoke-ExchangeCmdlet -Cmdlet Get-TransportPipeline -XmlOutputPath $outputPath\$ServerName-TransportPipeline.xml
#Get-ReceiveConnector -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ReceiveConnector.xml
#Get-ImapSettings -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ImapSettings.xml
#Get-PopSettings -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-PopSettings.xml
#Get-TransportAgent -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-TransportAgent.xml
#Get-TransportService $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-TransportService.xml
#Get-MailboxTransportService -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MailboxTransportService.xml
#Get-FrontendTransportService $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-FrontendTransportService.xml
#Get-TransportPipeline -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-TransportPipeline.xml

## Mailbox settings
$DagName = (Get-Cluster).Name
Invoke-ExchangeCmdlet -Identity $DagName -Cmdlet Get-DatabaseAvailabilityGroup -Status -XmlOutputPath $outputPath\$ServerName-DatabaseAvailabilityGroup.xml
Invoke-ExchangeCmdlet -Identity $DagName -Cmdlet Get-DatabaseAvailabilityGroupNetwork -XmlOutputPath $outputPath\$ServerName-DatabaseAvailabilityGroupNetwork.xml
Invoke-ExchangeCmdlet -Server $ServerName -Cmdlet Get-MailboxDatabase -Status -XmlOutputPath $outputPath\$ServerName-MailboxDatabase.xml
Invoke-ExchangeCmdlet -Identity $ServerName -Cmdlet Get-MailboxServer -XmlOutputPath $outputPath\$ServerName-MailboxServer.xml
#Invoke-ExchangeCmdlet -Identity $ServerName -Cmdlet Get-PublicFolderDatabase -XmlOutputPath $outputPath\$ServerName-PublicFolderDatabase.xml
#Get-DatabaseAvailabilityGroup (Get-Cluster).Name -Status -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-DatabaseAvailabilityGroup.xml
#Get-DatabaseAvailabilityGroupNetwork (Get-Cluster).Name -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-DatabaseAvailabilityGroupNetwork.xml
#Get-MailboxDatabase -Server $ServerName -WarningAction Ignore -Status -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MailboxDatabase.xml
#Get-MailboxServer $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MailboxServer.xml
#Get-PublicFolderDatabase -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-PublicFolderDatabase.xml

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

#region HealthChecker
if($HealthChecker) {
    Set-Location $env:ExchangeInstallPath\Scripts
    Unblock-File -Path .\HealthChecker.ps1 -Confirm:$False
    .\HealthChecker.ps1 -OutputFilePath "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings" -SkipVersionCheck
}
#endregion

Write-Verbose "Attempting to compress the results."
$ts = Get-Date -f yyyyMMddHHmmss
[string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$ServerName-Settings-$ts.zip"
$zipReady = $false
$zipAttempt = 0
while($zipReady -eq $false) {
    if(Get-Item -Path $zipFolder -ErrorAction Ignore) { 
        Write-Verbose "Compression completed successfully."
        $zipReady = $true }
    else {
        Write-Verbose "Compression attempt failed."
        if($zipAttempt -eq 3) { $zipReady = $true }
        else {
            Write-Verbose "Attempting to compress the results."
            Zip-CsvResults
            $zipAttempt++
            Start-Sleep -Seconds 10
        }
    }
}
