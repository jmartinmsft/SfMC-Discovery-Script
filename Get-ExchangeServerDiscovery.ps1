<#//***********************************************************************
//
// Get-ExchangeServerDiscovery.ps1
// Modified 21 April 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20230421.1909
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

Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1031 -Message "The SfMC Exchange Server discovery script has started." -Category 1
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
        Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1376 -Message "The SfMC Exchange server discovery script has completed." -Category 1
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

# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAdpCqseW35iwTz
# fXgFx2Y3lFxzKnYqCofFkWV+VkYE96CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPhygGjKc6NecX8fYwQZ0ig4
# 4H+kxP1Pu8oACfUDWiDnMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAbSMrpFRBUOeyDdvm6FEhBH6jHI73u4JMmNm7IxPzXTRKCKIfKZrTg
# y670dwjGgr/BB1/bAepUFiPi6iH9iphd1vcn+icNGl1MiksjxbC8ruFc9ClXN7X7
# ys62VXzqylCmnpqzh/qb+1ymZAQ/RWVlghJqrWTad7JgmtUiLr4nebTd/+7qsL7k
# ekcwWrpq7e4tklwioaKN++aqIo1hCwysR/9A+eok5d/zcf0dVol5xyIGZBJzYZTp
# gbS6xvwmDeWfXwNhQ7TkusPyxLQf9lPmsf0G5C2YwrB9XZHHNj6vTmCfyALrXUz2
# VB2DUsbtENpA+l9I8V4s/I+e0sKzpcJ7oYIXDDCCFwgGCisGAQQBgjcDAwExghb4
# MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIAGvruZh0NC+DEa/CV4dGpqu0c5BPpp9m10vlZj8PoF/AgZjEVAU
# +mUYEzIwMjIwOTA5MTc1NTA3Ljk0M1owBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3
# ODgwLUUzOTAtODAxNDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABqFXwYanMMBhcAAEAAAGoMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTEyM1oXDTIzMDUxMTE4NTEyM1owgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3ODgwLUUzOTAtODAx
# NDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAKPabcrALiXX8pjyXpcMN89KTvcmlAiD
# w4pU+HejZhibUeo/HUy+P9VxWhCX7ogeeKPJ677+LeVdPdG5hTvGDgSuo3w+Acmz
# cXZ2QCGUgUReLUKbmrr06bB0xhvtZwoelhxtPkjJFsbTGtSt+V7E4VCjPdYqQZ/i
# N0ArXXmgbEfVyCwS+h2uooBhM5UcbPogtr5VpgdzbUM4/rWupmFVjPB1asn3+wv7
# aBCK8j9QUJroY4y1pmZSf0SuGMWY7cm2cvrbdm7XldljqRdHW+CQAB4EqiOqgumf
# R+aSpo5T75KG0+nsBkjlGSsU1Bi15p4rP88pZnSop73Gem9GWO2GRLwP15YEnKsc
# zxhGY+Z8NEa0QwMMiVlksdPU7J5qK9gxAQjOJzqISJzhIwQWtELqgJoHwkqTxem3
# grY7B7DOzQTnQpKWoL0HWR9KqIvaC7i9XlPv+ue89j9e7fmB4nh1hulzEJzX6RMU
# 9THJMlbO6OrP3NNEKJW8jipCny8H1fuvSuFfuB7t++KK9g2c2NKu5EzSs1nKNqtl
# 4KO3UzyXLWvTRDO4D5PVQOda0tqjS/AWoUrxKC5ZPlkLE+YPsS5G+E/VCgCaghPy
# BZsHNK7wHlSf/26uhLnKp6XRAIroiEYl/5yW0mShjvnARPr0GIlSm0KrqSwCjR5c
# kWT1sKaEb8w3AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUNsfb4+L4UutlNh/MxjGk
# j0kLItUwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEAcTuCS2Rqqmf2mPr6OUydhmUx+m6vpEPszWioJXbnsRbny62n
# F9YXTKuSNWH1QFfyc/2N3YTEp4hE8YthYKgDM/HUhUREX3WTwGseYuuDeSxWRJWC
# orAHF1kwQzIKgrUc3G+uVwAmG/EI1ELRExA4ftx0Ehrf59aJm7Ongn0lTSSiKUeu
# GA+My6oCi/V8ETxz+eblvQANaltJgGfppuWXYT4jisQKETvoJjBv5x+BA0oEFu7g
# GaeMDkZjnO5vdf6HeKneILs9ZvwIWkgYQi2ZeozbxglG5YwExoixekxrRTDZwMok
# IYxXmccscQ0xXmh+I3vo7hV9ZMKTa9Paz5ne4cc8Odw1T+624mB0WaW9HAE1hojB
# 6CbfundtV/jwxmdKh15plJXnN1yM7OL924HqAiJisHanpOEJ4Um9b3hFUXE2uEJL
# 9aYuIgksVYIq1P29rR4X7lz3uEJH6COkoE6+UcauN6JYFghN9I8JRBWAhHX4GQHl
# ngsdftWLLiDZMynlgRCZzkYI24N9cx+D367YwclqNY6CZuAgzwy12uRYFQasYHYK
# 1hpzyTtuI/A2B8cG+HM6X1jf2d9uARwH6+hLkPtt3/5NBlLXpOl5iZyRlBi7iDXk
# WNa3juGfLAJ3ISDyNh7yu+H4yQYyRs/MVrCkWUJs9EivLKsNJ2B/IjNrStYwggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCCAjsCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo3ODgwLUUzOTAtODAxNDElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAbLr8xJ9BB4rL
# 4Yg58X1LZ5iQdyyggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAObFsYAwIhgPMjAyMjA5MDkxNjM1MTJaGA8yMDIy
# MDkxMDE2MzUxMlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5sWxgAIBADAKAgEA
# AgIh6QIB/zAHAgEAAgISzTAKAgUA5scDAAIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBACa68ebQWjyNjwLaHTe+aC5SgUuAtNzL7srEjZxCTjJkJGlQR7GECKYv
# ef6aFcsoE2J32XqphKzrNHCuFcX78aKd46C3XZIS2vYcpVVyhpjFhi+bPvjOFmZK
# w9LDLeKw857Yv+NXBfUMAhpT2tOvnsMGa7xbpXN6LwNq1VXx/2QOMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGoVfBhqcww
# GFwAAQAAAagwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgstMEwKnTPLmc78kjIi84MGfF0EHUouVW
# aU1ow/66ASAwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCB0/ssdAMsHwnNw
# hfFBXPlFnRvWhHqSX9YLUxBDl1xlpjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABqFXwYanMMBhcAAEAAAGoMCIEIKrYfH8NJALKOGaq
# qmkzuzR+HRR+Jo9gdmXdqSRHaCTUMA0GCSqGSIb3DQEBCwUABIICABMahDem8NXi
# AcmzLVbRcoNDmJ+m5GE6McP5OU3RKWsTHrYWGM9y53j2STn6SLTppjK45tsH2ytf
# WTdT3ZtolqRVcCv59K79pQV35cN+IHNBDXv8vzEsUe/f2YIEbT99tppHYnN6ojVt
# h9zpeKq4Bj0cOypzaOq/rvHtOQV1XhDm90EFIEF/XeeftTa88ClvYEIIEKut/td1
# G3XMwy43yQs1T5HxWW+3fueOyo06d/0z9f34Yd24Vl6xFeU+dZaR2iE0wPyV2J4/
# rImjqQYZI4orQjklUEmNa+POsp1FO9KiS2S7G1QTtwJRlwNXS8891A3B2q+ssCbi
# +T/Dn3QBBLmef6P5BBSCo01Ob8YV9DmDIRMdFw0drcpAC+sp1Hc0/680AG/aGKNP
# TMVtnJGrF4FZnv1LUdQ31vDxUqCrG/gXBmbjlTvW7PjQ+2oIpLFD2+zz9IVoViIc
# vd3kAALrHLOy+ieNyDZwk6W+ZrFuJQEqbtzKujTeXD8WtdpCIysm0EW3jyof7y9A
# Hyl7G1AXXmxmIIul47+4Y2O4/DEKhWmDZSZ6iflvrKD9MdeFz67at6U8GAjBQAhH
# +zqMVMFyXw2S3VUD9vdPvtQpiwBmlHCVXr8PO8McWhFro5QzaOGb3FaBgmo9CY7w
# U9wU/FrMI2oTFTzK269Jjh5sX9daTcQE
# SIG # End signature block
