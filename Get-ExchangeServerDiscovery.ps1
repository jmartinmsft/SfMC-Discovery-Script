<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>
# Version 20240506.1338
param(
    [Parameter(Mandatory=$true)] [bool]$HealthChecker,
    [Parameter(Mandatory=$false)] [string]$LogFile="$env:ExchangeInstallPath\Logging\SfMC Discovery\SfMC.log"
)
function Write-VerboseLog ($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}

function Write-HostLog ($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}

function Write-Host {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Proper handling of write host with colors')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [object]$Object,
        [switch]$NoNewLine,
        [string]$ForegroundColor
    )
    process {
        $consoleHost = $host.Name -eq "ConsoleHost"

        if ($null -ne $Script:WriteHostManipulateObjectAction) {
            $Object = & $Script:WriteHostManipulateObjectAction $Object
        }

        $params = @{
            Object    = $Object
            NoNewLine = $NoNewLine
        }

        if ([string]::IsNullOrEmpty($ForegroundColor)) {
            if ($null -ne $host.UI.RawUI.ForegroundColor -and
                $consoleHost) {
                $params.Add("ForegroundColor", $host.UI.RawUI.ForegroundColor)
            }
        } elseif ($ForegroundColor -eq "Yellow" -and
            $consoleHost -and
            $null -ne $host.PrivateData.WarningForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.WarningForegroundColor)
        } elseif ($ForegroundColor -eq "Red" -and
            $consoleHost -and
            $null -ne $host.PrivateData.ErrorForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.ErrorForegroundColor)
        } else {
            $params.Add("ForegroundColor", $ForegroundColor)
        }

        Microsoft.PowerShell.Utility\Write-Host @params

        if ($null -ne $Script:WriteHostDebugAction -and
            $null -ne $Object) {
            &$Script:WriteHostDebugAction $Object
        }
    }
}

function Invoke-CatchActionErrorLoop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$CurrentErrors,
        [Parameter(Mandatory = $false, Position = 1)]
        [ScriptBlock]$CatchActionFunction
    )
    process {
        if ($null -ne $CatchActionFunction -and
            $Error.Count -ne $CurrentErrors) {
            $i = 0
            while ($i -lt ($Error.Count - $currentErrors)) {
                & $CatchActionFunction $Error[$i]
                $i++
            }
        }
    }
}

function SetWriteHostAction ($DebugAction) {
    $Script:WriteHostDebugAction = $DebugAction
}

function Write-Verbose {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Verbose from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {

        if ($null -ne $Script:WriteVerboseManipulateMessageAction) {
            $Message = & $Script:WriteVerboseManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Verbose $Message

        if ($null -ne $Script:WriteVerboseDebugAction) {
            & $Script:WriteVerboseDebugAction $Message
        }

        # $PSSenderInfo is set when in a remote context
        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteVerboseDebugAction) {
            & $Script:WriteRemoteVerboseDebugAction $Message
        }
    }
}

function SetWriteVerboseAction ($DebugAction) {
    $Script:WriteVerboseDebugAction = $DebugAction
}

function Write-Warning {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Warning from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )
    process {

        if ($null -ne $Script:WriteWarningManipulateMessageAction) {
            $Message = & $Script:WriteWarningManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Warning $Message

        # Add WARNING to beginning of the message by default.
        $Message = "WARNING: $Message"

        if ($null -ne $Script:WriteWarningDebugAction) {
            & $Script:WriteWarningDebugAction $Message
        }

        # $PSSenderInfo is set when in a remote context
        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteWarningDebugAction) {
            & $Script:WriteRemoteWarningDebugAction $Message
        }
    }
}

function SetWriteWarningAction ($DebugAction) {
    $Script:WriteWarningDebugAction = $DebugAction
}

function Get-NewLoggerInstance {
    [CmdletBinding()]
    param(
        [string]$LogDirectory = (Get-Location).Path,

        [ValidateNotNullOrEmpty()]
        [string]$LogName = "Script_Logging",

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
            throw "Failed to create Log Directory: $LogDirectory. Inner Exception: $_"
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

function Invoke-CatchActionError {
    [CmdletBinding()]
    param(
        [ScriptBlock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}

function WriteErrorInformationBase {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0],
        [ValidateSet("Write-Host", "Write-Verbose")]
        [string]$Cmdlet
    )

    if ($null -ne $CurrentError.OriginInfo) {
        & $Cmdlet "Error Origin Info: $($CurrentError.OriginInfo.ToString())"
    }

    & $Cmdlet "$($CurrentError.CategoryInfo.Activity) : $($CurrentError.ToString())"

    if ($null -ne $CurrentError.Exception -and
        $null -ne $CurrentError.Exception.StackTrace) {
        & $Cmdlet "Inner Exception: $($CurrentError.Exception.StackTrace)"
    } elseif ($null -ne $CurrentError.Exception) {
        & $Cmdlet "Inner Exception: $($CurrentError.Exception)"
    }

    if ($null -ne $CurrentError.InvocationInfo.PositionMessage) {
        & $Cmdlet "Position Message: $($CurrentError.InvocationInfo.PositionMessage)"
    }

    if ($null -ne $CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage) {
        & $Cmdlet "Remote Position Message: $($CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage)"
    }

    if ($null -ne $CurrentError.ScriptStackTrace) {
        & $Cmdlet "Script Stack: $($CurrentError.ScriptStackTrace)"
    }
}

function Write-VerboseErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Verbose"
}

function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,

        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock,

        [string]
        $ScriptBlockDescription,

        [object]
        $ArgumentList,

        [bool]
        $IncludeNoProxyServerOption,

        [scriptblock]
        $CatchActionFunction,

        [System.Management.Automation.PSCredential]$Credential,
        [bool]$IsExchangeServer
    )
    begin {
        Write-Verbose ([string]::Format("Calling: {0}", $MyInvocation.MyCommand))
        $returnValue = $null
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Write-Verbose ([string]::Format("Description: ",$ScriptBlockDescription))
        }

        try {
            $script:LastError = $Error[0]
            if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {

                $params = @{
                    ComputerName = $ComputerName
                    ScriptBlock  = $ScriptBlock
                    ErrorAction  = "Ignore"
                }

                if ($Credential -notlike $null -and $IsExchangeServer -eq $false) {
                    Write-Verbose ([string]::Format("Including Credential"))
                    $params.Add("Credential", $Credential)
                }

                if ($IncludeNoProxyServerOption) {
                    Write-Verbose ([string]::Format("Including SessionOption"))
                    $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
                }

                if ($null -ne $ArgumentList) {
                    Write-Verbose ([string]::Format("Running Invoke-Command with argument list"))
                    $params.Add("ArgumentList", $ArgumentList)
                } else {
                    Write-Verbose ([string]::Format("IRunning Invoke-Command without argument list"))
                }
                Write-Verbose ([string]::Format("Running Invoke-Command using the following: "))
                Write-Verbose ($params | Out-String)
                $returnValue = Invoke-Command @params
            } else {

                if ($null -ne $ArgumentList) {
                    Write-Verbose ([string]::Format("Running Script Block Locally with argument list"))
                    # if an object array type expect the result to be multiple parameters
                    if ($ArgumentList.GetType().Name -eq "Object[]") {
                        Write-Verbose ([string]::Format("Running Invoke-Command using the following: "))
                        Write-Verbose ($params | ForEach-Object{ [pscustomobject]$_ })
                        $returnValue = & $ScriptBlock @ArgumentList
                    } else {
                        Write-Verbose ([string]::Format("Running Invoke-Command using the following: "))
                        Write-Verbose ($params | ForEach-Object{ [pscustomobject]$_ })
                        $returnValue = & $ScriptBlock @ArgumentList
                    }
                } else {
                    Write-Verbose ([string]::Format("Running Script Block Locally without argument list"))
                    Write-Verbose ([string]::Format("Running Invoke-Command using the following: "))
                    Write-Verbose ($params | ForEach-Object{ [pscustomobject]$_ })
                    $returnValue = & $ScriptBlock
                }
            }
        } catch {
            Write-Verbose ([string]::Format("Failed to run {0} ", $MyInvocation.MyCommand))
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        Write-Verbose ([string]::Format("Exiting: {0}", $MyInvocation.MyCommand))
        return $returnValue
    }
}

function GetExchangeInstallPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ExchangeServer
    )
    $s = Get-ExchangeServer $ExchangeServer
    $Filter = "(&(name=$($s.Name))(ObjectClass=msExchExchangeServer))"
    [string]$RootOU = $s.DistinguishedName
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($RootOU)")
    $Searcher.Filter = $Filter
    $Searcher.SearchScope = "Base"
    $SearcherResult = ($Searcher.FindAll()).Properties.msexchinstallpath
    [string]$exchInstallPath = $null
    if(($SearcherResult | Get-Member | Select-Object -First 1 TypeName).TypeName -notlike "*String*") {
        $SearcherResult| ForEach-Object { [string]$exchInstallPath = $exchInstallPath+[System.Text.Encoding]::ASCII.GetString($_) }
    }
    else {$exchInstallPath = $SearcherResult}
    return $exchInstallPath
}
function CheckOrgCollectionStarted{
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ExchangeServer
    )
    Write-Verbose ([string]::Format("Checking if Exchange organization data collection started on {0}.", $ExchangeServer))
    $eventParams = @{
        ScriptBlock         = {Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1125 -After (Get-Date -Date (Get-Date).AddMinutes(-2) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore}
        ComputerName        = $ExchangeServer
        Credential      = $Credential
    }
    $StartCheck = Invoke-ScriptBlockHandler @eventParams
    if($StartCheck) {
        Write-Verbose ([string]::Format("Exchange organization data collection has started on {0}.", $ExchangeServer))
        return $null
    }
    else {
        Write-Host ([string]::Format("Exchange organization data collection failed to start on {0}.", $ExchangeServer)) -ForegroundColor Yellow
        $OrgTask = Invoke-ScriptBlockHandler -ScriptBlock {Get-ScheduledTask ExchangeOrgDiscovery -ErrorAction Ignore -TaskPath \ } -ComputerName $ExchangeServer -Credential $Credential
        if($OrgTask -like $null) {
            Write-Verbose ([string]::Format("Failed to create scheduled task on {0}.", $ExchangeServer))
            return $null
        }
        else {
            Write-Verbose ([string]::Format("Exchange organization scheduled task found on {0}.", $ExchangeServer))
            Write-Verbose ([string]::Format("Attempting to start the Exchange organization scheduled task on {0}.", $ExchangeServer))
            Invoke-ScriptBlockHandler -ScriptBlock {Start-ScheduledTask ExchangeOrgDiscovery -TaskPath \ -ErrorAction Ignore } -ComputerName $ExchangeServer -Credential $Credential
        }
    }        
}
function CheckServerCollectionStarted{
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ExchangeServer
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose ([string]::Format("Checking if Exchange server data collection started on {0}.", $ExchangeServer))
    $eventParams = @{
        ScriptBlock         = {Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1031 -After (Get-Date -Date (Get-Date).AddMinutes(-2) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore}
        ComputerName        = $ExchangeServer
        Credential      = $Credential
    }
    $StartCheck = Invoke-ScriptBlockHandler @eventParams
    #$StartCheck = Invoke-ScriptBlockHandler -ScriptBlock {Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1031 -After (Get-Date -Date (Get-Date).AddMinutes(-2) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $s.Fqdn -Credential $Credential
    if($StartCheck){
        return $null
    }
    else {
        Write-Verbose ([string]::Format("Exchange server data collection failed to start on {0}.", $ExchangeServer))
        Write-Verbose ([string]::Format("Checking for Exchange server scheduled task on {0}.", $ExchangeServer))
        $ServerTask = Invoke-ScriptBlockHandler -ScriptBlock {Get-ScheduledTask ExchangeServerDiscovery -ErrorAction Ignore -TaskPath \ } -ComputerName $ExchangeServer -Credential $Credential
        if($ServerTask -like $null) {
            Write-Verbose ([string]::Format("Failed to create scheduled task on {0}.", $ExchangeServer))
            return $null
        }
        else {
            Write-Verbose ([string]::Format("Exchange server scheduled task found on {0}.", $ExchangeServer))
            Write-Verbose ([string]::Format("Attempting to start the Exchange server scheduled task on {0}.", $ExchangeServer))
            Invoke-ScriptBlockHandler -ScriptBlock {Start-ScheduledTask ExchangeServerDiscovery -TaskPath \ -ErrorAction Ignore } -ComputerName $ExchangeServer -Credential $Credential
        }
    }
    return $null  
}

function ConnectRemotePowerShell {
    
    Write-Host ([string]::Format("Script not running on an Exchange server. Attempting remote PowerShell session with {0}.", $ExchangeServer))
    $params = @{
        ConfigurationName = "Microsoft.Exchange"
        ConnectionUri = "http://$ExchangeServer/Powershell"
        AllowRedirection = $null
        Authentication = "Kerberos"
        Credential = $Credential
        ErrorAction = "Ignore"
        SessionOption = $Script:SessionOption
        WarningAction = "Ignore"
        Name = "SfMC"
    }
    try {
        Import-PSSession (New-PSSession @params) -WarningAction Ignore -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host ([string]::Format("Failed to establish a remote PowerShell session with {0}.", $ExchangeServer)) -ForegroundColor Red
        exit
    }

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
        Write-Verbose ([string]::Format("Calling: {0}", $MyInvocation.MyCommand))
        $returnValue = $null
    }
    process {
        try {
            Write-Host ([string]::Format("Running the following Exchange cmdlet: {0}", $Cmdlet)) -ForegroundColor Cyan
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
            Write-Host ([string]::Format("Failed to run: {0}", $MyInvocation.MyCommand)) -ForegroundColor Red
            InvokeCatchActionError $CatchActionFunction
        }
    }
    end {
        Write-Verbose ([string]::Format("Exiting: {0}", $MyInvocation.MyCommand))
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
            Write-Host ([string]::Format("Error: {0} when running the cmdlet: {1}", $Error.Exception.ErrorRecord, $CommandName)) -ForegroundColor Cyan
        }
		if($null -ne $Result) {	$Result | Export-Csv $outputPath\$ServerName-$CommandName.csv -NoTypeInformation -Force}
	}
}

function ZipCsvResults {
    param ([string]$ZipPath)
	## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    Write-Host ([string]::Format("Attempting to zip the results.")) -ForegroundColor Cyan
    try {[System.IO.Compression.ZipFile]::CreateFromDirectory($outputPath, $ZipPath)}
    catch {
        try{Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue}
        catch{Write-Warning "Failed to remove file."}
        $zipFile = [System.IO.Compression.ZipFile]::Open($ZipPath, 'update')
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
//***********************************************************************
"@
Write-Host $ScriptDisclaimer -ForegroundColor Yellow
#endregion

# Start the main script
$Date = (Get-Date).ToString("yyyyMMddhhmmss")

#region Logging Setup
## Set the destination for the data collection output
$OutputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings"
if(-not(Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory | Out-Null
}
else {
    Get-ChildItem -Path $OutputPath | Remove-Item -Confirm:$False -Force
    Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $env:COMPUTERNAME*.zip | Remove-Item -Confirm:$False -ErrorAction Ignore
}

$loggerParams = @{
    LogDirectory             = $OutputPath
    LogName                  = "SfMC-Discovery-$Date-Debug"
    AppendDateTimeToFileName = $false
    ErrorAction              = "SilentlyContinue"
}

$Script:Logger = Get-NewLoggerInstance @loggerParams
SetWriteHostAction ${Function:Write-HostLog}
SetWriteVerboseAction ${Function:Write-VerboseLog}
SetWriteWarningAction ${Function:Write-HostLog}
#endregion

Write-Host ([string]::Format("Writing event ID 1031 into the event log to notify the script has started.")) -ForegroundColor Cyan
Write-EventLog  -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1031 -Message "The SfMC Exchange Server discovery script has started." -Category 1

Write-Verbose ([string]::Format("Starting the Exchange Management Shell."))
$ServerName = $env:COMPUTERNAME
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
InvokeExchangeCmdlet -Cmdlet "Set-ADServerSettings" -ViewEntireForest:$True

#region GetExchangeInfo
Write-Host ([string]::Format("Starting general server information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-ExchangeServer -Status -XmlOutputPath $outputPath\$ServerName-ExchangeServer.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-ExchangeCertificate -XmlOutputPath $outputPath\$ServerName-ExchangeCertificate.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-ServerComponentState -XmlOutputPath $outputPath\$ServerName-ServerComponentState.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-ServerHealth -XmlOutputPath $outputPath\$ServerName-ServerHealth.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-ServerMonitoringOverride -XmlOutputPath $outputPath\$ServerName-ServerMonitoringOverride.xml
InvokeExchangeCmdlet -Cmdlet Get-EventLogLevel -XmlOutputPath $outputPath\$ServerName-EventLogLevel.xml
InvokeExchangeCmdlet -Identity * -Cmdlet Get-HealthReport -XmlOutputPath $outputPath\$ServerName-HealthReport.xml

## Client access settings
Write-Host ([string]::Format("Starting client access server information data collection.")) -ForegroundColor Cyan
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
Write-Host ([string]::Format("Starting transport server information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-ReceiveConnector -XmlOutputPath $outputPath\$ServerName-ReceiveConnector.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-ImapSettings -XmlOutputPath $outputPath\$ServerName-ImapSettings.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-PopSettings -XmlOutputPath $outputPath\$ServerName-PopSettings.xml
InvokeExchangeCmdlet -Cmdlet Get-TransportAgent -XmlOutputPath $outputPath\$ServerName-TransportAgent.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-TransportService -XmlOutputPath $outputPath\$ServerName-TransportService.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-MailboxTransportService -XmlOutputPath $outputPath\$ServerName-MailboxTransportService.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-FrontendTransportService -XmlOutputPath $outputPath\$ServerName-FrontendTransportService.xml

## Mailbox settings
Write-Host ([string]::Format("Starting mailbox server information data collection.")) -ForegroundColor Cyan
$DagName = (Get-Cluster).Name
InvokeExchangeCmdlet -Identity $DagName -Cmdlet Get-DatabaseAvailabilityGroup -Status -XmlOutputPath $outputPath\$ServerName-DatabaseAvailabilityGroup.xml
InvokeExchangeCmdlet -Identity $DagName -Cmdlet Get-DatabaseAvailabilityGroupNetwork -XmlOutputPath $outputPath\$ServerName-DatabaseAvailabilityGroupNetwork.xml
InvokeExchangeCmdlet -Server $ServerName -Cmdlet Get-MailboxDatabase -Status -XmlOutputPath $outputPath\$ServerName-MailboxDatabase.xml
InvokeExchangeCmdlet -Identity $ServerName -Cmdlet Get-MailboxServer -XmlOutputPath $outputPath\$ServerName-MailboxServer.xml

Write-Host ([string]::Format("Starting server OS information data collection.")) -ForegroundColor Cyan
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
    Write-Host ([string]::Format("Starting health checker data collection.")) -ForegroundColor Cyan
    Set-Location $env:ExchangeInstallPath\Scripts
    Unblock-File -Path .\HealthChecker.ps1 -Confirm:$False
    .\HealthChecker.ps1 -OutputFilePath "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings" -SkipVersionCheck
}
#endregion
$ts = Get-Date -f yyyyMMddHHmmss
[string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$ServerName-Settings-$ts.zip"
ZipCsvResults -ZipPath $zipFolder
Write-Host ([string]::Format("Writing event ID 1376 into the event log to notify the script has finished.")) -ForegroundColor Cyan
Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1376 -Message "The SfMC Exchange server discovery script has completed." -Category 1