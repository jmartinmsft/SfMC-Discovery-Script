﻿<#
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
# Version 20240708.1030
param(
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
$OutputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Org Settings"
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

Write-Host ([string]::Format("Writing event ID 1125 into the event log to notify the script has started.")) -ForegroundColor Cyan
Write-EventLog  -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1125 -Message "The SfMC Exchange Server discovery script has started." -Category 1

Write-Verbose ([string]::Format("Starting the Exchange Management Shell."))
$ServerName = $env:COMPUTERNAME
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
InvokeExchangeCmdlet -Cmdlet "Set-ADServerSettings" -ViewEntireForest:$True

[string]$orgName = (Get-OrganizationConfig).Name
Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $orgName*.zip | Remove-Item -Confirm:$False

## Data collection starts using XML files to capture multi-valued properties
Write-Host ([string]::Format("Getting list of Exchange servers in the organization.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-ExchangeServer" -XmlOutputPath $outputPath\$orgName-ExchangeServer.xml
## Transport settings
Write-Host ([string]::Format("Starting transport information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-AcceptedDomain" -XmlOutputPath $outputPath\$orgName-AcceptedDomain.xml
InvokeExchangeCmdlet -Cmdlet "Get-RemoteDomain" -XmlOutputPath $outputPath\$orgName-RemoteDomain.xml
InvokeExchangeCmdlet -Cmdlet "Get-TransportConfig" -XmlOutputPath $outputPath\$orgName-TransportConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-TransportRule" -XmlOutputPath $outputPath\$orgName-TransportRule.xml
InvokeExchangeCmdlet -Cmdlet "Get-TransportRuleAction" -XmlOutputPath $outputPath\$orgName-TransportRuleAction.xml
InvokeExchangeCmdlet -Cmdlet "Get-TransportRulePredicate" -XmlOutputPath $outputPath\$orgName-TransportRulePredicate.xml
InvokeExchangeCmdlet -Cmdlet "Get-JournalRule" -XmlOutputPath $outputPath\$orgName-JournalRule.xml
InvokeExchangeCmdlet -Cmdlet "Get-DeliveryAgentConnector" -XmlOutputPath $outputPath\$orgName-DeliveryAgentConnector.xml
InvokeExchangeCmdlet -Cmdlet "Get-EmailAddressPolicy" -XmlOutputPath $outputPath\$orgName-EmailAddressPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-SendConnector" -XmlOutputPath $outputPath\$orgName-SendConnector.xml
InvokeExchangeCmdlet -Cmdlet "Get-EdgeSubscription" -XmlOutputPath $outputPath\$orgName-EdgeSubscription.xml
InvokeExchangeCmdlet -Cmdlet "Get-EdgeSyncServiceConfig" -XmlOutputPath $outputPath\$orgName-EdgeSyncServiceConfig.xml

## Client access settings
Write-Host ([string]::Format("Starting client access information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-ActiveSyncOrganizationSettings" -XmlOutputPath $outputPath\$orgName-ActiveSyncOrganizationSettings.xml
InvokeExchangeCmdlet -Cmdlet "Get-MobileDeviceMailboxPolicy" -XmlOutputPath $outputPath\$orgName-MobileDeviceMailboxPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-ActiveSyncDeviceAccessRule" -XmlOutputPath $outputPath\$orgName-ActiveSyncDeviceAccessRule.xml
InvokeExchangeCmdlet -Cmdlet "Get-ActiveSyncDeviceAutoblockThreshold" -XmlOutputPath $outputPath\$orgName-ActiveSyncDeviceAutoblockThreshold.xml
InvokeExchangeCmdlet -Cmdlet "Get-ClientAccessArray" -XmlOutputPath $outputPath\$orgName-ClientAccessArray.xml
InvokeExchangeCmdlet -Cmdlet "Get-OwaMailboxPolicy" -XmlOutputPath $outputPath\$orgName-OwaMailboxPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-ThrottlingPolicy" -XmlOutputPath $outputPath\$orgName-ThrottlingPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-IRMConfiguration" -XmlOutputPath $outputPath\$orgName-IRMConfiguration.xml
InvokeExchangeCmdlet -Cmdlet "Get-OutlookProtectionRule" -XmlOutputPath $outputPath\$orgName-OutlookProtectionRule.xml
InvokeExchangeCmdlet -Cmdlet "Get-OutlookProvider" -XmlOutputPath $outputPath\$orgName-OutlookProvider.xml
InvokeExchangeCmdlet -Cmdlet "Get-ClientAccessRule" -XmlOutputPath $outputPath\$orgName-ClientAccessRule.xml

## Mailbox server settings
Write-Host ([string]::Format("Starting mailbox server information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-RetentionPolicyTag" -XmlOutputPath $outputPath\$orgName-RetentionPolicyTag.xml
InvokeExchangeCmdlet -Cmdlet "Get-RetentionPolicy" -XmlOutputPath $outputPath\$orgName-RetentionPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-SiteMailbox" -XmlOutputPath $outputPath\$orgName-SiteMailbox.xml

## Address book settings
Write-Host ([string]::Format("Starting address book information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-AddressBookPolicy" -XmlOutputPath $outputPath\$orgName-AddressBookPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-GlobalAddressList" -XmlOutputPath $outputPath\$orgName-GlobalAddressList.xml
InvokeExchangeCmdlet -Cmdlet "Get-AddressList" -XmlOutputPath $outputPath\$orgName-AddressList.xml
InvokeExchangeCmdlet -Cmdlet "Get-OfflineAddressBook" -XmlOutputPath $outputPath\$orgName-OfflineAddressBook.xml

## Administration settings
Write-Host ([string]::Format("Starting administration information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-AdminAuditLogConfig" -XmlOutputPath $outputPath\$orgName-AdminAuditLogConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-ManagementRole" -XmlOutputPath $outputPath\$orgName-ManagementRole.xml
InvokeExchangeCmdlet -Cmdlet "Get-ManagementRoleEntry" -XmlOutputPath $outputPath\$orgName-ManagementRoleEntry.xml -Identity "*\*"
InvokeExchangeCmdlet -Cmdlet "Get-ManagementRoleAssignment" -XmlOutputPath $outputPath\$orgName-ManagementRoleAssignment.xml
InvokeExchangeCmdlet -Cmdlet "Get-RoleGroup" -XmlOutputPath $outputPath\$orgName-RoleGroup.xml
InvokeExchangeCmdlet -Cmdlet "Get-ManagementScope" -XmlOutputPath $outputPath\$orgName-ManagementScope.xml
InvokeExchangeCmdlet -Cmdlet "Get-RoleAssignmentPolicy" -XmlOutputPath $outputPath\$orgName-RoleAssignmentPolicy.xml

## Federation settings
Write-Host ([string]::Format("Starting federation information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-FederationTrust" -XmlOutputPath $outputPath\$orgName-FederationTrust.xml
InvokeExchangeCmdlet -Cmdlet "Get-FederatedOrganizationIdentifier" -XmlOutputPath $outputPath\$orgName-FederatedOrganizationIdentifier.xml
InvokeExchangeCmdlet -Cmdlet "Get-SharingPolicy" -XmlOutputPath $outputPath\$orgName-SharingPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-OrganizationRelationship" -XmlOutputPath $outputPath\$orgName-OrganizationRelationship.xml

## Availability service
Write-Host ([string]::Format("Starting availability service information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-IntraOrganizationConnector" -XmlOutputPath $outputPath\$orgName-IntraOrganizationConnector.xml
InvokeExchangeCmdlet -Cmdlet "Get-IntraOrganizationConfiguration" -XmlOutputPath $outputPath\$orgName-IntraOrganizationConfiguration.xml
InvokeExchangeCmdlet -Cmdlet "Get-AvailabilityAddressSpace" -XmlOutputPath $outputPath\$orgName-AvailabilityAddressSpace.xml
InvokeExchangeCmdlet -Cmdlet "Get-AvailabilityConfig" -XmlOutputPath $outputPath\$orgName-AvailabilityConfig.xml

## General settings
Write-Host ([string]::Format("Starting general information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-OrganizationConfig" -XmlOutputPath $outputPath\$orgName-OrganizationConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-AuthConfig" -XmlOutputPath $outputPath\$orgName-AuthConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-AuthServer" -XmlOutputPath $outputPath\$orgName-AuthServer.xml
InvokeExchangeCmdlet -Cmdlet "Get-HybridConfiguration" -XmlOutputPath $outputPath\$orgName-HybridConfiguration.xml
InvokeExchangeCmdlet -Cmdlet "Get-MigrationEndpoint" -XmlOutputPath $outputPath\$orgName-MigrationEndpoint.xml
InvokeExchangeCmdlet -Cmdlet "Get-PartnerApplication" -XmlOutputPath $outputPath\$orgName-PartnerApplication.xml
InvokeExchangeCmdlet -Cmdlet "Get-PolicyTipConfig" -XmlOutputPath $outputPath\$orgName-PolicyTipConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-RMSTemplate" -XmlOutputPath $outputPath\$orgName-RMSTemplate.xml
InvokeExchangeCmdlet -Cmdlet "Get-SmimeConfig" -XmlOutputPath $outputPath\$orgName-SmimeConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-DlpPolicy" -XmlOutputPath $outputPath\$orgName-DlpPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-DlpPolicyTemplate" -XmlOutputPath $outputPath\$orgName-DlpPolicyTemplate.xml
InvokeExchangeCmdlet -Cmdlet "Get-GlobalMonitoringOverride" -XmlOutputPath $outputPath\$orgName-GlobalMonitoringOverride.xml
InvokeExchangeCmdlet -Cmdlet "Get-DomainController" -XmlOutputPath $outputPath\$orgName-DomainController.xml

## AD settings
Write-Host ([string]::Format("Starting AD information data collection.")) -ForegroundColor Cyan
InvokeExchangeCmdlet -Cmdlet "Get-ADSite" -XmlOutputPath $outputPath\$orgName-ADSite.xml
InvokeExchangeCmdlet -Cmdlet "Get-AdSiteLink" -XmlOutputPath $outputPath\$orgName-AdSiteLink.xml

Write-Host ([string]::Format("Attempting to compress the results.")) -ForegroundColor Cyan
$ts = Get-Date -f yyyyMMddHHmmss
[string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$orgName-OrgSettings-$ts.zip"
## Zip the results and sent to the location where the script was started
ZipCsvResults -ZipPath $zipFolder

Write-Host ([string]::Format("Writing event ID 1007 into the event log to notify the script has finished.")) -ForegroundColor Cyan
Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1007 -Message "The SfMC Exchange Organization discovery script has completed." -Category 1

# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC20C1fa8NMuEe+
# HwkUkE1myjWk+FIabU5DYAbdjBVctqCCDXYwggX0MIID3KADAgECAhMzAAADrzBA
# DkyjTQVBAAAAAAOvMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwOTAwWhcNMjQxMTE0MTkwOTAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOS8s1ra6f0YGtg0OhEaQa/t3Q+q1MEHhWJhqQVuO5amYXQpy8MDPNoJYk+FWA
# hePP5LxwcSge5aen+f5Q6WNPd6EDxGzotvVpNi5ve0H97S3F7C/axDfKxyNh21MG
# 0W8Sb0vxi/vorcLHOL9i+t2D6yvvDzLlEefUCbQV/zGCBjXGlYJcUj6RAzXyeNAN
# xSpKXAGd7Fh+ocGHPPphcD9LQTOJgG7Y7aYztHqBLJiQQ4eAgZNU4ac6+8LnEGAL
# go1ydC5BJEuJQjYKbNTy959HrKSu7LO3Ws0w8jw6pYdC1IMpdTkk2puTgY2PDNzB
# tLM4evG7FYer3WX+8t1UMYNTAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQURxxxNPIEPGSO8kqz+bgCAQWGXsEw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMTgyNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAISxFt/zR2frTFPB45Yd
# mhZpB2nNJoOoi+qlgcTlnO4QwlYN1w/vYwbDy/oFJolD5r6FMJd0RGcgEM8q9TgQ
# 2OC7gQEmhweVJ7yuKJlQBH7P7Pg5RiqgV3cSonJ+OM4kFHbP3gPLiyzssSQdRuPY
# 1mIWoGg9i7Y4ZC8ST7WhpSyc0pns2XsUe1XsIjaUcGu7zd7gg97eCUiLRdVklPmp
# XobH9CEAWakRUGNICYN2AgjhRTC4j3KJfqMkU04R6Toyh4/Toswm1uoDcGr5laYn
# TfcX3u5WnJqJLhuPe8Uj9kGAOcyo0O1mNwDa+LhFEzB6CB32+wfJMumfr6degvLT
# e8x55urQLeTjimBQgS49BSUkhFN7ois3cZyNpnrMca5AZaC7pLI72vuqSsSlLalG
# OcZmPHZGYJqZ0BacN274OZ80Q8B11iNokns9Od348bMb5Z4fihxaBWebl8kWEi2O
# PvQImOAeq3nt7UWJBzJYLAGEpfasaA3ZQgIcEXdD+uwo6ymMzDY6UamFOfYqYWXk
# ntxDGu7ngD2ugKUuccYKJJRiiz+LAUcj90BVcSHRLQop9N8zoALr/1sJuwPrVAtx
# HNEgSW+AKBqIxYWM4Ev32l6agSUAezLMbq5f3d8x9qzT031jMDT+sUAoCw0M5wVt
# CUQcqINPuYjbS1WgJyZIiEkBMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGg8wghoLAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJq9UznU8RlkZQP5SewYB3pL
# U5tvA1/eueqmxseq8UpoMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAhYL7w6dKKmuEdNCiliMbZY8dA2sayE+1Co5wnPYvXq3Ug4I2jY0NH
# E/clIDOVY+plC80/y7ZvryWC+BOA8Aako4VZNLPajd4PBAp8HxgTvnt55yLEVuPJ
# McGyF+4Rle1x6DOJNf2w+Na9lLm1Ok6pV6CYZFtSUlp6tNHVDmwnLoYdcyXdrbFn
# l9GE7UxqshGmDRDW0z1eFsb4V/x3Nx1i3DmLUwb7zkhv0NEBXfxBupdrH6WM+wTC
# A/tQP3umfpvw2QmeQ+JMp86I+Wtt433j/OKPjLId1B95Zmr8X+Yhq5/MvkGWiCpS
# mproO2oYWnqLjO6gqpNDjdvFkIKhtRKXoYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJn8a98u73MlwEPR/K+6qYcqWTCqmRkU7dA50rUFces9AgZmauRa
# bksYEzIwMjQwNzA4MTQ0MDA0LjMyNFowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo5MjAw
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEe0wggcgMIIFCKADAgECAhMzAAAB5y6PL5MLTxvpAAEAAAHnMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMTIwNjE4
# NDUxOVoXDTI1MDMwNTE4NDUxOVowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo5MjAwLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAMJXny/gi5Drn1c8zUO1pYy/38dFQLmR2IQXz1gE
# /r9GfuSOoyRnkRJ6Z/kSWLgIu1BVJ59GkXWPtLkssqKwxY4ZFotxpVsZN9yYjW8x
# EnW3MzAI0igKr+/LxYfxB1XUH8Bvmwr5D3Ii/MbDjtN9c8TxGWtq7Ar976dafAy3
# TrRqQRmIknPVWHUuFJgpqI/1nbcRmYYRMJaKCQpty4CeG+HfKsxrz24F9p4dBkQc
# ZCp2yQzjwQFxZJZ2mJJIGIDHKEdSRuSeX08/O0H9JTHNFmNTNYeD1t/WapnRwiIB
# YLQSMrs42GVB8pJEdUsos0+mXf/5QvheNzRi92pzzyA4tSv/zhP3/Ermvza6W9Gn
# YDz9qv1wbhbvrnS4poDFECaAviEqAhfn/RogCxvKok5ro4gZIX1r4N9eXUulA80p
# Hv3axwXu2MPlarAi6J9L1hSIcy9EuOMqTRJIJX+alcLQGg+STlqx/GuslsKwl48d
# I4RuWknNGbNo/o4xfBFytvtNcVA6xOQq6qRa+9gg+9XMLrxQz4yyQs+V3V6p044w
# rtJtt/a0ZJl/f6I7BZAxxZcH2DDmArcAhgrTxaQkm7LM+p+K2C5t1EKZiv0JWw06
# 5b7AcNgaFyIkMXYuSuOQVSNRxdIgl31/ayxiK1n0K6sZXvgFBx+vGO+TUvyO+03u
# a6UjAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUz/7gmICfNjh2kR/9mWuHUrvej1gw
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBAHSh8NuT6WVaLVwLqex+J7km2nT2jpvo
# BEKm+0M+rYoU/6GL5Q00/ssZyIq5ySpcKYFMUiF8F4ZLG+TrJyiR1CvfzXmkQ5ph
# ZOce9DT7yErLzqvUXit8G7igcHlxPLTxPiiGsb85gb8H+A2fPQ6Xq/u7+oSPPjzN
# dnpmXEobJnAqYplZoF3YNgTDMql0uQHGzoDp6dZlHSNj6rkV1tXjmCEZMqBKvkQI
# A6csPieMnB+MirSZFlbANlChe0lJpUdK7aUdAvdgcQWKS6dtRMl818EMsvsa/6xO
# ZGINmTLk4DGgsbaBpN+6IVt+mZJ89yCXkI5TN8xCfOkp9fr4WQjRBA2+4+lawNTy
# xH66eLZWYOjuuaomuibiKGBU10tox81Sq8EvlmJIrXOZoQsEn1r5g6MTmmZJqtbm
# wZufuJWQXZb0lAg4fq0ZYsUlLkezfrNqGSgeHyIP3rct4aNmqQW6wppRbvbIyP/L
# FN4YQM6givfmTBfGvVS77OS6vbL4W41jShmOmnOn3kBbWV6E/TFo76gFXVd+9oK6
# v8Hk9UCnbHOuiwwRRwDCkmmKj5Vh8i58aPuZ5dwZBhYDxSavwroC6j4mWPwh4VLq
# VK8qGpCmZ0HMAwao85Aq3U7DdlfF6Eru8CKKbdmIAuUzQrnjqTSxmvF1k+CmbPs7
# zD2Acu7JkBB7MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+
# F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU
# 88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqY
# O7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzp
# cGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0Xn
# Rm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1
# zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZN
# N3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLR
# vWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTY
# uVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUX
# k8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB
# 2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKR
# PEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0g
# BFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQM
# MAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQ
# W9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNv
# bS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBa
# BggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOX
# PTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6c
# qYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/z
# jj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz
# /AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyR
# gNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdU
# bZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo
# 3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4K
# u+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10Cga
# iQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9
# vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGC
# A1AwggI4AgEBMIH5oYHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTIwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# ALNyBOcZqxLB792u75w97U0X+/BDoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDqNlZgMCIYDzIwMjQwNzA4MTIx
# MzIwWhgPMjAyNDA3MDkxMjEzMjBaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOo2
# VmACAQAwCgIBAAICG3gCAf8wBwIBAAICE2YwCgIFAOo3p+ACAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQsFAAOCAQEADTIfULJb1Lpu5ogpYkcVa6c21FJ7CJmoZLEmekqP
# vGaaFvK/rle4fpepcX/4G+3mrFsJsRLp5IdU/EGK0WHJvNl6mtRaAAKc7lTcyK08
# Ogb3co4Nq2n7F4bgdw2w0RGSUl/4nPLRgOX0EYStfKLqGfi3Hl5hRrO92At15vs3
# JtQ0mRnP3oKkScnoPwcwkMvTGwFv5nBb2ShUM50vM5X2NQMcMgRpxhhKd/aG1cw9
# V9emh/JKFoOduiL73phGH0Zu733IgozNuIgDxuGo1nKJB3LX9k4JBHgyrHrrZZzA
# EhtN/uvFM6kKa4DEFykcPfndwvqobalmRW8OiDfXTTOqVTGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB5y6PL5MLTxvpAAEA
# AAHnMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEII4fa4ifvEvxsEKv05hsY8ol0BMFRSxjqBJWMTaL
# 7FxdMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg5TZdDXZqhv0N4MVcz1QU
# d4RfvgW/QAG9AwbuoLnWc60wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAecujy+TC08b6QABAAAB5zAiBCBh47xYxJd2UM+M8/LZHNh7
# AE8oYdZXxNv0iGOl2clbATANBgkqhkiG9w0BAQsFAASCAgBDndmgrHBohwc0E3mw
# hdyEX2Wr6l/sxcl9U73jnO1KrTzInZEnS69JAe6iBrhU1/fQMAqZDMloqfeVxd1X
# l+IC7AH8AonXERqXPCtaTcKc8ABEji4U827QeCKeKXsFcYCe5d40zYulSL5lYJVS
# i0ZnxbMkTXEhtgSO/GAJAPkx3TcRf049Y6X1mqa6Lv2RIp7TcYgdH3NZyGzhkBTh
# ov/6kGAHitnzgPUWEcphDGdMgP1hqa9DwJi+tDn4tTgn7S4iG+wSHzMm3BHwDAFU
# UCma62VOt02E+md1AJsHkZCx7nIAYu4O4sOEBSN34v2Ii88oJqBGVW937Sox6SEn
# dvKL6hVjIT1ocGKmw1jjzPwrfJlDs/Lf8+iz2SaJYShEYi5F+uhTJS1AR72DbXbg
# JvrPnfYGmrh1clFUgq3eMwtdHou7J8xwk9bxa3Sd4/Mi6p6k7orEFb2GdWOGBlmc
# YK5P6PyOx7Wo0o/c3wlOQXmT2ftsQ+6od6zbnzcB8OapOkjG9IOOzA41611G6FmG
# b24KfcUDadU7BCzkegKa0QaSgXGYp6l32wdF8y8Rrxj/YVtWpWi501I5wIwhZ3tP
# mDZHvGCTzb/6HXzkIfiEjTTkI5+NmCyYlMSfkJqJodauvYx9SH6F8qXTbvDr03Pw
# CcTZ0Fttro8z9ey8NknLKa/9og==
# SIG # End signature block
