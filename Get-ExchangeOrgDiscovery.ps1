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
//**********************************************************************​
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