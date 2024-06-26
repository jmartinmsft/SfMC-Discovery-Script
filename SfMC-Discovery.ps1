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
# Version 20240626.1047
param(
    [Parameter(Mandatory=$true,HelpMessage="The ExchangeServer parameter specifies the Exchange server for the remote PowerShell session")] [string]$ExchangeServer,
    [Parameter(Mandatory=$false,HelpMessage="The Credential parameter specifies the Exchange administrator credentials used for data collection")] [pscredential]$Credential,
    [Parameter(Mandatory=$false,HelpMessage="The ServerName parameter specifies the Exchange server for data collection")][ValidateScript( {[string]::IsNullOrEmpty($DagName) -and [string]::IsNullOrEmpty($ADSite)})][string]$ServerName,
    [Parameter(Mandatory=$false,HelpMessage="The DagName parameter specifies the database availability group for Exchange server data collection")][ValidateScript( {[string]::IsNullOrEmpty($ServerName) -and [string]::IsNullOrEmpty($ADSite)})] [string]$DagName,
    [Parameter(Mandatory=$false, HelpMessage="The ADSite parameter specifies the AD site for Exchange server data collection")][ValidateScript( {[string]::IsNullOrEmpty($ServerName) -and [string]::IsNullOrEmpty($DagName)})][string]$ADSite,
    [Parameter(Mandatory=$true,HelpMessage="The OutputPath parameter specifies the directory where the results are written")] [ValidateScript( {Test-Path $_})][string]$OutputPath,
    [Parameter(Mandatory=$false,HelpMessage="The OrgSettings parameter enables or disables the collection of Exchange organization settings")] [boolean]$OrgSettings=$true,
    [Parameter(Mandatory=$false,HelpMessage="The ServerSettings parameter enables or disables the collection of Exchange server settings")] [boolean]$ServerSettings=$true,
    [Parameter(Mandatory=$false,HelpMessage="If the HealthChecker switch is specified, HealthChecker data is collected")] [switch]$HealthChecker
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

function Test-ADCredentials {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credentials,

        [Parameter(Mandatory = $false)]
        [string]$Domain=$null,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    <#
        This function tests whether the credentials provided are valid by trying to connect to LDAP server using Kerberos authentication.
        It returns a PSCustomObject with two properties:
        - UsernameFormat: "local", "upn" or "downlevel" depending on the format of the username provided
        - CredentialsValid: $true if the credentials are valid, $false if they are not valid, $null if the function was unable to perform the validation
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $credentialsValid = $null
        # Username formats: https://learn.microsoft.com/windows/win32/secauthn/user-name-formats
        $usernameFormat = "local"
        try {
            Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to load System.DirectoryServices.Protocols"
            Write-Verbose "Exception: $_"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    process {
        if([string]::IsNullOrEmpty($Domain)) {
            $domain = $Credentials.GetNetworkCredential().Domain
        }
        if ([System.String]::IsNullOrEmpty($domain)) {
            Write-Verbose "Domain is empty which could be an indicator that UPN was passed instead of domain\username"
            $username = $Credentials.GetNetworkCredential().UserName
            if($username -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
                $domain = $username.Substring($username.IndexOf("@")+1)
                Write-Verbose "Domain was extracted from UPN"
                $usernameFormat = "upn"
            } else {
                Write-Verbose "Failed to extract domain from UPN - seems that username was passed without domain and so cannot be validated"
                $domain = $null
            }
        } else {
            Write-Verbose "Username was provided in down-level logon name format"
            $usernameFormat = "downlevel"
        }

        if (-not([System.String]::IsNullOrEmpty($domain))) {
            $ldapDirectoryIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($domain)
            # Use Kerberos authentication as NTLM might lead to false/positive results in case the password was changed recently
            $ldapConnection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection($ldapDirectoryIdentifier, $Credentials, [DirectoryServices.Protocols.AuthType]::Kerberos)
            # Enable Kerberos encryption (sign and seal)
            $ldapConnection.SessionOptions.Signing = $true
            $ldapConnection.SessionOptions.Sealing = $true
            try {
                $ldapConnection.Bind()
                Write-Verbose "Connection succeeded with credentials"
                $credentialsValid = $true
            } catch [System.DirectoryServices.Protocols.LdapException] {
                if ($_.Exception.ErrorCode -eq 49) {
                    # ErrorCode 49 means invalid credentials
                    Write-Verbose "Failed to connect to LDAP server with credentials provided"
                    $credentialsValid = $false
                } elseif ($_.Exception.ErrorCode -eq 81) {
                    Write-Verbose "Failed to connect to LDAP server using UPN domain"
                    Test-ADCredentials -Credentials $Credentials -Domain $env:USERDNSDOMAIN
                }
                else {
                    Write-Verbose "Failed to connect to LDAP server for other reason"
                    Write-Verbose "ErrorCode: $($_.Exception.ErrorCode)"
                }
                Write-Verbose "Exception: $_"
                Invoke-CatchActionError $CatchActionFunction
            } catch {
                Write-Verbose "Exception occurred while connecting to LDAP server - unable to perform credential validation"
                Write-Verbose "Exception: $_"
                Invoke-CatchActionError $CatchActionFunction
            }
        }
    }
    end {
        if ($null -ne $ldapConnection) {
            $ldapConnection.Dispose()
        }
        return [PSCustomObject]@{
            UsernameFormat   = $usernameFormat
            CredentialsValid = $credentialsValid
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

function Confirm-ExchangeShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$LoadExchangeShell = $true,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed: LoadExchangeShell: $LoadExchangeShell"
        $currentErrors = $Error.Count
        $edgeTransportKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole'
        $setupKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
        $remoteShell = (-not(Test-Path $setupKey))
        $toolsServer = (Test-Path $setupKey) -and
            (-not(Test-Path $edgeTransportKey)) -and
            ($null -eq (Get-ItemProperty -Path $setupKey -Name "Services" -ErrorAction SilentlyContinue))
        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction

        function IsExchangeManagementSession {
            [OutputType("System.Boolean")]
            param(
                [ScriptBlock]$CatchActionFunction
            )

            $getEventLogLevelCallSuccessful = $false
            $isExchangeManagementShell = $false

            try {
                $currentErrors = $Error.Count
                $attempts = 0
                do {
                    $eventLogLevel = Get-EventLogLevel -ErrorAction Stop | Select-Object -First 1
                    $attempts++
                    if ($attempts -ge 5) {
                        throw "Failed to run Get-EventLogLevel too many times."
                    }
                } while ($null -eq $eventLogLevel)
                $getEventLogLevelCallSuccessful = $true
                foreach ($e in $eventLogLevel) {
                    Write-Verbose "Type is: $($e.GetType().Name) BaseType is: $($e.GetType().BaseType)"
                    if (($e.GetType().Name -eq "EventCategoryObject") -or
                        (($e.GetType().Name -eq "PSObject") -and
                            ($null -ne $e.SerializationData))) {
                        $isExchangeManagementShell = $true
                    }
                }
                Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
            } catch {
                Write-Verbose "Failed to run Get-EventLogLevel"
                Invoke-CatchActionError $CatchActionFunction
            }

            return [PSCustomObject]@{
                CallWasSuccessful = $getEventLogLevelCallSuccessful
                IsManagementShell = $isExchangeManagementShell
            }
        }
    }
    process {
        $isEMS = IsExchangeManagementSession $CatchActionFunction
        if ($isEMS.CallWasSuccessful) {
            Write-Verbose "Exchange PowerShell Module already loaded."
        } else {
            if (-not ($LoadExchangeShell)) { return }

            #Test 32 bit process, as we can't see the registry if that is the case.
            if (-not ([System.Environment]::Is64BitProcess)) {
                Write-Warning "Open a 64 bit PowerShell process to continue"
                return
            }

            if (Test-Path "$setupKey") {
                Write-Verbose "We are on Exchange 2013 or newer"

                try {
                    $currentErrors = $Error.Count
                    if (Test-Path $edgeTransportKey) {
                        Write-Verbose "We are on Exchange Edge Transport Server"
                        [xml]$PSSnapIns = Get-Content -Path "$env:ExchangeInstallPath\Bin\exShell.psc1" -ErrorAction Stop

                        foreach ($PSSnapIn in $PSSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn) {
                            Write-Verbose ("Trying to add PSSnapIn: {0}" -f $PSSnapIn.Name)
                            Add-PSSnapin -Name $PSSnapIn.Name -ErrorAction Stop
                        }

                        Import-Module $env:ExchangeInstallPath\bin\Exchange.ps1 -ErrorAction Stop
                    } else {
                        Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1 -ErrorAction Stop
                        Connect-ExchangeServer -Auto -ClientApplication:ManagementShell
                    }
                    Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction

                    Write-Verbose "Imported Module. Trying Get-EventLogLevel Again"
                    $isEMS = IsExchangeManagementSession $CatchActionFunction
                    if (($isEMS.CallWasSuccessful) -and
                        ($isEMS.IsManagementShell)) {
                        Write-Verbose "Successfully loaded Exchange Management Shell"
                    } else {
                        Write-Warning "Something went wrong while loading the Exchange Management Shell"
                    }
                } catch {
                    Write-Warning "Failed to Load Exchange PowerShell Module..."
                    Invoke-CatchActionError $CatchActionFunction
                }
            } else {
                Write-Verbose "Not on an Exchange or Tools server"
            }
        }
    }
    end {

        $returnObject = [PSCustomObject]@{
            ShellLoaded = $isEMS.CallWasSuccessful
            Major       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMajor" -ErrorAction SilentlyContinue).MsiProductMajor)
            Minor       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMinor" -ErrorAction SilentlyContinue).MsiProductMinor)
            Build       = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMajor" -ErrorAction SilentlyContinue).MsiBuildMajor)
            Revision    = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMinor" -ErrorAction SilentlyContinue).MsiBuildMinor)
            EdgeServer  = $isEMS.CallWasSuccessful -and (Test-Path $setupKey) -and (Test-Path $edgeTransportKey)
            ToolsOnly   = $isEMS.CallWasSuccessful -and $toolsServer
            RemoteShell = $isEMS.CallWasSuccessful -and $remoteShell
            EMS         = $isEMS.IsManagementShell
        }

        return $returnObject
    }
}
function Invoke-ConfirmExchangeShell {

    $Script:ExchangeShellComputer = Confirm-ExchangeShell -CatchActionFunction ${Function:Invoke-CatchActions}

    if (-not ($Script:ExchangeShellComputer.ShellLoaded)) {
        Write-Warning "Failed to load Exchange Shell... stopping script"
        $Script:Logger.PreventLogCleanup = $true
        exit
    }

    if ($Script:ExchangeShellComputer.EdgeServer -and
        ($Script:ServerNameList.Count -gt 1 -or
        (-not ($Script:ServerNameList.ToLower().Contains($env:COMPUTERNAME.ToLower()))))) {
        Write-Warning "Can't run Exchange Health Checker from an Edge Server against anything but the local Edge Server."
        $Script:Logger.PreventLogCleanup = $true
        exit
    }

    if ($Script:ExchangeShellComputer.ToolsOnly -and
        $Script:ServerNameList.ToLower().Contains($env:COMPUTERNAME.ToLower()) -and
        -not ($LoadBalancingReport)) {
        Write-Warning "Can't run Exchange Health Checker Against a Tools Server. Use the -Server Parameter and provide the server you want to run the script against."
        $Script:Logger.PreventLogCleanup = $true
        exit
    }

    Write-Verbose("Script Executing on Server $env:COMPUTERNAME")
    Write-Verbose("ToolsOnly: $($Script:ExchangeShellComputer.ToolsOnly) | RemoteShell $($Script:ExchangeShellComputer.RemoteShell)")
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

# Start the main script
$Date = (Get-Date).ToString("yyyyMMddhhmmss")

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

#Create a new subfolder for the current results
Write-Verbose ([string]::Format("Creating a new subfolder for the results."))
New-Item -Path $OutputPath -Name $Date -ItemType Directory | Out-Null
$OriginalPath = $OutputPath
$OutputPath = "$OutputPath\$Date"

$loggerParams = @{
    LogDirectory             = $OutputPath
    LogName                  = "SfMC-Discovery-$Date-Debug"
    AppendDateTimeToFileName = $false
    ErrorAction              = "SilentlyContinue"
}

$Script:Logger = Get-NewLoggerInstance @loggerParams
$IsExchangeServer = $false
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

SetWriteHostAction ${Function:Write-HostLog}
SetWriteVerboseAction ${Function:Write-VerboseLog}
SetWriteWarningAction ${Function:Write-HostLog}

#region CredentialCheck
$credentialTestResult = Test-ADCredentials -Credentials $credential
if ($credentialTestResult.CredentialsValid) {
    Write-Verbose "Credentials validated successfully."
} 
elseif ($credentialTestResult.CredentialsValid -eq $false) {
    Write-Host "Credentials that were provided are incorrect. Please try again." -ForegroundColor Red
    exit
} else {
    Write-Host "Credentials couldn't be validated. Trying to use the credentials anyway." -ForegroundColor Yellow
    exit
}
#endregion

$Script:SessionOption = New-PSSessionOption -IdleTimeout 180000 -OperationTimeout 300000 -OutputBufferingMode Drop
$ServerList = New-Object System.Collections.ArrayList

$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()

## Script block to initiate Exchange server discovery
$ExchangeServerDiscovery = {
    param([boolean]$HealthChecker)
    Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -TaskPath \ -Confirm:$False -ErrorAction Ignore
    $startInDirectory = "$($env:ExchangeInstallPath)\Scripts"
    $scriptFile = ".\Get-ExchangeServerDiscovery.ps1"
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -WorkingDirectory $startInDirectory  -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -Command `"& $scriptFile -HealthChecker:`$$HealthChecker`""
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    Register-ScheduledTask ExchangeServerDiscovery -Action $Sta -Principal $STPrin
    Start-ScheduledTask ExchangeServerDiscovery -ErrorAction Ignore
}
## Script block to initiate Exchange organization discovery
$ExchangeOrgDiscovery = {
    Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -TaskPath \ -Confirm:$False -ErrorAction Ignore
    $scriptFile = "$($env:ExchangeInstallPath)\Scripts\Get-ExchangeOrgDiscovery.ps1"
    $scriptFile = "`"$scriptFile`""
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -file $scriptFile"
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    Register-ScheduledTask ExchangeOrgDiscovery -Action $Sta -Principal $STPrin
    Start-ScheduledTask ExchangeOrgDiscovery -ErrorAction Ignore
}

try{
    $ConfigContainer = (Get-ADRootDSE -Credential $Credential).configurationNamingContext
    try {
        $exchContainer = Get-ADObject -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase "CN=Services,$($ConfigContainer)" -SearchScope OneLevel -ErrorAction Ignore
        if(Get-ADObject -Filter "objectClass -eq 'msExchExchangeServer' -and name -eq '$($env:COMPUTERNAME)'" -SearchBase $exchContainer -SearchScope Subtree -ErrorAction Ignore) {
            Write-Host ([string]::Format("Found Exchange server with the name {0}.", $env:COMPUTERNAME))
            $IsExchangeServer = $true
            Invoke-ConfirmExchangeShell
        }
        else {
            Write-Verbose ([string]::Format("Checking the PowerShell version on '{0}'.", $env:COMPUTERNAME))
            if(($PSVersionTable).PSVersion -like "4*") {
                Write-Error ([string]::Format("PowerShell version on {0} is not version 5.0 or higher.", $env:COMPUTERNAME))
                exit
            }
            if(-not((Get-ConnectionInformation).Name -like "ExchangeOnline*")) {
                ConnectRemotePowerShell
            }
        }
    }
    catch {
        Write-Host ([string]::Format("Unable to locate Exchange configuration container.")) -ForegroundColor Red
        exit
    }
}
catch {
    Write-Host ([string]::Format("Unable to determine Active Directory domain.")) -ForegroundColor Red
    if(-not((Get-ConnectionInformation).Name -like "ExchangeOnline*")) {
        ConnectRemotePowerShell
    }
}

#region GetExchangeServerList
#Check if running against a single server
if($ServerName -notlike $null) {
    Write-Verbose ([string]::Format("Verifying {0} is a valid Exchange server.", $ServerName))
    $CheckServer = Get-ExchangeServer -Identity $ServerName -ErrorAction Ignore | Select-Object Fqdn, Name, DistinguishedName, OriginatingServer
    if($CheckServer -notlike $null) {
        $ServerList.Add($CheckServer) | Out-Null
        Write-Verbose ([string]::Format("Data collection will only run against {0}.", $ServerName))
    }
    else {
        Write-Host ([string]::Format("Unable to find an Exchange server with the name {0}. Exiting script.", $ServerName)) -ForegroundColor yellow
        exit
    }
}
#check if running against a single DAG
if($DagName -notlike $null) { 
    Get-DatabaseAvailabilityGroup $DagName -ErrorAction Ignore | Select-Object -ExpandProperty Servers | ForEach-Object { $ServerList.Add((Get-ExchangeServer $_ | Select-Object Fqdn, Name, DistinguishedName, OriginatingServer)) | Out-Null}
    if($ServerList.Count -eq 0){
        Write-Host ([string]::Format("Unable to find a database availability group with the name {0}. Exiting script.", $DagName)) Yellow
        exit
    }
    else {
        Write-Verbose ([string]::Format("Data collection will only run against the database availability group named {0}.", $DagName))
    }
}

#check if running against an AD site
if($ADSite -notlike $null) {
    Write-Verbose ([string]::Format("Checking for Exchange servers in the AD site named {0}.", $ADSite))
    Get-ExchangeServer | Where-Object {$_.Site -like "*$ADSite*" -and $_.ServerRole -ne "Edge"} | Select-Object Fqdn, Name, DistinguishedName, OriginatingServer | ForEach-Object { $ServerList.Add($_) | Out-Null}
    if($ServerList.Count -eq 0){
        Write-Host ([string]::Format("Unable to find any Exchange servers is the {0} site. Exiting script.", $ADSite)) Yellow
        exit
    }
    else {
        Write-Verbose ([string]::Format("Data collection will only run against Exchange servers in the {0} Active Directory site.", $ADSite))
    }
}

#otherwise run against all servers
if($ServerName -like $null -and $DagName -like $null -and $ADSite -like $null) {
    Write-Verbose ([string]::Format("Data collection will run against all Exchange servers in the organization."))
    Get-ExchangeServer | Where-Object { $_.ServerRole -ne "Edge"} | Select-Object Fqdn, Name, DistinguishedName, OriginatingServer | ForEach-Object { $ServerList.Add($_) | Out-Null }
}
#endregion

Write-Host ([string]::Format("Collecting data now, please be patient. This will take some time to complete.")) -ForegroundColor cyan
$ServerStart = Get-Date

#region GetExchOrgSettings
if($OrgSettings) {
    Write-Host ([string]::Format("Starting data collection for Exchange organization settings...")) -ForegroundColor Cyan
    ## Copy the discovery script to the Exchange server
    if($isExchangeServer) {
        $ExchangeServer = $env:COMPUTERNAME
        Copy-Item "$($ScriptPath)\Get-ExchangeOrgDiscovery.ps1" -Destination "$env:ExchangeInstallPath\Scripts" -Force
        Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false
    }
    else {
        $exchInstallPath = GetExchangeInstallPath -ExchangeServer $ExchangeServer
        Write-Verbose ([string]::Format("Found install path for {0}: {1}", $ExchangeServer,$exchInstallPath))
        $OrgSession = New-PSSession -ComputerName $ExchangeServer -Credential $Credential -Name SfMCOrgDiscovery -SessionOption $Script:SessionOption
        Copy-Item "$($ScriptPath)\Get-ExchangeOrgDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $OrgSession -ErrorAction Ignore
        Invoke-ScriptBlockHandler -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false} -Credential $Credential -ComputerName $ExchangeServer
    }
    Invoke-ScriptBlockHandler -ScriptBlock $ExchangeOrgDiscovery -ComputerName $ExchangeServer -Credential $Credential | Out-Null
    #CheckOrgCollectionStarted -ExchangeServer $ExchangeServer
    Remove-PSSession -Name SfMCOrgDiscovery -ErrorAction Ignore
}       
#endregion

#region GetExchServerSettings
if($ServerSettings) {
    $sAttempted = 0
    ## Collect server specific data from all the servers
    Write-Host ([string]::Format("Starting data collection on the Exchange servers...")) -ForegroundColor Cyan
    foreach ($s in $ServerList) {
        ## Get the Exchange install path for this server
        $exchInstallPath = $null
        $PercentComplete = (($sAttempted/$ServerList.Count)*100)
        $PercentComplete = [math]::Round($PercentComplete)
        Write-Progress -Activity "Exchange Discovery Assessment" -Status "Starting data collection on $($s.Name).....$PercentComplete% complete" -PercentComplete $PercentComplete
        if(Test-Connection -ComputerName $s.Fqdn -Count 1 -ErrorAction Ignore) {
            Write-Verbose ([string]::Format("Getting Exchange install path for {0}.", $s.Name))
            $exchInstallPath = GetExchangeInstallPath -ExchangeServer $s.Name
            Write-Verbose ([string]::Format("Found install path for {0}: {1}", $s.Name,$exchInstallPath))
            ## Create an array to store paths for data retrieval
            if(-not [string]::IsNullOrEmpty($exchInstallPath)) {
                New-Object -TypeName PSCustomObject -Property @{
                    ServerName = $s.Fqdn
                    ExchInstallPath = $exchInstallPath
                } | Export-Csv -Path $OutputPath\ExchInstallPaths.csv -NoTypeInformation -Append
                ## Copy the discovery script to the Exchange server
                if($s.Name -eq $env:COMPUTERNAME) {
                    try {
                        Copy-Item "$($ScriptPath)\Get-ExchangeServerDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ErrorAction Ignore
                        Write-Verbose ([string]::Format("Get-ExchangeServerDiscovery script successfully copied to {0}.", $s.Name))
                        Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeServerDiscovery.ps1" -Confirm:$false
                    }
                    catch {
                        Write-Host ([string]::Format("Failed to copy the Get-ExchangeServerDiscovery script to {0}.", $s.Name)) -ForegroundColor Red
                    }
                    if($HealthChecker) {
                        Write-Verbose ([string]::Format("Checking for the HealthChecker script on {0}.", $env:COMPUTERNAME))
                        if(-not (Get-Item .\HealthChecker.ps1 -ErrorAction Ignore)) {
                            try {
                                Invoke-WebRequest -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/HealthChecker.ps1" -OutFile "$ScriptPath\HealthChecker.ps1"
                                Write-Verbose ([string]::Format("Download of the HealthChecker script completed successfully."))
                                try {
                                    Copy-Item "$($ScriptPath)\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ErrorAction Ignore
                                    Write-Verbose ([string]::Format("HealthChecker script successfully copied to {0}.", $s.Name))
                                }
                                catch {
                                    Write-Host ([string]::Format("Failed to copy the HealthChecker script to {0}.", $s.Name)) -ForegroundColor Red
                                }
                            }
                            catch {
                                Write-Host ([string]::Format("Failed to download the HealthChecker script. Discovery results will not include the health check.")) -ForegroundColor Red
                                $HealthChecker = $false
                            }
                        }
                    }
                }
                else {
                    try{
                        $ServerSession = New-PSSession -ComputerName $s.fqdn -Credential $Credential -Name SfMCSrvDis -SessionOption $Script:SessionOption -ErrorAction Ignore
                        Write-Verbose ([string]::Format("Successfully created new PSSession to {0}.", $s.Name))
                        try {
                            Copy-Item "$($ScriptPath)\Get-ExchangeServerDiscovery.ps1" -Destination "$($exchInstallPath)\Scripts" -Force -ToSession $ServerSession #-ErrorAction Ignore
                            Write-Verbose ([string]::Format("Get-ExchangeServerDiscovery script successfully copied to {0}.", $s.Name))
                            Write-Verbose ([string]::Format("Unblocking the script file on server {0}.", $s.Name))
                            Invoke-ScriptBlockHandler -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeServerDiscovery.ps1" -Confirm:$false} -Credential $Credential -ComputerName $s.fqdn -IsExchangeServer $isExchangeServer
                        }
                        catch{
                            Write-Host ([string]::Format("Failed to copy the Get-ExchangeServerDiscovery script to {0}.", $s.Name)) -ForegroundColor Red
                        }
                        if($HealthChecker) {
                            try {
                                Invoke-WebRequest -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/HealthChecker.ps1" -OutFile "$ScriptPath\HealthChecker.ps1"
                                Write-Verbose ([string]::Format("Download of the HealthChecker script completed successfully."))
                                try {
                                    Copy-Item "$($ScriptPath)\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $ServerSession 
                                    Write-Verbose ([string]::Format("HealthChecker script successfully copied to {0}.", $s.Name))
                                    Write-Verbose ([string]::Format("Unblocking the HealthCheck script on server {0}.", $s.Name))
                                    Invoke-ScriptBlockHandler -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\HealthChecker.ps1" -Confirm:$false} -Credential $Credential -ComputerName $s.fqdn -IsExchangeServer $isExchangeServer
                                }
                                catch {
                                    Write-Host ([string]::Format("Failed to copy the HealthChecker script to {0}.", $s.Name)) -ForegroundColor Red
                                }
                            }
                            catch {
                                Write-Host ([string]::Format("Failed to download the HealthChecker script. Discovery results will not include the health check.")) -ForegroundColor Red
                                $HealthChecker = $false
                            }
                            Remove-PSSession -Name SfMCSrvDis -ErrorAction Ignore
                        }
                    }
                    catch{
                        Write-Verbose ([string]::Format("Failed to creat a new PSSession to {0}.", $s.Name))
                        Out-File $OutputPath\FailedServers.txt -InputObject "Unable to establish session on $($s.Name)" -Append
                    }
                }
                ## Initiate the data collection on the Exchange server
                Write-Verbose ([string]::Format("Starting data collection on the Exchange server {0}.", $s.Name))
                Invoke-ScriptBlockHandler -ScriptBlock $ExchangeServerDiscovery -ComputerName $s.Fqdn -ArgumentList $HealthChecker -Credential $Credential -IsExchangeServer $isExchangeServer | Out-Null
                #CheckServerCollectionStarted -ExchangeServer $s.Name
            }
            else {
                Out-File $OutputPath\FailedServers.txt -InputObject "Unable to determine the Exchange install path on $($s.Name)" -Append
                Write-Verbose ([string]::Format("Failed to determine the Exchange install path for {0}.", $s.Name))
            }
        }
        else {
            Write-Host ([string]::Format("Failed to connect to Exchange: {0}",$s.Fqdn)) -ForegroundColor Red
            Out-File $OutputPath\FailedServers.txt -InputObject "Unable to connect to $($s.Name)" -Append
        }
        $sAttempted++
    }
    Write-Verbose ([string]::Format("Exchange server data collection started."))
}
#endregion

#region CollectOrgResults
if($OrgSettings) {
    [int]$OrgResultsAttempt = 0
    [bool]$OrgResultsFound = $false
    Write-Host "Attempting to retrieve Exchange organization settings..." -ForegroundColor Cyan -NoNewLine
    while($OrgResultsAttempt -lt 4 -and $OrgResultsFound -eq $false) {
        $OrgResultsAttempt++
        $EndTime = (Get-Date).AddMinutes(1)
        $TimeSpanMinutes = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Minutes
        $TimeSpanHours = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Hours
        $TimeSpan = ($TimeSpanHours*60) + $TimeSpanMinutes
        $orgCheckParams = @{
            ScriptBlock             = {param($NumberOfMinutes);Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1007 -After (Get-Date -Date (Get-Date).AddMinutes($NumberOfMinutes) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore}
            Credential              = $Credential
            ComputerName            = $ExchangeServer
            ArgumentList            = $TimeSpan
        }
        if($isExchangeServer) {
            $orgCheckParams += @{
                IsExchangeServer    = $true
            }
        }
        #Check the event log to see if data collection completed
        Write-Verbose ([string]::Format("Checking if Exchange organization script completed on {0}.", $ExchangeServer))
        $orgCompleted = Invoke-ScriptBlockHandler @orgCheckParams
        if($orgCompleted -notlike $null) {
            Write-Verbose ([string]::Format("Exchange organization script completed on {0}.", $ExchangeServer))
            Write-Verbose ([string]::Format("Checking for Exchange organization results on {0}.", $ExchangeServer))
            if($IsExchangeServer) {
                if(Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip" -ErrorAction Ignore) {
                    Write-Verbose ([string]::Format("Exchange organization results found on {0}.", $ExchangeServer))
                    Write-Verbose ([string]::Format("Attempting to copy Exchange org results to output location."))
                    Copy-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip" -Destination $OutputPath -Force -ErrorAction Ignore
                    Write-Host "FOUND" -ForegroundColor White
                    $OrgResultsFound = $true
                }
                else{
                    Write-Verbose ([string]::Format("Exchange organization results not found on {0}.", $ExchangeServer))
                }
            }
            else {
                $orgResult = Invoke-ScriptBlockHandler -ScriptBlock {$orgFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip").FullName; return $orgFile} -ComputerName $ExchangeServer -Credential $Credential
                if($orgResult -notlike $null ) {
                    $Session = New-PSSession -ComputerName $ExchangeServer -Credential $Credential -Name OrgResults -SessionOption $SessionOption
                    Write-Verbose ([string]::Format("Attempting to copy Exchange organization results from {0} to output location.", $ExchangeServer))
                    Copy-Item $orgResult -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore
                    Write-Verbose ([string]::Format("Verifying Exchange org results were received."))
                    if(Get-Item $OutputPath\*OrgSettings* -ErrorAction Ignore) { 
                        Write-Host "FOUND" -ForegroundColor White
                        Write-Verbose ([string]::Format("Results received for Exchange organization settings."))
                        $OrgResultsFound = $true
                    }
                    else {
                        Write-Verbose ([string]::Format("Results not received for Exchange organization settings."))
                    }
                }
                else {
                    Write-Verbose ([string]::Format("Exchange organization results not found on {0}.", $ExchangeServer))
                }
            }
        }
        else {
            Write-Verbose ([string]::Format("Exchange organization script did not complete on {0}.", $ExchangeServer))
            CheckOrgCollectionStarted -ExchangeServer $ExchangeServer
        }

        if($OrgResultsFound -eq $false) {
            Write-Host "NOT FOUND" -ForegroundColor Red
            ## Wait x minutes before attempting to retrieve the data
            $TimeToWait = 120
            $TimeRemaining = $TimeToWait
            Write-Verbose ([string]::Format("Waiting two minutes before attempting to retrieve Exchange organization results."))
            while($TimeRemaining -gt 0) {
                Write-Progress -Activity "Exchange Discovery Assessment" -Status "Waiting for data collection to complete before attempting to retrive data... $TimeRemaining seconds remaining" -PercentComplete ((($TimeToWait-$TimeRemaining)/$TimeToWait)*100)
                Start-Sleep -Seconds 1
                $TimeRemaining = $TimeRemaining - 1
            }
            Write-Host "Attempting to retrieve Exchange organization settings..." -ForegroundColor Cyan -NoNewline
        }
    }
    Write-Verbose ([string]::Format("Removing scheduled task for Exchange org discovery."))
    Invoke-ScriptBlockHandler -ScriptBlock {Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -Confirm:$False} -ComputerName $ExchangeServer -Credential $Credential
    Remove-PSSession -Name OrgResults -ErrorAction Ignore -Confirm:$False
}
#endregion

#region CollectServerResults
if($ServerSettings){
    [int]$ServerResultsAttempt = 0
    [bool]$ServerResultsFound = $false
    ## Get list of servers and install paths to retrieve data
    [System.Collections.ArrayList]$ExchangeServers = Import-Csv $OutputPath\ExchInstallPaths.csv
    [int]$serverCount = $ExchangeServers.Count
    [int]$totalServerCount = $serverCount
    [int]$foundCount = 0
    ## Attempt to retrieve the data multiple times
    while($ServerResultsAttempt -lt 4 -and $ServerResultsFound -eq $false) {
        $ServersNotFound = New-Object System.Collections.ArrayList
        ## Check for results and retrieve if missing
        [int]$sAttempted = 0
        Write-Host "Attempting to retrieve Exchange server settings..." -ForegroundColor Cyan -NoNewline
        foreach($s in $ExchangeServers) {
            $CustomObject = New-Object -TypeName PSObject
            $ExchangeServerName = $s.ServerName
            $NetBIOSName= $ExchangeServerName.Substring(0, $ExchangeServerName.IndexOf("."))
            ## Check if server results have been received
            $PercentComplete = (($sAttempted/$ExchangeServers.Count)*100)
            $PercentComplete = [math]::Round($PercentComplete)
            Write-Progress -Activity "Exchange Discovery Assessment" -Status "Retrieving data from $ExchangeServerName.....$PercentComplete% complete" -PercentComplete $PercentComplete
            if(-not(Get-Item $OutputPath\$ExchangeServerName* -ErrorAction Ignore)) { 
                ## Attempt to copy results from Exchange server
                $params = @{
                    Destination = $OutputPath
                    Force = $null
                    ErrorAction = 'Ignore'
                }
                Write-Verbose ([string]::Format("Checking if Exchange server discovery completed on {0}.", $ExchangeServerName))
                #Check the event log to see if data collection completed
                $EndTime = (Get-Date).AddMinutes(1)
                $TimeSpanMinutes = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Minutes
                $TimeSpanHours = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Hours
                $TimeSpan = ($TimeSpanHours*60) + $TimeSpanMinutes
                $serverCompleted = Invoke-ScriptBlockHandler -ScriptBlock {param($NumberOfMinutes);Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1376 -After (Get-Date -Date (Get-Date).AddMinutes($NumberOfMinutes) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $ExchangeServerName -Credential $Credential -ArgumentList $TimeSpan
                if($serverCompleted -notlike $null) {
                    #Now look for the results zip file
                    $serverResult = Invoke-ScriptBlockHandler -ScriptBlock {$serverFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\$env:COMPUTERNAME*.zip").FullName; return $serverFile} -ComputerName $ExchangeServerName -Credential $Credential -IsExchangeServer $isExchangeServer
                    if($serverResult -notlike $null) {
                        Write-Verbose ([string]::Format("Attempting to copy results from {0}.", $ExchangeServerName))
                        if($env:COMPUTERNAME -ne $NetBIOSName) {
                            $Session = New-PSSession -ComputerName $ExchangeServerName -Credential $Credential -Name ServerResults -SessionOption $SessionOption
                            $params.Add("FromSession",$Session) | Out-Null
                        }
                        $params.Add("Path",$serverResult) | Out-Null
                        Copy-Item @params
                        #Check if the results were downloaded
                        if(Get-Item $OutputPath\$NetBIOSName* -ErrorAction Ignore) {
                            Write-Verbose ([string]::Format("Results from {0} were received.", $ExchangeServerName))
                            $foundCount++
                            Write-Verbose ([string]::Format("Attempting to remove scheduled task from {0}.", $ExchangeServerName))
                            Invoke-ScriptBlockHandler -ScriptBlock {Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -Confirm:$False} -ComputerName $ExchangeServerName -Credential $Credential
                            Remove-PSSession -Name ServerResults -ErrorAction Ignore -Confirm:$False
                        }
                        else {
                            Write-Verbose ([string]::Format("Failed to copy results from {0}.", $ExchangeServerName))
                            $CustomObject | Add-Member -MemberType NoteProperty -Name "ServerName" -Value $ExchangeServerName -Force
                            $CustomObject | Add-Member -MemberType NoteProperty -Name "ExchInstallPath" -Value $s.ExchInstallPath -Force
                            $ServersNotFound.Add($CustomObject) | Out-Null
                        }
                    }
                    else {
                        Write-Verbose ([string]::Format("Results not found on {0}.", $ExchangeServerName))
                    }
                }
                ## Add server to array to check again
                else {
                    Write-Verbose ([string]::Format("Script has not completed on {0}. Adding to retry list.", $ExchangeServerName))
                    $CustomObject | Add-Member -MemberType NoteProperty -Name "ServerName" -Value $s.ServerName -Force
                    $CustomObject | Add-Member -MemberType NoteProperty -Name "ExchInstallPath" -Value $s.ExchInstallPath -Force
                    $ServersNotFound.Add($CustomObject) | Out-Null
                    CheckServerCollectionStarted -ExchangeServer $NetBIOSName
                }
            }
            $sAttempted++
        }
        if($foundCount -eq $totalServerCount) { 
            Write-Verbose ([string]::Format("All results retrieved for Exchange server discovery."))
            Write-Host "FOUND";
            $ServerResultsFound = $true
        }
        else{
            if($foundCount -gt 0) {
                Write-Verbose ([string]::Format("Not all results were retrieved for Exchange server discovery."))
                Write-Host ([string]::Format("{0} of {1} found.", $foundCount, $totalServerCount)) -ForegroundColor Yellow
            }
            else {
                Write-Verbose ([string]::Format("No Exchange server settings results were found."))
                Write-Host "NOT FOUND" -ForegroundColor Red
            }
            ## Wait x minutes before attempting to retrieve the data
            $TimeToWait = 120
            $TimeRemaining = [math]::Round($TimeToWait)
            Write-Verbose ([string]::Format("Waiting two minutes before attempting to retrieve results again."))
            while($TimeRemaining -gt 0) {
                Write-Progress -Activity "Exchange Discovery Assessment" -Status "Waiting for data collection to complete before attempting to retrive data... $TimeRemaining seconds remaining" -PercentComplete ((($TimeToWait-$TimeRemaining)/$TimeToWait)*100)
                Start-Sleep -Seconds 1
                $TimeRemaining = $TimeRemaining - 1
            }
        }
        $ExchangeServers = New-Object System.Collections.ArrayList
        $ServersNotFound | ForEach-Object { $ExchangeServers.Add($_) | Out-Null }
        $serverCount = $ExchangeServers.Count
        $ServerResultsAttempt++
    }
}
foreach($s in $ServersNotFound) {
    Out-File $OutputPath\FailedServers.txt -InputObject "Unable to retrieve data for $($s.ServerName)" -Append
}
#endregion

Write-Host " "
$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
$timeStamp = Get-Date -Format yyyyMMddHHmmss
if(($PSVersionTable).PSVersion -like "5*") {
    $script:LastError = $Error[0]
    try {
        Write-Host ([string]::Format("Compressing results into zip file for upload.")) -ForegroundColor Gray
        Compress-Archive -Path $OutputPath -DestinationPath "$OriginalPath\DiscoveryResults-$timeStamp.zip"
    }
    catch{
        Write-Verbose ([string]::Format("Failed to compress the results into zip file.")) 
    }
}
else {
    ## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    $zipFolder = "$OriginalPath\DiscoveryResults-$timeStamp.zip"
    $script:LastError = $Error[0]
    try {
        Write-Host ([string]::Format("Compressing results into zip file for upload.")) -ForegroundColor Gray
        [System.IO.Compression.ZipFile]::CreateFromDirectory($OutputPath, $zipFolder)}
    catch {
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'update')
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        Get-ChildItem -Path $outputPath | Select-Object FullName | ForEach-Object {
            $script:LastError = $Error[0]
            try{
                Write-Verbose ([string]::Format("Compressing results into zip file for upload."))
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipFile, $_.FullName, (Split-Path $_.FullName -Leaf), $compressionLevel) | Out-Null 
            }
            catch {
                Write-Verbose ([string]::Format("Failed to compress the results into zip file.")) 
            }
        }
        $zipFile.Dispose()
    }
}

$ScriptComplete = @"
===================================================
SfMC Email Discovery data collection has finished.
Total collection time: $($totalTime) seconds
Please upload results to SfMC. - Thank you.
===================================================
"@
Write-Host $ScriptComplete -ForegroundColor Yellow