<#//***********************************************************************
//
// SfMC-Discovery.ps1
// Modified 10 May 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// .VERSION 20230510.1045
//
// .SYNOPSIS
//  Collect Exchange configuration via PowerShell
// 
// .DESCRIPTION
//  This script will run Get commands in your Exchange Management Shell to collect configuration data via PowerShell
//
// .PARAMETERS
//    ExchangeServer - The ExchangeServer parameter is required to make the initial remote PowerShell session to retrieve list of Exchange servers in the organization and is used to collect the Exchange organization settings.
//    UserName - The UserName parameter specifies the Exchange admin account used to run the data collection scripts
//    ServerName - The ServerName parameter specifies a single Exchange server to collect data against.
//    DagName - The DagName parameter specifies the name of the Exchange database availability group to collect data against.
//    OutputPath - The OutputPath parameters specifies the location for the data collection results.
//    ScriptPath - The ScriptPath parameter specifies the location for the data collection scripts.
//    ADSite - The ADSite parameter specifies the Active Directory site for the Exchange servers to collect data against.
//    OrgSettings - The OrgSettings parameter specifies whether or not Exchange organization settings are collected.
//    ServerSettings - The ServerSettings parameter specifies whether or not Exchange server settings are collected.
//    HealthChecker - The HealthChecker parameter specifies whether or not the Exchange HealthChecker script is run against each server
//
//.EXAMPLES
// .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -DagName E19DAG1 -OutputPath c:\Temp\Results
// This example collects the Exchange organization settings and Exchange server settings for the E19DAG1 database availability group and saves the results in C:\Temp\Results
//
// .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results
// This example collects the Exchange organization settings and Exchange server settings for all Exchange servers in the organization and saves the results in c:\Temp\Results
//
// .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results -ServerSettings:$False
// This example collects only the Exchange organization settings and saves the results to c:\Temp\Results
//
// .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results -OrgSettings:$False -ServerName clt-e19-mbx3.resource.local
// This example collects only the Exchange server settings for clt-e19-mbx3.resource.local and saves the results to c:\Temp\Results
//
//.NOTES
//  Exchange server specified should be the latest version in the environment
// 
// 3.7 - Update adds copying the HealthChecker.ps1 script to the Exchange servers for additional data collection
// 20220823.1657 - Logging, option to include HealthChecker (no longer mandatory), invoke-command only run remotely
// 20220908.1039 - Allow run from Exchange server using logged on user credentials
// 20221102.0949 - Allow run from Exchange server on Windows Server 2012 R2
// 20230510.1045 - Bug fix for timespan
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
    [Parameter(Mandatory=$true,HelpMessage="The ExchangeServer parameter specifies the Exchange server for the remote PowerShell session")] [string]$ExchangeServer,
    [Parameter(Mandatory=$false,HelpMessage="The UserName parameter specifies the Exchange administrator account used for data collection")] [string]$UserName,
    [Parameter(Mandatory=$false,HelpMessage="The Credential parameter specifies the Exchange administrator credentials used for data collection")] [pscredential]$Credential,
    [Parameter(Mandatory=$false,HelpMessage="The ServerName parameter specifies the Exchange server for data collection")] [string]$ServerName,
    [Parameter(Mandatory=$false,HelpMessage="The DagName parameter specifies the database availability group for Exchange server data collection")] [string]$DagName,
    [Parameter(Mandatory=$false,HelpMessage="The OutputPath parameter specifies the directory where the results are written")] [string]$OutputPath,
    [Parameter(Mandatory=$false,HelpMessage="The ScriptPath parameter specifies the directory where the discovery scripts are located")] [string]$ScriptPath,
    [Parameter(Mandatory=$false, HelpMessage="The ADSite parameter specifies the AD site for Exchange server data collection")] [string]$ADSite,
    [Parameter(Mandatory=$false,HelpMessage="The OrgSettings parameter enables or disables the collection of Exchange organization settings")] [boolean]$OrgSettings=$true,
    [Parameter(Mandatory=$false,HelpMessage="The ServerSettings parameter enables or disables the collection of Exchange server settings")] [boolean]$ServerSettings=$true,
    [Parameter(Mandatory=$false,HelpMessage="If the HealthChecker switch is specified, HealthChecker data is collected")] [switch]$HealthChecker,
    [Parameter(Mandatory=$true,HelpMessage="The LogFile parameter specifies The path and file name for the log file")][string]$LogFile
)

$script:ScriptVersion = "20230905.1418"

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
# Common method used to handle Invoke-Command within a script.
# Avoids using Invoke-Command when running locally on a server.
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
        LogVerbose([string]::Format("Calling: {0}", $MyInvocation.MyCommand))
        $returnValue = $null
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            LogVerbose([string]::Format("Description: ",$ScriptBlockDescription))
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
                    LogVerbose([string]::Format("Including Credential"))
                    $params.Add("Credential", $Credential)
                }

                if ($IncludeNoProxyServerOption) {
                    LogVerbose([string]::Format("Including SessionOption"))
                    $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
                }

                if ($null -ne $ArgumentList) {
                    LogVerbose([string]::Format("Running Invoke-Command with argument list"))
                    $params.Add("ArgumentList", $ArgumentList)
                } else {
                    LogVerbose([string]::Format("IRunning Invoke-Command without argument list"))
                }
                LogVerbose([string]::Format("Running Invoke-Command using the following: "))
                LogVerbose($params | Out-String)
                $returnValue = Invoke-Command @params
            } else {

                if ($null -ne $ArgumentList) {
                    LogVerbose([string]::Format("Running Script Block Locally with argument list"))
                    # if an object array type expect the result to be multiple parameters
                    if ($ArgumentList.GetType().Name -eq "Object[]") {
                        LogVerbose([string]::Format("Running Invoke-Command using the following: "))
                        LogVerbose($params | ForEach-Object{ [pscustomobject]$_ })
                        $returnValue = & $ScriptBlock @ArgumentList
                    } else {
                        LogVerbose([string]::Format("Running Invoke-Command using the following: "))
                        LogVerbose($params | ForEach-Object{ [pscustomobject]$_ })
                        $returnValue = & $ScriptBlock @ArgumentList
                    }
                } else {
                    LogVerbose([string]::Format("Running Script Block Locally without argument list"))
                    LogVerbose([string]::Format("Running Invoke-Command using the following: "))
                    LogVerbose($params | ForEach-Object{ [pscustomobject]$_ })
                    $returnValue = & $ScriptBlock
                }
            }
        } catch {
            LogVerbose([string]::Format("Failed to run {0} ", $MyInvocation.MyCommand))
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        LogVerbose([string]::Format("Exiting: {0}", $MyInvocation.MyCommand))
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
function Get-FolderPath {   
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location"
    $folderBrowser.SelectedPath = "C:\"
    $folderPath = $folderBrowser.ShowDialog()
    [string]$oPath = $folderBrowser.SelectedPath
    return $oPath
}
function TestADAuthentication {
    $UserName = $creds.UserName
    $Password = $creds.GetNetworkCredential().Password
    $Root = "LDAP://" + ([ADSI]'').distinguishedName
    $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
    if(!$Domain) { Write-Warning "Something went wrong" }
    else {
        if ($Domain.name -notlike $null) { return $true }
        else {return $false}
    }
}
function Start-Cleanup {
    Get-PSSession -Name SfMC* -ErrorAction Ignore | Remove-PSSession -ErrorAction Ignore
}
function CheckRunningFromExchangeServer {
    # Determine if script is running from an Exchange Server
    param(
        [Parameter(Mandatory = $true)] [string]$ComputerName
    )
    $isExchangeServer = $false
    try{
        $adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
    }
    catch {
        LogVerbose([string]::Format("Unable to determine Active Directory domain."))
    }
    if($adDomain -notlike $null) {
        try {
            $exchContainer = Get-ADObject -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase "CN=Services,CN=Configuration,$adDomain" -SearchScope OneLevel -ErrorAction Ignore
            if(Get-ADObject -Filter 'objectClass -eq "msExchExchangeServer" -and name -eq $ComputerName' -SearchBase $exchContainer -SearchScope Subtree -ErrorAction Ignore) {
                $isExchangeServer = $true
                LogVerbose([string]::Format("Found Exchange server with the name {0}.", $ComputerName))
            }
            else {
                LogVerbose([string]::Format("Unable to locate Exchange server with the name {0}.", $ComputerName))
            }
        }
        catch {
            LogVerbose([string]::Format("Unable to locate Exchange configuration container."))
        }
    }
    return $isExchangeServer
}
function CheckOrgCollectionStarted{
    LogVerbose([string]::Format("Checking if Exchange organization data collection started on {0}.", $ExchangeServer))
    $StartAttempts = 0
    $StartCheck = Invoke-ScriptBlockHandler -ScriptBlock {Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1125 -After (Get-Date -Date (Get-Date).AddMinutes(-2) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $ExchangeServer -Credential $creds
    while($StartAttempts -lt 2) {
        if($StartCheck -notlike $null -or $StartAttempts -eq 2) {
            LogVerbose([string]::Format("Exchange organization data collection has started on {0}.", $ExchangeServer))
            return $null
        }
        else {
            Log([string]::Format("Exchange organization data collection failed to start on {0}.", $ExchangeServer)) Yellow
            $OrgTask = Invoke-ScriptBlockHandler -ScriptBlock {Get-ScheduledTask ExchangeOrgDiscovery -ErrorAction Ignore -TaskPath \ } -ComputerName $ExchangeServer -Credential $creds
            if($OrgTask -like $null) {
                LogVerbose([string]::Format("Failed to create scheduled task on {0}.", $ExchangeServer))
                return $null
            }
            else {
                $StartAttempts++
                LogVerbose([string]::Format("Exchange organization scheduled task found on {0}.", $ExchangeServer))
                LogVerbose([string]::Format("Attempting to start the Exchange organization scheduled task on {0}.", $ExchangeServer))
                Invoke-ScriptBlockHandler -ScriptBlock {Start-ScheduledTask ExchangeOrgDiscovery -TaskPath \ -ErrorAction Ignore } -ComputerName $ExchangeServer -Credential $creds
                Start-Sleep 3
                $StartCheck = Invoke-ScriptBlockHandler -ScriptBlock {Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1031 -After (Get-Date -Date (Get-Date).AddMinutes(-2) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $s.Fqdn -Credential $creds
            }
        }
    }        
}
function CheckServerCollectionStarted{
    LogVerbose([string]::Format("Checking if Exchange server data collection started on {0}.", $s.Name))
    $StartAttempts = 0
    $StartCheck = Invoke-ScriptBlockHandler -ScriptBlock {Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1031 -After (Get-Date -Date (Get-Date).AddMinutes(-2) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $s.Fqdn -Credential $creds
    while($StartAttempts -lt 2) {
        if($StartCheck -notlike $null -or $StartAttempts -eq 2) {
            LogVerbose([string]::Format("Exchange server data collection has started on {0}.", $s.Name))
            return $null
        }
        else {
            LogVerbose([string]::Format("Exchange server data collection failed to start on {0}.", $s.Name))
            LogVerbose([string]::Format("Checking for Exchange server scheduled task on {0}.", $s.Name))
            $ServerTask = Invoke-ScriptBlockHandler -ScriptBlock {Get-ScheduledTask ExchangeServerDiscovery -ErrorAction Ignore -TaskPath \ } -ComputerName $s.Fqdn -Credential $creds
            if($ServerTask -like $null) {
                LogVerbose([string]::Format("Failed to create scheduled task on {0}.", $s.Name))
                return $null
            }
            else {
                $StartAttempts++
                LogVerbose([string]::Format("Exchange server scheduled task found on {0}.", $s.Name))
                LogVerbose([string]::Format("Attempting to start the Exchange server scheduled task on {0}.", $s.Name))
                Invoke-ScriptBlockHandler -ScriptBlock {Start-ScheduledTask ExchangeServerDiscovery -TaskPath \ -ErrorAction Ignore } -ComputerName $s.Fqdn -Credential $creds
                Start-Sleep 3
                $StartCheck = Invoke-ScriptBlockHandler -ScriptBlock {Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1031 -After (Get-Date -Date (Get-Date).AddMinutes(-2) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $s.Fqdn -Credential $creds
            }
        }
    }      
}

Add-Type -AssemblyName System.Windows.Forms
#$Script:Logger = Get-NewLoggerInstance -LogName "SfMCDiscovery-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue

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

#region ScriptBlocks
## Script block to initiate Exchange server discovery
$ExchangeServerDiscovery = {
    param([boolean]$HealthChecker)
    Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -TaskPath \ -Confirm:$False -ErrorAction Ignore
    $startInDirectory = $env:ExchangeInstallPath +"Scripts"
    $scriptFile = ".\Get-ExchangeServerDiscovery.ps1"
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -WorkingDirectory $startInDirectory  -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -Command `"& $scriptFile -HealthChecker:`$$HealthChecker`""
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    Register-ScheduledTask ExchangeServerDiscovery -Action $Sta -Principal $STPrin
    Start-ScheduledTask ExchangeServerDiscovery -ErrorAction Ignore
}
## Script block to initiate Exchange organization discovery
$ExchangeOrgDiscovery = {
    Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -TaskPath \ -Confirm:$False -ErrorAction Ignore
    $scriptFile = $env:ExchangeInstallPath +"Scripts\Get-ExchangeOrgDiscovery.ps1"
    $scriptFile = "`"$scriptFile`""
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -file $scriptFile"
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    Register-ScheduledTask ExchangeOrgDiscovery -Action $Sta -Principal $STPrin
    Start-ScheduledTask ExchangeOrgDiscovery -ErrorAction Ignore
}
#endregion

#region CheckRunningOnExchange
$ComputerName = $env:COMPUTERNAME
LogVerbose([string]::Format("Checking if '{0}' is an Exchange Server.", $ComputerName))
$isExchangeServer = CheckRunningFromExchangeServer -ComputerName $ComputerName
#endregion

#region CheckPowerShell
if(!($isExchangeServer)) {
    LogVerbose([string]::Format("Checking the PowerShell version on '{0}'.", $ComputerName))
    if(($PSVersionTable).PSVersion -like "4*") {
        ErrorReported([string]::Format("PowerShell version on {0} is not version 5.0 or higher.", $ComputerName))
        exit
    }
}
#endregion

#region Determine location of scripts
LogVerbose([string]::Format("Checking for the location of the discover scripts on {0}.", $ComputerName))
[boolean]$validPath = $false
while($validPath -eq $false) {
    if($ScriptPath -like $null) {[string]$scriptPath = (Get-Location).Path}
    else{
        if($ScriptPath.Substring($ScriptPath.Length-1,1) -eq "\") {$ScriptPath = $ScriptPath.Substring(0,$ScriptPath.Length-1)}
    }
    if(Test-Path -Path $ScriptPath) {$validPath = $true}
    else {
        Log([string]::Format("An invalid path to the scripts was provided. Please select the location")) Red
        $ScriptPath = Get-FolderPath
    }
}
#endregion

#region Check and get HealthChecker
if($HealthChecker -and $ServerSettings) {
    LogVerbose([string]::Format("Checking for the HealthChecker script on {0}.", $ComputerName))
    if(Get-Item $ScriptPath\HealthChecker.ps1 -ErrorAction Ignore) {
        $HCPresent = $true
    } else {
        $HCPresent = $false
    }
    $script:LastError = $Error[0]
    try { Invoke-WebRequest -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/HealthChecker.ps1" -OutFile "$ScriptPath\HealthChecker.ps1"
    }
    catch {}
    ErrorReported "DownloadHealthChecker"
    if($HCPresent) {
        Log([string]::Format("Unable to download the latest version of the HealthChecker script on {0}.", $ComputerName)) Yellow
    }
    else {
        ErrorReported "HealthCheckerDownload"
        exit
    }
}
#endregion

#region Determine the location for the results
LogVerbose([string]::Format("Checking the location for the results."))
[boolean]$validPath = $false
while($validPath -eq $false) {
    if($OutputPath -like $null) {
        Log([string]::Format("Select the location to save the results.", $Subject)) Yellow
        $OutputPath = Get-FolderPath
    }
    else {
        if($OutputPath.Substring($OutputPath.Length-1,1) -eq "\") {$OutputPath = $OutputPath.Substring(0,$OutputPath.Length-1)}
    }
    if(Test-Path -Path $OutputPath) {$validPath = $true}
    else {
        Log([string]::Format("An invalid path for the output was provided. Please select the location")) Red
        $OutputPath = Get-FolderPath
    }
}
#Create a new subfolder for the current results
LogVerbose([string]::Format("Creating a new subfolder for the results."))
$timeStamp = Get-Date -Format yyyyMMddHHmmss
New-Item -Path $OutputPath -Name $timeStamp -ItemType Directory | Out-Null
$OriginalPath = $OutputPath
$OutputPath = "$OutputPath\$timeStamp"
#endregion

#region GetAdminCreds
#Credentials only needed when not running from an Exchange server
if(!($isExchangeServer)) {
    LogVerbose([string]::Format("Prompting for Exchange admin credentials."))
    if($UserName -like $null) {
        $domain = $env:USERDNSDOMAIN
        $UserName = $env:USERNAME
        $UserName = "$UserName@$domain"
    }
    $validCreds = $false
    [int]$credAttempt = 0
    while($validCreds -eq $false) {
        Log([string]::Format("Please enter the Exchange admin credentials using UPN format.")) Green
        Start-Sleep -Seconds 1
        $upnFound = $false
        while($upnFound -eq $false) {
            if($null -eq $Credential) {
                $creds = [System.Management.Automation.PSCredential](Get-Credential -UserName $UserName.ToLower() -Message "Exchange admin credentials using UPN")
            }
            else {
                $creds = $Credential
            }
            if($creds.UserName -like "*@*") {$upnFound = $True}
            else {
                Log([string]::Format("The username must be in UPN format. (ex. jimm@contoso.com).")) Yellow
            }
        }
        $validCreds =  TestADAuthentication
        if($validCreds -eq $false) {
            Log([string]::Format("Unable to validate your credentials. Please try again.")) Yellow
            $credAttempt++
        }
        if($credAttempt -eq 3) {
            Log([string]::Format("Too many credential failures. Exiting script..")) Red
            exit
        }
    }
}
#endregion

## Set the idle time for the remote PowerShell session
$SessionOption = New-PSSessionOption -IdleTimeout 180000 -OperationTimeout 300000 -OutputBufferingMode Drop
## Create an array for the list of Exchange servers
$ServerList = New-Object System.Collections.ArrayList
## Set a timer for the data collection process
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()

#region ConnectExchangePowerShell
$isConnected = $false
try{ 
    Get-ExchangeServer $ExchangeServer -ErrorAction Ignore | Out-Null
    $isConnected = $true
}
catch {
    LogVerbose([string]::Format("Exchange PowerShell session was not found."))
}
[int]$retryAttempt = 0
Log([string]::Format("Attempting to connect to Exchange remote PowerShell on {0} to get a list of servers for data collection.", $ExchangeServer)) Gray
while($isConnected -eq $false) {
    $params = @{
        ConfigurationName = "Microsoft.Exchange"
        ConnectionUri = "http://$ExchangeServer/Powershell"
        AllowRedirection = $null
        Authentication = "Kerberos"
        ErrorAction = "Ignore"
        SessionOption = $SessionOption
        WarningAction = "Ignore"
        Name = "SfMC"
    }
    $script:LastError = $Error[0]
    if(!($isExchangeServer)) { $params.Add("Credential", $creds) }
    try {
        Import-PSSession (New-PSSession @params) -WarningAction Ignore -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
    }
    catch {}
    ErrorReported "RemotePowerShell"
    try{
        $testServer = Get-ExchangeServer $ExchangeServer -ErrorAction Ignore
    }
    catch{
        $ExchangeServer = Read-Host "Please enter the FQDN of another Exchange Server: "
        $retryAttempt++
    }
    if($testServer -like $null) {
        if($retryAttempt -eq 4) {
            Log([string]::Format("Maximum number of attempts has been reached. Check credentials and try again. Exiting script.")) Yellow
            exit
        }
    }
    else{$isConnected = $true}
}
#endregion

#region GetExchangeServerList
## Connect to the Exchange server to get a list of servers for data collection
#Check if running against a single server
if($ServerName -notlike $null) {
    LogVerbose([string]::Format("Verifying {0} is a valid Exchange server.", $ServerName))
    $CheckServer = Get-ExchangeServer -Identity $ServerName -ErrorAction Ignore | Select-Object Fqdn, Name, DistinguishedName, OriginatingServer
    if($CheckServer -notlike $null) {
        $ServerList.Add($CheckServer) | Out-Null
        LogVerbose([string]::Format("Data collection will only run against {0}.", $ServerName))
    }
    else {
        Log([string]::Format("Unable to find an Exchange server with the name {0}. Exiting script.", $ServerName)) Yellow
        Start-Cleanup
        exit
    }
}
#check if running against a single DAG
else {
    if($DagName -notlike $null) { 
        Get-DatabaseAvailabilityGroup $DagName -ErrorAction Ignore | Select-Object -ExpandProperty Servers | ForEach-Object { $ServerList.Add((Get-ExchangeServer $_ | Select-Object Fqdn, Name, DistinguishedName, OriginatingServer)) | Out-Null}
        if($ServerList.Count -eq 0){
            Log([string]::Format("Unable to find a database availability group with the name {0}. Exiting script.", $DagName)) Yellow
            Start-Cleanup
            exit
        }
        else {
            LogVerbose([string]::Format("Data collection will only run against the database availability group named {0}.", $DagName))
        }
    }
    #check if running against an AD site
    else {
        if($ADSite -notlike $null) {
            LogVerbose([string]::Format("Checking for Exchange servers in the AD site named {0}.", $ADSite))
            Get-ExchangeServer | Where-Object {$_.Site -like "*$ADSite*" -and $_.ServerRole -ne "Edge"} | Select-Object Fqdn, Name, DistinguishedName, OriginatingServer | ForEach-Object { $ServerList.Add($_) | Out-Null}
            if($ServerList.Count -eq 0){
                Log([string]::Format("Unable to find any Exchange servers is the {0} site. Exiting script.", $ADSite)) Yellow
                Start-Cleanup
                exit
            }
            else {
                LogVerbose([string]::Format("Data collection will only run against Exchange servers in the {0} Active Directory site.", $ADSite))
            }
        }
        #otherwise run against all servers
        else {
            LogVerbose([string]::Format("Data collection will run against all Exchange servers in the organization."))
            Get-ExchangeServer | Where-Object { $_.ServerRole -ne "Edge"} | Select-Object Fqdn, Name, DistinguishedName, OriginatingServer | ForEach-Object { $ServerList.Add($_) | Out-Null }
        }
    }
}
#endregion

Log([string]::Format("Collecting data now, please be patient. This will take some time to complete.")) Cyan

#region GetExchOrgSettings
## Collect Exchange organization settings
if($OrgSettings) {
    Log([string]::Format("Starting data collection for Exchange organization settings...")) Cyan
    ## Copy the discovery script to the Exchange server
    if($isExchangeServer) {
        Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$env:ExchangeInstallPath\Scripts" -Force
        Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false
        Invoke-ScriptBlockHandler -ScriptBlock $ExchangeOrgDiscovery -ComputerName $ComputerName | Out-Null
        CheckOrgCollectionStarted
    }
    else {
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
        else {
            $exchInstallPath = $SearcherResult
        }
        LogVerbose([string]::Format("Found install path for {0}: {1}", $ADSite,$SearcherResult))
        #$orgResultPath = $exchInstallPath
        $OrgSession = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name SfMCOrgDiscovery -SessionOption $SessionOption
        Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $OrgSession -ErrorAction Ignore
        ## Initiate the data collection on the Exchange server
        Write-Verbose "Unblocking the PowerShell script."
        Invoke-ScriptBlockHandler -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false} -Credential $creds -ComputerName $ExchangeServer
        Invoke-ScriptBlockHandler -ScriptBlock $ExchangeOrgDiscovery -ComputerName $ExchangeServer -Credential $creds | Out-Null
        CheckOrgCollectionStarted
        Remove-PSSession -Name SfMCOrgDiscovery -ErrorAction Ignore
    }
}       
#endregion

#region GetExchServerSettings
$ServerSettingsTimer = New-Object -TypeName System.Diagnostics.Stopwatch
$ServerSettingsTimer.Start()
$ServerStart = Get-Date
if($ServerSettings) {
    Log([string]::Format("Starting data collection on the Exchange servers...")) Cyan
    $sAttempted = 0
    ## Collect server specific data from all the servers
    foreach ($s in $ServerList) {
        ## Get the Exchange install path for this server
        $exchInstallPath = $null
        $PercentComplete = (($sAttempted/$ServerList.Count)*100)
        $PercentComplete = [math]::Round($PercentComplete)
        Write-Progress -Activity "Exchange Discovery Assessment" -Status "Starting data collection on $($s.Name).....$PercentComplete% complete" -PercentComplete $PercentComplete
        if(Test-Connection -ComputerName $s.Fqdn -Count 2 -ErrorAction Ignore) {
            LogVerbose([string]::Format("Getting Exchange install path for {0}.", $s.Name))
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
            LogVerbose([string]::Format("Found install path for {0}: {1}", $s.Name,$SearcherResult))
            #$exchInstallPath = (Get-ADObject -Filter "name -eq '$($s.Name)' -and ObjectClass -eq 'msExchExchangeServer'" -SearchBase $s.DistinguishedName -Properties msExchInstallPath -Server $s.OriginatingServer).msExchInstallPath
            ## Create an array to store paths for data retrieval
            if($exchInstallPath -notlike $null) {
                New-Object -TypeName PSCustomObject -Property @{
                    ServerName = $s.Fqdn
                    ExchInstallPath = $exchInstallPath
                } | Export-Csv -Path $OutputPath\ExchInstallPaths.csv -NoTypeInformation -Append
                ## Copy the discovery script to the Exchange server
                if($isExchangeServer) {
                    $exchInstallPath = $exchInstallPath.Replace(":","$")
                    $exchInstallPath = "\\$($s.Fqdn)\$exchInstallPath"
                    $script:LastError = $Error[0]
                    try {
                        Copy-Item "$ScriptPath\Get-ExchangeServerDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ErrorAction Ignore
                        LogVerbose([string]::Format("Get-ExchangeServerDiscovery script successfully copied to {0}.", $s.Name))
                    }
                    catch {}
                    ErrorReported "CopyExchangeServerDiscoveryScript"
                    #Write-Verbose "Failed to copy Get-ExchangeServerDiscovery script to $s"
                    $script:LastError = $Error[0]
                    if($HealthChecker) { 
                        try {
                            Copy-Item "$ScriptPath\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ErrorAction Ignore
                            LogVerbose([string]::Format("HealthChecker script successfully copied to {0}.", $s.Name))
                        }
                        catch {}
                        ErrorReported "CopyHealthCheckerScript"
                        #Write-Verbose "Failed to copy HealthChecker script to $s"
                    }
                }
                else {
                    $ServerSession = New-PSSession -ComputerName $s.fqdn -Credential $creds -Name SfMCSrvDis -SessionOption $SessionOption -ErrorAction Ignore
                    $script:LastError = $Error[0]
                    if($ServerSession) {
                        try {
                            Copy-Item "$ScriptPath\Get-ExchangeServerDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $ServerSession -ErrorAction Ignore
                            LogVerbose([string]::Format("Get-ExchangeServerDiscovery script successfully copied to {0}.", $s.Name))
                        }
                        catch{}
                        ErrorReported "CopyExchangeServerDiscoveryScript"
                        $script:LastError = $Error[0]
                        try {
                            LogVerbose([string]::Format("Unblocking the script file on server {0}.", $s.Name))
                            Invoke-ScriptBlockHandler -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeServerDiscovery.ps1" -Confirm:$false} -Credential $creds -ComputerName $s.fqdn -IsExchangeServer $isExchangeServer
                        }
                        catch {}
                        ErrorReported "UnblockExchangeServerDiscoveryScript"
                        #Write-Verbose "Failed to copy Get-ExchangeServerDiscovery to $s"
                        if($HealthChecker) { 
                            Copy-Item "$ScriptPath\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $ServerSession 
                            LogVerbose([string]::Format("HealthChecker script successfully copied to {0}.", $s.Name))
                        }
                        Remove-PSSession -Name SfMCSrvDis -ErrorAction Ignore
                    }
                    else {
                        Out-File $OutputPath\FailedServers.txt -InputObject "Unable to establish session on $($s.Name)" -Append
                    }
                }
                ## Initiate the data collection on the Exchange server
                LogVerbose([string]::Format("Starting data collection on the Exchange server {0}.", $s.Name))
                Invoke-ScriptBlockHandler -ScriptBlock $ExchangeServerDiscovery -ComputerName $s.Fqdn -ArgumentList $HealthChecker -Credential $creds -IsExchangeServer $isExchangeServer | Out-Null
                CheckServerCollectionStarted
            }
            else {
                Out-File $OutputPath\FailedServers.txt -InputObject "Unable to determine the Exchange install path on $($s.Name)" -Append
                LogVerbose([string]::Format("Failed to determine the Exchange install path for {0}.", $s.Name))
            }
        }
        else {
            Log([string]::Format("Failed to connect to Exchange: {0}",$s.Fqdn)) Red
            Out-File $OutputPath\FailedServers.txt -InputObject "Unable to connect to $($s.Name)" -Append
        }
        $sAttempted++
    }
    LogVerbose([string]::Format("Exchange server data collection started."))
}
#endregion

#region CollectOrgResults
if($OrgSettings) {
    [int]$OrgResultsAttempt = 0
    [bool]$OrgResultsFound = $false
    LogVerbose([string]::Format("Attempting to retrieve Exchange organization settings."))
    Write-Host "Attempting to retrieve Exchange organization settings..." -ForegroundColor Cyan -NoNewline
    while($OrgResultsAttempt -lt 4 -and $OrgResultsFound -eq $false) {
        $OrgResultsAttempt++
        #$sourcePath = $orgResultPath+"Logging\SfMC Discovery"
        if($isExchangeServer) {
            #Check the event log to see if data collection completed
            LogVerbose([string]::Format("Checking if Exchange organization script completed on {0}.", $ExchangeServer))
            $EndTime = Get-Date
            $TimeSpanMinutes = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Minutes
            $TimeSpanHours = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Hours
            $TimeSpan = ($TimeSpanHours*60) + $TimeSpanMinutes
            $orgCompleted = Invoke-ScriptBlockHandler -ScriptBlock {param($NumberOfMinutes);Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1007 -After (Get-Date -Date (Get-Date).AddMinutes($NumberOfMinutes) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $ExchangeServer -Credential $creds -ArgumentList $TimeSpan -IsExchangeServer:$true
            if($orgCompleted -notlike $null) {
                LogVerbose([string]::Format("Exchange organization script completed on {0}.", $ExchangeServer))
                LogVerbose([string]::Format("Checking for Exchange organization results on {0}.", $ExchangeServer))
                if(Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip" -ErrorAction Ignore) {
                    LogVerbose([string]::Format("Exchange organization results found on {0}.", $ExchangeServer))
                    LogVerbose([string]::Format("Attempting to copy Exchange org results to output location."))
                    Copy-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip" -Destination $OutputPath -Force -ErrorAction Ignore
                    Write-Host "FOUND" -ForegroundColor White
                    $OrgResultsFound = $true
                }
                else{
                    LogVerbose([string]::Format("Exchange organization results not found on {0}.", $ExchangeServer))
                }
            }
            else {
                LogVerbose([string]::Format("Exchange organization script has not completed on {0}.", $ExchangeServer))
            }
        }
        else {
            #Check the event log to see if data collection completed
            LogVerbose([string]::Format("Checking if Exchange organization script completed on {0}.", $ExchangeServer))
            $EndTime = Get-Date
            $TimeSpanMinutes = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Minutes
            $TimeSpanHours = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Hours
            $TimeSpan = ($TimeSpanHours*60) + $TimeSpanMinutes
            #$TimeSpan = (New-TimeSpan -Start (Get-Date) -End $ServerStart).Minutes
            $orgCompleted = Invoke-ScriptBlockHandler -ScriptBlock {param($NumberOfMinutes);Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1007 -After (Get-Date -Date (Get-Date).AddMinutes($NumberOfMinutes) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $ExchangeServer -Credential $creds -ArgumentList $TimeSpan
            if($orgCompleted -notlike $null) {
                #Check for resulting zip file
                LogVerbose([string]::Format("Exchange organization script completed on {0}.", $ExchangeServer))
                LogVerbose([string]::Format("Checking for Exchange organization results on {0}.", $ExchangeServer))
                $orgResult = Invoke-ScriptBlockHandler -ScriptBlock {$orgFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip").FullName; return $orgFile} -ComputerName $ExchangeServer -Credential $creds
                if($orgResult -notlike $null ) {
                    $Session = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name OrgResults -SessionOption $SessionOption
                    LogVerbose([string]::Format("Attempting to copy Exchange organization results from {0} to output location.", $ExchangeServer))
                    Copy-Item $orgResult -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore
                    LogVerbose([string]::Format("Verifying Exchange org results were received."))
                    if(Get-Item $OutputPath\*OrgSettings* -ErrorAction Ignore) { 
                        Write-Host "FOUND" -ForegroundColor White
                        LogVerbose([string]::Format("Results found for Exchange organization settings."))
                        $OrgResultsFound = $true
                        LogVerbose([string]::Format("Removing scheduled task for Exchange org discovery."))
                        Invoke-ScriptBlockHandler -ScriptBlock {Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -Confirm:$False} -ComputerName $ExchangeServer -Credential $creds
                        Remove-PSSession -Name OrgResults -ErrorAction Ignore -Confirm:$False
                    }                
                    else {
                        LogVerbose([string]::Format("Copy of Exchange organization results failed."))
                        Write-Verbose ""
                    }
                }
                else {
                    LogVerbose([string]::Format("Exchange organization results were not found on {0}.", $ExchangeServer))
                }
            }
            else {
                LogVerbose([string]::Format("Exchange organization script did not complete on {0}.", $ExchangeServer))
            }
        }
        if($OrgResultsFound -eq $false) {
            LogVerbose([string]::Format("Results for the Exchange organization discovery were not found."))
            Write-Host "NOT FOUND" -ForegroundColor Red
            LogVerbose([string]::Format("Attempting to retrieve Exchange organization settings."))
            Write-Host "Attempting to retrieve Exchange organization settings..." -ForegroundColor Cyan -NoNewline
            ## Wait x minutes before attempting to retrieve the data
            $TimeToWait = 120
            $TimeRemaining = $TimeToWait
            LogVerbose([string]::Format("Waiting two minutes before attempting to retrieve Exchange organization results."))
            while($TimeRemaining -gt 0) {
                Write-Progress -Activity "Exchange Discovery Assessment" -Status "Waiting for data collection to complete before attempting to retrive data... $TimeRemaining seconds remaining" -PercentComplete ((($TimeToWait-$TimeRemaining)/$TimeToWait)*100)
                Start-Sleep -Seconds 1
                $TimeRemaining = $TimeRemaining - 1
            }
        }
    }
}
#endregion

#region CollectServerResults
[int]$ServerResultsAttempt = 0
[bool]$ServerResultsFound = $false
## Create an array to track remaining servers to pull results
#[System.Collections.ArrayList]$NotFoundList = @()
if($ServerSettings){
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
        LogVerbose([string]::Format("Attempting to retrieve Exchange server setting results."))
        Write-Host "Attempting to retrieve Exchange server settings..." -ForegroundColor Cyan -NoNewline
        foreach($s in $ExchangeServers) {
            $CustomObject = New-Object -TypeName psobject
            $ExchangeServerName = $s.ServerName
            $NetBIOSName= $ExchangeServerName.Substring(0, $ExchangeServerName.IndexOf("."))
            ## Check if server results have been received
            $PercentComplete = (($sAttempted/$ExchangeServers.Count)*100)
            $PercentComplete = [math]::Round($PercentComplete)
            Write-Progress -Activity "Exchange Discovery Assessment" -Status "Retrieving data from $ExchangeServerName.....$PercentComplete% complete" -PercentComplete $PercentComplete
            if(!(Get-Item $OutputPath\$ExchangeServerName* -ErrorAction Ignore)) { 
                ## Attempt to copy results from Exchange server
                $params = @{
                    Destination = $OutputPath
                    Force = $null
                    ErrorAction = 'Ignore'
                }
                if(!($isExchangeServer)) {
                    $Session = New-PSSession -ComputerName $ExchangeServerName -Credential $creds -Name ServerResults -SessionOption $SessionOption
                    $params.Add("FromSession",$Session) | Out-Null
                }
                LogVerbose([string]::Format("Checking if Exchange server discovery completed on {0}.", $ExchangeServerName))
                #Check the event log to see if data collection completed
                $EndTime = Get-Date
                $TimeSpanMinutes = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Minutes
                $TimeSpanHours = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Hours
                $TimeSpan = ($TimeSpanHours*60) + $TimeSpanMinutes
                $serverCompleted = Invoke-ScriptBlockHandler -ScriptBlock {param($NumberOfMinutes);Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1376 -After (Get-Date -Date (Get-Date).AddMinutes($NumberOfMinutes) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $ExchangeServerName -Credential $creds -ArgumentList $TimeSpan
                if($serverCompleted -notlike $null) {
                    #Now look for the results zip file
                    $serverResult = Invoke-ScriptBlockHandler -ScriptBlock {$serverFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\$env:COMPUTERNAME*.zip").FullName; return $serverFile} -ComputerName $ExchangeServerName -Credential $creds -IsExchangeServer $isExchangeServer
                    if($serverResult -notlike $null) {
                        LogVerbose([string]::Format("Attempting to copy results from {0}.", $ExchangeServerName))
                        if($isExchangeServer) {
                            $serverResult = $serverResult.Replace(":","$")
                            $serverResult = "\\$ExchangeServerName\$serverResult"
                        }
                        $params.Add("Path",$serverResult) | Out-Null
                        Copy-Item @params
                        #Check if the results were downloaded
                        if(Get-Item $OutputPath\$NetBIOSName* -ErrorAction Ignore) {
                            LogVerbose([string]::Format("Results from {0} were received.", $ExchangeServerName))
                            $foundCount++
                            LogVerbose([string]::Format("Attempting to remove scheduled task from {0}.", $ExchangeServerName))
                            Invoke-ScriptBlockHandler -ScriptBlock {Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -Confirm:$False} -ComputerName $ExchangeServerName -Credential $creds -IsExchangeServer $isExchangeServer
                            Remove-PSSession -Name ServerResults -ErrorAction Ignore -Confirm:$False
                        }
                        else {
                            LogVerbose([string]::Format("Failed to copy results from {0}.", $ExchangeServerName))
                            $CustomObject | Add-Member -MemberType NoteProperty -Name "ServerName" -Value $ExchangeServerName -Force
                            $CustomObject | Add-Member -MemberType NoteProperty -Name "ExchInstallPath" -Value $s.ExchInstallPath -Force
                            $ServersNotFound.Add($CustomObject) | Out-Null
                        }
                    }
                    else {
                        LogVerbose([string]::Format("Results not found on {0}.", $ExchangeServerName))
                    }
                }
                ## Add server to array to check again
                else {
                    LogVerbose([string]::Format("Script has not completed on {0}. Adding to retry list.", $ExchangeServerName))
                    $CustomObject | Add-Member -MemberType NoteProperty -Name "ServerName" -Value $s.ServerName -Force
                    $CustomObject | Add-Member -MemberType NoteProperty -Name "ExchInstallPath" -Value $s.ExchInstallPath -Force
                    $ServersNotFound.Add($CustomObject) | Out-Null
                }
            }
            $sAttempted++
        }
        if($foundCount -eq $totalServerCount) { 
            LogVerbose([string]::Format("All results retrieved for Exchange server discovery."))
            Write-Host "FOUND";
            $ServerResultsFound = $true
        }
        else{
            if($foundCount -gt 0) {
                LogVerbose([string]::Format("Not all results were retrieved for Exchange server discovery."))
                Log([string]::Format("{0} of {1} found.", $foundCount, $totalServerCount)) Yellow
            }
            else {
                LogVerbose([string]::Format("No Exchange server settings results were found."))
                Write-Host "NOT FOUND" -ForegroundColor Red
            }
            ## Wait x minutes before attempting to retrieve the data
            $TimeToWait = 120
            $TimeRemaining = [math]::Round($TimeToWait)
            LogVerbose([string]::Format("Waiting two minutes before attempting to retrieve results again."))
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
        Log([string]::Format("Compressing results into zip file for upload.")) Gray
        Compress-Archive -Path $OutputPath -DestinationPath "$OriginalPath\DiscoveryResults-$timeStamp.zip"
    }
    catch{}
    ErrorReported "CompressResults"
}
else {
    ## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    $zipFolder = "$OriginalPath\DiscoveryResults-$timeStamp.zip"
    $script:LastError = $Error[0]
    try {
        Log([string]::Format("Compressing results into zip file for upload.")) Gray
        [System.IO.Compression.ZipFile]::CreateFromDirectory($OutputPath, $zipFolder)}
    catch {
        ErrorReported "CompressResults"
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'update')
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        Get-ChildItem -Path $outputPath | Select-Object FullName | ForEach-Object {
            $script:LastError = $Error[0]
            try{
                Log([string]::Format("Compressing results into zip file for upload.")) Gray
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipFile, $_.FullName, (Split-Path $_.FullName -Leaf), $compressionLevel) | Out-Null 
            }
            catch {}
            ErrorReported "CompressResults"
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
Start-Cleanup
