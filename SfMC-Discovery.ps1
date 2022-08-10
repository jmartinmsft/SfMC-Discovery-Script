<#//***********************************************************************
//
// SfMC-Discovery.ps1
// Modified 10 August 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// .VERSION 3.7
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
//    ServerSettings - The ServerSettings parameter specifies wheter or no Exchange server settings are collected.
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
// 3.7 Update adds copying the HealthChecker.ps1 script to the Exchange servers for additional data collection
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
    [Parameter(Mandatory=$true)] [string]$ExchangeServer,
    [Parameter(Mandatory=$false)] [string]$UserName,
    [Parameter(Mandatory=$false)] [string]$ServerName,
    [Parameter(Mandatory=$false)] [string]$DagName,
    [Parameter(Mandatory=$false)] [string]$OutputPath,
    [Parameter(Mandatory=$false)] [string]$ScriptPath,
    [Parameter(Mandatory=$false)] [string]$ADSite,
    [boolean]$OrgSettings=$true,
    [boolean]$ServerSettings=$true
)
Clear-Host
#region Disclaimer
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
#Start-Sleep -Seconds 2
function Start-Cleanup {
    Remove-PSSession -Name SfMC -ErrorAction Ignore
    Remove-PSSession -Name SfMCOrgDis -ErrorAction Ignore
    Get-PSSession -Name SfMCSrvDis -ErrorAction Ignore | Remove-PSSession -ErrorAction Ignore
}
function Get-FolderPath {   
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location"
    $folderBrowser.SelectedPath = "C:\"
    $folderPath = $folderBrowser.ShowDialog()
    [string]$oPath = $folderBrowser.SelectedPath
    return $oPath
}
function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    }
    else {
        return $false
    }
}
function Test-ADAuthentication {
    $UserName = $creds.UserName
    #$UserName = $UserName.Substring(0, $UserName.IndexOf("@"))
    $Password = $creds.GetNetworkCredential().Password
    #(New-Object DirectoryServices.DirectoryEntry "",$username,$password).PsBase.Name -ne $null
    $Root = "LDAP://" + ([ADSI]'').distinguishedName
    $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
    if(!$Domain) { Write-Warning "Something went wrong" }
    else {
        if ($Domain.name -ne $null) { return $true }
        else {return $false}
    }
}
#region CheckAdmin
if(-not (Is-Admin)) {
	Write-host;Write-Warning "The SfMC-Discovery.ps1 script needs to be executed in elevated mode. Please start PowerShell 'as Administrator' and try again." 
	Write-host;Start-Sleep -Seconds 2;
	exit
}
#endregion
#region CheckPowerShell
if(($PSVersionTable).PSVersion -like "4*") {
    Write-Host; Write-Warning "The SfMC-Discovery.ps1 script must be executed using Windows PowerShell version 5.0 or higher"
    Write-Host; Start-Sleep -Seconds 2
    exit
}
#endregion
Write-Host " "
Write-Host " "
Write-Host -ForegroundColor Cyan "==============================================================================="
Write-Host " "
Write-Host -ForegroundColor Cyan " The SfMC Email Discovery process is about to begin gathering data. "
Write-Host -ForegroundColor Cyan " It will take some time to complete depending on the size of your environment. "
Write-Host " "
Write-Host -ForegroundColor Cyan "==============================================================================="
Write-Host " "

## Script block to initiate Exchange server discovery
$scriptBlock1 = {
    Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -Confirm:$False
    $scriptFile = $env:ExchangeInstallPath +"Scripts\Get-ExchangeServerDiscovery.ps1"
    $scriptFile = "`"$scriptFile`""
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -file $scriptFile"
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    $Stt = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMilliseconds(5000)
    Register-ScheduledTask ExchangeServerDiscovery -Action $Sta -Principal $STPrin -Trigger $Stt
}
## Script block to initiate Exchange organization discovery
$scriptBlock2 = {
    Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -Confirm:$False
    $scriptFile = $env:ExchangeInstallPath +"Scripts\Get-ExchangeOrgDiscovery.ps1"
    $scriptFile = "`"$scriptFile`""
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -file $scriptFile"
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    $Stt = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMilliseconds(5000)
    Register-ScheduledTask ExchangeOrgDiscovery -Action $Sta -Principal $STPrin -Trigger $Stt
}
## Script block to determine Exchange install path for server
$scriptBlock3 = {
    $env:ExchangeInstallPath
}
#region ScriptLocation
#Determine location of scripts
Add-Type -AssemblyName System.Windows.Forms
[boolean]$validPath = $false
while($validPath -eq $false) {
    if($ScriptPath -like $null) {[string]$scriptPath = (Get-Location).Path}
    else{
        if($ScriptPath.Substring($ScriptPath.Length-1,1) -eq "\") {$ScriptPath = $ScriptPath.Substring(0,$ScriptPath.Length-1)}
    }
    if(Test-Path -Path $ScriptPath) {$validPath = $true}
    else {
        Write-Warning "An invalid path to the scripts was provided. Please select the location."
        Start-Sleep -Seconds 3
        $ScriptPath = Get-FolderPath
    }
}
#endregion
#region OutputPath
# Determine the current location which will be used to store the results
[boolean]$validPath = $false
while($validPath -eq $false) {
    if($OutputPath -like $null) {
        Write-Host "Select the location where to save the data." -ForegroundColor Yellow
        $OutputPath = Get-FolderPath
    }
    else {
        if($OutputPath.Substring($OutputPath.Length-1,1) -eq "\") {$OutputPath = $OutputPath.Substring(0,$OutputPath.Length-1)}
    }
    if(Test-Path -Path $OutputPath) {$validPath = $true}
    else {
        Write-Warning "An invalid path for the output was provided. Please select the location."
        Start-Sleep -Seconds 3
        $OutputPath = Get-FolderPath
    }
}
#Create a new subfolder for the current results
$timeStamp = Get-Date -Format yyyyMMddHHmmss
New-Item -Path $OutputPath -Name $timeStamp -ItemType Directory | Out-Null
$OriginalPath = $OutputPath
$OutputPath = "$OutputPath\$timeStamp"
#endregion
#region GetAdminCreds
## Get the current user name and prompt for credentials
if($UserName -like $null) {
    $domain = $env:USERDNSDOMAIN
    $UserName = $env:USERNAME
    $UserName = "$UserName@$domain"
}
$validCreds = $false
[int]$credAttempt = 0
while($validCreds -eq $false) {
    Write-Host "Please enter the Exchange admin credentials using UPN format" -ForegroundColor Green
    Start-Sleep -Seconds 2
    $upnFound = $false
    while($upnFound -eq $false) {
        $creds = [System.Management.Automation.PSCredential](Get-Credential -UserName $UserName.ToLower() -Message "Exchange admin credentials using UPN")
        if($creds.UserName -like "*@*") {$upnFound = $True}
        else {Write-Warning "The username must be in UPN format. (ex. jimm@contoso.com)"}
    }
    $validCreds =  Test-ADAuthentication
    if($validCreds -eq $false) {
        Write-Warning "Unable to validate your credentials. Please try again."
        $credAttempt++
    }
    if($credAttempt -eq 3) {
        Write-Warning "Too many credential failures. Exiting script."
        exit
    }
}
#endregion
## Set the idle time for the remote PowerShell session
$SessionOption = New-PSSessionOption -IdleTimeout 300000 -OperationTimeout 300000 -OutputBufferingMode Drop
## Create an array for the list of Exchange servers
$servers = New-Object System.Collections.ArrayList
## Set a timer for the data collection process
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()
#region GetExchangeServerList
## Connect to the Exchange server to get a list of servers for data collection
$isConnected = $false
[int]$retryAttempt = 0
while($isConnected -eq $false) {
    $Error.Clear()
    try {Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeServer/Powershell -AllowRedirection -Authentication Kerberos -Name SfMC -WarningAction Ignore -Credential $creds -ErrorAction Ignore -SessionOption $SessionOption) -WarningAction Ignore -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null}
    catch {
        Write-Warning "Unable to create a remote PowerShell session with $ExchangeServer."
        Start-Sleep -Seconds 2
        $ExchangeServer = Read-Host "Please enter the FQDN of another Exchange Server: "
    }
    $Error.Clear()
    try{$testServer = Get-ExchangeServer $ExchangeServer -ErrorAction Ignore}
    catch{$retryAttempt++}
    if($testServer -like $null) {
        if($retryAttempt -eq 4) {
            Write-Warning "Maximum number of attempts has been reached. Check credentials and try again. Exiting script."
            exit
        }
    }
    else{$isConnected = $true}
}
[string]$orgName = (Get-OrganizationConfig).Name
#Check if running against a single server
if($ServerName -notlike $null) {
    $CheckServer = (Get-ExchangeServer -Identity $ServerName -ErrorAction Ignore).Fqdn
    if($CheckServer -notlike $null) {
        $servers.Add($CheckServer) | Out-Null
    }
    else {
        Write-Warning "Unable to find an Exchange server with the name $ServerName. Exiting script"
        Start-Cleanup
        exit
    }
}
#check if running against a single DAG
else {
    if($DagName -notlike $null) { 
        Get-DatabaseAvailabilityGroup $DagName -ErrorAction Ignore | Select -ExpandProperty Servers | ForEach-Object { $servers.Add((Get-ExchangeServer $_ ).Fqdn) | Out-Null}
        if($servers.Count -eq 0){
            Write-Warning "Unable to find a database availability group with the name $DagName. Exiting script"
            Start-Cleanup
            exit
        }
    }
    #check if running against an AD site
    else {
        if($ADSite -notlike $null) {
            Get-ExchangeServer | Where {$_.Site -like "*$ADSite*" -and $_.ServerRole -ne "Edge"} | ForEach-Object { $servers.Add($_.Fqdn) | Out-Null}
            if($servers.Count -eq 0){
                Write-Warning "Unable to find any Exchange servers is the $ADSite site. Exiting script"
                Start-Cleanup
                exit
            }
        }
        #otherwise run against all servers
        else {Get-ExchangeServer | Where { $_.ServerRole -ne "Edge"} | ForEach-Object { $servers.Add($_.Fqdn) | Out-Null } }
    }
}
#endregion
Write-host -ForegroundColor Cyan "Collecting data now, please be patient. This will take some time to complete!"
#region GetExchOrgSettings
## Collect Exchange organization settings
if($OrgSettings) {
    Write-Host -ForegroundColor Cyan "Starting data collection for Exchange organization settings..." -NoNewline
    ## Get the Exchange install path for this server    
    $exchInstallPath = Invoke-Command -Credential $creds -ScriptBlock $scriptBlock3 -ComputerName $ExchangeServer -ErrorAction Stop
    $orgResultPath = $exchInstallPath
    ## Copy the discovery script to the Exchange server
    $Session = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name CopyOrgScript
    Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $Session
    ## Initiate the data collection on the Exchange server
    try {Invoke-Command -Credential $creds -ScriptBlock $scriptBlock2 -ComputerName $ExchangeServer -ArgumentList $creds -InDisconnectedSession -ErrorAction Stop -SessionName SfMCOrgDis -SessionOption $SessionOption | Out-Null}
    catch {
        Write-Host "FAILED"
        Write-Warning "Unable to collect Exchange organization settings."
    }
    Invoke-Command -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false} -Session $Session
    Remove-PSSession -Name CopyOrgScript -ErrorAction Ignore
    Write-Host "STARTED"
}
#endregion
#region GetExchServerSettings
if($ServerSettings) {
    Write-Host "Starting data collection on the Exchange servers..." -ForegroundColor Cyan -NoNewline
    $sAttempted = 0
    ## Collect server specific data from all the servers
    foreach ($s in $servers) {
        ## Get the Exchange install path for this server
        $exchInstallPath = $null
        $PercentComplete = (($sAttempted/$servers.Count)*100)
        $PercentComplete = [math]::Round($PercentComplete)
        Write-Progress -Activity "Exchange Discovery Assessment" -Status "Starting data collection on $s.....$PercentComplete% complete" -PercentComplete $PercentComplete
        if(Test-Connection -ComputerName $s -Count 2 -ErrorAction Ignore) {
            $exchInstallPath = Invoke-Command -Credential $creds -ScriptBlock $scriptBlock3 -ComputerName $ExchangeServer -ErrorAction Stop
            ## Create an array to store paths for data retrieval
            if($exchInstallPath -notlike $null) {
                New-Object -TypeName PSCustomObject -Property @{
                    ServerName = $s
                    ExchInstallPath = $exchInstallPath
                } | Export-Csv -Path $OutputPath\ExchInstallPaths.csv -NoTypeInformation -Append
                ## Copy the discovery script to the Exchange server
                $Session = New-PSSession -ComputerName $s -Credential $creds -Name CopyServerScript -SessionOption $SessionOption
                Copy-Item "$ScriptPath\Get-ExchangeServerDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $Session
                Copy-Item "$ScriptPath\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $Session
                ## Initiate the data collection on the Exchange server
                try{ Invoke-Command -Credential $creds -ScriptBlock $scriptBlock1 -ComputerName $s -ArgumentList $creds -InDisconnectedSession -ErrorAction Stop -SessionName SfMCSrvDis -SessionOption $SessionOption | Out-Null}
                catch{ Write-Warning "Unable to initiate data collection on $s."}
                Invoke-Command -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeServerDiscovery.ps1" -Confirm:$false} -Session $Session -ErrorAction Ignore
                Remove-PSSession -Name CopyServerScript -ErrorAction Ignore
            }
            else {Out-File $OutputPath\FailedServers.txt -InputObject "Unable to determine the Exchange install path on $s" -Append}
        }
        else {Out-File $OutputPath\FailedServers.txt -InputObject "Unable to connect to $s" -Append}
        $sAttempted++
    }
    Write-Host "STARTED"
}
#endregion
## Check for results
Write-Host "Attempting to retrieve results..." -ForegroundColor Cyan
#region CollectResults
[int]$fileCheckAttempt = 0
if($OrgSettings) {$orgResultsIn = $false}
## Get list of servers and install paths to retrieve data
if($ServerSettings) {
    $Servers = Import-Csv $OutputPath\ExchInstallPaths.csv
    $serverCount = $servers.ServerName.Count
}
else {$serverCount = 1}
$totalServerCount = $serverCount
$foundCount = 0
## Attempt to retrieve the data multiple times
while($fileCheckAttempt -lt 4) {
    if($serverCount -gt 0 -or $orgResultsIn -eq $false) { 
        ## Wait x minutes before attempting to retrieve the data
        $waitTimer = New-Object -TypeName System.Diagnostics.Stopwatch
        $waitTimer.Start()
        while($waitTimer.ElapsedMilliseconds -lt 60000){
            $TimeRemaining = $waitTimer.ElapsedMilliseconds/1000
            $TimeRemaining = 120 - [math]::Round($TimeRemaining)
            Write-Progress -Activity "Exchange Discovery Assessment" -Status "Waiting two minutes before attempting to retrive data... $TimeRemaining seconds remaining" -PercentComplete (($waitTimer.ElapsedMilliseconds/120000)*100)
            Start-Sleep -Seconds 1
        }
    }
    else {break}
    ## Check for results and retrieve if missing
    $fileCheckResult = $False
    if($OrgSettings) {
        if($orgResultsIn -eq $false) {
            Write-Host "Retrieving Exchange organization settings..." -ForegroundColor Cyan -NoNewline
            if(Get-Item $OutputPath\*OrgSettings* -ErrorAction Ignore) { 
                Write-Host "FOUND" -ForegroundColor White
                $orgResultsIn = $true
            }
            else {
                $sourcePath = $orgResultPath
                $sourcePath = $sourcePath+"Logging\SfMC Discovery"
                $Session = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name OrgResults
                $scriptBlock5 = {$orgFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip").FullName; return $orgFile}
                $orgResult = Invoke-Command -ScriptBlock $scriptBlock5 -Session $Session -ErrorAction Ignore
                if($orgResult -notlike $null ) {
                    Copy-Item $orgResult -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore
                    if(Get-Item $OutputPath\*OrgSettings* -ErrorAction Ignore) { 
                        Write-Host "FOUND" -ForegroundColor White
                        $orgResultsIn = $true
                        Invoke-Command -ScriptBlock {Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -Confirm:$False} -Session $Session
                        Remove-PSSession -Name OrgResults -ErrorAction Ignore -Confirm:$False
                    }
                }
                else {
                    Write-Host "NOT FOUND" -ForegroundColor Red
                }
            }
        }
    }
    $fileCheckResult = $False
    ## Create an array to track remaining servers to pull results
    [System.Collections.ArrayList]$NotFoundList = @()
    [int]$sAttempted = 0
    if($ServerSettings) {
        Write-Host "Retrieving Exchange server settings..." -ForegroundColor Cyan -NoNewline
        $servers | ForEach-Object {
            $s = $_.ServerName.Substring(0, $_.ServerName.IndexOf("."))
            $sourcePath = $_.ExchInstallPath
            $sourcePath = $sourcePath+"Logging\SfMC Discovery"
            ## Check if server results have been received
            $PercentComplete = (($sAttempted/$servers.Count)*100)
            $PercentComplete = [math]::Round($PercentComplete)
            Write-Progress -Activity "Exchange Discovery Assessment" -Status "Retrieving data from $s.....$PercentComplete% complete" -PercentComplete (($foundCount/$totalServerCount)*100)
            if(!(Get-Item $OutputPath\$s* -ErrorAction Ignore)) { 
                ## Attempt to copy results from Exchange server
                $Session = New-PSSession -ComputerName $_.ServerName -Credential $creds -Name ServerResults
                $scriptBlock5 = {$serverFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\$env:COMPUTERNAME*.zip").FullName; return $serverFile}
                $serverResult = Invoke-Command -ScriptBlock $scriptBlock5 -Session $Session -ErrorAction Ignore
                if($serverResult -notlike $null) {
                    Copy-Item $serverResult -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore 
                    ## Check if the results were found
                    if(Get-Item $OutputPath\$s* -ErrorAction Ignore) {
                        $foundCount++
                        $scripBlock4 = {Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -Confirm:$False}
                        Invoke-Command -ScriptBlock $scripBlock4 -Session $Session -ErrorAction Ignore
                        Remove-PSSession -Name ServerResults -ErrorAction Ignore -Confirm:$False
                        $sAttempted++
                    }
                }
                ## Add server to array to check again
                else {$NotFoundList.Add($_) | Out-Null}
            }
        }
    }
    if($foundCount -eq $totalServerCount) { Write-Host "FOUND"; $ServerSettings = $False}
    else{
        if($foundCount -gt 0) {Write-Host "$foundCount of $totalServerCount FOUND" -ForegroundColor Yellow}
        else {Write-Host "NOT FOUND" -ForegroundColor Red}
    }
    $Servers = $NotFoundList
    $serverCount = $servers.ServerName.Count
    $fileCheckAttempt++
}
foreach($s in $NotFoundList) {
    $mServer = $s.ServerName
    Out-File $OutputPath\FailedServers.txt -InputObject "Unable to retrieve data for $mServer" -Append
}
#endregion
Write-Host " "
$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
$timeStamp = Get-Date -Format yyyyMMddHHmmss
Compress-Archive -Path $OutputPath -DestinationPath "$OriginalPath\DiscoveryResults-$timeStamp.zip"
Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC Email Discovery data collection has finished!"
Write-Host -ForegroundColor Cyan "          Total collection time: $($totalTime) seconds"
Write-Host -ForegroundColor Cyan "    Please upload results to SfMC. - Thank you!!!"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "
Start-Cleanup

# SIG # Begin signature block
# MIInsQYJKoZIhvcNAQcCoIInojCCJ54CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCaz4IVBM26Aujh
# 9DclNzlWu4Tf9JPFjx7hv88fQrwD9aCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGZEwghmNAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBRrxfkTBEMju5+jFAYv8JhP
# Fkd/1lCeC9WCA6Z5uIoOMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBRmX1i3d1joT4kKCm90i2+KY8e1lFPjwWG7DrgXGI9vNRSepzeCG7E
# LVSWL9RVLKxqOrw7w7HwwS9eV+YWqwtMsiDP71UTwOTsF5pNcpoRB9O2XACOLJz/
# QjXH4Y07D4aZgDD1q0nGc4UAVt85j2jBfDUdYT42ZYujN0XJ52rhW3AuAvSTnFU2
# YAYQrrbLt3L7xMh12oychwQTwX9/SAqNhYMfyHEsvEVP6hc75Ftk32mF+PIoi67k
# bt1DgsE2F6tDZXDulTfADyYR4/AZr234fjQcgwkyXBrM2PeDgM67dJbWt3kQSYP7
# eUI0T2+NadbVNF1oXRx5M9fRjUghNL5QoYIXGTCCFxUGCisGAQQBgjcDAwExghcF
# MIIXAQYJKoZIhvcNAQcCoIIW8jCCFu4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIPMw9NssSC7dDOPdC9NIEyAc5qRlm8z/JVvcj9eidgEdAgZi3oid
# FG4YEzIwMjIwODEwMTgwNTE0LjY0M1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFoMIIHFDCCBPygAwIBAgITMwAAAY/zUajrWnLdzAABAAABjzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDZaFw0yMzAxMjYxOTI3NDZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmVc+/rXPFx6Fk4+CpLru
# bDrLTa3QuAHRVXuy+zsxXwkogkT0a+XWuBabwHyqj8RRiZQQvdvbOq5NRExOeHia
# CtkUsQ02ESAe9Cz+loBNtsfCq846u3otWHCJlqkvDrSr7mMBqwcRY7cfhAGfLvlp
# MSojoAnk7Rej+jcJnYxIeN34F3h9JwANY360oGYCIS7pLOosWV+bxug9uiTZYE/X
# clyYNF6XdzZ/zD/4U5pxT4MZQmzBGvDs+8cDdA/stZfj/ry+i0XUYNFPhuqc+UKk
# wm/XNHB+CDsGQl+ZS0GcbUUun4VPThHJm6mRAwL5y8zptWEIocbTeRSTmZnUa2iY
# H2EOBV7eCjx0Sdb6kLc1xdFRckDeQGR4J1yFyybuZsUP8x0dOsEEoLQuOhuKlDLQ
# Eg7D6ZxmZJnS8B03ewk/SpVLqsb66U2qyF4BwDt1uZkjEZ7finIoUgSz4B7fWLYI
# eO2OCYxIE0XvwsVop9PvTXTZtGPzzmHU753GarKyuM6oa/qaTzYvrAfUb7KYhvVQ
# KxGUPkL9+eKiM7G0qenJCFrXzZPwRWoccAR33PhNEuuzzKZFJ4DeaTCLg/8uK0Q4
# QjFRef5n4H+2KQIEibZ7zIeBX3jgsrICbzzSm0QX3SRVmZH//Aqp8YxkwcoI1WCB
# izv84z9eqwRBdQ4HYcNbQMMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBTzBuZ0a65J
# zuKhzoWb25f7NyNxvDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDNf9Oo9zyhC5n1jC8iU7NJY39FizjhxZwJbJY/
# Ytwn63plMlTSaBperan566fuRojGJSv3EwZs+RruOU2T/ZRDx4VHesLHtclE8GmM
# M1qTMaZPL8I2FrRmf5Oop4GqcxNdNECBClVZmn0KzFdPMqRa5/0R6CmgqJh0muvI
# mikgHubvohsavPEyyHQa94HD4/LNKd/YIaCKKPz9SA5fAa4phQ4Evz2auY9SUluI
# d5MK9H5cjWVwBxCvYAD+1CW9z7GshJlNjqBvWtKO6J0Aemfg6z28g7qc7G/tCtrl
# H4/y27y+stuwWXNvwdsSd1lvB4M63AuMl9Yp6au/XFknGzJPF6n/uWR6JhQvzh40
# ILgeThLmYhf8z+aDb4r2OBLG1P2B6aCTW2YQkt7TpUnzI0cKGr213CbKtGk/OOIH
# SsDOxasmeGJ+FiUJCiV15wh3aZT/VT/PkL9E4hDBAwGt49G88gSCO0x9jfdDZWdW
# GbELXlSmA3EP4eTYq7RrolY04G8fGtF0pzuZu43A29zaI9lIr5ulKRz8EoQHU6cu
# 0PxUw0B9H8cAkvQxaMumRZ/4fCbqNb4TcPkPcWOI24QYlvpbtT9p31flYElmc5wj
# GplAky/nkJcT0HZENXenxWtPvt4gcoqppeJPA3S/1D57KL3667epIr0yV290E2ot
# ZbAW8DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLXMIIC
# QAIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD5NL4IEdudIBwdGoCaV0WBbQZpqoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmnh56MCIYDzIwMjIwODEw
# MjAwOTMwWhgPMjAyMjA4MTEyMDA5MzBaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIF
# AOaeHnoCAQAwCgIBAAICAqQCAf8wBwIBAAICEV4wCgIFAOafb/oCAQAwNgYKKwYB
# BAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGG
# oDANBgkqhkiG9w0BAQUFAAOBgQCtKGkaZulMDj/335Wgdtto48nJoK3Q7Qx+Kr94
# 7icXaKbpvh7a+s/0Uaa1d1ppCEL9xzmHFJk7ZpbTVJSxoYnVy0E2KZyollpKFq3K
# fEDz/ztLPRAqOOX0YSWdLEVC0GJ8Jcyy5yuKYksaeeeEDfvkc61BceK3qw1GDG91
# pGZ6eTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABj/NRqOtact3MAAEAAAGPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG
# 9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEILQHJuHMFm9ZAGsX
# FmUAftimgqGPuk9weWa+5B7RmXuuMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCB
# vQQgl3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAi
# BCCqCJmkf3v7/R1NZHZjsQINMMvjOE5oO5nHE5w70WWAIDANBgkqhkiG9w0BAQsF
# AASCAgCJKDyYFrpK8mhWzzb4UkQbbLah1Pu1RA7L8rZvMBSZ8dYKX9LQxT19BxNH
# U/wiwYtk1KCzRChnz7XUVoxrdkG7c4tp0O4XFADVzVjjr32U9dx6vgOhEucIzCi6
# blmH0ebROkT6LcPeNnzTOFyKNeyrUelfJ0KJMW7FrDHAkHYn7x+ue7wEjWV0a/nO
# tij0ukmyC1sk+MYoWtsy4pE543CFkZUlxDz3kgVKo75iZa2O935HfijwWExZkD59
# e6ZqUEmWgyqupsdnvUOumv8Phk3rOxUY+aUvELu4duuaXLSv/Dr657uA58s1iTvo
# 9A62hLCjXKel5EW6fxpT71A+ScWex+WaPNS222Gv66mFXEqCBAYA9gwhEs3ugoPk
# AirrBZO6RLeckkGiWTJfl0FfVSlWlbU/XsHpcg0mZ+y7ulwYgFMHKVwgXWMgtJ9z
# EbRQCE9JH6U7IWRyOPfi23OU0pqMB2VBB7BaN4Dz/u3WRSkSpkUTCHiBH+IzWLHP
# r+8dU3ltObJTggWQfcquE9Cr5PBThvYirdx/HN9XkILzQ68CUn/bVourqTRzOVZ4
# 2rfa4oHR61Mv2plI+N2MFtTIYDzk4jJ7JmkcAjul3jyXPew+aD22VLisvwiDewO8
# Y9BF23uHFL90NDMHhKxKaMIO3uBVCMkd4n2wrDA4JBBAquNmCw==
# SIG # End signature block
