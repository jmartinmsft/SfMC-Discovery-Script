<#
#################################################################################
#  DISCLAIMER: 									#
#										#
#  	THIS CODE IS SAMPLE CODE. THESE SAMPLES ARE PROVIDED "AS IS" WITHOUT	#
#  	WARRANTY OF ANY KIND. MICROSOFT FURTHER DISCLAIMS ALL IMPLIED		#
#	WARRANTIES INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OF 	#
#	MERCHANTABILITY OR OF FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE 	#
#	RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SAMPLES REMAINS 	#
#	WITH YOU. IN NO EVENT SHALL MICROSOFT OR ITS SUPPLIERS BE LIABLE FOR	#
#	ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR 	#
#	LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS 	#
#	INFORMATION, OR OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OF OR 	#
#	INABILITY TO USE THE SAMPLES, EVEN IF MICROSOFT HAS BEEN ADVISED OF 	#
#	THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME STATES DO NOT ALLOW THE 	#
#	EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL 	#
#	DAMAGES, THE ABOVE LIMITATION MAY NOT APPLY TO YOU.			#
#										#
#################################################################################
.VERSION 2.1
.SYNOPSIS
  Collect Exchange configuration via PowerShell
 
.DESCRIPTION
  This script will run Get commands in your Exchange Management Shell to collect configuration data via PowerShell

.PARAMETERS
    ExchangeServer - The ExchangeServer parameter is required to make the initial remote PowerShell session to retrieve list of Exchange servers in the organization and is used to collect the Exchange organization settings.

    UserName - The UserName parameter specifies the Exchange admin account used to run the data collection scripts

    ServerName - The ServerName parameter specifies a single Exchange server to collect data against.

    DagName - The DagName parameter specifies the name of the Exchange database availability group to collect data against.

    OutputPath - The OutputPath parameters specifies the location for the data collection results.

    ScriptPath - The ScriptPath parameter specifies the location for the data collection scripts.

    ADSite - The ADSite parameter specifies the Active Directory site for the Exchange servers to collect data against.

    OrgSettings - The OrgSettings parameter specifies whether or not Exchange organization settings are collected.

    ServerSettings - The ServerSettings parameter specifies wheter or no Exchange server settings are collected.

.EXAMPLES
 .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -DagName E19DAG1 -OutputPath c:\Temp\Results
 This example collects the Exchange organization settings and Exchange server settings for the E19DAG1 database availability group and saves the results in C:\Temp\Results

 .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results
 This example collects the Exchange organization settings and Exchange server settings for all Exchange servers in the organization and saves the results in c:\Temp\Results

 .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results -ServerSettings:$False
 This example collects only the Exchange organization settings and saves the results to c:\Temp\Results

 .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results -OrgSettings:$False -ServerName clt-e19-mbx3.resource.local
 This example collects only the Exchange server settings for clt-e19-mbx3.resource.local and saves the results to c:\Temp\Results

.NOTES
  Exchange server specified should be the latest version in the environment
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
function Start-Cleanup {
    Remove-PSSession -Name SfMC -ErrorAction Ignore
    Remove-PSSession -Name SfMCOrgDis -ErrorAction Ignore
    Get-PSSession -Name SfMCSrvDis -ErrorAction Ignore | Remove-PSSession -ErrorAction Ignore
    if($winRmRule.Enabled -ne $true) { Set-NetFirewallRule $winRmRule.InstanceID -Enabled False }

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
    $UserName = $UserName.Substring(0, $UserName.IndexOf("@"))
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
#Clear-Host
if(-not (Is-Admin)) {
	Write-host;Write-Warning "The SfMC-Exchange-Discovery.ps1 script needs to be executed in elevated mode. Please start PowerShell 'as Administrator' and try again." 
	Write-host;Start-Sleep -Seconds 2;
	exit
}
Write-host " "
    Write-host " "
    Write-host -ForegroundColor Cyan "==============================================================================="
    Write-host " "
    Write-Host -ForegroundColor Cyan " The SfMC Email Discovery process is about to begin gathering data. "
    Write-host -ForegroundColor Cyan " It will take some time to complete depending on the size of your environment. "
    Write-host " "
    Write-host -ForegroundColor Cyan "==============================================================================="
    Write-host " "
## Get the current firewall settings for WinRM
$winRmRule = Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where {$_.Profile -match "Domain" -and $_.Direction -eq "Inbound"}
if($winRmRule.Enabled -ne $true) { Set-NetFirewallRule $winRmRule.InstanceID -Enabled True }
## Script block to initiate Exchange server discovery
$scriptBlock1 = {
Param($param1)
Start-Transcript
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Confirm:$False
Import-Module $env:ExchangeInstallPath\Bin\RemoteExchange.ps1
Connect-ExchangeServer -UserName $param1 -Auto
Set-Location $env:ExchangeInstallPath\Scripts
Write-Warning (Get-Location)
Write-Warning ((Get-ChildItem *Discover* | Select-Object Name).Name | Out-String)
Unblock-File -Path $env:ExchangeInstallPath\Scripts\Get-ExchangeServerDiscovery.ps1 -Confirm:$False
.\Get-ExchangeServerDiscovery.ps1 -Creds $param1
}
## Script block to initiate Exchange organization discovery
$scriptBlock2 = {
Param($param1)
Start-Transcript
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Confirm:$False
Import-Module $env:ExchangeInstallPath\Bin\RemoteExchange.ps1
Connect-ExchangeServer -UserName $param1 -Auto
Set-Location $env:ExchangeInstallPath\Scripts
Write-Warning (Get-Location)
Write-Warning ((Get-ChildItem *Discover* | Select-Object Name).Name | Out-String)
Unblock-File -Path $env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1 -Confirm:$False
.\Get-ExchangeOrgDiscovery.ps1 -Creds $param1
}
## Script block to determine Exchange install path for server
$scriptBlock3 = {
    $env:ExchangeInstallPath
}
## Get the location for the scripts
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
Write-Warning "Removing any existing results from $OutputPath."
Start-Sleep -Seconds 2
Get-ChildItem $OutputPath\*.zip | Remove-Item -Force
Remove-Item $OutputPath\ExchInstallPaths.csv -Force -ErrorAction Ignore
## Get the current user name and prompt for credentials
if($UserName -like $null) {
    $domain = $env:USERDNSDOMAIN
    $UserName = $env:USERNAME
    $UserName = "$UserName@$domain"
}
Start-Sleep -Seconds 2
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
    #$creds = [System.Management.Automation.PSCredential](Get-Credential -UserName $UserName.ToLower() -Message "Exchange admin credentials using UPN")
    $validCreds =  Test-ADAuthentication #-username $UserName -password $Password #-root $Root
    if($validCreds -eq $false) {
        Write-Warning "Unable to validate your credentials. Please try again."
        $credAttempt++
    }
    if($credAttempt -eq 3) {
        Write-Warning "Too many credential failures. Exiting script."
        exit
    }
}
## Set the idle time for the remote PowerShell session
$SessionOption = New-PSSessionOption -IdleTimeout 900000
## Create an array for the list of Exchange servers
$servers = New-Object System.Collections.ArrayList
## Set a timer
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()
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
else {
    if($DagName -notlike $null) { 
        Get-DatabaseAvailabilityGroup $DagName -ErrorAction Ignore | Select -ExpandProperty Servers | ForEach-Object { $servers.Add((Get-ExchangeServer $_ ).Fqdn) | Out-Null}
        if($servers.Count -eq 0){
            Write-Warning "Unable to find a database availability group with the name $DagName. Exiting script"
            Start-Cleanup
            exit
        }
    }
    else {
        if($ADSite -notlike $null) {
            Get-ExchangeServer | Where {$_.Site -like "*$ADSite*" -and $_.ServerRole -ne "Edge"} | ForEach-Object { $servers.Add($_.Fqdn) | Out-Null}
            if($servers.Count -eq 0){
                Write-Warning "Unable to find any Exchange servers is the $ADSite site. Exiting script"
                Start-Cleanup
                exit
            }
        }
        else {Get-ExchangeServer | Where { $_.ServerRole -ne "Edge"} | ForEach-Object { $servers.Add($_.Fqdn) | Out-Null } }
    }
}
Write-host -ForegroundColor Yellow "Collecting data now, please be patient. This will take some time to complete!"
## Collect Exchange organization settings
if($OrgSettings) {
    Write-Host -ForegroundColor Yellow "Collecting Exchange organization settings..."
    ## Get the Exchange install path for this server    
    $exchInstallPath = Invoke-Command -Credential $creds -ScriptBlock $scriptBlock3 -ComputerName $ExchangeServer -ErrorAction Stop
    $orgResultPath = $exchInstallPath
    ## Copy the discovery script to the Exchange server
    $Session = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name CopyOrgScript
    Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $Session
    Remove-PSSession -Name CopyOrgScript -ErrorAction Ignore
    ## Initiate the data collection on the Exchange server
    try {Invoke-Command -Credential $creds -ScriptBlock $scriptBlock2 -ComputerName $ExchangeServer -ArgumentList $creds -InDisconnectedSession -ErrorAction Stop -SessionName SfMCOrgDis -SessionOption $SessionOption | Out-Null}
    catch {
        Write-Host "FAILED"
        Write-Warning "Unable to collect Exchange organization settings."
    }
}
if($ServerSettings) {
    Write-Host "Starting data collection on the Exchange servers..." -ForegroundColor Yellow 
    ## Collect server specific data from all the servers
    foreach ($s in $servers) {
        ## Get the Exchange install path for this server
        $exchInstallPath = $null
        Write-Host "Attempting to trigger data collection from $s" -ForegroundColor Cyan
        if(Test-Connection -ComputerName $s -Count 2 -ErrorAction Ignore) {
            $exchInstallPath = Invoke-Command -Credential $creds -ScriptBlock $scriptBlock3 -ComputerName $ExchangeServer -ErrorAction Stop
            ## Create an array to store paths for data retrieval
            if($exchInstallPath -notlike $null) {
                New-Object -TypeName PSCustomObject -Property @{
                    ServerName = $s
                    ExchInstallPath = $exchInstallPath
                } | Export-Csv -Path $OutputPath\ExchInstallPaths.csv -NoTypeInformation -Append
        
                ## Copy the discovery script to the Exchange server
                $Session = New-PSSession -ComputerName $s -Credential $creds -Name CopyServerScript
                Copy-Item "$ScriptPath\Get-ExchangeServerDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $Session
                Remove-PSSession -Name CopyServerScript -ErrorAction Ignore
                ## Initiate the data collection on the Exchange server
                try{ Invoke-Command -Credential $creds -ScriptBlock $scriptBlock1 -ComputerName $s -ArgumentList $creds -InDisconnectedSession -ErrorAction Stop -SessionName SfMCSrvDis -SessionOption $SessionOption | Out-Null}
                catch{ Write-Warning "Unable to initiate data collection on $s."}
            }
            else {Write-Warning "Unable to determine the Exchange install path on $s."}
        }
        else {Write-Warning "Unable to connect to $s to collect data."}
    }
}
$monitorWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$monitorWatch.Start()
## Check for results
Write-Host "Attempting to retrieve results..." -ForegroundColor Yellow
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
    Write-Progress -PercentComplete (($foundCount/$totalServerCount)*100) -Activity "SfMC Discovery data collection"
    ## Only pause when waiting for results
    if($serverCount -gt 0 -or $orgResultsIn -eq $false) { Start-Sleep -Seconds 120 }
    else {break}
    ## Check for results and retrieve if missing
    if($OrgSettings) {
        if($orgResultsIn -eq $false) {
            if(Get-Item $OutputPath\*OrgSettings* -ErrorAction Ignore) { 
                Write-Host "Organization results found" -ForegroundColor Green
                $orgResultsIn = $true
            }
            else {
                $sourcePath = $orgResultPath
                $sourcePath = $sourcePath+"Logging\SfMC Discovery"
                $Session = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name OrgResults
                Copy-Item "$sourcePath\*OrgSettings*.zip" -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore
                if(Get-Item $OutputPath\*OrgSettings* -ErrorAction Ignore) { 
                    Write-Host "Organization results found" -ForegroundColor Green
                    $orgResultsIn = $true
                }
                Remove-PSSession -Name OrgResults -ErrorAction Ignore -Confirm:$False
            }
        }
    }
    ## Create an array to track remaining servers to pull results
    [System.Collections.ArrayList]$NotFoundList = @()
    if($ServerSettings) {
        $servers | ForEach-Object {
            $s = $_.ServerName.Substring(0, $_.ServerName.IndexOf("."))
            $sourcePath = $_.ExchInstallPath
            $sourcePath = $sourcePath+"Logging\SfMC Discovery"
            ## Check if server results have been received
            if(Get-Item $OutputPath\$s* -ErrorAction Ignore) { Write-Host "Results found for "$_.ServerName -ForegroundColor Cyan }
            else { 
                ## Attempt to copy results from Exchange server
                $Session = New-PSSession -ComputerName $_.ServerName -Credential $creds -Name ServerResults
                Copy-Item "$sourcePath\$s*.zip" -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore 
                ## Check if the results were found
                if(Get-Item $OutputPath\$s* -ErrorAction Ignore) { 
                    Write-Host "Results found for "$_.ServerName -ForegroundColor Cyan;
                    $foundCount++ 
                    Write-Progress -PercentComplete (($foundCount/$totalServerCount)*100) -Activity "SfMC Discovery data collection"
                }
                ## Add server to array to check again
                else {$NotFoundList.Add($_) | Out-Null}
                Remove-PSSession -Name ServerResults -ErrorAction Ignore -Confirm:$False
            }
        }
    }
    $Servers = $NotFoundList
    $serverCount = $servers.ServerName.Count
    $fileCheckAttempt++
}
foreach($s in $NotFoundList) {
    $s.ServerName | Out-File $OutputPath\MissingServerResults.txt -Append
}
Write-Host " "
$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
$timeStamp = Get-Date -Format yyyyMMddHHmmss
Write-Host $LocalOutputPath
Compress-Archive -Path $OutputPath -DestinationPath ".\DiscoveryResults-$timeStamp.zip"
Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC Email Discovery data collection has finished!"
Write-Host -ForegroundColor Cyan "          Total collection time: $($totalTime) seconds"
Write-Host -ForegroundColor Cyan "    Please upload results to SfMC. - Thank you!!!"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "
Start-Cleanup