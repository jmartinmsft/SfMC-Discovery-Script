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
.SYNOPSIS
  Collect Exchange configuration via PowerShell
 
.DESCRIPTION
  This script will run Get commands in your Exchange Management Shell to collect configuration data via PowerShell

.NOTES
  Exchange server specified should be the latest version in the environment
#>
param(
    [Parameter(Mandatory=$true)] [string]$ExchangeServer,
    [Parameter(Mandatory=$false)] [string]$UserName,
    [Parameter(Mandatory=$false)] [string]$ServerName,
    [Parameter(Mandatory=$false)] [string]$DagName,
    [Parameter(Mandatory=$false)] [string]$OutputPath,
    [Parameter(Mandatory=$false)] [string]$ScriptPath
)
function Test-ADAuthentication {
    $UserName = $creds.UserName
    $UserName = $UserName.Substring(0, $UserName.IndexOf("@"))
    $Password = $creds.GetNetworkCredential().Password
    (New-Object DirectoryServices.DirectoryEntry "",$username,$password).PsBase.Name -ne $null
}
function Start-Cleanup {
    Remove-PSSession -Name SfMC -ErrorAction Ignore
    Remove-SmbShare -Name SfMCOutput$ -Force -Confirm:$False -ErrorAction Ignore
    Remove-SmbShare -Name SfMCScript$ -Force -Confirm:$False -ErrorAction Ignore
}
function Get-FolderPath {   
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location"
    $folderBrowser.SelectedPath = "C:\"
    $folderPath = $folderBrowser.ShowDialog()
    [string]$oPath = $folderBrowser.SelectedPath
    return $oPath
}
function Zip-CsvResults {
	#Change to the Script Location 
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    $date1 = Get-Date -UFormat "%d%b%Y"
    [string]$zipFolder = "$env:ExchangeInstallPath\Logging\ExchangeOrgSettings-$date1.zip"
    Remove-Item $zipFolder -Force -ErrorAction Ignore
    Set-Location $outputPath
    [system.io.compression.zipfile]::CreateFromDirectory($outputPath, $zipFolder)
    return $zipFolder
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
#Clear-Host
if(-not (Is-Admin)) {
	Write-host;Write-Warning "The SfMC-Exchange-Discovery.ps1 script needs to be executed in elevated mode. Please start PowerShell 'as Administrator' and try again." 
	Write-host;Start-Sleep -Seconds 2;
	exit
}
if(Get-SmbShare SfMCOutput$ -ErrorAction Ignore) {Remove-SmbShare -Name SfMCOutput$ -Confirm:$false }
if(Get-SmbShare SfMCScript$ -ErrorAction Ignore) {Remove-SmbShare -Name SfMCScript$ -Confirm:$false }
Write-host " "
    Write-host " "
    Write-host -ForegroundColor Cyan "==============================================================================="
    Write-host " "
    Write-Host -ForegroundColor Cyan " The SfMC Email Discovery process is about to begin gathering data. "
    Write-host -ForegroundColor Cyan " It will take some time to complete depending on the size of your environment. "
    Write-host " "
    Write-host -ForegroundColor Cyan "==============================================================================="
    Write-host " "
$scriptBlock1 = {
Param($param1,$param2,$param3)
New-PSDrive -Name "SfMC" -PSProvider FileSystem -Root $param3 -Credential $param1 | Out-Null
Copy-Item -Path SfMC:\Get-ExchangeServerDiscovery.ps1 -Destination "$env:ExchangeInstallPath\Scripts"
Set-Location $env:ExchangeInstallPath\Scripts
.\Get-ExchangeServerDiscovery.ps1 -Creds $param1 -destPath $param2 -sPath $param3
}
$scriptBlock2 = {
Param($param1,$param2,$param3)
New-PSDrive -Name "SfMC" -PSProvider FileSystem -Root $param3 -Credential $param1 | Out-Null
Copy-Item -Path SfMC:\Get-ExchangeOrgDiscovery.ps1 -Destination "$env:ExchangeInstallPath\Scripts"
Set-Location $env:ExchangeInstallPath\Scripts
.\Get-ExchangeOrgDiscovery.ps1 -Creds $param1 -destPath $param2 -sPath $param3
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
$MonitorFolder = $OutputPath
Write-Warning "Removing any existing results from $OutputPath."
Start-Sleep -Seconds 2
Get-ChildItem $OutputPath\*.zip | Remove-Item -Force
## Get the current user name and prompt for credentials
if($UserName -like $null) {
    $domain = $env:USERDNSDOMAIN
    $UserName = $env:USERNAME
    $UserName = "$UserName@$domain"
}
$validCreds = $false
[int]$credAttempt = 0
while($validCreds -eq $false) {
    $creds = [System.Management.Automation.PSCredential](Get-Credential -UserName $UserName.ToLower() -Message "Exchange admin credentials")
    $validCreds =  Test-ADAuthentication -username $UserName -password $Password -root $Root
    if($validCreds -eq $false) {
        Write-Warning "Unable to validate your credentials. Please try again."
        $credAttempt++
    }
    if($credAttempt -eq 3) {
        Write-Warning "Too many credential failures. Exiting script."
        exit
    }
}
## Create temporary file shares to save the results
try {New-SmbShare -Name SfMCOutput$ -Path $OutputPath -FullAccess $creds.UserName -Description "Temporary share for SfMC Discovery" -ErrorAction Stop | Out-Null}
catch {
    Write-Warning "Unable to create the SfMCOutput share. Exiting script"
    exit
}
try {New-SmbShare -Name SfMCScript$ -Path $ScriptPath -FullAccess $creds.UserName -Description "Temporary share for SfMC Discovery" -ErrorAction Stop | Out-Null}
catch {
    Write-Warning "Unable to create the SfMCScript share. Exiting script"
    exit
}
## Update variable values with the new share values
$OutputPath = "\\$env:COMPUTERNAME\SfMCOutput$"
$ScriptPath = "\\$env:COMPUTERNAME\SfMCScript$"
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
    try {Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeServer/Powershell -AllowRedirection -Authentication Kerberos -Name SfMC -WarningAction Ignore -Credential $creds -ErrorAction Ignore) -WarningAction Ignore -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null}
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
    else {Get-ExchangeServer | Where { $_.ServerRole -ne "Edge"} | ForEach-Object { $servers.Add($_.Fqdn) | Out-Null } }
}
Write-host -ForegroundColor Yellow "Collecting data now, please be patient. This will take some time to complete!"
Write-Host -ForegroundColor Yellow "Collecting Exchange organization settings..." -NoNewline
## Collect Exchange organization settings
$Error.Clear()
try {Invoke-Command -Credential $creds -ScriptBlock $scriptBlock2 -ComputerName $ExchangeServer -ArgumentList $creds, $OutputPath, $ScriptPath -InDisconnectedSession -ErrorAction Stop | Out-Null}
catch {
    Write-Host "FAILED"
    Write-Warning "Unable to collect Exchange organization settings."
}
Write-Host "COMPLETE"
Write-Host "Starting data collection on the Exchange servers..." -ForegroundColor Yellow 
## Collect server specific data from all the servers
$failedServers = New-Object System.Collections.ArrayList
foreach($s in $servers) {
    $Error.Clear()
    Write-Host "Attempt to collect data from $s..." -ForegroundColor Cyan
    try{Invoke-Command -Credential $creds -ScriptBlock $scriptBlock1 -ComputerName $s -ArgumentList $creds, $OutputPath, $ScriptPath -InDisconnectedSession -ErrorAction Stop | Out-Null}
    catch{
        Write-Warning "Unable to connect to $s to collect data."
        $failedServers.Add($s) | Out-Null
    }
}
if($failedServers.Count -gt 0) {
    foreach($f in $failedServers) {
        $servers.Remove($f) | Out-Null
    }
}
$AllResultsUploaded = $false
$monitorWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$monitorWatch.Start()
while($AllResultsUploaded -eq $false) {
    Get-ChildItem "$MonitorFolder\*.zip" -ErrorAction Ignore| Select Name | ForEach-Object {
        foreach($s in $servers) {
            [string]$server = $s.Substring(0, $s.IndexOf("."))
            if($_.Name -like "$server*") {
                Write-Host "Results for $s have been received." -ForegroundColor Green
                $servers.Remove($s) | Out-Null
                break
                $monitorWatch.Restart()
            }
        }
        if($servers.Count -eq 0) {$AllResultsUploaded = $true}
    }
    if($monitorWatch.Elapsed.TotalMinutes -ge 5) {
               Write-Warning "Delay detected in receiving results."
                $AllResultsUploaded = $true
                [int]$EarlyExit = 1
    }
}
if($EarlyExit -eq 1) {Write-Host "Not all results have been received." -ForegroundColor Yellow}
else{Write-Host "All results have been received." -ForegroundColor Yellow}
Write-Host " "
Write-Host " "
$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
$timeStamp = Get-Date -Format yyyyMMddHHmmss
Compress-Archive -Path $MonitorFolder -DestinationPath ".\DiscoveryResults-$timeStamp.zip"
Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC Email Discovery data collection has finished!"
Write-Host -ForegroundColor Cyan "          Total collection time: $($totalTime) seconds"
Write-Host -ForegroundColor Cyan "    Please upload results to SfMC. - Thank you!!!"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "
Start-Cleanup