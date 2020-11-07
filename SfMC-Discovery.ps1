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
  Should be run from Exchange Management Shell on Exchange 2010 CAS or 2013/2016 MBX, but could be run from mgmt remote powershell connected workstation
#>
param(
    #[Parameter(Mandatory=$true)][System.Collections.ArrayList]$servers,
    [Parameter(Mandatory=$true)] [string]$ExchangeServer,
    [Parameter(Mandatory=$false)] [string]$DagName
)
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
Clear-Host
if(-not (Is-Admin)) {
	Write-host;Write-Warning "The SfMC-Exchange-Discovery-1.ps1 script needs to be executed in elevated mode. Please start PowerShell 'as Administrator' and try again." 
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
[string]$scriptPath = (Get-Location).Path
## Convert the current location to a UNC path
$scriptPath = $scriptPath.Replace(":","$")
$scriptPath = "\\$env:COMPUTERNAME\$scriptPath"
## Determine the current location which will be used to store the results
Add-Type -AssemblyName System.Windows.Forms
Write-Host "Select the location where to save the data." -ForegroundColor Yellow
$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$folderBrowser.Description = "Select the location where to save the data"
$folderBrowser.SelectedPath = "C:\"
$folderPath = $folderBrowser.ShowDialog()
[string]$logPath = $folderBrowser.SelectedPath
## Convert the current location to a UNC path
$logPath = $logPath.Replace(":","$")
$logPath = "\\$env:COMPUTERNAME\$logPath"
## Get the current user name and prompt for credentials
$domain = $env:USERDNSDOMAIN
$UserName = $env:USERNAME
$upn = "$UserName@$domain"
$c = [System.Management.Automation.PSCredential](Get-Credential -UserName $upn.ToLower() -Message "Exchange admin credentials")
## Set a timer
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()
## Connect to the Exchange server to get a list of servers for data collection
Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeServer/Powershell -AllowRedirection -Authentication Kerberos -Name SfMC -WarningAction Ignore) -WarningAction Ignore -DisableNameChecking -AllowClobber | Out-Null
if($DagName.Length -gt 0) { $servers = Get-DatabaseAvailabilityGroup $DagName | Select -ExpandProperty Servers }
else {$servers = Get-ExchangeServer | Where { $_.ServerRole -ne "Edge"} | Select Name | ForEach-Object { $_.Name }}
Write-host -ForegroundColor Yellow "Collecting data now, please be patient. This will take some time to complete!"
Write-Host -ForegroundColor Yellow "Collecting Exchange organization settings..." -NoNewline
## Collect Exchange organization settings
Invoke-Command -ScriptBlock $scriptBlock2 -ComputerName $ExchangeServer -ArgumentList $c, $logPath, $scriptPath -ErrorAction Ignore -AsJob | Out-Null
Write-Host "COMPLETE"
Write-Host "Starting data collection on the Exchange servers..." -ForegroundColor Yellow -NoNewline
## Collect server specific data from all the servers
Invoke-Command -ScriptBlock $scriptBlock1 -ComputerName $servers -ArgumentList $c, $logPath, $scriptPath -ErrorAction Ignore -AsJob | Out-Null
## Collect Exchange orgnization settings from one server
Write-Host "COMPLETE"
$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC Email Discovery data collection has finished!"
Write-Host -ForegroundColor Cyan "          Total collection time: $($totalTime) seconds"
Write-Host -ForegroundColor Cyan "    Please upload results to SfMC. - Thank you!!!"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "
Remove-PSSession -Name SfMC