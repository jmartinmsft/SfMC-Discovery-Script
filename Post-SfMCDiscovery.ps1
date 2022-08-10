<#//***********************************************************************
//
// Post-SfMCDiscovery.ps1
// Modified 10 August 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v1.1
//
//.NOTES
// 1.1 Adds the HealthChecker script data collection
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
    [Parameter(Mandatory=$false)] [string]$OutputPath
)
function Get-FolderPath {   
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location"
    $folderBrowser.SelectedPath = "C:\"
    $folderPath = $folderBrowser.ShowDialog()
    [string]$oPath = $folderBrowser.SelectedPath
    return $oPath
}
## Work with discovery data
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
Add-Type -AssemblyName System.Windows.Forms
# Determine the current location which will be used to store the results
[boolean]$validPath = $false
while($validPath -eq $false) {
    if($OutputPath -like $null) {
        Write-Host "Select the location for the customer results." -ForegroundColor Yellow
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
## Set a timer
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Write-Host -ForegroundColor Cyan " The SfMC Email Discovery process is about to begin processing data. "
Write-host -ForegroundColor Cyan " It will take some time to complete depending on the customer environment. "
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Start-Sleep -Seconds 3
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()
Get-ChildItem -Path $OutputPath -Filter *.zip | Select FullName,Name | ForEach-Object {
    if($_.Name -notlike "*OrgSettings*") {
        $serverName = $_.Name.Substring(0,$_.Name.IndexOf("-Settings"))
        $serverPath = $null
        $serverPath = "$outputPath\$serverName"
        try{Expand-Archive -Path $_.FullName -DestinationPath $serverPath -ErrorAction Stop -Force}
        catch{$zipName = $_.FullName
            Write-Warning "Unable to extract $zipName."
        }
    }
}
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Write-Host -ForegroundColor Cyan " The SfMC Email Discovery is merging the CSV data. "
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Get-ChildItem $outputPath -Filter *ActiveSyncVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ActiveSyncVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *AutodiscoverVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\AutodiscoverVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Bios.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Bios.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ClientAccessServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ClientAccessServer.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ComputerSystem.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ComputerSystem.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *CrashControl.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\CrashControl.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Culture.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Culture.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *DatabaseAvailabilityGroup.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\DatabaseAvailabilityGroup.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *DatabaseAvailabilityGroupNetwork.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\DatabaseAvailabilityGroupNetwork.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Disk.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Disk.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *EcpVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\EcpVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *EventLogLevel.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\EventLogLevel.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ExchangeCertificate.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\ExchangeCertificate.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ExchangeServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ExchangeServer.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *FrontendTransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\FrontendTransportService.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *HotFix.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\HotFix.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ImapSettings.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ImapSettings.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *LogFile.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\LogFile.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *LogicalDisk.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\LogicalDisk.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MailboxDatabase.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\MailboxDatabase.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MailboxServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\MailboxServer.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MailboxTransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\MailboxTransportService.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MapiVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\MapiVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Memory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Memory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *NetAdapter.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\NetAdapter.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *NetIPAddress.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\NetIPAddress.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *NetOffloadGlobalSetting.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\NetOffloadGlobalSetting.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *NetRoute.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\NetRoute.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OabVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OabVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OperatingSystem.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OperatingSystem.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OutlookAnywhere.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OutlookAnywhere.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OwaVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OwaVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Partition.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Partition.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *PopSettings.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\PopSettings.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *PowerShellVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\PowerShellVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Processor.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Processor.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Product.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Product.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *RpcClientAccess.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\RpcClientAccess.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ReceiveConnector.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ReceiveConnector.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ScheduledTask.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ScheduledTask.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ServerComponentState.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ServerComponentState.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ServerHealth.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ServerHealth.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *-Service.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Service.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *TransportAgent.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\TransportAgent.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *TransportPipeline.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\TransportPipeline.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *-TransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\TransportService.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *WebServicesVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\WebServicesVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *WindowsFeature.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\WindowsFeature.csv -NoTypeInformation -Append
if(!(Get-Item $OutputPath\HealthChecker -ErrorAction Ignore)){
    New-Item -Path $OutputPath\HealthChecker -ItemType Directory | Out-Null
}
Get-ChildItem $OutputPath -Filter HealthChecker*.xml -Recurse | Select-Object -ExpandProperty FullName | Move-Item -Destination $OutputPath\HealthChecker -Confirm:$False -Force
.\HealthChecker.ps1 -XMLDirectoryPath $OutputPath\HealthChecker -BuildHtmlServersReport

$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC Email Discovery data processing has finished!"
Write-Host -ForegroundColor Cyan "          Total time: $($totalTime) seconds"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "

# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZOkROIe5PxWOk
# +nWL28xKNH9Z49+Vhnw1iJFNOwmCyqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIC1SsLoScfp3f2hhBYEdOLnk
# 5pK3G8edHCVeW1+BW9C1MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB7VSPU6Q5f/yW1bEWLG1JyKdVpbFw/ojfHHKazRmhn4SSqmtlpLsnf
# ZslXR6M9dhQ301CJyGAqmYe5r6bzXWdiIypmOH0AHpg3cMYOm3IR+/vuYV0EqBV3
# 26QvDrowWeJv2rlmQYIVTw2yjyx3Gyx6HmssldgPYV/T3UnLG2LUzVsggU22WLf0
# rWCGYfTezRa5K2ZiwGgqz3+ghJqI7OqCxrIqA6duaEssbic6Kzset+PWBAloscya
# sjzLMwmJlpha8ZYwqDlDPs6zsJeFZFopuR+72h2vMimkrpFUlRv53+ANIA/Mvi8I
# bedOM6BG41PDP7/aSgpaaHdp4noUO1cXoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIICNJzcaHkjAeJdrqdOuytLjtCmztfm1hHGQ8YctdH+QAgZi3nYF
# tZAYEzIwMjIwODEwMTgwNTEwLjA5OFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046QTI0MC00QjgyLTEzMEUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY16VS54dJkqtwABAAABjTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDVaFw0yMzAxMjYxOTI3NDVaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkEyNDAt
# NEI4Mi0xMzBFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2jRILZg+O6U7dLcuwBPM
# B+0tJUz0wHLqJ5f7KJXQsTzWToADUMYV4xVZnp9mPTWojUJ/l3O4XqegLDNduFAO
# bcitrLyY5HDsxAfUG1/2YilcSkSP6CcMqWfsSwULGX5zlsVKHJ7tvwg26y6eLklU
# dFMpiq294T4uJQdXd5O7mFy0vVkaGPGxNWLbZxKNzqKtFnWQ7jMtZ05XvafkIWZr
# NTFv8GGpAlHtRsZ1A8KDo6IDSGVNZZXbQs+fOwMOGp/Bzod8f1YI8Gb2oN/mx2cc
# vdGr9la55QZeVsM7LfTaEPQxbgAcLgWDlIPcmTzcBksEzLOQsSpBzsqPaWI9ykVw
# 5ofmrkFKMbpQT5EMki2suJoVM5xGgdZWnt/tz00xubPSKFi4B4IMFUB9mcANUq9c
# HaLsHbDJ+AUsVO0qnVjwzXPYJeR7C/B8X0Ul6UkIdplZmncQZSBK3yZQy+oGsuJK
# XFAq3BlxT6kDuhYYvO7itLrPeY0knut1rKkxom+ui6vCdthCfnAiyknyRC2lknqz
# z8x1mDkQ5Q6Ox9p6/lduFupSJMtgsCPN9fIvrfppMDFIvRoULsHOdLJjrRli8co5
# M+vZmf20oTxYuXzM0tbRurEJycB5ZMbwznsFHymOkgyx8OeFnXV3car45uejI1B1
# iqUDbeSNxnvczuOhcpzwackCAwEAAaOCATYwggEyMB0GA1UdDgQWBBR4zJFuh59G
# wpTuSju4STcflihmkzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQA1r3Oz0lEq3VvpdFlh3YBxc4hnYkALyYPDa9FO
# 4XgqwkBm8Lsb+lK3tbGGgpi6QJbK3iM3BK0ObBcwRaJVCxGLGtr6Jz9hRumRyF8o
# 4n2y3YiKv4olBxNjFShSGc9E29JmVjBmLgmfjRqPc/2rD25q4ow4uA3rc9ekiauf
# gGhcSAdek/l+kASbzohOt/5z2+IlgT4e3auSUzt2GAKfKZB02ZDGWKKeCY3pELj1
# tuh6yfrOJPPInO4ZZLW3vgKavtL8e6FJZyJoDFMewJ59oEL+AK3e2M2I4IFE9n6L
# VS8bS9UbMUMvrAlXN5ZM2I8GdHB9TbfI17Wm/9Uf4qu588PJN7vCJj9s+KxZqXc5
# sGScLgqiPqIbbNTE+/AEZ/eTixc9YLgTyMqakZI59wGqjrONQSY7u0VEDkEE6ikz
# +FSFRKKzpySb0WTgMvWxsLvbnN8ACmISPnBHYZoGssPAL7foGGKFLdABTQC2PX19
# WjrfyrshHdiqSlCspqIGBTxRaHtyPMro3B/26gPfCl3MC3rC3NGq4xGnIHDZGSiz
# UmGg8TkQAloVdU5dJ1v910gjxaxaUraGhP8IttE0RWnU5XRp/sGaNmDcMwbyHuSp
# aFsn3Q21OzitP4BnN5tprHangAC7joe4zmLnmRnAiUc9sRqQ2bmsMAvUpsO8nlOF
# miM1LzCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046QTI0MC00QjgyLTEzMEUxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAIBzlZM9TRND4PgtpLWQZkSPYVcJoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmnguqMCIYDzIwMjIwODEw
# MTg0OTE0WhgPMjAyMjA4MTExODQ5MTRaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaeC6oCAQAwBwIBAAICHu0wBwIBAAICEU0wCgIFAOafXSoCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQBBa9s5bLkp6kF3bLR1uiWzfa/2wIzj/Iz+UUJBLrPm
# W4VhF7RyYhCguOeVoBBqC4+lAICOKxnmkmhVhnMBe/gyCiuf1MmZPUEfaV8cmcbW
# bwbPBpzFMdXufj4TVA0oBdz3e4L71YPHYwuzzJt3rJHvwgU8PIO4KrtmjJ27LKsA
# ZjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABjXpVLnh0mSq3AAEAAAGNMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEICMjuBgQX9zbqYCJxdvM
# 6//spjrdntJJiaF4bVA3okLIMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# npYRM/odXkDAnzf2udL569W8cfGTgwVuenQ8ttIYzX8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY16VS54dJkqtwABAAABjTAiBCDO
# 2MA4MPi2qgFgVnEcgyWyJVrikjgys0pZwvA+BQuHmjANBgkqhkiG9w0BAQsFAASC
# AgBeb8mU9MfHZcIvmaC4RKcUTNwHefB24jQlyZKNipde8cNl+AnmQmv66ovy8nxI
# tyIVmsZYEIenslAFzD/EO+1Nl2+IRRSHjom4KxYUqwnVa6CXYvP5Fsz6LchyME+U
# PVWpfYEAkPh89k/zCuPsasX8u7KGd5h9JI3ScxiWVsx7rkYRiqdLQ08RwnugSVa3
# CeeuooVrpSCx5WlkdhxGpN26LJCLgk8SAmhI0kZrnukHGek08plVLqPTJSIZ++4l
# NLBXEpPiGF3lVap/wpSzZy/LLx8kPai0D+rUvm1b6lOjBLq5s0XeCQd0KgvnSIGc
# qvOb6IcwJxJN2+uOZz2kJK67ILs9v2l/BvnQnc2ujTW0oZlX7oRb0c4o8B77mruN
# mS5Z0xPLXJ1ZJyCfIqRu1uVNm3z6RHah2fF9cM3np2xb1YDWSYBTHk3RRSOLAl7A
# p0YoVdH8TkyOTpavjIpTnoAgexP7kK111U45KS8ugL64nE7qK3UqAGcGX17RUu2M
# Xld5B7bvgIQaexgCSrmrMDLCpwkTcFY15C7psA+msW+fU+LgEIm5ZM5sTiGLwux0
# TCimBpV50kxtRjSvFwxeNGcOMf6EiPubRfEYHCZGQO9b0W/5myHKoXswPAfvqH+f
# tp8Gc1e2+fJNpmfQYjVldPp2YOBDdoj1H8erR3AvcAaeHw==
# SIG # End signature block
