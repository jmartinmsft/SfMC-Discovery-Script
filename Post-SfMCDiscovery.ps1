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
    [Parameter(Mandatory=$false)] [string]$DiscoveryZipFile,
    [Parameter(Mandatory=$false,HelpMessage="The OutputPath parameter specifies the directory where the results are written")] [ValidateScript( {Test-Path $_})][string]$OutputPath
)

#region Disclaimer
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

$Date = (Get-Date).ToString("yyyyMMddhhmmss")
# Determine the current location which will be used to store the results
if([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = $DiscoveryZipFile.Substring(0, $DiscoveryZipFile.IndexOf("DiscoveryResults"))
}

$ScriptDisclaimer = @"
//***********************************************************************
//
// The SfMC Email Discovery process is about to begin processing data.
// It will take some time to complete depending on the customer environment.
//
//**********************************************************************​
"@
Write-Host $ScriptDisclaimer -ForegroundColor Cyan

## Set a timer
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()
Unblock-File -Path $DiscoveryZipFile -Confirm:$false
#region ExpandDiscoveryResults
try{
    $Results = Expand-Archive -Path $DiscoveryZipFile -PassThru -Confirm:$false -DestinationPath $OutputPath -Force
    $ExpandFolderPath = $Results.DirectoryName[0]
}
catch{
    Write-Host "Failed to unzip the Discovery results." -ForegroundColor Red
    exit
}
#endregion

#region ExpandOrgAndServerResults
$ServerResultsPath = New-Item -Path $ExpandFolderPath -Name ServerResults -ItemType Directory
$OrgResultsPath = New-Item -Path $ExpandFolderPath -Name OrgResults -ItemType Directory

Get-ChildItem -Path $ExpandFolderPath -Filter *.zip | ForEach-Object {
    if($_.Name -notlike "*OrgSettings*") {
        $ServerName = $_.Name.Substring(0,$_.Name.IndexOf("-Settings"))
        $ServerPath = New-Item -Path $ServerResultsPath.FullName -Name $ServerName -ItemType Directory
        try{
            Expand-Archive -Path $_.FullName -DestinationPath $ServerPath.FullName -Confirm:$false -ErrorAction Stop -Force
        }
        catch{
            Write-Warning "Unable to extract $($_.FullName)."
        }
    }
    else {
        try{
            Expand-Archive -Path $_.FullName -DestinationPath $OrgResultsPath.FullName -Confirm:$false -Force
        }
        catch{
            Write-Host "Failed to expand the organization results." -ForegroundColor Red
        }
    }
}
#endregion

Get-ChildItem -Path $ServerResultsPath.FullName -Directory | ForEach-Object {
    $CsvPath = New-Item -Path $_.FullName -Name CsvFiles -ItemType Directory
    Get-ChildItem -Path $_.FullName -Filter *.xml | ForEach-Object {
        Import-Clixml $_.FullName | Export-Csv "$($CsvPath.FullName)\$($_.BaseName).csv" -NoTypeInformation -Force
    }
}

$ScriptDisclaimer = @"
//***********************************************************************
//
// The SfMC Email Discovery is merging the CSV data.
//
//**********************************************************************​
"@
Write-Host $ScriptDisclaimer -ForegroundColor Cyan

Get-ChildItem $ServerResultsPath.FullName -Filter *ActiveSyncVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\ActiveSyncVirtualDirectory.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *AutodiscoverVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\AutodiscoverVirtualDirectory.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *Bios.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\Bios.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *ClientAccessServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\ClientAccessServer.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *ComputerSystem.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\ComputerSystem.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *CrashControl.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\CrashControl.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *Culture.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\Culture.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *DatabaseAvailabilityGroup.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv "$($ServerResultsPath.FullName)\DatabaseAvailabilityGroup.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *DatabaseAvailabilityGroupNetwork.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Identity | Export-Csv "$($ServerResultsPath.FullName)\DatabaseAvailabilityGroupNetwork.csv" -NoTypeInformation -Append -Force
Get-ChildItem $ServerResultsPath.FullName -Filter *Disk.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\Disk.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *EcpVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\EcpVirtualDirectory.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *EventLogLevel.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\EventLogLevel.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *ExchangeCertificate.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv "$($ServerResultsPath.FullName)\ExchangeCertificate.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *ExchangeServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\ExchangeServer.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *FrontendTransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\FrontendTransportService.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *HotFix.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\HotFix.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *ImapSettings.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\ImapSettings.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *LogFile.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\LogFile.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *LogicalDisk.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\LogicalDisk.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *MailboxDatabase.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv "$($ServerResultsPath.FullName)\MailboxDatabase.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *MailboxServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\MailboxServer.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *MailboxTransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\MailboxTransportService.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *MapiVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\MapiVirtualDirectory.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *Memory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\Memory.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *NetAdapter.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\NetAdapter.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *NetIPAddress.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\NetIPAddress.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *NetOffloadGlobalSetting.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\NetOffloadGlobalSetting.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *NetRoute.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\NetRoute.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *OabVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\OabVirtualDirectory.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *OperatingSystem.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\OperatingSystem.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *OutlookAnywhere.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\OutlookAnywhere.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *OwaVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\OwaVirtualDirectory.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *Partition.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\Partition.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *PopSettings.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\PopSettings.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *PowerShellVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\PowerShellVirtualDirectory.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *Processor.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\Processor.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *Product.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\Product.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *RpcClientAccess.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\RpcClientAccess.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *ReceiveConnector.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\ReceiveConnector.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *ScheduledTask.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\ScheduledTask.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *ServerComponentState.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\ServerComponentState.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *ServerHealth.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\ServerHealth.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *-Service.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\Service.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *TransportAgent.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\TransportAgent.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *TransportPipeline.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\TransportPipeline.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *-TransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\TransportService.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *WebServicesVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\WebServicesVirtualDirectory.csv" -NoTypeInformation -Append
Get-ChildItem $ServerResultsPath.FullName -Filter *WindowsFeature.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$($ServerResultsPath.FullName)\WindowsFeature.csv" -NoTypeInformation -Append

$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds

$ScriptDisclaimer = @"
//***********************************************************************
//
// SfMC Email Discovery data processing has finished!"
//         Total time: $($totalTime) seconds
//
//**********************************************************************​
"@
Write-Host $ScriptDisclaimer -ForegroundColor Cyan

# SIG # Begin signature block
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAmqbMzqDOILF3Y
# h7aBBwZutlY+jq7OEL7yqt1hvlDKiqCCDXYwggX0MIID3KADAgECAhMzAAADrzBA
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGgwwghoIAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJ05hIyF+j3fkT4iGRJ2FVbv
# bkgGZSuFx0SJ4a5Coh4dMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBUpkwiBQySRdUYznPaJ/u62pBb5eE7QQeNdziGdpBmhVlK4cqjYiHv
# FubemuX3DVWOzj8AdWb+SkHfTS4CXvXYLCKN8Yq96QhU63qIuwHdWqbqqDbRoTWP
# Y6w4JM+u6FiP5c23v0gkGZp40wvewu9jblJvIy6rfZ4EOJLG0uUz4NzeEWeqxvk1
# hrY6X4KQgr4SRDwl9O90jpn1D3XNQS6aEjSYTqY+lVy0KrFwSugE9XWfR46OfdPT
# Rg2qrUTQeIAF1BZ/eHXX3y4SU1ZI8s9Z1/7Xw3t2mNnQhA4KELy39LU34B2rq2Nv
# GiLEdkd7yj0D+5CdvVE0l3Xl1xpB1olvoYIXlDCCF5AGCisGAQQBgjcDAwExgheA
# MIIXfAYJKoZIhvcNAQcCoIIXbTCCF2kCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIK1Jp7tl0v8RqavcRLM0e6TrrvxheiqHMqDckIqDQKmWAgZmRlBU
# vLUYEzIwMjQwNzA4MTYzMDA1LjU0MlowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpFMDAy
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEeowggcgMIIFCKADAgECAhMzAAAB7gXTAjCymp2nAAEAAAHuMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMTIwNjE4
# NDU0NFoXDTI1MDMwNTE4NDU0NFowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpFMDAyLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAL7xvKXXooSJrzEpLi9UvtEQ45HsvNgItcS1aB6r
# I5WWvO4TP4CgJri0EYRKNsdNcQJ4w7A/1M94popqV9NTldIaOkmGkbHn1/EwmhNh
# Y/PMPQ7ZECXIGY4EGaIsNdENAkvVG24CO8KIu6VVB6I8jxXv4eFNHf3VNsLVt5LH
# Bd90ompjWieMNrCoMkCa3CwD+CapeAfAX19lZzApK5eJkFNtTl9ybduGGVE3Dl3T
# gt3XllbNWX9UOn+JF6sajYiz/RbCf9rd4Y50eu9/Aht+TqVWrBs1ATXU552fa69G
# MpYTB6tcvvQ64Nny8vPGvLTIR29DyTL5V+ryZ8RdL3Ttjus38dhfpwKwLayjJcbc
# 7AK0sDujT/6Qolm46sPkdStLPeR+qAOWZbLrvPxlk+OSIMLV1hbWM3vu3mJKXlan
# UcoGnslTxGJEj69jaLVxvlfZESTDdas1b+Nuh9cSz23huB37JTyyAqf0y1WdDrmz
# pAbvYz/JpRkbYcwjfW2b2aigfb288E72MMw4i7QvDNROQhZ+WB3+8RZ9M1w9YRCP
# t+xa5KhW4ne4GrA2ZFKmZAPNJ8xojO7KzSm9XWMVaq2rDAJxpj9Zexv9rGTEH/MJ
# N0dIFQnxObeLg8z2ySK6ddj5xKofnyNaSkdtssDc5+yzt74lsyMqZN1yOZKRvmg3
# ypTXAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUEIjNPxrZ3CCevfvF37a/X9x2pggw
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBAHdnIC9rYQo5ZJWkGdiTNfx/wZmNo6zn
# vsX2jXgCeH2UrLq1LfjBeg9cTJCnW/WIjusnNlUbuulTOdrLaf1yx+fenrLuRiQe
# q1K6AIaZOKIGTCEV9IHIo8jTwySWC8m8pNlvrvfIZ+kXA+NDBl4joQ+P84C2liRP
# shReoySLUJEwkqB5jjBREJxwi6N1ZGShW/gner/zsoTSo9CYBH1+ow3GMjdkKVXE
# DjCIze01WVFsX1KCk6eNWjc/8jmnwl3jWE1JULH/yPeoztotIq0PM4RQ2z5m2OHO
# eZmBR3v8BYcOHAEd0vntMj2HueJmR85k5edxiwrEbiCvJOyFTobqwBilup0wT/7+
# DW56vtUYgdS0urdbQCebyUB9L0+q2GyRm3ngkXbwId2wWr/tdUG0WXEv8qBxDKUk
# 2eJr5qeLFQbrTJQO3cUwZIkjfjEb00ezPcGmpJa54a0mFDlk3QryO7S81WAX4O/T
# myKs+DR+1Ip/0VUQKn3ejyiAXjyOHwJP8HfaXPUPpOu6TgTNzDsTU6G04x/sMeA8
# xZ/pY51id/4dpInHtlNcImxbmg6QzSwuK3EGlKkZyPZiOc3OcKmwQ9lq3SH7p3u6
# VFpZHlEcBTIUVD2NFrspZo0Z0QtOz6cdKViNh5CkrlBJeOKB0qUtA8GVf73M6gYA
# mGhl+umOridAMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
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
# A00wggI1AgEBMIH5oYHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046RTAwMi0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# AIijptU29+UXFtRYINDdhgrLo76ToIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDqNgGJMCIYDzIwMjQwNzA4MDYx
# MTIxWhgPMjAyNDA3MDkwNjExMjFaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOo2
# AYkCAQAwBwIBAAICM04wBwIBAAICE0QwCgIFAOo3UwkCAQAwNgYKKwYBBAGEWQoE
# AjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkq
# hkiG9w0BAQsFAAOCAQEAeCwvbcm2aYSgWqcbV/dnfR7X6O6VSIEw/IuAvh5j4l9L
# GNdilJagkYk3coYlXGcuZIHjwXkz0sRDhlANzkjMVV0e2v5R5btPl8V7e0pEiFAm
# ehBxSYh8D932VtPYtYt6ZGs0jBf5tK0yoD4GGdNsQ3O5jABoj6gM/GOGAc32V2Je
# PlXINb49F/nShaTx7IW5C02mS5hshmOySEYoGsHEu67D/WbDgaRkzxWU/fvkyAZp
# OMzmM8ji9wBtXS4SGMTdrr17b4mnKJaY5wb8rwyBoHuWafm9PhdXD23Wt1wIaXim
# +6JlE1kvd59tXKJwJli8Ars/sQ6BongtNHNBLMwoEjGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB7gXTAjCymp2nAAEAAAHu
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIKCKg+60IFTfkFUin9Rf5Z+untqkbz+k7VtjDByqJapC
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgT1B3FJWF+r5V1/4M+z7kQiQH
# P2gJL85B+UeRVGF+MCEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAe4F0wIwspqdpwABAAAB7jAiBCBvJxR3ZWzDVZZPKIBuQj5VFYcA
# KfcTA3puRhxo/aAHRjANBgkqhkiG9w0BAQsFAASCAgAD9GNzQ2MllyaYae3Yu1Hl
# YHKoo3yJsHjh1nSF2Q6WDUbpHTAtMaVS7gJSrXH5vAZhBHYGd7pegBeS5KTpOC5Z
# BXWX9Eg0qaPjok1h7EkznsvxS4ApyhPJixbOWiz0XDrfiOX413Tm3g2Dl5HH3m9G
# tHPR70tpnY3U7ALl+vCO+8AMfwRwCbUU+r2NUKThv6BL81SiVru/I8l3vupy774e
# gfvqCmkjMjp/scfo7+vCfFmdCZxxPtT221w/hjS6vqLP1w18ifdLoPL6POQJ5TUr
# dCt1cq6JOOHztjkp3D1igu+7hPFA5OrwQWPDzyH4dXu8TuPcgp5EyvEqNA2HYBjy
# AODBtrkQeO1pLsqJxWz4L+bIGAadi6tLjVmgQiJPQ0aC4yPHiWDln9sauAwr45Zu
# mvjpbHd+sLjTVR1Q7ahYo7/PhI2Mp7dlqN++MgihXwIEeeqOX01FaMdUqmdaw6nN
# o6C+0lKThMeAYAaMbAGS54P7z5yt0DhHP/H3tdbeHihH1JL9SL7jAT3FJStBikCP
# XJWvNxXyVArr1ldYSmMSnN7W+qnV8hkab5Yoe9nqcPtLEyJpXLcewAvhFsG5WrBJ
# AyL751nVIbs4zjBf+i2v3/Cg3P1RybLRVfyFgCwU11qLlZRlT6xZW+eVRkxCi4Hb
# OJSyyEPV2KT07z/pmQPitw==
# SIG # End signature block
