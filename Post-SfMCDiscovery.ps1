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