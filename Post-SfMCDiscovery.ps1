## Work with discovery data
Clear-Host
Add-Type -AssemblyName System.Windows.Forms
Write-Host "Select the location where the data resides." -ForegroundColor Yellow
$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$folderBrowser.Description = "Select the location where the data resides"
$folderBrowser.SelectedPath = "C:\Hyper-V"
$folderPath = $folderBrowser.ShowDialog()
$dataPath = $folderBrowser.SelectedPath
[string]$outputPath = $dataPath + "\Results"
if(-not(Test-Path $outputPath)) { New-Item -Path $outputPath -ItemType Directory -Force -ErrorAction Ignore | Out-Null}
Get-ChildItem -Path $dataPath -Filter *.zip | Select FullName,Name | ForEach-Object { 
    $serverName = $_.Name.Substring(0,$_.Name.IndexOf("-Settings"))
    $serverPath = $null
    $serverPath = "$outputPath\$serverName"
    Expand-Archive -Path $_.FullName -DestinationPath $serverPath -ErrorAction Ignore
}
Get-ChildItem $outputPath -Filter *DagInfo.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\DAGinfo.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *AdSite.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\AdSite.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *AdSiteLink.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\AdSiteLink.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ArbitrationMailbox.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ArbitrationMailboxes.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *AutoDVDir.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\AutoDVDir.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ClientAccessServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ClientAccessServer.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *DagNetwork.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\DagNetwork.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *EasVDir.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\EasVDir.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *EcpVDir.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\EcpVDir.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *EwsVDir.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\EwsVDir.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ExchangeCertificate.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ExchangeCertificate.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ImapSettings.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ImapSettings.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MailboxDatabase.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\MailboxDatabases.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MailboxServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\MailboxServers.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MapiVDir.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\MapiVDir.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OabVDir.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OabVDir.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OutlookAnywhere.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OutlookAnywhere.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OwaVDir.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OWAVDirs.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *PopSettings.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\PopSettings.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *PShellVDir.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\PShellVDir.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *PublicFolderDatabase.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\PublicFolderDatabases.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *PublicFolderMailbox.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\PublicFolderMailboxes.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ReceiveConnector.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ReceiveConnectors.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *RpcClientAccess.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\RpcClientAccess.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *TransportAgent.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\TransportAgent.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *TransportPipeline.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\TransportPipeline.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *TransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\TransportService.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ExchangeServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ExchangeServers.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Partition.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Partition.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Disk.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Disk.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *EventLogLevel.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\EventLogLevel.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *HealthReport.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\HealthReport.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ServerComponentState.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ServerComponentState.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ServerHealth.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ServerHealth.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ServerMonitoringOverride.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ServerMonitoringOverride.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MailboxTransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\MailboxTransportService.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *FrontendTransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\FrontendTransportService.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *DagConfiguration.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\DagConfiguration.csv -NoTypeInformation -Append