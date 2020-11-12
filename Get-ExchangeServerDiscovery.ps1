param( [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$creds,
[string]$destPath,
[string]$sPath
)
 function Zip-CsvResults {
     param( [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credentials,
        [string]$Destination
    )
	## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    $ts = Get-Date -f yyyyMMddHHmmss
    [string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$ServerName-Settings-$ts.zip"
    Get-ChildItem "$env:ExchangeInstallPath\Logging\SfMC Discovery\*.zip" | Remove-Item -Force -ErrorAction Ignore
    ## Attempt to zip the results
    try {[System.IO.Compression.ZipFile]::CreateFromDirectory($outputPath, $zipFolder)}
    catch {
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'create')
        $zipFile.Dispose()
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'update')
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        Get-ChildItem -Path $outputPath | Select FullName | ForEach-Object {
            try{ [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipFile, $_.FullName, (Split-Path $_.FullName -Leaf), $compressionLevel) | Out-Null 
            }
	        catch{Write-warning "failed to add"}
        }
        $zipFile.Dispose()
    }
    ## Send data back to collection system
    New-PSDrive -Name "SfMC" -PSProvider FileSystem -Root $Destination -Credential $Credentials | Out-Null
    $resultsSent = $false
    [int]$retryAttempt = 0
    while($resultsSent -eq $false) {
        Copy-Item -Path $zipFolder -Destination "SfMC:\" -Force
        if(Test-Path "SfMC:\$ServerName-Settings-$date1.zip") {$resultsSent = $true}
        else {Start-Sleep -Seconds 3; $retryAttempt++}
        if($retryAttempt -eq 4) { Write-Error -Message "Unable to move results" }
    }
    ## Clean up
    Remove-PSDrive -Name "SfMC" -Force | Out-Null
}
$ServerName = $env:COMPUTERNAME
## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings"
if(!(Test-Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory | Out-Null
}
else {Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force }
## Create a remote PowerShell session with this server
Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ServerName/Powershell -AllowRedirection -Authentication Kerberos -Credential $creds -Name SfMC -WarningAction Ignore) -WarningAction Ignore -DisableNameChecking | Out-Null
## Data collection starts
## General information
Get-ExchangeServer $ServerName -Status | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-ExchangeServer.csv" -NoTypeInformation
Get-ExchangeCertificate -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-ExchangeCertificate.csv" -NoTypeInformation
Get-Disk | where {$_.Number -notlike $null} | ForEach-Object { Get-Partition -DiskNumber $_.Number | Select * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-Partition.csv" -NoTypeInformation}
Get-Disk | where {$_.Number -notlike $null} | Select * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-Disk.csv" -NoTypeInformation
Get-EventLogLevel -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-EventLogLevel.csv" -NoTypeInformation
Get-HealthReport * -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-HealthReport.csv" -NoTypeInformation
Get-ServerComponentState $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-ServerComponentState.csv" -NoTypeInformation
Get-ServerHealth $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-ServerHealth.csv" -NoTypeInformation
Get-ServerMonitoringOverride $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-ServerMonitoringOverride.csv" -NoTypeInformation
## Client access settings
Get-AutodiscoverVirtualDirectory -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-AutoDVDir.csv" -NoTypeInformation
Get-ClientAccessServer $ServerName -WarningAction Ignore -IncludeAlternateServiceAccountCredentialStatus | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-ClientAccessServer.csv" -NoTypeInformation
Get-EcpVirtualDirectory -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-EcpVDir.csv" -NoTypeInformation
Get-WebServicesVirtualDirectory  -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-EwsVDir.csv" -NoTypeInformation
Get-MapiVirtualDirectory -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-MapiVDir.csv" -NoTypeInformation
Get-ActiveSyncVirtualDirectory -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-EasVDir.csv" -NoTypeInformation
Get-OabVirtualDirectory -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-OabVDir.csv" -NoTypeInformation
Get-OwaVirtualDirectory -Server $ServerName -WarningAction Ignore| Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-OwaVDir.csv" -NoTypeInformation
Get-OutlookAnywhere -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-OutlookAnywhere.csv" -NoTypeInformation
Get-PowerShellVirtualDirectory -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-PShellVDir.csv" -NoTypeInformation
Get-RpcClientAccess -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-RpcClientAccess.csv" -NoTypeInformation
## Transport settings
Get-ReceiveConnector -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-ReceiveConnector.csv" -NoTypeInformation
Get-ImapSettings -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-ImapSettings.csv" -NoTypeInformation
Get-PopSettings -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-PopSettings.csv" -NoTypeInformation
Get-TransportAgent -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-TransportAgent.csv" -NoTypeInformation
Get-TransportService $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-TransportService.csv" -NoTypeInformation
Get-MailboxTransportService -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-MailboxTransportService.csv" -NoTypeInformation
Get-FrontendTransportService $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-FrontendTransportService.csv" -NoTypeInformation
Get-TransportPipeline -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-TransportPipeline.csv" -NoTypeInformation
## Mailbox settings
if((Get-Cluster -ErrorAction Ignore -WarningAction Ignore).Name.Length -gt 0) {
    Get-DatabaseAvailabilityGroup (Get-Cluster).Name -Status -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-DagInfo.csv" -NoTypeInformation
    Get-DatabaseAvailabilityGroupNetwork -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-DagNetwork.csv" -NoTypeInformation
    Get-DatabaseAvailabilityGroupConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-DagConfiguration.csv" -NoTypeInformation
}
Get-MailboxDatabase -Server $ServerName -WarningAction Ignore -Status | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-MailboxDatabase.csv" -NoTypeInformation
Get-MailboxServer $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-MailboxServer.csv" -NoTypeInformation
Get-PublicFolderDatabase -Server $ServerName -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-PublicFolderDatabase.csv" -NoTypeInformation
Get-Mailbox -Server $ServerName -WarningAction Ignore -PublicFolder | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-PublicFolderMailbox.csv" -NoTypeInformation
Get-Mailbox -Server $ServerName -WarningAction Ignore -Arbitration| Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-ArbitrationMailbox.csv" -NoTypeInformation
## AD settings
Get-ADSite -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-AdSite.csv" -NoTypeInformation
Get-AdSiteLink -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv "$outputPath\$ServerName-AdSiteLink.csv" -NoTypeInformation
Zip-CsvResults -Destination $destPath -Credentials $creds
## Clean up
Remove-PSSession -Name SfMC -ErrorAction Ignore | Out-Null