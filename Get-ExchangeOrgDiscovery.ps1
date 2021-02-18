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
VERSION 2.0
#>
param( [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$creds)
function Write-Log {
    param( [string]$Message, [string]$Cmdlet )
    [pscustomobject]@{
        Time = (Get-Date -f o)
        Cmdlet = $Cmdlet
        Message = $Message
    } | Export-Csv -Path "$outputPath\$ServerName-LogFile.csv" -Append -NoTypeInformation
 }
function Get-OrgData {
	foreach ($h in $hash.GetEnumerator()) {
		$Result = $null
        $CommandName = $h.Name 
		$Command = $h.Value
        $Error.Clear()
        Write-Log -Message $Command -Cmdlet $CommandName
        try{$Result = Invoke-Expression $h.Value}
        catch{Write-Log -Message $Error.Exception.ErrorRecord -Cmdlet $CommandName}
		if($Result -ne $null) {	$Result | Export-Csv $outputPath\$orgName-$CommandName.csv -NoTypeInformation -Force}
	}
}
function Zip-CsvResults {
	## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    try {[System.IO.Compression.ZipFile]::CreateFromDirectory($outputPath, $zipFolder)}
    catch {
        try{Remove-Item -Path $zipFolder -Force -ErrorAction Stop}
        catch{Write-Warning "Failed to remove file."}
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'update')
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        Get-ChildItem -Path $outputPath | Select FullName | ForEach-Object {
            try{[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipFile, $_.FullName, (Split-Path $_.FullName -Leaf), $compressionLevel) | Out-Null }
            catch {Write-Warning "failed to add"}
        }
        $zipFile.Dispose()
    }
}
$ServerName = $env:COMPUTERNAME
## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Org Settings"
if(!(Test-Path $outputPath)) {New-Item -Path $outputPath -ItemType Directory | Out-Null}
## Remove any previous data
else {Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force }
## Create a remote PowerShell session with this server
[string]$orgName = (Get-OrganizationConfig).Name
Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $orgName*.zip | Remove-Item -Confirm:$False
Set-ADServerSettings -ViewEntireForest:$True
## Data collection starts
$hash = @{
'ExchangeServer' = 'Get-ExchangeServer -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Transport settings
'AcceptedDomain' = 'Get-AcceptedDomain -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'RemoteDomain' = 'Get-RemoteDomain -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'TransportConfig' = 'Get-TransportConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'TransportRule' = 'Get-TransportRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'TransportRuleAction' = 'Get-TransportRuleAction -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'TransportRulePredicate' = 'Get-TransportRulePredicate -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'JournalRule' = 'Get-JournalRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'DeliveryAgentConnector' = 'Get-DeliveryAgentConnector -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'EmailAddressPolicy' = 'Get-EmailAddressPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'SendConnector' = 'Get-SendConnector -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'EdgeSubscription' = 'Get-EdgeSubscription -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'EdgeSyncServiceConfig' = 'Get-EdgeSyncServiceConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Client access settings
'ActiveSyncOrganizationSettings' = 'Get-ActiveSyncOrganizationSettings -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'MobileDeviceMailboxPolicy' = 'Get-MobileDeviceMailboxPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ActiveSyncDeviceAccessRule' = 'Get-ActiveSyncDeviceAccessRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ActiveSyncDeviceAutoblockThreshold' = 'Get-ActiveSyncDeviceAutoblockThreshold -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ClientAccessArray' = 'Get-ClientAccessArray -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'OwaMailboxPolicy' = 'Get-OwaMailboxPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ThrottlingPolicy' = 'Get-ThrottlingPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'IRMConfiguration' = 'Get-IRMConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'OutlookProtectionRule' = 'Get-OutlookProtectionRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'OutlookProvider' = 'Get-OutlookProvider -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ClientAccessRule' = 'Get-ClientAccessRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Mailbox server settings
'RetentionPolicyTag' = 'Get-RetentionPolicyTag -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'RetentionPolicy' = 'Get-RetentionPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'SiteMailbox' = 'Get-SiteMailbox -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Address book settings
'AddressBookPolicy' = 'Get-AddressBookPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'GlobalAddressList' = 'Get-GlobalAddressList -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'AddressList' = 'Get-AddressList -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'OfflineAddressBook' = 'Get-OfflineAddressBook -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Administration settings
'AdminAuditLogConfig' = 'Get-AdminAuditLogConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ManagementRole' = 'Get-ManagementRole -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ManagementRoleEntry' = 'Get-ManagementRoleEntry "*\*" -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ManagementRoleAssignment' = 'Get-ManagementRoleAssignment -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'RoleGroup' = 'Get-RoleGroup -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'ManagementScope' = 'Get-ManagementScope -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'RoleAssignmentPolicy' = 'Get-RoleAssignmentPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Federation settings
'FederationTrust' = 'Get-FederationTrust -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'FederatedOrganizationIdentifier' = 'Get-FederatedOrganizationIdentifier -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'SharingPolicy' = 'Get-SharingPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'OrganizationRelationship' = 'Get-OrganizationRelationship -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## Availability service
'IntraOrganizationConnector' = 'Get-IntraOrganizationConnector -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'IntraOrganizationConfiguration' = 'Get-IntraOrganizationConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'AvailabilityAddressSpace' = 'Get-AvailabilityAddressSpace -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'AvailabilityConfig' = 'Get-AvailabilityConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## General settings
'OrganizationConfig' = 'Get-OrganizationConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'AuthConfig' = 'Get-AuthConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'AuthServer' = 'Get-AuthServer -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'HybridConfiguration' = 'Get-HybridConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'MigrationEndpoint' = 'Get-MigrationEndpoint -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'PartnerApplication' = 'Get-PartnerApplication -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'PolicyTipConfig' = ' Get-PolicyTipConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'RMSTemplate' = 'Get-RMSTemplate -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'SmimeConfig' = 'Get-SmimeConfig | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'DlpPolicy' = 'Get-DlpPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'DlpPolicyTemplate' = 'Get-DlpPolicyTemplate -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'GlobalMonitoringOverride' = 'Get-GlobalMonitoringOverride -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'DomainController' = 'Get-DomainController | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
## AD settings
'ADSite' = 'Get-ADSite -WarningAction Ignore -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'AdSiteLink' = 'Get-AdSiteLink -WarningAction Ignore -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
}
Get-OrgData
Write-Log -Message "Attempting to zip results" -Cmdlet "ZipCsvResults"
$ts = Get-Date -f yyyyMMddHHmmss
[string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$orgName-OrgSettings-$ts.zip"
## Zip the results and sent to the location where the script was started
Zip-CsvResults
$zipReady = $false
$zipAttempt = 1
while($zipReady -eq $false) {
    if(Get-Item -Path $zipFolder -ErrorAction Ignore) { $zipReady = $true }
    else {
        Start-Sleep -Seconds 10
        if($zipAttempt -lt 4) { $zipReady = $true }
        else {
            Zip-CsvResults
            $zipAttempt++
        }
    }
}
## Cleanup
Remove-PSSession -Name SfMCOrgDis -ErrorAction Ignore | Out-Null