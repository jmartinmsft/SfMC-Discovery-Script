param( [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$creds,
[string]$destPath
)
function Zip-CsvResults {
	## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    $date1 = Get-Date -UFormat "%d%b%Y"
    [string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$orgName-Settings-$date1.zip"
    Remove-Item $zipFolder -Force -ErrorAction Ignore
    Set-Location $outputPath
    [system.io.compression.zipfile]::CreateFromDirectory($outputPath, $zipFolder)
    return $zipFolder
}
$ServerName = $env:COMPUTERNAME
## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Org Settings"
if(!(Test-Path $outputPath)) {New-Item -Path $outputPath -ItemType Directory | Out-Null}
## Remove any previous data
else {Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force }
## Create a remote PowerShell session with this server
Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ServerName/Powershell -AllowRedirection -Authentication Kerberos -Credential $creds -Name SfMC2 -WarningAction Ignore) -WarningAction Ignore -DisableNameChecking | Out-Null
[string]$orgName = (Get-OrganizationConfig).Name
Set-ADServerSettings -ViewEntireForest:$True
## Data collection starts
## Transport settings
Get-AcceptedDomain -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AcceptedDomain.csv -NoTypeInformation
Get-RemoteDomain -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RemoteDomain.csv -NoTypeInformation
Get-TransportConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportConfig.csv -NoTypeInformation
Get-TransportRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportRule.csv -NoTypeInformation
Get-TransportRuleAction -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportRuleAction.csv -NoTypeInformation
Get-TransportRulePredicate -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportRulePredicate.csv -NoTypeInformation
Get-JournalRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-JournalRule.csv -NoTypeInformation
Get-DeliveryAgentConnector -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DeliveryAgentConnector.csv -NoTypeInformation
Get-EmailAddressPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EmailAddressPolicy.csv -NoTypeInformation
Get-SendConnector -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SendConnector.csv -NoTypeInformation
Get-EdgeSubscription -WarningAction SilentlyContinue | Export-Csv $outputPath\$orgName-EdgeSubscription.csv -NoTypeInformation
Get-EdgeSyncServiceConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EdgeSyncServiceConfig.csv -NoTypeInformation
## Client access settings
Get-ActiveSyncOrganizationSettings -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EasOrganizationSettings.csv -NoTypeInformation
Get-MobileDeviceMailboxPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EasDeviceMailboxPolicy.csv -NoTypeInformation
Get-ActiveSyncDeviceAccessRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EasDeviceAccessRule.csv -NoTypeInformation
Get-ActiveSyncDeviceAutoblockThreshold -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EasDDeviceAutoblockThreshold.csv -NoTypeInformation
Get-ClientAccessArray -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ClientAccessArray.csv -NoTypeInformation
Get-OwaMailboxPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OwaMailboxPolicy.csv -NoTypeInformation
Get-ThrottlingPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ThrottlingPolicy.csv -NoTypeInformation
Get-IRMConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-IRMConfiguration.csv -NoTypeInformation
Get-OutlookProtectionRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OutlookProtectionRule.csv -NoTypeInformation
Get-OutlookProvider -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OutlookProvider.csv -NoTypeInformation
Get-ClientAccessRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ClientAccessRule.csv -NoTypeInformation
## Mailbox server settings
Get-RetentionPolicyTag -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RetentionPolicyTag.csv -NoTypeInformation
Get-RetentionPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RetentionPolicy.csv -NoTypeInformation
Get-SiteMailbox -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SiteMailbox.csv -NoTypeInformation
## Address book settings
Get-AddressBookPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AddressBookPolicy.csv -NoTypeInformation
Get-GlobalAddressList -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-GlobalAddressList.csv -NoTypeInformation
Get-AddressList -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AddressList.csv -NoTypeInformation
Get-OfflineAddressBook -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OfflineAddressBook.csv -NoTypeInformation
## Administration settings
Get-AdminAuditLogConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AdminAuditLogConfig.csv -NoTypeInformation
Get-ManagementRole -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementRole.csv -NoTypeInformation
Get-ManagementRoleEntry "*\*" -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementRoleEntry.csv -NoTypeInformation
Get-ManagementRoleAssignment -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementRoleAssignment.csv -NoTypeInformation
Get-RoleGroup -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RoleGroup.csv -NoTypeInformation
Get-ManagementScope -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementScope.csv -NoTypeInformation
Get-RoleAssignmentPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RoleAssignmentPolicy.csv -NoTypeInformation
## Federation settings
Get-FederationTrust -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-FederationTrust.csv -NoTypeInformation
Get-FederatedOrganizationIdentifier -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-FederatedOrganizationIdentifier.csv -NoTypeInformation
Get-SharingPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SharingPolicy.csv -NoTypeInformation
Get-OrganizationRelationship -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OrganizationRelationship.csv -NoTypeInformation
## Availability service
Get-IntraOrganizationConnector -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-IntraOrgConnector.csv -NoTypeInformation
Get-IntraOrganizationConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-IntraOrgConfiguration.csv -NoTypeInformation
Get-AvailabilityAddressSpace -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AvailabilityAddressSpace.csv -NoTypeInformation
Get-AvailabilityConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AvailabilityConfig.csv -NoTypeInformation
## General settings
Get-OrganizationConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OrganizationConfig.csv -NoTypeInformation
Get-AuthConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuthConfig.csv -NoTypeInformation
Get-AuthServer -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuthServer.csv -NoTypeInformation
Get-HybridConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HybridConfiguration.csv -NoTypeInformation
Get-MigrationEndpoint -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MigrationEndpoint.csv -NoTypeInformation
Get-PartnerApplication -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PartnerApplication.csv -NoTypeInformation
Get-PolicyTipConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PolicyTipConfig.csv -NoTypeInformation
Get-RMSTemplate -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RmsTemplate.csv -NoTypeInformation
Get-SmimeConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SmimeConfig.csv -NoTypeInformation
Get-DlpPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpPolicy.csv -NoTypeInformation
Get-DlpPolicyTemplate -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpPolicyTemplate.csv -NoTypeInformation
Get-GlobalMonitoringOverride -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-GlobalMonitoringOverride.csv -NoTypeInformation
Get-DomainController | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DomainController.csv -NoTypeInformation
## Zip the results and sent to the location where the script was started
New-PSDrive -Name "SfMC2" -PSProvider FileSystem -Root $destPath -Credential $creds | Out-Null
[string]$serverResults = Zip-CsvResults
Move-Item -Path $serverResults -Destination "SfMC2:\" -Force
## Cleanup
Remove-PSDrive -Name "SfMC2" -Force | Out-Null
Remove-PSSession -Name SfMC2 -ErrorAction Ignore | Out-Null