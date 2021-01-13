param(
    [Parameter(Mandatory=$true)] [string]$UserPrincipalName,
    [Parameter(Mandatory=$false)] [string]$OutputPath,
    [Parameter(Mandatory=$false)] $SessionOptions
    )
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
Write-Host -ForegroundColor Cyan " The SfMC EXO Discovery process is about to begin gathering data. "
Write-host -ForegroundColor Cyan " It may take some time to complete depending on the environment. "
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Start-Sleep -Seconds 2
## Set a timer
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()
Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow -NoNewline
try { Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -PSSessionOption $SessionOptions -ShowBanner:$False}
catch { Write-Host "FAILED"
    Write-Warning "The ExchangeOnlineManagement module is required to run this script."
    Start-Sleep -Seconds 3
    Write-Host " "
    write-host "Please install the module using 'Install-Module -Name ExchangeOnlineManagement'." -ForegroundColor Cyan
    Write-Host "Then add the module using 'Import-Module ExchangeOnlineManagement'." -ForegroundColor Cyan
    Write-Host " "
    Write-host " "
    Write-Host "For more information about the Exchange Online PowerShell V2 Module go to:" -ForegroundColor Cyan
    Write-Host "https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2" -ForegroundColor Cyan
    break
}
Write-Host "COMPLETE"
if($OutputPath -like $null) {
    Add-Type -AssemblyName System.Windows.Forms
    Write-Host "Select the location where to save the data." -ForegroundColor Yellow
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location where to save the data"
    $folderBrowser.SelectedPath = "C:\"
    $folderPath = $folderBrowser.ShowDialog()
    [string]$OutputPath = $folderBrowser.SelectedPath
}
else {
    if($OutputPath.Substring($OutputPath.Length-1,1) -eq "\") {$OutputPath = $OutputPath.Substring(0,$OutputPath.Length-1)}
}
[string]$orgName = (Get-OrganizationConfig).Name
$orgName = $orgName.Substring(0, $orgName.IndexOf("."))
$wAction = $WarningPreference
$eAction = $ErrorActionPreference
$WarningPreference = "Ignore"
$ErrorActionPreference = "Ignore"
## Connect to Exchange Online and collect data
Write-Host "Collecting data from Exchange Online..." -ForegroundColor Yellow -NoNewline
Get-AcceptedDomain | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AcceptedDomain.csv -NoTypeInformation
Get-ActiveSyncDeviceAccessRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ActiveSyncDeviceAccessRule.csv -NoTypeInformation
Get-ActiveSyncOrganizationSettings | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ActiveSyncOrganizationSettings.csv -NoTypeInformation
Get-AddressBookPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AddressBookPolicy.csv -NoTypeInformation
Get-AdminAuditLogConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AdminAuditLogConfig.csv -NoTypeInformation
Get-App | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-App.csv -NoTypeInformation
Get-AuthenticationPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuthenticationPolicy.csv -NoTypeInformation
Get-AuthServer | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuthServer.csv -NoTypeInformation
Get-AvailabilityAddressSpace | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AvailabilityAddressSpace.csv -NoTypeInformation
Get-AvailabilityConfig -WarningVariable Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AvailabilityConfig.csv -NoTypeInformation
Get-CASMailboxPlan | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-CASMailboxPlan.csv -NoTypeInformation
Get-ClientAccessRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ClientAccessRule.csv -NoTypeInformation
Get-EmailAddressPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EmailAddressPolicy.csv -NoTypeInformation
Get-FederatedOrganizationIdentifier | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-FederatedOrganizationIdentifier.csv -NoTypeInformation
Get-HybridMailflow | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HybridMailflow.csv -NoTypeInformation
Get-HybridMailflowDatacenterIPs | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HybridMailflowDatacenterIPs.csv -NoTypeInformation
#Get-ImapSubscription | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ImapSubscription.csv -NoTypeInformation
Get-InboundConnector | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-InboundConnector.csv -NoTypeInformation
Get-OnPremisesOrganization | Get-IntraOrganizationConfiguration -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-IntraOrganizationConfiguration.csv -NoTypeInformation
Get-IntraOrganizationConnector | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-IntraOrganizationConnector.csv -NoTypeInformation
Get-IRMConfiguration | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-IRMConfiguration.csv -NoTypeInformation
Get-JournalRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-JournalRule.csv -NoTypeInformation
Get-MailboxPlan | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MailboxPlan.csv -NoTypeInformation
Get-ManagementRole | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementRole.csv -NoTypeInformation
Get-ManagementRoleAssignment | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementRoleAssignment.csv -NoTypeInformation
Get-ManagementRoleEntry *\* | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementRoleEntry.csv -NoTypeInformation
Get-ManagementScope | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementScope.csv -NoTypeInformation
Get-MigrationEndpoint | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MigrationEndpoint.csv -NoTypeInformation
Get-MobileDeviceMailboxPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MobileDeviceMailboxPolicy.csv -NoTypeInformation
Get-OMEConfiguration | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OMEConfiguration.csv -NoTypeInformation
Get-OnPremisesOrganization | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OnPremisesOrganization.csv -NoTypeInformation
Get-OrganizationConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OrganizationConfig.csv -NoTypeInformation
Get-OrganizationRelationship | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OrganizationRelationship.csv -NoTypeInformation
Get-OutboundConnector | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OutboundConnector.csv -NoTypeInformation
Get-OutlookProtectionRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OutlookProtectionRule.csv -NoTypeInformation
Get-OwaMailboxPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OwaMailboxPolicy.csv -NoTypeInformation
Get-PartnerApplication | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PartnerApplication.csv -NoTypeInformation
Get-PerimeterConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PerimeterConfig.csv -NoTypeInformation
#Get-PopSubscription | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PopSubscription.csv -NoTypeInformation
Get-RemoteDomain | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RemoteDomain.csv -NoTypeInformation
Get-ResourceConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ResourceConfig.csv -NoTypeInformation
Get-RetentionPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RetentionPolicy.csv -NoTypeInformation
Get-RetentionPolicyTag | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RetentionPolicyTag.csv -NoTypeInformation
Get-RoleAssignmentPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RoleAssignmentPolicy.csv -NoTypeInformation
Get-RoleGroup | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RoleGroup.csv -NoTypeInformation
Get-SharingPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SharingPolicy.csv -NoTypeInformation
Get-SmimeConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SmimeConfig.csv -NoTypeInformation
Get-TransportConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportConfig.csv -NoTypeInformation
Get-TransportRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportRule.csv -NoTypeInformation
Get-TransportRuleAction | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportRuleAction.csv -NoTypeInformation
Get-TransportRulePredicate | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportRulePredicate.csv -NoTypeInformation
Get-AntiPhishPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AntiPhishPolicy.csv -NoTypeInformation
Get-AntiPhishRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AntiPhishRule.csv -NoTypeInformation
Get-AtpPolicyForO365 | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AtpPolicyForO365.csv -NoTypeInformation
Get-ATPProtectionPolicyRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ATPProtectionPolicyRule.csv -NoTypeInformation
Get-AuditConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuditConfig.csv -NoTypeInformation
Get-AuditConfigurationPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuditConfigurationPolicy.csv -NoTypeInformation
Get-AuditConfigurationRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuditConfigurationRule.csv -NoTypeInformation
Get-BlockedSenderAddress | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-BlockedSenderAddress.csv -NoTypeInformation
Get-ClassificationRuleCollection | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ClassificationRuleCollection.csv -NoTypeInformation
Get-CompliancePolicyFileSyncNotification | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-CompliancePolicyFileSyncNotification.csv -NoTypeInformation
Get-CompliancePolicySyncNotification | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-CompliancePolicySyncNotification.csv -NoTypeInformation
Get-ComplianceTag | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ComplianceTag.csv -NoTypeInformation
Get-ComplianceTagStorage | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ComplianceTagStorage.csv -NoTypeInformation
Get-CustomizedUserSubmission | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-CustomizedUserSubmission.csv -NoTypeInformation
Get-DataClassification | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DataClassification.csv -NoTypeInformation
Get-DataClassificationConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DataClassificationConfig.csv -NoTypeInformation
Get-DataEncryptionPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DataEncryptionPolicy.csv -NoTypeInformation
Get-DkimSigningConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DkimSigningConfig.csv -NoTypeInformation
Get-DlpPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpPolicy.csv -NoTypeInformation
Get-DlpPolicyTemplate | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpPolicyTemplate.csv -NoTypeInformation
Get-ElevatedAccessApprovalPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ElevatedAccessApprovalPolicy.csv -NoTypeInformation
Get-ElevatedAccessAuthorization | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ElevatedAccessAuthorization.csv -NoTypeInformation
Get-EOPProtectionPolicyRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EOPProtectionPolicyRule.csv -NoTypeInformation
Get-HostedConnectionFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedConnectionFilterPolicy.csv -NoTypeInformation
Get-HostedContentFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedContentFilterPolicy.csv -NoTypeInformation
Get-HostedContentFilterRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedContentFilterRule.csv -NoTypeInformation
Get-HostedOutboundSpamFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedOutboundSpamFilterPolicy.csv -NoTypeInformation
Get-HostedOutboundSpamFilterRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedOutboundSpamFilterRule.csv -NoTypeInformation
Get-MalwareFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MalwareFilterPolicy.csv -NoTypeInformation
Get-MalwareFilterRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MalwareFilterRule.csv -NoTypeInformation
Get-PhishFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PhishFilterPolicy.csv -NoTypeInformation
Get-PolicyConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PolicyConfig.csv -NoTypeInformation
Get-PolicyTipConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PolicyTipConfig.csv -NoTypeInformation
Get-RMSTemplate | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RMSTemplate.csv -NoTypeInformation
Get-ReportSubmissionPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ReportSubmissionPolicy.csv -NoTypeInformation
Get-SafeAttachmentPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SafeAttachmentPolicy.csv -NoTypeInformation
Get-SafeAttachmentRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SafeAttachmentRule.csv -NoTypeInformation
Get-SafeLinksPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SafeLinksPolicy.csv -NoTypeInformation
Get-SafeLinksRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SafeLinksRule.csv -NoTypeInformation
Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore | Out-Null
## Connect to Exchange Online Protection
try { Connect-IPPSSession -Credential -UserPrincipalName $UserPrincipalName -PSSessionOption $SessionOptions -ShowBanner:$False}
catch { Write-Warning "Failed to connect to Exchange Online Protection PowerShell." }
Get-DlpKeywordDictionary | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpKeywordDictionary.csv -NoTypeInformation
Get-DlpSensitiveInformationTypeConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpSensitiveInformationTypeConfig.csv -NoTypeInformation
Get-DlpSensitiveInformationTypeRulePackage | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpSensitiveInformationTypeRulePackage.csv -NoTypeInformation
Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore | Out-Null
Write-Host "COMPLETE"
$WarningPreference = $wAction
$ErrorActionPreference = $eAction
$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
if(Test-Path "$OutputPath\$orgName.zip") {Remove-Item -Path "$OutputPath\$orgName.zip" -Force}
Write-Host "Creating zip file with the results..." -ForegroundColor Yellow -NoNewline
Get-ChildItem -Path $OutputPath -Filter "$orgName*.csv" | Select-Object FullName | ForEach-Object { Compress-Archive -DestinationPath "$OutputPath\$orgName.zip" -Path $_.FullName -Update }
Get-ChildItem -Path $OutputPath -Filter "$orgName*.csv" | Remove-Item -Confirm:$False -Force
Write-Host "COMPLETE"
Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC EXO Discovery data collection has finished!"
Write-Host -ForegroundColor Cyan "          Total collection time: $($totalTime) seconds"
Write-Host -ForegroundColor Cyan "    Please upload results to SfMC. - Thank you!!!"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "
