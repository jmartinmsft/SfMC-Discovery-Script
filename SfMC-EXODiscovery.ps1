<#//***********************************************************************
//
// SfMC-EXODiscovery.ps1
// Modified 10 August 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v1.1
//Syntax for running this script:
//
// .\SfMC-EXODiscovery.ps1 -UserPrincipalName admin@contoso.com -OutputPath C:\Temp\Results
//
//.NOTES
// 1.1 Updated EOP data collection
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
    [Parameter(Mandatory=$true)] [string]$UserPrincipalName,
    [Parameter(Mandatory=$false)] [string]$OutputPath,
    [Parameter(Mandatory=$false)] $SessionOptions
)
Clear-Host
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
Start-Sleep -Seconds 2
function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    }
    else {
        return $false
    }
}
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
try { 
    Connect-IPPSSession -Credential -UserPrincipalName $UserPrincipalName -PSSessionOption $SessionOptions -ShowBanner:$False
    Get-DlpKeywordDictionary | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpKeywordDictionary.csv -NoTypeInformation
    Get-DlpSensitiveInformationTypeConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpSensitiveInformationTypeConfig.csv -NoTypeInformation
    Get-DlpSensitiveInformationTypeRulePackage | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpSensitiveInformationTypeRulePackage.csv -NoTypeInformation
    Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore | Out-Null
}
catch { Write-Warning "Failed to connect to Exchange Online Protection PowerShell." }
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

# SIG # Begin signature block
# MIInsQYJKoZIhvcNAQcCoIInojCCJ54CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAFwpuQQYrgCgUH
# T40CVT8tUCL+qR46b876AHHn4fu/SaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGZEwghmNAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPgLwy6v8w3hUeTMtR/uKiC3
# YyC05uuH0cQDXyeqIwjYMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQC1i97TkZSX2TcmHeLfwWw2x7FfRyVVm3PS0GRpBX4Z7wUYJdD36vOT
# 0NpHAgjN/3nbpB/WsAqqUlpTu1rEyVNlf3mRB+jBsQF7m8IXDgc47gAxiLSmoZr3
# 9Qa6HRmhQPk5pBhFGbjY/rOe3RAzpbcQ9Jr0vuxQZv/YW8lVwTawJqDQQ1jRInT1
# HDCzLkKJNnjB3E2GlyYSbPFFeo9PzOEmhsXbRdqkcMWCJf8DGxXmN7v87myRZIoc
# nDshCCNyj4VE3B9Q+ec+kSs+cMn43G8lVFh0YTkr4GT9hzCqVxASpbaqCp0Vn7kC
# VBnXCVb8tEoMLXOLHKdTdZiscXRJd7kJoYIXGTCCFxUGCisGAQQBgjcDAwExghcF
# MIIXAQYJKoZIhvcNAQcCoIIW8jCCFu4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIEFBImI4pmp0biQIK4APzk7mZbcsVNDWSCNpm2bQML96AgZi3oid
# FHYYEzIwMjIwODEwMTgwNTE1LjA4NVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFoMIIHFDCCBPygAwIBAgITMwAAAY/zUajrWnLdzAABAAABjzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDZaFw0yMzAxMjYxOTI3NDZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmVc+/rXPFx6Fk4+CpLru
# bDrLTa3QuAHRVXuy+zsxXwkogkT0a+XWuBabwHyqj8RRiZQQvdvbOq5NRExOeHia
# CtkUsQ02ESAe9Cz+loBNtsfCq846u3otWHCJlqkvDrSr7mMBqwcRY7cfhAGfLvlp
# MSojoAnk7Rej+jcJnYxIeN34F3h9JwANY360oGYCIS7pLOosWV+bxug9uiTZYE/X
# clyYNF6XdzZ/zD/4U5pxT4MZQmzBGvDs+8cDdA/stZfj/ry+i0XUYNFPhuqc+UKk
# wm/XNHB+CDsGQl+ZS0GcbUUun4VPThHJm6mRAwL5y8zptWEIocbTeRSTmZnUa2iY
# H2EOBV7eCjx0Sdb6kLc1xdFRckDeQGR4J1yFyybuZsUP8x0dOsEEoLQuOhuKlDLQ
# Eg7D6ZxmZJnS8B03ewk/SpVLqsb66U2qyF4BwDt1uZkjEZ7finIoUgSz4B7fWLYI
# eO2OCYxIE0XvwsVop9PvTXTZtGPzzmHU753GarKyuM6oa/qaTzYvrAfUb7KYhvVQ
# KxGUPkL9+eKiM7G0qenJCFrXzZPwRWoccAR33PhNEuuzzKZFJ4DeaTCLg/8uK0Q4
# QjFRef5n4H+2KQIEibZ7zIeBX3jgsrICbzzSm0QX3SRVmZH//Aqp8YxkwcoI1WCB
# izv84z9eqwRBdQ4HYcNbQMMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBTzBuZ0a65J
# zuKhzoWb25f7NyNxvDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDNf9Oo9zyhC5n1jC8iU7NJY39FizjhxZwJbJY/
# Ytwn63plMlTSaBperan566fuRojGJSv3EwZs+RruOU2T/ZRDx4VHesLHtclE8GmM
# M1qTMaZPL8I2FrRmf5Oop4GqcxNdNECBClVZmn0KzFdPMqRa5/0R6CmgqJh0muvI
# mikgHubvohsavPEyyHQa94HD4/LNKd/YIaCKKPz9SA5fAa4phQ4Evz2auY9SUluI
# d5MK9H5cjWVwBxCvYAD+1CW9z7GshJlNjqBvWtKO6J0Aemfg6z28g7qc7G/tCtrl
# H4/y27y+stuwWXNvwdsSd1lvB4M63AuMl9Yp6au/XFknGzJPF6n/uWR6JhQvzh40
# ILgeThLmYhf8z+aDb4r2OBLG1P2B6aCTW2YQkt7TpUnzI0cKGr213CbKtGk/OOIH
# SsDOxasmeGJ+FiUJCiV15wh3aZT/VT/PkL9E4hDBAwGt49G88gSCO0x9jfdDZWdW
# GbELXlSmA3EP4eTYq7RrolY04G8fGtF0pzuZu43A29zaI9lIr5ulKRz8EoQHU6cu
# 0PxUw0B9H8cAkvQxaMumRZ/4fCbqNb4TcPkPcWOI24QYlvpbtT9p31flYElmc5wj
# GplAky/nkJcT0HZENXenxWtPvt4gcoqppeJPA3S/1D57KL3667epIr0yV290E2ot
# ZbAW8DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLXMIIC
# QAIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD5NL4IEdudIBwdGoCaV0WBbQZpqoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmnh56MCIYDzIwMjIwODEw
# MjAwOTMwWhgPMjAyMjA4MTEyMDA5MzBaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIF
# AOaeHnoCAQAwCgIBAAICAqQCAf8wBwIBAAICEV4wCgIFAOafb/oCAQAwNgYKKwYB
# BAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGG
# oDANBgkqhkiG9w0BAQUFAAOBgQCtKGkaZulMDj/335Wgdtto48nJoK3Q7Qx+Kr94
# 7icXaKbpvh7a+s/0Uaa1d1ppCEL9xzmHFJk7ZpbTVJSxoYnVy0E2KZyollpKFq3K
# fEDz/ztLPRAqOOX0YSWdLEVC0GJ8Jcyy5yuKYksaeeeEDfvkc61BceK3qw1GDG91
# pGZ6eTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABj/NRqOtact3MAAEAAAGPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG
# 9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEICw5+pE1WeN4Tisc
# ezo4vWMjqtPCuO1fdMiUItk1w3bZMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCB
# vQQgl3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAi
# BCCqCJmkf3v7/R1NZHZjsQINMMvjOE5oO5nHE5w70WWAIDANBgkqhkiG9w0BAQsF
# AASCAgBFxwvdTK+wf+9PZ88UfQMDf1A8FdUkWhoIDwyNO7t1Ae4c7D+vHOwl6nq1
# PLikE8zJ36Ng/xz7H/rRU6a1xSWzNXvpwSn8aCv5ffRG6Qi3BJg3zTKICRUUzHQe
# RJmg9rmta1hhEXKEPgODGjuiGiab9XRYjAMJNd0dM0jpXrLpV4yFXUNbGvE6qfxa
# 3uV0QmiPvBf4hnliLMbUnR5fZKA9rN2+nfmMrjecGegiY45jjml6eHK0cpi8oLLQ
# 8Mr2XQwib+BQZ2zneOqB6ZXQBR27iNCexlumn5ytgZ7Ow3oaVBUnVE0Mf846VN0X
# OHFRSAmuddS80OMylQ6w6fJiiueglGpPs03N01YI9h1NRdJBwfHqASuNEB54t2Ma
# eBmOnumoYihCsgROYaI2Vq2IRx9HvXiCtt28VoMkHoO1FqavUqRG/CcEyZjb/HrS
# nxjrq2NZhsrv/48rWp7chrHeXX7v9jlt9F5felqjwgC6Qv+SNcs+4mBJeBKfri8L
# 1QHPueYu7Ln810p5CZTxsj8prCp57OPWeAp+ZA1wj+jtn4Yk12l9g7oA8DXLsXO/
# 8p5ARurU5q/2jQoMqEADNIA8HlGvK/CXh0ZJ1Y3pNZjKyV9gwyGrFtDrEA/68AlC
# SDlNFUe2eApIAZQJaxADNvX6ftVKM1dytNXm5ir/fsSI+gksdQ==
# SIG # End signature block
