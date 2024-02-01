<#//***********************************************************************
//
// SfMC-EXODiscovery.ps1
// Modified 28 November 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: 20231128.1454
//Syntax for running this script:
//
// .\SfMC-EXODiscovery.ps1 -UserPrincipalName admin@contoso.com -OutputPath C:\Temp\Results
//
//.NOTES
// 1.1 Updated EOP data collection
// 20230905.1418 Updated error handling and removed cmdlet requiring RPSSession
// 20231128.1454 Added inbound connector settings
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
    [Parameter(Mandatory=$true,HelpMessage="Log file - activity is logged to this file if specified")][string]$LogFile,
    [Parameter(Mandatory=$true,HelpMessage="UserPrincipalName - the user account used to connect to Exchange Online PowerShell")] [string]$UserPrincipalName,
    [Parameter(Mandatory=$false,HelpMessage="OutputPath - the location for the data collection results")] [string]$OutputPath,
    [Parameter(Mandatory=$false,HelpMessage="SessionOptions - the session options required to make an PowerShell connection to EXO")] $SessionOptions
)
#region Dislaimer
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
//**********************************************************************​
"@
Write-Host $ScriptDisclaimer -ForegroundColor Yellow
#Start-Sleep -Seconds 2
#endregion

$script:ScriptVersion = "20231128.1454"

function LogToFile([string]$Details) {
	if ( [String]::IsNullOrEmpty($LogFile) ) { return }
	"$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToLongTimeString())   $Details" | Out-File $LogFile -Append
}

function Log([string]$Details, [ConsoleColor]$Colour) {
    if ($Colour -eq $null)
    {
        $Colour = [ConsoleColor]::White
    }
    Write-Host $Details -ForegroundColor $Colour
    LogToFile $Details
}

function LogVerbose([string]$Details) {
    Write-Verbose $Details
    LogToFile $Details
}
LogVerbose "$($MyInvocation.MyCommand.Name) version $($script:ScriptVersion) starting"

function LogDebug([string]$Details) {
    Write-Debug $Details
    LogToFile $Details
}

$script:LastError = $Error[0]
function ErrorReported($Context) {
    # Check for any error, and return the result ($true means a new error has been detected)

    # We check for errors using $Error variable, as try...catch isn't reliable when remoting
    if ([String]::IsNullOrEmpty($Error[0])) { return $false }

    # We have an error, have we already reported it?
    if ($Error[0] -eq $script:LastError) { return $false }

    # New error, so log it and return $true
    $script:LastError = $Error[0]
    if ($Context)
    {
        Log "Error ($Context): $($Error[0])" Red
    }
    else
    {
        Log "Error: $($Error[0])" Red
    }
    return $true
}

function ReportError($Context) {
    # Reports error without returning the result
    ErrorReported $Context | Out-Null
}

function Invoke-ExchangeCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Cmdlet,
        [string]$Identity,
        [string]$CsvOutputPath,
        [scriptblock]$CatchActionFunction        
    )
    begin {
        $returnValue = $null
    }
    process {
        try {
            LogVerbose "Running the following Exchange cmdlet: $Cmdlet "
            if($Identity -notlike $null) {
                $returnValue = & $Cmdlet -Identity $Identity | Select-Object * -ExcludeProperty SerializationData| Export-Csv $CsvOutputPath -NoTypeInformation
            }
            else {
                $returnValue = & $Cmdlet | Select-Object * -ExcludeProperty SerializationData| Export-Csv $CsvOutputPath -NoTypeInformation
            }
        } 
        catch {}
        ReportError $Cmdlet
    }
    end {
        #Log "Exiting: $($MyInvocation.MyCommand)"
        return $returnValue
    }
}


function PowerShellRoleCheck {    
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        LogVerbose "PowerShell is running 'as Administrator'."
        return $true
    }
    else {
        LogVerbose "PowerShell is not running 'as Administrator'."
        return $false
    }
}

if(-not (PowerShellRoleCheck)) {
	Write-Warning "The SfMC-Exchange-Discovery-1.ps1 script needs to be executed in elevated mode. Please start PowerShell 'as Administrator' and try again." 
	Start-Sleep -Seconds 2;
	exit
}

$ScriptBanner = @'
===============================================================================

The SfMC EXO Discovery process is about to begin gathering data.
It may take some time to complete depending on the environment.

===============================================================================
'@
Write-Host $ScriptBanner -ForegroundColor Cyan
Start-Sleep -Seconds 2

## Set a timer
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()

#region ExoModule
try {
    $ExoModule = Get-InstalledModule -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue
}
catch {}
ReportError "GetExoModule"

if(!$ExoModule -or $ExoModule.Version -lt 3.2.0) {
    Log "Exchange Online Management module is missing or not the latest version." Yellow
    Log "Attempting to install the ExchangeOnlineManagement module." Yellow
    try {
        Install-Module -Name ExchangeOnlineManagement -MinimumVersion 3.2.0 -Force
    }
    catch {}
    $ExoModuleInstall = ReportError "InstallEXOModule"
}
if($ExoModuleInstall) {
    Write-Warning "Failed to find or install the ExchangeOnlineManagement module."
    exit
}
else {
    $ExoModule = Get-InstalledModule -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue
    LogVerbose "Using $($ExoModule.Name) version $($ExoModule.Version)"
}
#endregion

#region ConnectExo
Log "Attempting to connect to Exchange Online as $UserPrincipalName..." Yellow
try{
    Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -PSSessionOption $SessionOptions -ShowBanner:$false
}
catch{}
$ExoConnectFailed = ReportError "ConnectEXO"
if($ExoConnectFailed) {
    Log "Failed to connect to Exchange Online." Red
    exit
}
else {
    LogVerbose "Connected to Exchange Online using $UserPrincipalName."
}
#endregion

#region OutputPath
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
#endregion

#region DataCollection
[string]$orgName = (Get-OrganizationConfig).Name
Log "Starting data collection for $orgName..." Green
$orgName = $orgName.Substring(0, $orgName.IndexOf("."))
Invoke-ExchangeCmdlet -Cmdlet Get-AcceptedDomain -CsvOutputPath $outputPath\$orgName-AcceptedDomain.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ActiveSyncDeviceAccessRule -CsvOutputPath $outputPath\$orgName-ActiveSyncDeviceAccessRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ActiveSyncOrganizationSettings -CsvOutputPath $outputPath\$orgName-ActiveSyncOrganizationSettings.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AddressBookPolicy -CsvOutputPath $outputPath\$orgName-AddressBookPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AdminAuditLogConfig -CsvOutputPath $outputPath\$orgName-AdminAuditLogConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-App -CsvOutputPath $outputPath\$orgName-App.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AuthenticationPolicy -CsvOutputPath $outputPath\$orgName-AuthenticationPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AuthServer -CsvOutputPath $outputPath\$orgName-AuthServer.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AvailabilityAddressSpace -CsvOutputPath $outputPath\$orgName-AvailabilityAddressSpace.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AvailabilityConfig -CsvOutputPath $outputPath\$orgName-AvailabilityConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-CASMailboxPlan -CsvOutputPath $outputPath\$orgName-CASMailboxPlan.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ClientAccessRule -CsvOutputPath $outputPath\$orgName-ClientAccessRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-EmailAddressPolicy -CsvOutputPath $outputPath\$orgName-EmailAddressPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-FederatedOrganizationIdentifier -CsvOutputPath $outputPath\$orgName-FederatedOrganizationIdentifier.csv
Invoke-ExchangeCmdlet -Cmdlet Get-HybridMailflow -CsvOutputPath $outputPath\$orgName-HybridMailflow.csv
Invoke-ExchangeCmdlet -Cmdlet Get-HybridMailflowDatacenterIPs -CsvOutputPath $outputPath\$orgName-HybridMailflowDatacenterIPs.csv
Invoke-ExchangeCmdlet -Cmdlet Get-OnPremisesOrganization -CsvOutputPath $outputPath\$orgName-OnPremisesOrganization.csv
Invoke-ExchangeCmdlet -Cmdlet Get-IntraOrganizationConnector -CsvOutputPath $outputPath\$orgName-IntraOrganizationConnector.csv
Invoke-ExchangeCmdlet -Cmdlet Get-IRMConfiguration -CsvOutputPath $outputPath\$orgName-IRMConfiguration.csv
Invoke-ExchangeCmdlet -Cmdlet Get-JournalRule -CsvOutputPath $outputPath\$orgName-JournalRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-MailboxPlan -CsvOutputPath $outputPath\$orgName-MailboxPlan.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ManagementRole -CsvOutputPath $outputPath\$orgName-ManagementRole.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ManagementRoleAssignment -CsvOutputPath $outputPath\$orgName-ManagementRoleAssignment.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ManagementRoleEntry *\* -CsvOutputPath $outputPath\$orgName-ManagementRoleEntry.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ManagementScope -CsvOutputPath $outputPath\$orgName-ManagementScope.csv
Invoke-ExchangeCmdlet -Cmdlet Get-MigrationEndpoint -CsvOutputPath $outputPath\$orgName-MigrationEndpoint.csv
Invoke-ExchangeCmdlet -Cmdlet Get-MobileDeviceMailboxPolicy -CsvOutputPath $outputPath\$orgName-MobileDeviceMailboxPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-OMEConfiguration -CsvOutputPath $outputPath\$orgName-OMEConfiguration.csv
Invoke-ExchangeCmdlet -Cmdlet Get-OrganizationConfig -CsvOutputPath $outputPath\$orgName-OrganizationConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-OrganizationRelationship -CsvOutputPath $outputPath\$orgName-OrganizationRelationship.csv
Invoke-ExchangeCmdlet -Cmdlet Get-InboundConnector -CsvOutputPath $outputPath\$orgName-InboundConnector.csv
Invoke-ExchangeCmdlet -Cmdlet Get-OutboundConnector -CsvOutputPath $outputPath\$orgName-OutboundConnector.csv
Invoke-ExchangeCmdlet -Cmdlet Get-OutlookProtectionRule -CsvOutputPath $outputPath\$orgName-OutlookProtectionRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-OwaMailboxPolicy -CsvOutputPath $outputPath\$orgName-OwaMailboxPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-PartnerApplication -CsvOutputPath $outputPath\$orgName-PartnerApplication.csv
Invoke-ExchangeCmdlet -Cmdlet Get-PerimeterConfig -CsvOutputPath $outputPath\$orgName-PerimeterConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-RemoteDomain -CsvOutputPath $outputPath\$orgName-RemoteDomain.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ResourceConfig -CsvOutputPath $outputPath\$orgName-ResourceConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-RetentionPolicy -CsvOutputPath $outputPath\$orgName-RetentionPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-RetentionPolicyTag -CsvOutputPath $outputPath\$orgName-RetentionPolicyTag.csv
Invoke-ExchangeCmdlet -Cmdlet Get-RoleAssignmentPolicy -CsvOutputPath $outputPath\$orgName-RoleAssignmentPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-RoleGroup -CsvOutputPath $outputPath\$orgName-RoleGroup.csv
Invoke-ExchangeCmdlet -Cmdlet Get-SharingPolicy -CsvOutputPath $outputPath\$orgName-SharingPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-SmimeConfig -CsvOutputPath $outputPath\$orgName-SmimeConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-TransportConfig -CsvOutputPath $outputPath\$orgName-TransportConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-TransportRule -CsvOutputPath $outputPath\$orgName-TransportRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-TransportRuleAction -CsvOutputPath $outputPath\$orgName-TransportRuleAction.csv
Invoke-ExchangeCmdlet -Cmdlet Get-TransportRulePredicate -CsvOutputPath $outputPath\$orgName-TransportRulePredicate.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AntiPhishPolicy -CsvOutputPath $outputPath\$orgName-AntiPhishPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AntiPhishRule -CsvOutputPath $outputPath\$orgName-AntiPhishRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-PhishSimOverridePolicy -CsvOutputPath $outputPath\$orgName-PhishSimOverridePolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-PhishSimOverrideRule -CsvOutputPath $outputPath\$orgName-PhishSimOverrideRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AtpPolicyForO365 -CsvOutputPath $outputPath\$orgName-AtpPolicyForO365.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ATPProtectionPolicyRule -CsvOutputPath $outputPath\$orgName-ATPProtectionPolicyRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AdminAuditLogConfig -CsvOutputPath $outputPath\$orgName-AdminAuditLogConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AuditConfigurationPolicy -CsvOutputPath $outputPath\$orgName-AuditConfigurationPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-AuditConfigurationRule -CsvOutputPath $outputPath\$orgName-AuditConfigurationRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-BlockedSenderAddress -CsvOutputPath $outputPath\$orgName-BlockedSenderAddress.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ClassificationRuleCollection -CsvOutputPath $outputPath\$orgName-ClassificationRuleCollection.csv
Invoke-ExchangeCmdlet -Cmdlet Get-CompliancePolicyFileSyncNotification -CsvOutputPath $outputPath\$orgName-CompliancePolicyFileSyncNotification.csv
Invoke-ExchangeCmdlet -Cmdlet Get-CompliancePolicySyncNotification -CsvOutputPath $outputPath\$orgName-CompliancePolicySyncNotification.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ComplianceTag -CsvOutputPath $outputPath\$orgName-ComplianceTag.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ComplianceTagStorage -CsvOutputPath $outputPath\$orgName-ComplianceTagStorage.csv
Invoke-ExchangeCmdlet -Cmdlet Get-CustomizedUserSubmission -CsvOutputPath $outputPath\$orgName-CustomizedUserSubmission.csv
Invoke-ExchangeCmdlet -Cmdlet Get-DataClassification -CsvOutputPath $outputPath\$orgName-DataClassification.csv
Invoke-ExchangeCmdlet -Cmdlet Get-DataClassificationConfig -CsvOutputPath $outputPath\$orgName-DataClassificationConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-DataEncryptionPolicy -CsvOutputPath $outputPath\$orgName-DataEncryptionPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-DkimSigningConfig -CsvOutputPath $outputPath\$orgName-DkimSigningConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-DlpPolicy -CsvOutputPath $outputPath\$orgName-DlpPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ElevatedAccessApprovalPolicy -CsvOutputPath $outputPath\$orgName-ElevatedAccessApprovalPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ElevatedAccessAuthorization -CsvOutputPath $outputPath\$orgName-ElevatedAccessAuthorization.csv
Invoke-ExchangeCmdlet -Cmdlet Get-EOPProtectionPolicyRule -CsvOutputPath $outputPath\$orgName-EOPProtectionPolicyRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ExternalInOutlook -CsvOutputPath $outputPath\$orgName-ExternalInOutlook.csv
Invoke-ExchangeCmdlet -Cmdlet Get-HostedConnectionFilterPolicy -CsvOutputPath $outputPath\$orgName-HostedConnectionFilterPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-HostedContentFilterPolicy -CsvOutputPath $outputPath\$orgName-HostedContentFilterPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-HostedContentFilterRule -CsvOutputPath $outputPath\$orgName-HostedContentFilterRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-HostedOutboundSpamFilterPolicy -CsvOutputPath $outputPath\$orgName-HostedOutboundSpamFilterPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-HostedOutboundSpamFilterRule -CsvOutputPath $outputPath\$orgName-HostedOutboundSpamFilterRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-MalwareFilterPolicy -CsvOutputPath $outputPath\$orgName-MalwareFilterPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-MalwareFilterRule -CsvOutputPath $outputPath\$orgName-MalwareFilterRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-PolicyConfig -CsvOutputPath $outputPath\$orgName-PolicyConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-PolicyTipConfig -CsvOutputPath $outputPath\$orgName-PolicyTipConfig.csv
Invoke-ExchangeCmdlet -Cmdlet Get-RMSTemplate -CsvOutputPath $outputPath\$orgName-RMSTemplate.csv
Invoke-ExchangeCmdlet -Cmdlet Get-ReportSubmissionPolicy -CsvOutputPath $outputPath\$orgName-ReportSubmissionPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-SafeAttachmentPolicy -CsvOutputPath $outputPath\$orgName-SafeAttachmentPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-SafeAttachmentRule -CsvOutputPath $outputPath\$orgName-SafeAttachmentRule.csv
Invoke-ExchangeCmdlet -Cmdlet Get-SafeLinksPolicy -CsvOutputPath $outputPath\$orgName-SafeLinksPolicy.csv
Invoke-ExchangeCmdlet -Cmdlet Get-SafeLinksRule -CsvOutputPath $outputPath\$orgName-SafeLinksRule.csv
Log "Completed data collection for $orgName." Green
#endregion

$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
if(Test-Path "$OutputPath\EXO-$orgName-Results.zip") {Remove-Item -Path "$OutputPath\EXO-$orgName-Results.zip" -Force}
Log "Creating zip file with the results..." Yellow
Get-ChildItem -Path $OutputPath -Filter "$orgName*.csv" | Select-Object FullName | ForEach-Object { 
    try {
        Compress-Archive -DestinationPath "$OutputPath\EXO-$orgName-Results.zip" -Path $_.FullName -Update -ErrorAction Ignore
    }
    catch {}
    ErrorReported ZipResults | Out-Null
}
try {
    Compress-Archive -DestinationPath "$OutputPath\EXO-$orgName-Results.zip" -Path $LogFile -Update -ErrorAction Ignore
}
catch {}
ErrorReported ZipLogFile | Out-Null
Get-ChildItem -Path $OutputPath -Filter "$orgName*.csv" | Remove-Item -Confirm:$False -Force

$ScriptBanner = @"
===============================================================================

SfMC EXO Discovery data collection has finished!"
Total collection time: $($totalTime) seconds"
Please upload results to SfMC. - Thank you!!!"

===============================================================================
"@
Write-Host $ScriptBanner -ForegroundColor Cyan

# SIG # Begin signature block
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDjQDhzUaIwCXFu
# Hh6dI/ynHWW0JPUKCXEm74Y0hVRIq6CCDXYwggX0MIID3KADAgECAhMzAAADrzBA
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIB/D6eODk8jdwoZ7XLFA9zwf
# g1sFN3QT4O0rT2kb6KS3MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBjgAlZbjowDdkEGrgQOmC7OxIq1Ag+N/25VhRSG0PuAxriNDgOhfGi
# PmrPA2y76bpYRaj7JK6Askn69CB1Vr06puPIE9E7waQJYKLKjAF+hulmFs07amyx
# cRyxAW/0zc/dhYaR6yDsmz71dwsiDEGH3kQYKJJsj0H5Xy3eNzCwUmt1d2nsw6pt
# 9SOrPLmEKwErATU+42/0/K0M3UtTDD8K8uYT2oE+j5sPzr3dtOULDCTamyxUQGJn
# QroW1BCo//1YcRqts/Vg8qeBLXTX57sCT4RvyaGcw8LBARVxPeq3uj5540vwKg1W
# OXufh122E3g4RnfMsnDyfN1qW1TjysqioYIXlDCCF5AGCisGAQQBgjcDAwExgheA
# MIIXfAYJKoZIhvcNAQcCoIIXbTCCF2kCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIACYwdqq3bE0NF7hrCqmSCFGFlOSqUnkZCHGVLrFHP3vAgZlul13
# uCEYEzIwMjQwMjAxMTcyNTA2LjA4NlowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBNDAw
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEeowggcgMIIFCKADAgECAhMzAAAB1idp/3ItVsiuAAEAAAHWMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDUyNTE5
# MTIzNFoXDTI0MDIwMTE5MTIzNFowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBNDAwLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAM8szY6byvm7d9xsMQ5fJ0m1uRblTfgoVp+0L7xD
# I2qmUwjNJMLVOgTTNzB5AK88h+li3I8HeO3p89Gmu+HAKSxTD2nQ5+ZnNY8O+S3j
# QFRK27zXdCWuWhF2mUvPbGmTb2Mg5nj6sFsppmQE9nhHgtdCGSQed7Rj9iHzlmow
# xFoxaQEzqdTBXloOLBep0T0nKXSLVpZhsKrPAFF03sJOUAnGsnjui/e5/+UWD2Gd
# VBypBiBGtEWkM0Uw4/SDDPk2PprbgZmdwUQZGYrAiYv7kpY+dWC9p0lJGnpmqthX
# cWZsGZm2wXSFKVWMtA7yfF6UZXtO+oghIiy/ZtAyBQFUTPzAcXJTfzreAePwEJsS
# knObvl8smwvc/rqUlQ1E3sJGx80Rsd1f93qOilU4XAXuiaZNCOlTfsD/thHTAkNO
# 3pmxdT6P/BiWj1vba3WpS2GqNGzfagZ/ZNFMKhBYuEl7dwAhhGWVr+AQqVu4MOwb
# f3brLgQwcXFOOyOtxkRsNbCMHfCunXUPKDVApwPItSzZqcGiW9DAlM3SYw65c7y0
# HPbSeD/5fD7jD5b08yS9bV9piLjflWMpFmwd/Eg+MjNnTB/gWJuZU8kdn5pPEaxU
# k/HJ0KG+8YJ/h97xd9hj0/mVuf1Jwpzhp1N3jgYKsGUn8k6ygDg680djpb5dwpVw
# ggZbAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUYZpUNjtNAGIwIqDb6P/NFNxixk4w
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBANS/5GM2J3AnFJsyTUi9Lwt/E0zxVpWG
# nFHVKRb4VFjoAqSfazc6fb2cYRWVq1uUi/WpVMqStTEtgxnTP5EDqaZ9e57Zjv9g
# FvMzmRR5SBTbLUyZuKfrFp1P0PMQJ4TsTj7eTYOZnG5X4YsVhCyqQNt7yjLv7cFK
# JTb2rJkBhP29EMAs9QLlnDKg+Q18puqOXdWAVOoi5sRCvnozRh0xaWoKqrTJWWf2
# Y9uEcfNcc6NpCy6uiEcJ/tVPxy3v2mjfgV3xdyyqbKF0oHLWN3KSeuKT4Xe8SX/3
# Spqifk3wpNmga04WVokU+dnYOpC1vZZaR+4CgZasZIDjczKXv49htSyuL82sy8B3
# 1n4n0WWqwzBdAXEAHu6MmLiE/wEfyPqqSbLi66VTlJJBrpeQSVxopBhKklxKOSPJ
# MMg6l/otkFNoXHp56ioNnSVRGGJGo77XKjy5c7z17qSAF4Ly3VY3khOpeeOhxiAO
# /IWmm2xQOCdFSIjUz9CX87b31WS0yQgvvaLpB3gEGyuPdn6IsSco/16lTCiw/Wbc
# 3a/3KFdDUeK6wmXrch9cjJ8Elpa9AOBTcmTh4hlKv/YoiPim1e3j3oJGIdOLTXWR
# zAOl2NAsBCIK+iPWm7KF/BV/YblnAGm0heK81FtrfgqQPmiqYSgXXJEVDziIOx/+
# CLKf9chPthj/MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
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
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTQwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# APmvcNVGkAZCj2xMtQd4ELzs2kr6oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDpZi0+MCIYDzIwMjQwMjAxMTQ0
# NjIyWhgPMjAyNDAyMDIxNDQ2MjJaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOlm
# LT4CAQAwBwIBAAICG9EwBwIBAAICGzcwCgIFAOlnfr4CAQAwNgYKKwYBBAGEWQoE
# AjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkq
# hkiG9w0BAQsFAAOCAQEARWjVEMBzfFbdkcr/TdFu3AkxOHjVL3D6uMI39IZVhib8
# enNWFycxPj4KvbzrlGglEqHCtOKZrVGyVuL8vTRoxN20aBCwc/CU4zz0KcGWcQ4K
# LLh85/EndQIMujZ6f4UJvFLz9nOI0jOaBsfdnlH1t6gC+UDDsxNt0bmNxEJFQCim
# Rf3yFdvzNehmHXb287nXvARR4yYwmDISeHU2O4MPnUvlTFyic4/4v8RCYLpaCcg1
# X49utx8AQ5lb/c8aRQJOom3f5fo6xrpa6Cs1969dPgYBnSyC2K8e6QjRvPGJV2nx
# xKU35AUFht0naqdl6EB3Nu5t19/h+RUKk5HiiQNEgTGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB1idp/3ItVsiuAAEAAAHW
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIIqB601g4fBTauB/fqeGtHoDP007qEglU3Kq5i1JVRoV
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg1stNDVd40z4QGKc4QkyNl3SM
# w0O6v4Ar47w/XaPlJPwwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAdYnaf9yLVbIrgABAAAB1jAiBCA4h0kAS0Ocbmy1YWpz8QgOc3/A
# oubFV2PgGjITUZGYpDANBgkqhkiG9w0BAQsFAASCAgC1IvzGFNYD26+SiVaIWj3l
# ltQgO6MREzGqB5nMTQR/T/0ygPcORnBLhQKhb7Nb960Rp6g8dwAUjEjbFJU7xjvj
# peZ2lwTIFh5ZJprd2Az60W8MlgrzHfim59aDgOqbR8qi28Brkn3M51zCtpcco6HT
# PfeqgUbFXCllaSozW/bWEmVd6X9CQ2P+4LJKb5IMxgx+vtOHS7jR9tXqXvudlQ6s
# ZZ6P1UAgURg/6MsLB9hFd0JNaMdvIWC7fqk0VFBlpMfVpVU6deVMprNCswKttX4S
# iacJ91tBNNohXIjZEDwBtwe+fGqXJTLNc0/LWzPLC/gciH33fJzENNkhSo6ySxkw
# 8tuHQh2ZYaU6UKniAMKzXwES9L2gZSF8FGaz4b/0je/PMLLy+6JTDdH9IZ+U4mNJ
# ddML/cWTBdkUk2I1x0dJz7+tC/JIWwoc6h7UiJ1uF3ukzggqy505sy1/ccHvXe3V
# tEw8PbWHZdZTKf0iy5yZX2/w0hKzJplZyUuCBfJgyw0HXfZfzpMrIfbsQeH4XXOE
# a0DWx9JHBVay+ixuzhWvVwpnL+8zHnxvbzdLnxnsoiIFJXBSiSGOQyg2WWV7y1MB
# QdzL5R3F+s0f9jF4YNvRWzER+9JdujpndON1vkocR1QWp8HrCWVqiHjdTponA7r3
# dEFoJC8K4hB2NXQ91BBPAQ==
# SIG # End signature block
