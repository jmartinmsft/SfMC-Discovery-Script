<#//***********************************************************************
//
// SfMC-EXODiscovery.ps1
// Modified 05 September 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: 20230905.0819
//Syntax for running this script:
//
// .\SfMC-EXODiscovery.ps1 -UserPrincipalName admin@contoso.com -OutputPath C:\Temp\Results
//
//.NOTES
// 1.1 Updated EOP data collection
// 20230905.1418 Updated error handling and removed cmdlet requiring RPSSession
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

$script:ScriptVersion = "20230905.1418"

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