<#//***********************************************************************
//
// Get-ExchangeOrgDiscovery.ps1
// Modified 21 April 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20230421.1909
//
//.NOTES
// 20220823.1655 - Additional logging
// 20230421.1909 - Write event logs for start and finish
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
    [Parameter(Mandatory=$false)] [string]$LogFile="$env:ExchangeInstallPath\Logging\SfMC Discovery\SfMC.log"
)

$script:ScriptVersion = "v20230921.1931"
if(!(Test-Path "$env:ExchangeInstallPath\Logging\SfMC Discovery")) {
    New-Item -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -ItemType Directory | Out-Null
}
if(Test-Path $LogFile -ErrorAction Ignore) {
    Remove-Item -Path $LogFile -Confirm:$false -Force
}


function LogToFile([string]$Details) {
	if ( [String]::IsNullOrEmpty($LogFile) ) { return }
	"$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToLongTimeString())   $Details" | Out-File $LogFile -Append
}

function Log([string]$Details, [ConsoleColor]$Colour) {
    if ($Colour -notlike $null)
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
    if ([String]::IsNullOrEmpty($Error[0])) { return } #$false }

    # We have an error, have we already reported it?
    if ($Error[0] -eq $script:LastError) { return  } #$false }

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
    return #$true
}

function ReportError($Context) {
    # Reports error without returning the result
    ErrorReported $Context | Out-Null
}

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
#endregion


function ZipCsvResults {
	## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    try {[System.IO.Compression.ZipFile]::CreateFromDirectory($outputPath, $zipFolder)}
    catch {
        try{Remove-Item -Path $zipFolder -Force -ErrorAction Stop}
        catch{Write-Warning "Failed to remove file."}
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'update')
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        Get-ChildItem -Path $outputPath | Select-Object FullName | ForEach-Object {
            try{[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipFile, $_.FullName, (Split-Path $_.FullName -Leaf), $compressionLevel) | Out-Null }
            catch {Write-Warning "failed to add"}
        }
        $zipFile.Dispose()
    }
}

function InvokeExchangeCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Cmdlet,
        [Parameter(Mandatory = $false)][bool]$ViewEntireForest,
        [string]$XmlOutputPath,[string]$Identity,
        [scriptblock]$CatchActionFunction        
    )
    begin {
        Log([string]::Format("Calling: {0}", $MyInvocation.MyCommand)) Gray       
        $returnValue = $null
    }
    process {
        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Log([string]::Format("Description: {0}", $ScriptBlockDescription)) Gray       
        }
        try {
            if($ViewEntireForest) {
                Write-Verbose "Running the following Exchange cmdlet: $Cmdlet"
                $returnValue = & $Cmdlet -ViewEntireForest:$True
            }
            else{
                Log([string]::Format("Running the following Exchange cmdlet: {0}", $Cmdlet)) Gray
                if($Identity -notlike $null) { 
                    $returnValue = & $Cmdlet -Identity $Identity | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $XmlOutputPath
                }
                else {
                    $returnValue = & $Cmdlet | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $XmlOutputPath
                }
            }
        } 
        catch {
            Log([string]::Format("Failed to run: {0}", $MyInvocation.MyCommand)) Gray       
            InvokeCatchActionError $CatchActionFunction
        }
    }
    end {
        Log([string]::Format("Exiting: {0}", $MyInvocation.MyCommand)) Gray       
        return $returnValue
    }
}

function InvokeCatchActionError {
    [CmdletBinding()]
    param(
        [scriptblock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}

Log([string]::Format("Writing event ID 1125 into the event log to notify the script has started.")) Gray
Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1125 -Message "The SfMC Exchange Organization discovery script has started." -Category 1
#region OutputPath
## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Org Settings"
if(!(Test-Path $outputPath)) {
    Log([string]::Format("Creating logging directory for the discovery script results.")) Gray
    New-Item -Path $outputPath -ItemType Directory | Out-Null
}
## Remove any previous data
else {
    Log([string]::Format("Removing any existing discovery script results.")) Gray
    Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force 
}
#endregion

Log([string]::Format("Adding Exchange Management snapin.")) Gray
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

[string]$orgName = (Get-OrganizationConfig).Name
Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $orgName*.zip | Remove-Item -Confirm:$False

Log([string]::Format("Setting AD to view the entire forest for data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Set-ADServerSettings" -ViewEntireForest:$True

## Data collection starts using XML files to capture multi-valued properties
Log([string]::Format("Getting list of Exchange servers in the organization.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-ExchangeServer" -XmlOutputPath $outputPath\$orgName-ExchangeServer.xml
## Transport settings
Log([string]::Format("Starting transport information data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-AcceptedDomain" -XmlOutputPath $outputPath\$orgName-AcceptedDomain.xml
InvokeExchangeCmdlet -Cmdlet "Get-RemoteDomain" -XmlOutputPath $outputPath\$orgName-RemoteDomain.xml
InvokeExchangeCmdlet -Cmdlet "Get-TransportConfig" -XmlOutputPath $outputPath\$orgName-TransportConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-TransportRule" -XmlOutputPath $outputPath\$orgName-TransportRule.xml
InvokeExchangeCmdlet -Cmdlet "Get-TransportRuleAction" -XmlOutputPath $outputPath\$orgName-TransportRuleAction.xml
InvokeExchangeCmdlet -Cmdlet "Get-TransportRulePredicate" -XmlOutputPath $outputPath\$orgName-TransportRulePredicate.xml
InvokeExchangeCmdlet -Cmdlet "Get-JournalRule" -XmlOutputPath $outputPath\$orgName-JournalRule.xml
InvokeExchangeCmdlet -Cmdlet "Get-DeliveryAgentConnector" -XmlOutputPath $outputPath\$orgName-DeliveryAgentConnector.xml
InvokeExchangeCmdlet -Cmdlet "Get-EmailAddressPolicy" -XmlOutputPath $outputPath\$orgName-EmailAddressPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-SendConnector" -XmlOutputPath $outputPath\$orgName-SendConnector.xml
InvokeExchangeCmdlet -Cmdlet "Get-EdgeSubscription" -XmlOutputPath $outputPath\$orgName-EdgeSubscription.xml
InvokeExchangeCmdlet -Cmdlet "Get-EdgeSyncServiceConfig" -XmlOutputPath $outputPath\$orgName-EdgeSyncServiceConfig.xml

## Client access settings
Log([string]::Format("Starting client access information data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-ActiveSyncOrganizationSettings" -XmlOutputPath $outputPath\$orgName-ActiveSyncOrganizationSettings.xml
InvokeExchangeCmdlet -Cmdlet "Get-MobileDeviceMailboxPolicy" -XmlOutputPath $outputPath\$orgName-MobileDeviceMailboxPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-ActiveSyncDeviceAccessRule" -XmlOutputPath $outputPath\$orgName-ActiveSyncDeviceAccessRule.xml
InvokeExchangeCmdlet -Cmdlet "Get-ActiveSyncDeviceAutoblockThreshold" -XmlOutputPath $outputPath\$orgName-ActiveSyncDeviceAutoblockThreshold.xml
InvokeExchangeCmdlet -Cmdlet "Get-ClientAccessArray" -XmlOutputPath $outputPath\$orgName-ClientAccessArray.xml
InvokeExchangeCmdlet -Cmdlet "Get-OwaMailboxPolicy" -XmlOutputPath $outputPath\$orgName-OwaMailboxPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-ThrottlingPolicy" -XmlOutputPath $outputPath\$orgName-ThrottlingPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-IRMConfiguration" -XmlOutputPath $outputPath\$orgName-IRMConfiguration.xml
InvokeExchangeCmdlet -Cmdlet "Get-OutlookProtectionRule" -XmlOutputPath $outputPath\$orgName-OutlookProtectionRule.xml
InvokeExchangeCmdlet -Cmdlet "Get-OutlookProvider" -XmlOutputPath $outputPath\$orgName-OutlookProvider.xml
InvokeExchangeCmdlet -Cmdlet "Get-ClientAccessRule" -XmlOutputPath $outputPath\$orgName-ClientAccessRule.xml

## Mailbox server settings
Log([string]::Format("Starting mailbox server information data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-RetentionPolicyTag" -XmlOutputPath $outputPath\$orgName-RetentionPolicyTag.xml
InvokeExchangeCmdlet -Cmdlet "Get-RetentionPolicy" -XmlOutputPath $outputPath\$orgName-RetentionPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-SiteMailbox" -XmlOutputPath $outputPath\$orgName-SiteMailbox.xml

## Address book settings
Log([string]::Format("Starting address book information data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-AddressBookPolicy" -XmlOutputPath $outputPath\$orgName-AddressBookPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-GlobalAddressList" -XmlOutputPath $outputPath\$orgName-GlobalAddressList.xml
InvokeExchangeCmdlet -Cmdlet "Get-AddressList" -XmlOutputPath $outputPath\$orgName-AddressList.xml
InvokeExchangeCmdlet -Cmdlet "Get-OfflineAddressBook" -XmlOutputPath $outputPath\$orgName-OfflineAddressBook.xml

## Administration settings
Log([string]::Format("Starting administration information data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-AdminAuditLogConfig" -XmlOutputPath $outputPath\$orgName-AdminAuditLogConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-ManagementRole" -XmlOutputPath $outputPath\$orgName-ManagementRole.xml
InvokeExchangeCmdlet -Cmdlet "Get-ManagementRoleEntry" -XmlOutputPath $outputPath\$orgName-ManagementRoleEntry.xml -Identity "*\*"
InvokeExchangeCmdlet -Cmdlet "Get-ManagementRoleAssignment" -XmlOutputPath $outputPath\$orgName-ManagementRoleAssignment.xml
InvokeExchangeCmdlet -Cmdlet "Get-RoleGroup" -XmlOutputPath $outputPath\$orgName-RoleGroup.xml
InvokeExchangeCmdlet -Cmdlet "Get-ManagementScope" -XmlOutputPath $outputPath\$orgName-ManagementScope.xml
InvokeExchangeCmdlet -Cmdlet "Get-RoleAssignmentPolicy" -XmlOutputPath $outputPath\$orgName-RoleAssignmentPolicy.xml

## Federation settings
Log([string]::Format("Starting federation information data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-FederationTrust" -XmlOutputPath $outputPath\$orgName-FederationTrust.xml
InvokeExchangeCmdlet -Cmdlet "Get-FederatedOrganizationIdentifier" -XmlOutputPath $outputPath\$orgName-FederatedOrganizationIdentifier.xml
InvokeExchangeCmdlet -Cmdlet "Get-SharingPolicy" -XmlOutputPath $outputPath\$orgName-SharingPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-OrganizationRelationship" -XmlOutputPath $outputPath\$orgName-OrganizationRelationship.xml

## Availability service
Log([string]::Format("Starting availability service information data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-IntraOrganizationConnector" -XmlOutputPath $outputPath\$orgName-IntraOrganizationConnector.xml
InvokeExchangeCmdlet -Cmdlet "Get-IntraOrganizationConfiguration" -XmlOutputPath $outputPath\$orgName-IntraOrganizationConfiguration.xml
InvokeExchangeCmdlet -Cmdlet "Get-AvailabilityAddressSpace" -XmlOutputPath $outputPath\$orgName-AvailabilityAddressSpace.xml
InvokeExchangeCmdlet -Cmdlet "Get-AvailabilityConfig" -XmlOutputPath $outputPath\$orgName-AvailabilityConfig.xml

## General settings
Log([string]::Format("Starting general information data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-OrganizationConfig" -XmlOutputPath $outputPath\$orgName-OrganizationConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-AuthConfig" -XmlOutputPath $outputPath\$orgName-AuthConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-AuthServer" -XmlOutputPath $outputPath\$orgName-AuthServer.xml
InvokeExchangeCmdlet -Cmdlet "Get-HybridConfiguration" -XmlOutputPath $outputPath\$orgName-HybridConfiguration.xml
InvokeExchangeCmdlet -Cmdlet "Get-MigrationEndpoint" -XmlOutputPath $outputPath\$orgName-MigrationEndpoint.xml
InvokeExchangeCmdlet -Cmdlet "Get-PartnerApplication" -XmlOutputPath $outputPath\$orgName-PartnerApplication.xml
InvokeExchangeCmdlet -Cmdlet "Get-PolicyTipConfig" -XmlOutputPath $outputPath\$orgName-PolicyTipConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-RMSTemplate" -XmlOutputPath $outputPath\$orgName-RMSTemplate.xml
InvokeExchangeCmdlet -Cmdlet "Get-SmimeConfig" -XmlOutputPath $outputPath\$orgName-SmimeConfig.xml
InvokeExchangeCmdlet -Cmdlet "Get-DlpPolicy" -XmlOutputPath $outputPath\$orgName-DlpPolicy.xml
InvokeExchangeCmdlet -Cmdlet "Get-DlpPolicyTemplate" -XmlOutputPath $outputPath\$orgName-DlpPolicyTemplate.xml
InvokeExchangeCmdlet -Cmdlet "Get-GlobalMonitoringOverride" -XmlOutputPath $outputPath\$orgName-GlobalMonitoringOverride.xml
InvokeExchangeCmdlet -Cmdlet "Get-DomainController" -XmlOutputPath $outputPath\$orgName-DomainController.xml

## AD settings
Log([string]::Format("Starting AD information data collection.")) Gray
InvokeExchangeCmdlet -Cmdlet "Get-ADSite" -XmlOutputPath $outputPath\$orgName-ADSite.xml
InvokeExchangeCmdlet -Cmdlet "Get-AdSiteLink" -XmlOutputPath $outputPath\$orgName-AdSiteLink.xml

## Convert the XML into CSV files
Log([string]::Format("Converting the XML results into CSV files.")) Gray
Get-ChildItem $outputPath -Filter *.xml | ForEach-Object { Import-Clixml $_.FullName | Export-Csv $outputPath\$($_.BaseName).csv -NoTypeInformation -Force }
Get-ChildItem $outputPath -Filter *.xml | Remove-Item

#Zip the results
Log([string]::Format("Attempting to compress the results.")) Gray
$ts = Get-Date -f yyyyMMddHHmmss
[string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$orgName-OrgSettings-$ts.zip"
## Zip the results and sent to the location where the script was started
ZipCsvResults
$zipReady = $false
$zipAttempt = 1
while($zipReady -eq $false) {
    Write-Verbose "Compressing the results into a zip file for upload."
    if(Get-Item -Path $zipFolder -ErrorAction Ignore) { 
        $zipReady = $true 
        Log([string]::Format("Compression completed successfully.")) Gray
        Log([string]::Format("Writing event ID 1007 into the event log to notify the script has finished.")) Gray
        Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1007 -Message "The SfMC Exchange Organization discovery script has completed." -Category 1
    }
    else {
        Start-Sleep -Seconds 10
        Log([string]::Format("Compression attempt failed.")) Gray
        if($zipAttempt -gt 4) { $zipReady = $true }
        else {
            Log([string]::Format("Attempting to compress the results.")) Gray
            Zip-CsvResults
            $zipAttempt++
        }
    }
}
