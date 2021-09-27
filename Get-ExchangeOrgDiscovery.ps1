<#//***********************************************************************
//
// Get-ExchangeOrgDiscovery.ps1
// Modified 2021/09/27
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v4.0
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

param( [Parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$creds)
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
function Write-Log {
    param( [string]$Message, [string]$Cmdlet )
    [pscustomobject]@{
        Time = (Get-Date -f o)
        Cmdlet = $Cmdlet
        Message = $Message
    } | Export-Csv -Path "$outputPath\$ServerName-LogFile.csv" -Append -NoTypeInformation
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
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Org Settings"
if(!(Test-Path $outputPath)) {New-Item -Path $outputPath -ItemType Directory | Out-Null}
## Remove any previous data
else {Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force }
## Create a remote PowerShell session with this server
[string]$orgName = (Get-OrganizationConfig).Name
Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $orgName*.zip | Remove-Item -Confirm:$False
Set-ADServerSettings -ViewEntireForest:$True
## Data collection starts using XML files to capture multi-valued properties
Get-ExchangeServer -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ExchangeServer.xml
## Transport settings
Get-AcceptedDomain -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-AcceptedDomain.xml
Get-RemoteDomain -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-RemoteDomain.xml
Get-TransportConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-TransportConfig.xml
Get-TransportRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-TransportRule.xml
Get-TransportRuleAction -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-TransportRuleAction.xml
Get-TransportRulePredicate -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-TransportRulePredicate.xml
Get-JournalRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-JournalRule.xml
Get-DeliveryAgentConnector -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-DeliveryAgentConnector.xml
Get-EmailAddressPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-EmailAddressPolicy.xml
Get-SendConnector -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-SendConnector.xml
Get-EdgeSubscription -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-EdgeSubscription.xml
Get-EdgeSyncServiceConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-EdgeSyncServiceConfig.xml
## Client access settings
Get-ActiveSyncOrganizationSettings -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ActiveSyncOrganizationSettings.xml
Get-MobileDeviceMailboxPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-MobileDeviceMailboxPolicy.xml
Get-ActiveSyncDeviceAccessRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ActiveSyncDeviceAccessRule.xml
Get-ActiveSyncDeviceAutoblockThreshold -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ActiveSyncDeviceAutoblockThreshold.xml
Get-ClientAccessArray -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ClientAccessArray.xml
Get-OwaMailboxPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-OwaMailboxPolicy.xml
Get-ThrottlingPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ThrottlingPolicy.xml
Get-IRMConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-IRMConfiguration.xml
Get-OutlookProtectionRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-OutlookProtectionRule.xml
Get-OutlookProvider -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-OutlookProvider.xml
Get-ClientAccessRule -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ClientAccessRule.xml
## Mailbox server settings
Get-RetentionPolicyTag -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-RetentionPolicyTag.xml
Get-RetentionPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-RetentionPolicy.xml
Get-SiteMailbox -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-SiteMailbox.xml
## Address book settings
Get-AddressBookPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-AddressBookPolicy.xml
Get-GlobalAddressList -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-GlobalAddressList.xml
Get-AddressList -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-AddressList.xml
Get-OfflineAddressBook -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-OfflineAddressBook.xml
## Administration settings
Get-AdminAuditLogConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-AdminAuditLogConfig.xml
Get-ManagementRole -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ManagementRole.xml
Get-ManagementRoleEntry "*\*" -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ManagementRoleEntry.xml
Get-ManagementRoleAssignment -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ManagementRoleAssignment.xml
Get-RoleGroup -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-RoleGroup.xml
Get-ManagementScope -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ManagementScope.xml
Get-RoleAssignmentPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-RoleAssignmentPolicy.xml
## Federation settings
Get-FederationTrust -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-FederationTrust.xml
Get-FederatedOrganizationIdentifier -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-FederatedOrganizationIdentifier.xml
Get-SharingPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-SharingPolicy.xml
Get-OrganizationRelationship -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-OrganizationRelationship.xml
## Availability service
Get-IntraOrganizationConnector -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-IntraOrganizationConnector.xml
Get-IntraOrganizationConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-IntraOrganizationConfiguration.xml
Get-AvailabilityAddressSpace -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-AvailabilityAddressSpace.xml
Get-AvailabilityConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-AvailabilityConfig.xml
## General settings
Get-OrganizationConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-OrganizationConfig.xml
Get-AuthConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-AuthConfig.xml
Get-AuthServer -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-AuthServer.xml
Get-HybridConfiguration -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-HybridConfiguration.xml
Get-MigrationEndpoint -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-MigrationEndpoint.xml
Get-PartnerApplication -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-PartnerApplication.xml
Get-PolicyTipConfig -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-PolicyTipConfig.xml
Get-RMSTemplate -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-RMSTemplate.xml
Get-SmimeConfig | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-SmimeConfig.xml
Get-DlpPolicy -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-DlpPolicy.xml
Get-DlpPolicyTemplate -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-DlpPolicyTemplate.xml
Get-GlobalMonitoringOverride -WarningAction Ignore | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-GlobalMonitoringOverride.xml
Get-DomainController | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-DomainController.xml
## AD settings
Get-ADSite -WarningAction Ignore -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-ADSite.xml
Get-AdSiteLink -WarningAction Ignore -ErrorAction Stop | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$orgName-AdSiteLink.xml
## Convert the XML into CSV files
Get-ChildItem $outputPath -Filter *.xml | ForEach-Object { Import-Clixml $_.FullName | Export-Csv $outputPath\$($_.BaseName).csv -NoTypeInformation -Force }
Get-ChildItem $outputPath -Filter *.xml | Remove-Item
#Zip the results
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
# SIG # Begin signature block
# MIIFvQYJKoZIhvcNAQcCoIIFrjCCBaoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBsBYDDBWhrCyAK
# FUlRv82Nk/VqVQ8FPA9clCYxAa90P6CCAzYwggMyMIICGqADAgECAhA8ATOaNhKD
# u0LkWaETEtc0MA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMMFWptYXJ0aW5AbWlj
# cm9zb2Z0LmNvbTAeFw0yMTAzMjYxNjU5MDdaFw0yMjAzMjYxNzE5MDdaMCAxHjAc
# BgNVBAMMFWptYXJ0aW5AbWljcm9zb2Z0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMSWhFMKzV8qMywbj1H6lg4h+cvR9CtxmQ1J3V9uf9+R2d9p
# laoDqCNS+q8wz+t+QffvmN2YbcsHrXp6O7bF+xYjuPtIurv8wM69RB/Uy1xvsUKD
# L/ZDQZ0zewMDLb5Nma7IYJCPYelHiSeO0jsyLXTnaOG0Rq633SUkuPv+C3N8GzVs
# KDnxozmHGYq/fdQEv9Bpci2DkRTtnHvuIreeqsg4lICeTIny8jMY4yC6caQkamzp
# GcJWWO0YZlTQOaTgHoVVnSZAvdJhzxIX2wqd0/VaVIbpN0HcPKtMrgXv0O2Bl4Lo
# tmZR7za7H6hamxaPYQHHyReFs2xM7hlVVWhnfpECAwEAAaNoMGYwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMCAGA1UdEQQZMBeCFWptYXJ0aW5A
# bWljcm9zb2Z0LmNvbTAdBgNVHQ4EFgQUCB04A8myETdoRJU9zsScvFiRGYkwDQYJ
# KoZIhvcNAQELBQADggEBAEjsxpuXMBD72jWyft6pTxnOiTtzYykYjLTsh5cRQffc
# z0sz2y+jL2WxUuiwyqvzIEUjTd/BnCicqFC5WGT3UabGbGBEU5l8vDuXiNrnDf8j
# zZ3YXF0GLZkqYIZ7lUk7MulNbXFHxDwMFD0E7qNI+IfU4uaBllsQueUV2NPx4uHZ
# cqtX4ljWuC2+BNh09F4RqtYnocDwJn3W2gdQEAv1OQ3L6cG6N1MWMyHGq0SHQCLq
# QzAn5DpXfzCBAePRcquoAooSJBfZx1E6JeV26yw2sSnzGUz6UMRWERGPeECSTz3r
# 8bn3HwYoYcuV+3I7LzEiXOdg3dvXaMf69d13UhMMV1sxggHdMIIB2QIBATA0MCAx
# HjAcBgNVBAMMFWptYXJ0aW5AbWljcm9zb2Z0LmNvbQIQPAEzmjYSg7tC5FmhExLX
# NDANBglghkgBZQMEAgEFAKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJ
# AzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8G
# CSqGSIb3DQEJBDEiBCDPg9/70vWFxdSjh0E9fy7dBLILTZ4koBmAN85rEIDIKzAN
# BgkqhkiG9w0BAQEFAASCAQCREa1uyiH6h7zR58Sw1QpFreEyvv/gTwiqPXocVXtJ
# Ivaar/MxLBCrnvKTt59ORR4f/kVkDuzHZ/ndSXp/YhrWt1YxaL/bFG3Mz5KgZcwr
# PUBq8npsGOiBpSxXWsrNw5zc04knXVjiDH1S8jZNLnoD9Z3jwZm6g+8jRwqm4ZwF
# VOJmzvE7Fm2UWAqzeDrRmh8mhTFY4DyuY7w1/m2OuakT/6ER19JVfxPdEozVlE65
# Ty31FBLa1kSur2pDLCrw4jZvHSGWPuOlCxBmRlmdYaSA+djxpq7Q5YcH/SzJXbbf
# vo0qBeJ9OmdIyFfeE3AeeAoJGc/0ZjbFVZvFBJE4lVJm
# SIG # End signature block
