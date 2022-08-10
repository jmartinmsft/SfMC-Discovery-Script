<#//***********************************************************************
//
// Get-ExchangeOrgDiscovery.ps1
// Modified 10 August 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v4.1
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
# MIInsQYJKoZIhvcNAQcCoIInojCCJ54CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAyjFlAKRG1lnLQ
# kEzDYsH1e+SZGWtOCL46bnjoMfrq+aCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAugRnx1moaEgmv1IR87lEkl
# NDvqqnW6lwbssfjCNh89MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAEaC/I+cQRSvq4JDkUJE7pepTOW7/2IF6y5iL/CYP+2GNt+zRZgI0S
# TCmd24NcuRjUGCwbL5g6iRnsQdrGq256ziCCK+rMn7O1J9DYzhYGypyFD6XGS6b2
# l2jqM863apkT1Enx+iwYKfcg27nU8oo1iGz85w0ad00sfbyro2uH+jmPLUspsIfY
# AlQn5AViAp9AA2uGy6Qnlh6QQc+46cTq5iP1KJawUKVkL7k6c9VHqUma2qOffjyU
# N+b7xFWgSzNmAQ6i/3xUAKF1ahh32A5hG7FO27EaBgXwbMDkcVE7xqGFLEVjlca7
# QXkulLYGybBeJD/VzSQjxrzOpJwMbPFooYIXGTCCFxUGCisGAQQBgjcDAwExghcF
# MIIXAQYJKoZIhvcNAQcCoIIW8jCCFu4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIOnXPmk3IjecPzEfZGm5z+ZaClKeo0SndJkCDJNDl6r6AgZi3oid
# E6cYEzIwMjIwODEwMTgwNTA0LjU5MVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
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
# 9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIB2GBrOfZB+jJIxR
# qnZmjUGo0sN3Sn4CH9FgdwSWvoU4MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCB
# vQQgl3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAi
# BCCqCJmkf3v7/R1NZHZjsQINMMvjOE5oO5nHE5w70WWAIDANBgkqhkiG9w0BAQsF
# AASCAgBO/1fzVlHybw6NC/jgGNsnJEhYQOKXMkH/VmP1AkAmXMbI0FK7FIBrITiv
# gjinpEOGWYpbc3PE6Xn9k5yGkcwShbQZrkv2EaPLG/aY0NsdwrlgngqfJ7V5JKvR
# l5tOaIWhDIAGRawOKoU4EhPMArG/Vpb5H7RJ7V0F9vPrbYjO1qZhyP/byj8kQFxO
# REIEPaUDJPa0hMpBNAJLd8lFgJKYiBC5SIVuGd4RS8R+cb+9SrBkLUCNvQAMpd2y
# /9x4tz+LS9j0YVwY5Je96QpXr8WAIU5Ds4AZFy/vNjn1QpO22mINDfxTBZd6RvK5
# JSWzkpZF0S0kAsUOwPFPRn/MXKoCyoWNxH1GSH3ke2QcDAKVet0XnxVTyMKHIx5J
# T2AfXqFieVnC/8/dC6ArvcW+wLKKCy5GH4mUAPz/YecDaNB4TSphaV+tJRDv5Dpb
# lpkiBoVsFWO5Z+MqdxOcCVnW/OruzAXsO4X7Myhbd1cjzmv5UEOvYVUcp0djVEAT
# 1/i1LuI2zLu1FB81T2ADDu2bk0TSflyFpc04mLp+qrEM69mDXumD33/NXHtPUiqk
# VhGQ/+OfRjpA5+ORJcXQb5sKDA6p8gH6FpToM1xdQXTieGL/KZed+PwPnbg3EZy5
# BX2wZMnB9krtowQOpfBHy/cGcbLupM+ozg5Bboj3kuGj1/qEJA==
# SIG # End signature block
