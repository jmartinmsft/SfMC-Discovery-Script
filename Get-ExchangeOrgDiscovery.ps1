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

#region Disclaimer
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
#endregion

function Write-Verbose {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Verbose from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {
        #write to the debug log and call Write-Verbose normally
        Write-VerboseLog $Message
        Microsoft.PowerShell.Utility\Write-Verbose $Message
    }
}

function Write-VerboseLog ($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}

function Get-NewLoggerInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)] [string]$LogDirectory,
        [ValidateNotNullOrEmpty()][string]$LogName = "Script_Logging",
        [bool]$AppendDateTime = $true,
        [bool]$AppendDateTimeToFileName = $true,
        [int]$MaxFileSizeMB = 10,
        [int]$CheckSizeIntervalMinutes = 10,
        [int]$NumberOfLogsToKeep = 10
    )

    $fileName = if ($AppendDateTimeToFileName) { "{0}_{1}.txt" -f $LogName, ((Get-Date).ToString('yyyyMMddHHmmss')) } else { "$LogName.txt" }
    $fullFilePath = [System.IO.Path]::Combine($LogDirectory, $fileName)

    if (-not (Test-Path $LogDirectory)) {
        try {
            New-Item -ItemType Directory -Path $LogDirectory -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to create Log Directory: $LogDirectory"
        }
    }

    return [PSCustomObject]@{
        FullPath                 = $fullFilePath
        AppendDateTime           = $AppendDateTime
        MaxFileSizeMB            = $MaxFileSizeMB
        CheckSizeIntervalMinutes = $CheckSizeIntervalMinutes
        NumberOfLogsToKeep       = $NumberOfLogsToKeep
        BaseInstanceFileName     = $fileName.Replace(".txt", "")
        Instance                 = 1
        NextFileCheckTime        = ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
        PreventLogCleanup        = $false
        LoggerDisabled           = $false
    } | Write-LoggerInstance -Object "Starting Logger Instance $(Get-Date)"
}

function Write-LoggerInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance,

        [Parameter(Mandatory = $true, Position = 1)]
        [object]$Object
    )
    process {
        if ($LoggerInstance.LoggerDisabled) { return }

        if ($LoggerInstance.AppendDateTime -and
            $Object.GetType().Name -eq "string") {
            $Object = "[$([System.DateTime]::Now)] : $Object"
        }

        # Doing WhatIf:$false to support -WhatIf in main scripts but still log the information
        $Object | Out-File $LoggerInstance.FullPath -Append -WhatIf:$false

        #Upkeep of the logger information
        if ($LoggerInstance.NextFileCheckTime -gt [System.DateTime]::Now) {
            return
        }

        #Set next update time to avoid issues so we can log things
        $LoggerInstance.NextFileCheckTime = ([System.DateTime]::Now).AddMinutes($LoggerInstance.CheckSizeIntervalMinutes)
        $item = Get-ChildItem $LoggerInstance.FullPath

        if (($item.Length / 1MB) -gt $LoggerInstance.MaxFileSizeMB) {
            $LoggerInstance | Write-LoggerInstance -Object "Max file size reached rolling over" | Out-Null
            $directory = [System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)
            $fileName = "$($LoggerInstance.BaseInstanceFileName)-$($LoggerInstance.Instance).txt"
            $LoggerInstance.Instance++
            $LoggerInstance.FullPath = [System.IO.Path]::Combine($directory, $fileName)

            $items = Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*"

            if ($items.Count -gt $LoggerInstance.NumberOfLogsToKeep) {
                $item = $items | Sort-Object LastWriteTime | Select-Object -First 1
                $LoggerInstance | Write-LoggerInstance "Removing Log File $($item.FullName)" | Out-Null
                $item | Remove-Item -Force
            }
        }
    }
    end {
        return $LoggerInstance
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

function Invoke-ExchangeCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Cmdlet,

        [Parameter(Mandatory = $false)]
        [bool]
        $ViewEntireForest,
        
        [string]
        $XmlOutputPath,

        [string]
        $Identity,

        [scriptblock]
        $CatchActionFunction        
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $returnValue = $null
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Write-Verbose "Description: $ScriptBlockDescription"
        }

        try {
            if($ViewEntireForest) {
                Write-Verbose "Running the following Exchange cmdlet: $Cmdlet"
                $returnValue = & $Cmdlet -ViewEntireForest:$True
            }
            else{
                Write-Verbose "Running the following Exchange cmdlet: $Cmdlet "
                if($Identity -notlike $null) { 
                    $returnValue = & $Cmdlet -Identity $Identity | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $XmlOutputPath
                }
                else {
                    $returnValue = & $Cmdlet | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $XmlOutputPath
                }
            }
            
        } catch {
            Write-Verbose "Failed to run $($MyInvocation.MyCommand)"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return $returnValue
    }
}

function Invoke-CatchActionError {
    [CmdletBinding()]
    param(
        [scriptblock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}
Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1125 -Message "The SfMC Exchange Organization discovery script has started." -Category 1
$ServerName = $env:COMPUTERNAME
#region OutputPath
## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Org Settings"
if(!(Test-Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory | Out-Null
}
## Remove any previous data
else {
    Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force 
}
#endregion
$Script:Logger = Get-NewLoggerInstance -LogName "SfMCOrgSettings-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue -LogDirectory $outputPath
Write-Verbose "Adding Exchange Management snapin."
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

Write-Verbose "Removing any existing results."
[string]$orgName = (Get-OrganizationConfig).Name
Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $orgName*.zip | Remove-Item -Confirm:$False
Invoke-ExchangeCmdlet -Cmdlet "Set-ADServerSettings" -ViewEntireForest:$True

## Data collection starts using XML files to capture multi-valued properties
Invoke-ExchangeCmdlet -Cmdlet "Get-ExchangeServer" -XmlOutputPath $outputPath\$orgName-ExchangeServer.xml
## Transport settings
Invoke-ExchangeCmdlet -Cmdlet "Get-AcceptedDomain" -XmlOutputPath $outputPath\$orgName-AcceptedDomain.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-RemoteDomain" -XmlOutputPath $outputPath\$orgName-RemoteDomain.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-TransportConfig" -XmlOutputPath $outputPath\$orgName-TransportConfig.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-TransportRule" -XmlOutputPath $outputPath\$orgName-TransportRule.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-TransportRuleAction" -XmlOutputPath $outputPath\$orgName-TransportRuleAction.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-TransportRulePredicate" -XmlOutputPath $outputPath\$orgName-TransportRulePredicate.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-JournalRule" -XmlOutputPath $outputPath\$orgName-JournalRule.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-DeliveryAgentConnector" -XmlOutputPath $outputPath\$orgName-DeliveryAgentConnector.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-EmailAddressPolicy" -XmlOutputPath $outputPath\$orgName-EmailAddressPolicy.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-SendConnector" -XmlOutputPath $outputPath\$orgName-SendConnector.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-EdgeSubscription" -XmlOutputPath $outputPath\$orgName-EdgeSubscription.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-EdgeSyncServiceConfig" -XmlOutputPath $outputPath\$orgName-EdgeSyncServiceConfig.xml

## Client access settings
Invoke-ExchangeCmdlet -Cmdlet "Get-ActiveSyncOrganizationSettings" -XmlOutputPath $outputPath\$orgName-ActiveSyncOrganizationSettings.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-MobileDeviceMailboxPolicy" -XmlOutputPath $outputPath\$orgName-MobileDeviceMailboxPolicy.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-ActiveSyncDeviceAccessRule" -XmlOutputPath $outputPath\$orgName-ActiveSyncDeviceAccessRule.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-ActiveSyncDeviceAutoblockThreshold" -XmlOutputPath $outputPath\$orgName-ActiveSyncDeviceAutoblockThreshold.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-ClientAccessArray" -XmlOutputPath $outputPath\$orgName-ClientAccessArray.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-OwaMailboxPolicy" -XmlOutputPath $outputPath\$orgName-OwaMailboxPolicy.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-ThrottlingPolicy" -XmlOutputPath $outputPath\$orgName-ThrottlingPolicy.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-IRMConfiguration" -XmlOutputPath $outputPath\$orgName-IRMConfiguration.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-OutlookProtectionRule" -XmlOutputPath $outputPath\$orgName-OutlookProtectionRule.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-OutlookProvider" -XmlOutputPath $outputPath\$orgName-OutlookProvider.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-ClientAccessRule" -XmlOutputPath $outputPath\$orgName-ClientAccessRule.xml

## Mailbox server settings
Invoke-ExchangeCmdlet -Cmdlet "Get-RetentionPolicyTag" -XmlOutputPath $outputPath\$orgName-RetentionPolicyTag.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-RetentionPolicy" -XmlOutputPath $outputPath\$orgName-RetentionPolicy.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-SiteMailbox" -XmlOutputPath $outputPath\$orgName-SiteMailbox.xml

## Address book settings
Invoke-ExchangeCmdlet -Cmdlet "Get-AddressBookPolicy" -XmlOutputPath $outputPath\$orgName-AddressBookPolicy.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-GlobalAddressList" -XmlOutputPath $outputPath\$orgName-GlobalAddressList.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-AddressList" -XmlOutputPath $outputPath\$orgName-AddressList.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-OfflineAddressBook" -XmlOutputPath $outputPath\$orgName-OfflineAddressBook.xml

## Administration settings
Invoke-ExchangeCmdlet -Cmdlet "Get-AdminAuditLogConfig" -XmlOutputPath $outputPath\$orgName-AdminAuditLogConfig.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-ManagementRole" -XmlOutputPath $outputPath\$orgName-ManagementRole.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-ManagementRoleEntry" -XmlOutputPath $outputPath\$orgName-ManagementRoleEntry.xml -Identity "*\*"
Invoke-ExchangeCmdlet -Cmdlet "Get-ManagementRoleAssignment" -XmlOutputPath $outputPath\$orgName-ManagementRoleAssignment.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-RoleGroup" -XmlOutputPath $outputPath\$orgName-RoleGroup.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-ManagementScope" -XmlOutputPath $outputPath\$orgName-ManagementScope.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-RoleAssignmentPolicy" -XmlOutputPath $outputPath\$orgName-RoleAssignmentPolicy.xml

## Federation settings
Invoke-ExchangeCmdlet -Cmdlet "Get-FederationTrust" -XmlOutputPath $outputPath\$orgName-FederationTrust.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-FederatedOrganizationIdentifier" -XmlOutputPath $outputPath\$orgName-FederatedOrganizationIdentifier.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-SharingPolicy" -XmlOutputPath $outputPath\$orgName-SharingPolicy.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-OrganizationRelationship" -XmlOutputPath $outputPath\$orgName-OrganizationRelationship.xml

## Availability service
Invoke-ExchangeCmdlet -Cmdlet "Get-IntraOrganizationConnector" -XmlOutputPath $outputPath\$orgName-IntraOrganizationConnector.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-IntraOrganizationConfiguration" -XmlOutputPath $outputPath\$orgName-IntraOrganizationConfiguration.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-AvailabilityAddressSpace" -XmlOutputPath $outputPath\$orgName-AvailabilityAddressSpace.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-AvailabilityConfig" -XmlOutputPath $outputPath\$orgName-AvailabilityConfig.xml

## General settings
Invoke-ExchangeCmdlet -Cmdlet "Get-OrganizationConfig" -XmlOutputPath $outputPath\$orgName-OrganizationConfig.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-AuthConfig" -XmlOutputPath $outputPath\$orgName-AuthConfig.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-AuthServer" -XmlOutputPath $outputPath\$orgName-AuthServer.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-HybridConfiguration" -XmlOutputPath $outputPath\$orgName-HybridConfiguration.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-MigrationEndpoint" -XmlOutputPath $outputPath\$orgName-MigrationEndpoint.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-PartnerApplication" -XmlOutputPath $outputPath\$orgName-PartnerApplication.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-PolicyTipConfig" -XmlOutputPath $outputPath\$orgName-PolicyTipConfig.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-RMSTemplate" -XmlOutputPath $outputPath\$orgName-RMSTemplate.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-SmimeConfig" -XmlOutputPath $outputPath\$orgName-SmimeConfig.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-DlpPolicy" -XmlOutputPath $outputPath\$orgName-DlpPolicy.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-DlpPolicyTemplate" -XmlOutputPath $outputPath\$orgName-DlpPolicyTemplate.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-GlobalMonitoringOverride" -XmlOutputPath $outputPath\$orgName-GlobalMonitoringOverride.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-DomainController" -XmlOutputPath $outputPath\$orgName-DomainController.xml

## AD settings
Invoke-ExchangeCmdlet -Cmdlet "Get-ADSite" -XmlOutputPath $outputPath\$orgName-ADSite.xml
Invoke-ExchangeCmdlet -Cmdlet "Get-AdSiteLink" -XmlOutputPath $outputPath\$orgName-AdSiteLink.xml

## Convert the XML into CSV files
Write-Verbose "Converting XML files into CSV files."
Get-ChildItem $outputPath -Filter *.xml | ForEach-Object { Import-Clixml $_.FullName | Export-Csv $outputPath\$($_.BaseName).csv -NoTypeInformation -Force }
Get-ChildItem $outputPath -Filter *.xml | Remove-Item
#Zip the results
$ts = Get-Date -f yyyyMMddHHmmss
[string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$orgName-OrgSettings-$ts.zip"
## Zip the results and sent to the location where the script was started
Zip-CsvResults
$zipReady = $false
$zipAttempt = 1
while($zipReady -eq $false) {
    Write-Verbose "Compressing the results into a zip file for upload."
    if(Get-Item -Path $zipFolder -ErrorAction Ignore) { 
        $zipReady = $true 
        Write-Verbose "Compression completed successfully."
        Write-EventLog -LogName Application -Source "MSExchange ADAccess" -EntryType Information -EventId 1007 -Message "The SfMC Exchange Organization discovery script has completed." -Category 1
    }
    else {
        Start-Sleep -Seconds 10
        Write-Verbose "Compression failed."
        if($zipAttempt -gt 4) { $zipReady = $true }
        else {
            Zip-CsvResults
            $zipAttempt++
        }
    }
}


# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAyZE+o/2hkCqPn
# 65U+hSQGPjPJxjhTfdoj3W/uuYQo2qCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFvtC/Lm1U8t3NDWGH6X+1Zm
# AiPSw8nmGEx7V5TMmtQmMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAPV9q3jXa14vZAxrGbSSKEaI3dicN7LrW64UvCf0iwU2GzrerE9DDK
# Ub/3G4xDNSsydCdfOTxprskhGYlvDQDXHuOq9VBM+qozV3sUzcQodcxjrycFe2KC
# E6L2ojpJKqNlxI+vCBa0DSpmlNZND1YzsZBUzuGKTR56vJcaFHv6G26UDeGKd1hq
# TWI4USy6TYqqSGriXpiOT2Y52Wa0CzSnJhJBWnStRKfzc0me2CBCSn8hk9wsVR6M
# LggZd66sRSo/+eR/oDh4d7wEahr+7f/HSpD8eIhqp0i4K4LR4f5JPZ0WrkcLI0vJ
# lz3j7ZecW2JhaVXFbgEWAvsDoxueWtRboYIXDDCCFwgGCisGAQQBgjcDAwExghb4
# MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIOHex8dOtoVLj7ioopzTSBw9skSjzuJ0DlKTrcTvUT1hAgZjEUcv
# 2LUYEzIwMjIwOTA5MTc1NTA1LjIwNlowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0
# NjJGLUUzMTktM0YyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABpAfP44+jum/WAAEAAAGkMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTExOFoXDTIzMDUxMTE4NTExOFowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0NjJGLUUzMTktM0Yy
# MDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMBHjgD6FPy81PUhcOIVGh4bOSaq634Y
# +TjW2hNF9BlnWxLJCEuMiV6YF5x6YTM7T1ZLM6NnH0whPypiz3bVZRmwgGyTURKf
# VyPJ89R3WaZ/HMvcAJZnCMgL+mOpxE94gwQJD/qo8UquOrCKCY/fcjchxV8yMkfI
# qP69HnWfW0ratk+I2GZF2ISFyRtvEuxJvacIFDFkQXj3H+Xy9IHzNqqi+g54iQjO
# AN6s3s68mi6rqv6+D9DPVPg1ev6worI3FlYzrPLCIunsbtYt3Xw3aHKMfA+SH8CV
# 4iqJ/eEZUP1uFJT50MAPNQlIwWERa6cccSVB5mN2YgHf8zDUqQU4k2/DWw+14iLk
# wrgNlfdZ38V3xmxC9mZc9YnwFc32xi0czPzN15C8wiZEIqCddxbwimc+0LtPKand
# RXk2hMfwg0XpZaJxDfLTgvYjVU5PXTgB10mhWAA/YosgbB8KzvAxXPnrEnYg3XLW
# kgBZ+lOrHvqiszlFCGQC9rKPVFPCCsey356VhfcXlvwAJauAk7V0nLVTgwi/5ILy
# HffEuZYDnrx6a+snqDTHL/ZqRsB5HHq0XBo/i7BVuMXnSSXlFCo3On8IOl8JOKQ4
# CrIlri9qWJYMxsSICscotgODoYOO4lmXltKOB0l0IAhEXwSSKID5QAa9wTpIagea
# 2hzjI6SUY1W/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU4tATn6z4CBL2xZQd0jjN
# 6SnjJMIwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEACVYcUNEMlyTuPDBGhiZ1U548ssF6J2g9QElWEb2cZ4dL0+5G
# 8721/giRtTPvgxQhDF5rJCjHGj8nFSqOE8fnYz9vgb2YclYHvkoKWUJODxjhWS+S
# 06ZLR/nDS85HeDAD0FGduAA80Q7vGzknKW2jxoNHTb74KQEMWiUK1M2PDN+eISPX
# PhPudGVGLbIEAk1Goj5VjzbQuLKhm2Tk4a22rkXkeE98gyNojHlBhHbb7nex3zGB
# TBGkVtwt2ud7qN2rcpuJhsJ/vL/0XYLtyOk7eSQZdfye0TT1/qj18iSXHsIXDhHO
# uTKqBiiatoo4Unwk7uGyM0lv38Ztr+YpajSP+p0PEMRH9RdfrKRm4bHV5CmOTIzA
# mc49YZt40hhlVwlClFA4M+zn3cyLmEGwfNqD693hD5W3vcpnhf3xhZbVWTVpJH1C
# PGTmR4y5U9kxwysK8VlfCFRwYUa5640KsgIv1tJhF9LXemWIPEnuw9JnzHZ3iSw5
# dbTSXp9HmdOJIzsO+/tjQwZWBSFqnayaGv3Y8w1KYiQJS8cKJhwnhGgBPbyan+E5
# D9TyY9dKlZ3FikstwM4hKYGEUlg3tqaWEilWwa9SaNetNxjSfgah782qzbjTQhwD
# gc6Jf07F2ak0YMnNJFHsBb1NPw77dhmo9ki8vrLOB++d6Gm2Z/jDpDOSst8wggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCCAjsCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo0NjJGLUUzMTktM0YyMDElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUANBwo4pNrfEL6
# DVo+tw96vGJvLp+ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAObFqMQwIhgPMjAyMjA5MDkxNTU3NTZaGA8yMDIy
# MDkxMDE1NTc1NlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5sWoxAIBADAKAgEA
# AgIaLAIB/zAHAgEAAgIRHzAKAgUA5sb6RAIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBAIH4BJvxs0xbCoohxyySYH8C44LDiY6p2j6ckRFJYM8yHYLCwuIPhokQ
# RzwtnT1D3qW6UtoWfro9xRhOhot1fTvV4ZZLHMajE2IzJu932z55NoAGdv1FxPqj
# 7A2DFpQIGm4oujni1SYcatYus3w+Q0aCxqu5NdPiTkI7Z2xSxFZYMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGkB8/jj6O6
# b9YAAQAAAaQwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgVnHaD7hH9TDV2AY732M/qIQ579HTOhtL
# vvvXDjP+fqcwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAF/OCjISZwpMBJ
# 8MJ3WwMCF3qOa5YHFG6J4uHjaup5+DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABpAfP44+jum/WAAEAAAGkMCIEICQ1XhUQ6ZX4BBGy
# y2fGQGe/XU94PIqR8mHseffLv9QBMA0GCSqGSIb3DQEBCwUABIICAAC9cgIY3oCc
# 59c3c5b1kUvILtflGDZ/4rrzby+qiRbwrTCAABlD+dOxaoUOGPsKBfL5BIZcQalG
# 3vJG8uNxwdoTghDDn1TJmUsB5IkglZEShIPf0bNAyyApYPH0/5V5jQlhpnhLchoc
# wOBX4oMabnV0qLxfSlEgjnseYDQTRwHjdZyMd6DD1pd92wnXFbD3q0qtx8F4EYx5
# ub2CASF5lIn/ywG46VvRZayaLgztuWRsNV8kIKavVkcMdZ123FjKlq7Q1y0TR8wp
# JiG07lW4uWLqlnChYT8euhYN7TtFjERqezSFtaXJTtPc7cXMrK5RCAG27IjaspfA
# oEPXG8fkzUKG98+aA7r+uzCosbVSfBEGqdWDFqpuokihx8mFJz32mrFzUVChVen7
# +8/jv8qBiLTfhYIqBQy8n2lDp6+jRdvNphJGyxoqWM6o1xawP5D5pOR8ZO+CW1jT
# Os8FVW07ISSbNa8w6eXdCP1l30yB9Xh2nkNW7LTM/ghTpL4Wb6y6t91g9CIXd84F
# S1ColuQkb5zgvwTS8WPqe3SyMSeAQhdQVylqIgg5BOo+HW0+uqCDmE1y1Cy7DIEa
# grd9Vej9U1DMougy9nvz6JTXdLA1Apk3UQB8i6Ce9zh1GsqPnuJuDUimtFRSllcH
# b6wzSQ3P3Zf+VlNH6bZuJzimSnaxByvF
# SIG # End signature block
