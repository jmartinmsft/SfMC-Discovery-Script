# Support for Mission Critical Discovery

This is a data collection script for the discovery assessment performed by the Exchange SfMC team.

## Description
This script collect data from the on-premises Exchange enivronment. Here's a high-level overview how the script works:

1. The SfMC-Discovery script is run to initiate the collection of data from the Exchange servers.
2. The Get-ExchangeOrgDiscovery script is copied into the Scripts folder on the Exchange server specified. A scheduled task is created on that Exchange server to trigger the data collection locally on the server.
3. The Get-ExchangeServerDiscovery script is copied into the Scripts folder on the Exchange servers selected. A scheduled task is create on each Exchange server to trigger the data collection locally on the server.
4. The script checks each server for the results and copies them from the Exchange server to the local machine.
5. All the results are compressed into a single file to share with the Exchange CSA.

## Requirements
1. The script requires PowerShell version 5.0 or later.
2. An account with Organization Management role (This account has local admin rights to Exchange server to copy files and create the scheduled task.)

## Notes
1. The SfMC-Discovery script can be run from a workstation or an Exchange server. The Credential parameter is not required when running from an Exchange server as it will run as the currently logged in user.
2. Full qualified domain names (FQDNs) should be used for server names.

## Usage
Collect data for the entire Exchange organization (Recommended):
```powershell
.\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results
```
Collect data for a single Database Availability Group:
```powershell
.\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -DagName E19DAG1 -OutputPath c:\Temp\Results
```
Collect only the Exchange organization settings:
```powershell
.\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results -ServerSettings:$False
```

## Parameters

**ExchangeServer** - The ExchangeServer parameter specifies the Exchange server for the remote PowerShell session.

**Credential** - The Credential parameter specifies the Exchange administrator credentials used for data collection.

**ServerName** - The ServerName parameter specifies the Exchange server for data collection.

**DagName** - The DagName parameter specifies the database availability group for Exchange server data collection.

**ADSite** - The ADSite parameter specifies the AD site for Exchange server data collection.

**OutputPath** - The OutputPath parameter specifies the directory where the results are written.

**OrgSettings** - The OrgSettings parameter enables or disables the collection of Exchange organization settings.

**ServerSettings** - The ServerSettings parameter enables or disables the collection of Exchange server settings.

**HealthChecker** - The HealthChecker switch enables the HealthChecker data to be collected.