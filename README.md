SfMC-Discovery-Script

This PowerShell script is used to collect Exchange configuration information from the environment. 

Requirements
The SfMC-Discovery.ps1 script requires an account Exchange organization management permissions. The script will connect to the Exchange servers in the environment using this account to start the Get-ExchangeServerDiscovery.ps1 and Get-ExchangeOrgDiscovery.ps1 scripts locally.

How To Run
This syntax will collect all the recommended configuration information, including HealthChecker results:

.\SfMC-Discovery.ps1 -ExchangeServer conex1.contoso.com -Credential (Get-Credential) -OutputPath C:\Temp\Results -HealthChecker

This syntax will collect configuration information for all members of the database availability group named DAG1:

.\SfMC-Discovery.ps1 -ExchangeServer conex1.contoso.com -Credential (Get-Credential) -OutputPath C:\Temp\Results -DagName DAG1 -OrgSettings:$False

This syntax will collect only the Exchange organization settings:

.\SfMC-Discovery.ps1 -ExchangeServer conex1.contoso.com -Credential (Get-Credential) -OutputPath C:\Temp\Results -ServerSettings:$False


Parameters

ExchangeServer - The ExchangeServer parameter specifies the Exchange server for the remote PowerShell session.

Credential - The Credential parameter specifies the Exchange administrator credentials used for data collection.

ServerName - The ServerName parameter specifies the Exchange server for data collection.

DagName - The DagName parameter specifies the database availability group for Exchange server data collection.
    
ADSite - The ADSite parameter specifies the AD site for Exchange server data collection.

OutputPath - The OutputPath parameter specifies the directory where the results are written.

OrgSettigns - The OrgSettings parameter enables or disables the collection of Exchange organization settings.

ServerSettings - The ServerSettings parameter enables or disables the collection of Exchange server settings.

HealthChecker - The HealthChecker parameter is a switch to determine if HealthChecker data is collected.
