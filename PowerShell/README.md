# PowerShell for Sentinel, Defender, Azure Monitor, Log Analytics Workspaces

Included here are some PowerShell scripts used for Sentinel / Defender / Log Analytics

- [Export-AzMonitorTable](https://github.com/joelst/Sentinel/blob/main/PowerShell/Export-AzMonitorTable.ps1) Export data from Azure Monitor (Log Analytics) to JSON files and upload to Azure Storage. There is a 100 second limit on returning data from Log Analytics using the
     Invoke-AzOperationalInsightsQuery cmdlet. This script will export data in 12 hour increments to avoid this limitation. This script provides methods for reducing the 
     scope of the query to return the data within the 100 second limit.
- [Export-SentinelTablev1](https://github.com/joelst/Sentinel/blob/main/PowerShell/Export-SentinelTable-v1.ps1) (Original Version) Export data from Azure Monitor (Log Analytics) to JSON files and upload to Azure Storage. There is a 100 second limit on returning data from Log Analytics using the
     Invoke-AzOperationalInsightsQuery cmdlet. This script will export data in 12 hour increments to avoid this limitation. This script provides methods for reducing the 
     scope of the query to return the data within the 100 second limit.
