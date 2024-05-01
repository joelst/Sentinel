#requires -version 7 -modules Az.OperationalInsights
<#
 THIS SCRIPT IS PROVIDED AS-IS. NO WARRANTY IS EXPRESSED OR IMPLIED. 
 
.SYNOPSIS
    Export data from Azure Monitor (Log Analytics) to JSON files and upload to Azure Storage. There is a 100 second limit on returning data from Log Analytics using the
     Invoke-AzOperationalInsightsQuery cmdlet. This script will export data in 12 hour increments to avoid this limitation. This script provides methods for reducing the 
     scope of the query to return the data within the 100 second limit.
.DESCRIPTION
    This script exports data from Azure Monitor (Log Analytics) to JSON files and uploads the files to Azure Storage. 
    The script requires the Azure Tenant ID, Azure Subscription ID, Log Analytics Workspace ID, Azure Storage Account name, 
    Azure Storage Container name, and Azure Storage Account resource group. 
.PARAMETER TableName
    The table name(s) to export data.
.PARAMETER ExportPath
    The local path to export the data files to.
.PARAMETER StartDate
    The start date to export data from. Should be in the format MM/dd/yyyy.
.PARAMETER EndDate
    The end date to export data to. Should be in the format MM/dd/yyyy.
.PARAMETER TenantId
    The Azure Tenant ID for the Azure Subscription.
.PARAMETER SubscriptionId
    The Azure Subscription ID for the Azure Monitor (Sentinel) workspace and the Azure Storage Account.
.PARAMETER WorkspaceId
    The Log Analytics Workspace ID.
.PARAMETER AzureStorageAccountName
    The name of the Azure Storage Account to upload the data to.
.PARAMETER AzureStorageContainer
    The name of the Azure Storage Container to upload the data to.
.PARAMETER AzureStorageAccountResourceGroup
    The resource group for the Azure Storage Account.
.PARAMETER HourIncrements
    The number of hours to get data for in each iteration. This must be evenly divisible by 24. The default is 12 hours.
.PARAMETER DoNotUpload
    Set to $true to not upload the data to Azure Storage.
.PARAMETER LogPath
    The path to write the log file. The default is the export path.
.EXAMPLE
    .\Export-AzMonitorTable.ps1 -TableName "DeviceInfo" -ExportPath "C:\ExportTables" -StartDate "1/1/2023" -EndDate "1/11/2023" -TenantId "00000000-0000-0000-0000-000000000000" -SubscriptionId "00000000-0000-0000-0000-000000000000" -WorkspaceId "00000000-0000-0000-0000-000000000000" -AzureStorageAccountName "storageaccountname" -AzureStorageContainer "containername" -AzureStorageAccountResourceGroup "resourcegroupname" -HourIncrements 12 -LogPath "C:\SentinelTables"
    #>
[CmdletBinding()]
param (
    # The table name(s) to export data. This can be a single table or an array of tables.
    [array]$TableName = "DeviceInfo",
    # The local path to export data files to.
    $ExportPath = (Join-Path "C:/" "ExportedTables"),
    # The start date to export data from, should be in the format MM/dd/yyyy
    [datetime]$StartDate = "4/1/2024",
    # The end date to export data to, should be in the format MM/dd/yyyy
    [datetime]$EndDate = "4/11/2024",
    $TenantId = "",
    # The Azure Subscription ID for Sentinel and the Azure Storage Account
    $SubscriptionId = "",
    # The Log Analytics Workspace ID for Sentinel
    $WorkspaceId = "",
    # The name of the Azure Storage Account to upload the data to
    $AzureStorageAccountName = "",
    # The resource group for the Azure Storage Account
    $AzureStorageAccountResourceGroup = "",
    # You can specify a specific storage path. If you do not specify one, the default path will be used.
    [string]$AzureStoragePath,
    # Blob Storage tier to write the data
    [ValidateSet('Hot', 'Cool', 'Archive', 'Cold')]$StandardBlobTier = "Hot",
    # The number of hours to get data for in each iteration. This should be evenly divisible by 24. The default is 12 hours. It can be as low as 1/60 (one minute).
    $HourIncrements = 24,
    # The path to write the log file. The default is the export path.
    $LogPath = $ExportPath,
    # Specify if you do not upload the data to Azure Storage
    [switch]$DoNotUpload,
    # Specify if you do not want to compress the JSON file.
    [switch]$DoNotCompress,
    # Sentinel workspace resource group.
    [string]$SentinelResourceGroup = "",
    # Sentinel workspace name.
    [string]$SentinelWorkspaceName = ""
)

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Debug', 'Information', 'Warning', 'Error', 'Test')]
        [string]
        $Severity = "Information",
        $LogFilePath = $Script:LogFilePath
    )
    
    if ([string]::IsNullOrWhiteSpace($LogFilePath)) {    
        $LogFilePath = Join-Path (Get-Location) "$(Get-Date -f yy.MM).log"
    }
    switch ($Severity) {
        Debug { 
            Write-Verbose $Message
        }
        Warning { 
            Write-Warning $Message
            $Script:logContent += "<p>$Message</p>`n"
        }
        Error { 
            Write-Error $Message
            $Script:logContent += "<p>$Message</p>`n"
        }
        Information { 
            Write-Output $Message
            $Script:logContent += "<p>$Message</p>`n"
        }
        Test { 
            Write-Host " [TestOnly] $Message" -ForegroundColor Green
            
        } 
        Default { 
            Write-Host $Message
        }
    }

    $null = [pscustomobject]@{
        Time     = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
        Message  = $Message.Replace("`n", '').Replace("`t", '').Replace("``", '').Replace('""', '"_empty"')
        Severity = $Severity
    } | Export-Csv -Path $LogFilePath -Append -NoTypeInformation -Force -ErrorAction SilentlyContinue
} 

function Read-ValidatedBlobTierHost {
    <#
.SYNOPSIS
    Gets validated user input. It will continue to prompt until valid text is provided.
.PARAMETER Prompt
    Text that will be displayed to user
#>
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Prompt
    )
    # Add a blank line before the prompt
    Write-Host ""
    $returnString = ""
    do {
        try {
            [ValidateSet('Hot', 'Cool', 'Archive', 'Cold')]
            $returnString = Read-Host -Prompt $Prompt
        } 
        catch {}
    } until ($?)
        
    return $returnString

}

# This was an attempt to set the maximum idle time for the service point to 10 minutes (600000 milliseconds) instead of the default 1000 milliseconds.
[System.Net.ServicePointManager]::MaxServicePointIdleTime = 600000

# Validate all parameters have been provided, if not prompt for them.
if (-not $TableName) {
    $TableName = Read-Host "Enter the table name:"
}
if (-not $ExportPath) {
    $ExportPath = Read-Host "Enter the local export path:"
}
if (-not $StartDate) {
    $StartDate = Read-Host "Enter the start date (MM/dd/yyyy):"
}
if (-not $EndDate) {
    $EndDate = Read-Host "Enter the end date (MM/dd/yyyy):"
}
if (-not $TenantId) {
    $TenantId = Read-Host "Enter the Azure Tenant ID:"
}
if (-not $SubscriptionId) {
    $SubscriptionId = Read-Host "Enter the Azure Subscription ID:"
}
if (-not $WorkspaceId) {
    $WorkspaceId = Read-Host "Enter the Log Analytics Workspace ID:"
}

# If the DoNotUpload parameter is set to $true, the AzureStorageAccountName, and AzureStorageAccountResourceGroup parameters are not required.
if ($false -eq $DoNotUpload.IsPresent) {
    if (-not $AzureStorageAccountName) {
        $AzureStorageAccountName = Read-Host "Enter the Azure Storage Account name:"
    }
    if (-not $AzureStorageAccountResourceGroup) {
        $AzureStorageAccountResourceGroup = Read-Host "Enter the Azure Storage Account resource group:"
    }
    if (-not $StandardBlobTier) {
        $StandardBlobTier = Read-ValidatedBlobTierHost "Enter a blob tier [Hot/Cool/Archive/Cold]:"
    }
    if (-not $SentinelResourceGroup) {
        $SentinelResourceGroup = Read-Host "Enter the Sentinel workspace resource group name:"
    }
    if (-not $SentinelWorkspaceName) {
        $SentinelWorkspaceName = Read-Host "Enter the Sentinel workspace name:"
    }
}

if (-not $HourIncrements) {
    $HourIncrements = Read-Host "Enter the number of hours to get data for in each iteration (must be divisable by 24):"
}

# Authenticate to Azure
Write-Log "Authenticating to Azure." -Severity Information
$null = Connect-AzAccount -TenantId $TenantId -Subscription $SubscriptionId | Out-Null

# Get the Azure Storage Account context if the DoNotUpload parameter is set to $false.
if ($false -eq $DoNotUpload.IsPresent) {
    $context = (Get-AzStorageAccount -ResourceGroupName $AzureStorageAccountResourceGroup -Name $AzureStorageAccountName).Context
}
# Create the export path if it does not exist.
if (!(Test-Path $ExportPath)) { 
    $null = New-Item -ItemType Directory -Path $ExportPath
} 

# Loop to get data for one day at a time but for the entire range specified by $StartDate and $EndDate and $EndDate
$EndDate = $EndDate.AddDays(1)
# Calculate the number of hours between the start and end dates
$hours = ($EndDate - $StartDate).TotalHours

# Loop through all tables specified
foreach ($table in $TableName) {
    if ($AzureStoragePath) {

        $azureStorageContainer = $AzureStoragePath.Split("/")[0]
    }
    else {
        $azureStorageContainer = "am-$($table.ToLower())"
    }
    # Try to create the storage container, trying to create it again won't do anything.
    $null = New-AzStorageContainer -Name $azureStorageContainer -Context $context -ErrorAction SilentlyContinue | Out-Null

    # Set the log file path for the current table.
    $Script:LogFilePath = Join-Path $LogPath "$table-$(Get-Date -f yy.MM).log"
        
    # Loop through each timespan in the range
    for ($i = 0; $i -lt $hours; $i = $i + $HourIncrements) {

        # Calculate the current date based on the start date and the loop index
        if (-not $currentDate) {
            $currentDate = $StartDate.AddHours($i)
        }
        
        $nextDate = $currentDate.AddHours($HourIncrements)

        # If there is a fraction that doesn't result in exact minute increments, round up to a whole minute.
        if ($nextDate.Second -ne 0) {
            $nextDate = $nextDate.AddSeconds(-$nextDate.Second)
            $nextDate = $nextDate.AddMinutes(1)
        }
        
        # If the hour increments were not even, the nextDate might be past the EndDate. If that happens just use the EndDate
        if ($nextDate -gt $EndDate) {
            $nextDate = $EndDate
        }

        # Construct the file names for the current date
        $jsonFileName = "$table-$($currentDate.ToString('yyyy-MM-dd-HHmm'))-$($nextDate.ToString('yyyy-MM-dd-HHmm')).json"
        $outputJsonFile = Join-Path $ExportPath $jsonFileName
        # Added to support previous longer file name
        $outputOldJsonFileName = Join-Path $ExportPath "$table-$($currentDate.ToString('yyyy-MM-dd-HHmm'))-$($nextDate.ToString('yyyy-MM-dd-HHmm')).json"

        $zipFileName = "$table-$($currentDate.ToString('yyyy-MM-dd-HHmm'))-$($nextDate.ToString('yyyy-MM-dd-HHmm')).json.zip"
        $outputZipFile = Join-Path $ExportPath $zipFileName
        # Added to support previous longer file names
        $outputOldZipFileName = Join-Path $ExportPath "$table-$($currentDate.ToString('yyyy-MM-dd-HHmm'))-$($nextDate.ToString('yyyy-MM-dd-HHmm')).json.zip"
        
        # if the file already exists, skip querying the data
        if ((Test-Path $outputZipFile) -or (Test-Path $outputOldZipFileName)) {
            Write-Log "$outputZipFile exists. Skipping." -Severity Information
            continue
        }
        elseif ((Test-Path $outputJsonFile) -or (Test-Path $outputOldJsonFileName)) {
            Write-Log "$outputJsonFile exists. Skipping." -Severity Information
            continue
        }
        else {
        
            # Construct the query for the current date
            $currentQuery = $table
            $currentTimeSpan = New-TimeSpan -Start $currentDate -End $nextDate
            Write-Log "Getting data from $currentQuery for $currentDate to $nextDate"
            # Get the Table data from Log Analytics for the current date
            $currentTableResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $currentQuery -wait 600 -Timespan $currentTimeSpan | Select-Object Results -ExpandProperty Results -ExcludeProperty Results
            
            if ($? -eq $false) {
                Write-Log -Message "Error: $table from $currentDate to $nextDate $($error.Exception) " -Severity Error
                Write-Log -Message "Debug: EXCEPTION: $($error.Exception) `n CATEGORY: $($error.CategoryInfo) `n ERROR ID: $($error.FullyQualifiedErrorId) `n SCRIPT STACK TRACE: $($error.ScriptStackTrace)" -Severity Debug
                continue
            }

            # Write file for the current date
            if (($currentTableResult | Measure-Object).Count -ge 1) {
                # output Json file with query response.
                $currentTableResult | ConvertTo-json -Depth 100 -Compress | Out-File $outputJsonFile -Force
        
                if ((Test-Path $outputJsonFile) -and ($DoNotCompress.IsPresent -eq $false)) {
                    $outputJsonFile | Compress-Archive -DestinationPath $outputZipFile -Force
                }
                else {
                    $outputZipFile = $outputJsonFile 
                }
        
                if (Test-Path $outputZipFile) {    

                    if ($DoNotCompress.IsPresent -eq $false) {
                        # Remove the JSON file if the zip file was created.  
                        $null = Remove-Item $outputJsonFile -Force  
                    }   

                    # upload the zip file to Azure Storage
                    if ($false -eq $DoNotUpload.IsPresent) {

                        if ($AzureStoragePath) {
                            if ($DoNotCompress.IsPresent) {
                                $blobPath = "$($AzureStoragePath)/$($outputJsonFile)"
                            }
                            else {
                                $blobPath = "$($AzureStoragePath)/$($outputZipFile)"
                            }
                        }
                        else {
                            if ($DoNotCompress.IsPresent) {
                                $timeSpanFileName = "$([System.Xml.XmlConvert]::ToString($currentTimeSpan)).json"
                            } 
                            else {
                                $timeSpanFileName = "$([System.Xml.XmlConvert]::ToString($currentTimeSpan)).json.zip"
                            }

                            $blobPath = "WorkspaceResourceId=/subscriptions/$SubscriptionId/resourcegroups/$($SentinelResourceGroup.ToLower())/providers/microsoft.operational.insights/workspaces/$($SentinelWorkspaceName.ToLower())/y=$($currentDate.ToString("yyyy"))/m=$($currentDate.ToString("MM"))/d=$($currentDate.ToString("dd"))/h=$($currentDate.ToString("HH"))/m=$($currentDate.ToString("mm"))/$($timeSpanFileName)"                                

                        }
                        Write-Log "BlobPath: $blobPath" -Severity Debug

                        $result = Set-AzStorageBlobContent -Context $context -Container $azureStorageContainer -File $outputZipFile -Blob $blobPath -Force -ErrorAction Continue
                        if ($result) {
                            Write-Log " File $outputZipFile uploaded to Azure Storage" -Severity Debug
                        }
                        else {
                            Write-Log " Failed to upload $outputZipFile to Azure Storage" -Severity Error
                        }
                    }
                }
                else {
                    Write-Log " Failed to create file $outputZipFile" -Severity Debug
                }       
            }
            else {
                Write-Log -Message "    No data returned for $table from $currentDate to $nextDate" -Severity Information
            }
        }
        $currentDate = $nextDate
    }
}
