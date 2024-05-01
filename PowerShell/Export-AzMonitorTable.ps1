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
    The Azure Tenant ID (GUID) for the Azure Subscription.
.PARAMETER SubscriptionId
    The Azure Subscription ID (GUID) for the Azure Monitor (Sentinel) workspace and the Azure Storage Account.
.PARAMETER WorkspaceId
    The Log Analytics Workspace ID (GUID).
.PARAMETER WorkspaceResourceGroup
    The resource group where the Log Analytics Workspace is located.
.PARAMETER WorkspaceName
    The Log Analytics Workspace name.
.PARAMETER AzureStorageAccountName
    The name of the Azure Storage Account to upload the data to.
.PARAMETER AzureStorageAccountResourceGroup
    The resource group for the Azure Storage Account.
.PARAMETER AzureStoragePath
    Specify a path starting with the storage container name for where to store the exported data to override the default path. Example: storage-container-name/sentinelExport/2024/
.PARAMETER StandardBlobTier
    Specify the storage tier to store the uploaded file content. Can be Hot, Cool, Archive, or Cold. 
.PARAMETER HourIncrements
    The number of hours to get data for in each iteration. This should be evenly divisible by 24. The default is 12 hours. To specify increments in minutes, use fractions of an hour [1/60, 2/60, 3/60...]. You cannot specify a time less than one minute.
.PARAMETER LogPath
    The path to write the log file. The default is the export path.
.PARAMETER DoNotUpload
    Specify this switch to disable upload the data to Azure Storage.
.PARAMETER DoNotCompress
    Specify this switch to disable compressing the JSON file using Zip compression.
.EXAMPLE
    .\Export-AzMonitorTable.ps1 -TableName "DeviceInfo" -ExportPath "C:\ExportTables" -StartDate "1/1/2023" -EndDate "1/11/2023" -TenantId "00000000-0000-0000-0000-000000000000" -SubscriptionId "00000000-0000-0000-0000-000000000000" -WorkspaceId "00000000-0000-0000-0000-000000000000" -AzureStorageAccountName "storageaccountname" -AzureStorageAccountResourceGroup "resourcegroupname" -HourIncrements 12 -LogPath "C:\SentinelTables"
    
#>
[CmdletBinding()]
param (
    [array]$TableName = "DeviceInfo",
    $ExportPath = (Join-Path "C:/" "ExportedTables"),
    [datetime]$StartDate = "4/1/2024",
    [datetime]$EndDate = "4/11/2024",
    [guid]$TenantId,
    [guid]$SubscriptionId,
    [guid]$WorkspaceId,
    [string]$WorkspaceResourceGroup = "",
    [string]$WorkspaceName = "",
    [string]$AzureStorageAccountName = "",
    [string]$AzureStorageAccountResourceGroup = "",
    [string]$AzureStoragePath,
    [string][ValidateSet('Hot', 'Cool', 'Archive', 'Cold')]$StandardBlobTier = "Hot",
    [decimal]$HourIncrements = 24,
    [string]$LogPath = $ExportPath,
    [switch]$DoNotUpload,
    [switch]$DoNotCompress
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


function Test-IsGuid {
    param (
        [Parameter(Mandatory = $true)]
        [string]$StringGuid
    )
    $ObjectGuid = [System.Guid]::empty
    return [System.Guid]::TryParse($StringGuid, [System.Management.Automation.PSReference]$ObjectGuid)
}

function Read-ValidatedHost
{
<#
.SYNOPSIS
    Gets validated user input and ensures that it is not empty. It will continue to prompt until valid text is provided.
.PARAMETER Prompt
    Text that will be displayed to user
.PARAMETER ValidationType
    Specify 'NotNull' to check for a non-null response and 'Confirm' to make sure the response is Y/Yes or N/No.
.PARAMETER MinLength
    Specifies the minimum number of characters the input value can be. The default is 1.
.PARAMETER MaxLength
    Specifies the maximum number of characters the input value can be. The default is 1024.
#>

[OutputType([string])]
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true,Position=0)]
    [string]
    $Prompt,
    [ValidateSet("NotNull","Confirm","Guid")]
    [Parameter(Mandatory=$false,Position=1)]
    [string]
    $ValidationType="NotNull",
    $MinLength = 1,
    $MaxLength = 1024
)
    # Add a blank line before the prompt
    Write-Host ""
    $returnString = ""
    if ($ValidationType -eq "NotNull")
    {

        do
        {
            $returnString = Read-Host -Prompt $Prompt
        } while (($returnString -eq "") -or ($returnString.Length -lt $MinLength) -or ($returnString.Length -gt $MaxLength))           
        return $returnString
    }
    elseif ($ValidationType -eq "Confirm")
    {
        do
        {
            try
            {
                [ValidateSet("Y","Yes","N","No")]$returnString = Read-Host -Prompt $Prompt
            } 
            catch {

            }
        } until ($?)

        if (($returnString -eq "Yes") -or ($returnString -eq "Y"))
        {
            $returnString = "y"
        }
        else
        {
            $returnString = "n"
        } 
        
        return $returnString

    }
    elseif ($ValidationType -eq "Guid"){
        do
        {
            $returnString = Read-Host -Prompt $Prompt

    } while (-not (Test-IsGuid $returnString))           
    return $returnString
    }
    else{
        return ""
    
    }
}

# This was an attempt to set the maximum idle time for the service point to 10 minutes (600000 milliseconds) instead of the default 1000 milliseconds.
[System.Net.ServicePointManager]::MaxServicePointIdleTime = 600000

# Validate all parameters have been provided, if not prompt for them.
if (-not $TableName) {
    $TableName = Read-ValidatedHost -Prompt "Enter the table name"
}
if (-not $ExportPath) {
    $ExportPath = Read-ValidatedHost -Prompt "Enter the local export path"
}
if (-not $StartDate) {
    $StartDate = Read-ValidatedHost -Prompt "Enter the start date (MM/dd/yyyy)"
}
if (-not $EndDate) {
    $EndDate = Read-ValidatedHost -Prompt "Enter the end date (MM/dd/yyyy)"
}
if (-not $TenantId) {
    [guid]$TenantId = Read-ValidatedHost -Prompt "Enter the Azure Tenant ID (GUID)" -ValidationType Guid
}
else {
    if (-not (Test-IsGuid $TenantId)){
        [guid]$TenantId = Read-ValidatedHost -Prompt "Enter the Azure Tenant ID (GUID)" -ValidationType Guid
    }
}

if (-not $SubscriptionId) {
    [guid]$SubscriptionId = Read-ValidatedHost -Prompt "Enter the Azure Subscription ID (GUID)" -ValidationType Guid
}
else {
    if (-not (Test-IsGuid $SubscriptionId)){
        [guid]$SubscriptionId = Read-ValidatedHost -Prompt "Enter the Azure Subscription ID (GUID)" -ValidationType Guid
    }
}
if (-not $WorkspaceId) {
    [guid]$WorkspaceId = Read-ValidatedHost "Enter the Log Analytics Workspace ID" -ValidationType Guid
}
else {
    if (-not (Test-IsGuid $WorkspaceId)) {
    }
}

# If the DoNotUpload parameter is set to $true, the AzureStorageAccountName, and AzureStorageAccountResourceGroup parameters are not required.
if ($false -eq $DoNotUpload.IsPresent) {
    if (-not $AzureStorageAccountName) {
        $AzureStorageAccountName = Read-ValidatedHost "Enter the Azure Storage Account name:"
    }
    if (-not $AzureStorageAccountResourceGroup) {
        $AzureStorageAccountResourceGroup = Read-ValidatedHost "Enter the Azure Storage Account resource group"
    }
    if (-not $StandardBlobTier) {
        $StandardBlobTier = Read-ValidatedBlobTierHost "Enter a blob tier [Hot/Cool/Archive/Cold]"
    }
    if (-not $WorkspaceResourceGroup) {
        $WorkspaceResourceGroup = Read-ValidatedHost "Enter the Sentinel workspace resource group name"
    }
    if (-not $WorkspaceName) {
        $WorkspaceName = Read-ValidatedHost "Enter the Sentinel workspace name"
    }
}

if (-not $HourIncrements) {
    [decimal]$HourIncrements = Read-ValidatedHost "Enter the number of hours to get data for in each iteration (must be divisable by 24. To specify increments in minutes, use fractions of an hour [1/60, 2/60, 3/60...])"
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
    $currentDate = $StartDate
    # Loop through each timespan in the range
    for ($i = 0; $i -lt $hours; $i = $i + $HourIncrements) {
        
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
            $currentDate = $nextDate
            continue
        }
        elseif ((Test-Path $outputJsonFile) -or (Test-Path $outputOldJsonFileName)) {
            Write-Log "$outputJsonFile exists. Skipping." -Severity Information
            $currentDate = $nextDate
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

                            $blobPath = "WorkspaceResourceId=/subscriptions/$SubscriptionId/resourcegroups/$($WorkspaceResourceGroup.ToLower())/providers/microsoft.operationalinsights/workspaces/$($WorkspaceName.ToLower())/y=$($currentDate.ToString("yyyy"))/m=$($currentDate.ToString("MM"))/d=$($currentDate.ToString("dd"))/h=$($currentDate.ToString("HH"))/m=$($currentDate.ToString("mm"))/$($timeSpanFileName)"                                

                        }
                        Write-Log "BlobPath: $blobPath" -Severity Debug

                        $result = Set-AzStorageBlobContent -Context $context -Container $azureStorageContainer -File $outputZipFile -Blob $blobPath -Force -ErrorAction Continue -AsJob
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
        # Assign this so that we start where we left off for the next run.
        $currentDate = $nextDate
        Write-Log " Azure Blob copy jobs running: $((Get-Job -Command "Set-AzStorageBlobContent" -ErrorAction SilentlyContinue | Where-Object {$_.State -eq "Running"}).Count)" -Severity Information
    }
}
