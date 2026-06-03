<#
.SYNOPSIS
Exports Microsoft Sentinel automation rules and identifies likely overlaps or conflicts.

.DESCRIPTION
Read-only script that uses Azure Resource Manager to export automation rules
from a Microsoft Sentinel workspace, then performs static analysis for
governance issues such as duplicate scope, overlapping conditions, same-order
rules, broad actions, enabled expired rules, and rules that mutate the same
incident fields in conflicting ways.

The analysis is intentionally conservative: findings are candidates for human
review, not proof that a rule is wrong. The absence of findings does not prove
there are no conflicts because condition overlap detection is syntactic.

.PARAMETER SubscriptionId
Azure subscription ID that contains the Sentinel workspace.

.PARAMETER ResourceGroupName
Resource group that contains the Log Analytics workspace.

.PARAMETER WorkspaceName
Log Analytics workspace name for Microsoft Sentinel.

.PARAMETER TenantId
Optional tenant ID. Useful when your account has access to multiple tenants.

.PARAMETER OutputDirectory
Directory where exported rules and analysis files are written.

.PARAMETER ApiVersion
Microsoft.SecurityInsights automationRules API version.

.PARAMETER IncludeDisabled
Include disabled automation rules in overlap/conflict analysis. Disabled rules
are always exported, but excluded from findings by default.

.EXAMPLE
./Scripts/Export-SentinelAutomationRuleAnalysis.ps1 `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -ResourceGroupName "rg-sentinel-prod" `
  -WorkspaceName "law-sentinel-prod" `
  -OutputDirectory ".\AutomationRuleAssessment"

.EXAMPLE
./Scripts/Export-SentinelAutomationRuleAnalysis.ps1 `
  -TenantId "11111111-1111-1111-1111-111111111111" `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -ResourceGroupName "rg-sentinel-prod" `
  -WorkspaceName "law-sentinel-prod" `
  -IncludeDisabled

.NOTES
Prerequisites:
  Install-Module Az.Accounts -MinimumVersion 2.13.0 -Scope CurrentUser
  Connect-AzAccount

Least privilege:
  The script is read-only. Use Microsoft Sentinel Reader or Reader scoped to
  the Log Analytics workspace or resource group. Contributor, Responder, and
  Owner are not required.

Known limitations:
  Overlap detection is static and syntactic. It finds likely candidates for
  review but cannot prove that rules never conflict at runtime.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$OutputDirectory = ".\SentinelAutomationRuleExport",

    [Parameter()]
    [string]$ApiVersion = "2024-03-01",

    [Parameter()]
    [switch]$IncludeDisabled
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-CanonicalJson {
    param([AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) {
        return "null"
    }

    if ($InputObject -is [string] -or $InputObject -is [bool] -or $InputObject -is [int] -or $InputObject -is [long] -or $InputObject -is [double] -or $InputObject -is [decimal]) {
        return ($InputObject | ConvertTo-Json -Compress)
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in ($InputObject.Keys | Sort-Object)) {
            $ordered[$key] = ConvertFrom-Json -InputObject (ConvertTo-CanonicalJson -InputObject $InputObject[$key])
        }
        return ($ordered | ConvertTo-Json -Depth 50 -Compress)
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ConvertFrom-Json -InputObject (ConvertTo-CanonicalJson -InputObject $item)
        }
        return ($items | ConvertTo-Json -Depth 50 -Compress)
    }

    return ($InputObject | ConvertTo-Json -Depth 50 -Compress)
}

function Get-PropertyValue {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($PropertyName)) {
        return $Object[$PropertyName]
    }

    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Get-ConditionTokens {
    param([AllowNull()][object[]]$Conditions)

    $tokens = New-Object System.Collections.Generic.List[string]

    foreach ($condition in @($Conditions)) {
        if ($null -eq $condition) {
            continue
        }

        $conditionType = Get-PropertyValue -Object $condition -PropertyName "conditionType"
        $props = Get-PropertyValue -Object $condition -PropertyName "conditionProperties"

        $propertyName = Get-PropertyValue -Object $props -PropertyName "propertyName"
        $operator = Get-PropertyValue -Object $props -PropertyName "operator"
        $propertyValues = Get-PropertyValue -Object $props -PropertyName "propertyValues"

        if ($null -ne $propertyValues) {
            $values = @($propertyValues) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object
            $token = "{0}|{1}|{2}|{3}" -f $conditionType, $propertyName, $operator, ($values -join ",")
        }
        else {
            $token = "{0}|{1}" -f $conditionType, (ConvertTo-CanonicalJson -InputObject $props)
        }

        $tokens.Add($token.ToLowerInvariant())
    }

    return @($tokens | Sort-Object -Unique)
}

function Test-Subset {
    param(
        [string[]]$CandidateSubset,
        [string[]]$CandidateSuperset
    )

    foreach ($item in @($CandidateSubset)) {
        if ($CandidateSuperset -notcontains $item) {
            return $false
        }
    }

    return $true
}

function Get-ActionSummary {
    param([AllowNull()][object[]]$Actions)

    $actionTypes = New-Object System.Collections.Generic.List[string]
    $mutatedFields = New-Object System.Collections.Generic.List[string]
    $playbookIds = New-Object System.Collections.Generic.List[string]
    $rawTokens = New-Object System.Collections.Generic.List[string]

    foreach ($action in @($Actions)) {
        if ($null -eq $action) {
            continue
        }

        $actionType = Get-PropertyValue -Object $action -PropertyName "actionType"
        $config = Get-PropertyValue -Object $action -PropertyName "actionConfiguration"
        $actionTypes.Add(("$actionType").ToLowerInvariant())
        $rawTokens.Add((ConvertTo-CanonicalJson -InputObject $action).ToLowerInvariant())

        switch -Regex ("$actionType") {
            "RunPlaybook" {
                $logicAppResourceId = Get-PropertyValue -Object $config -PropertyName "logicAppResourceId"
                if ([string]::IsNullOrWhiteSpace($logicAppResourceId)) {
                    $logicAppResourceId = Get-PropertyValue -Object $config -PropertyName "playbookResourceId"
                }
                if (-not [string]::IsNullOrWhiteSpace($logicAppResourceId)) {
                    $playbookIds.Add($logicAppResourceId.ToLowerInvariant())
                }
            }
            "ModifyProperties" {
                foreach ($field in @("classification", "classificationComment", "classificationReason", "labels", "owner", "severity", "status", "tasks", "title")) {
                    if ($null -ne (Get-PropertyValue -Object $config -PropertyName $field)) {
                        $mutatedFields.Add($field.ToLowerInvariant())
                    }
                }
            }
            "AddIncidentTask" {
                $mutatedFields.Add("tasks")
            }
            default {
                if ($null -ne $config) {
                    foreach ($property in $config.PSObject.Properties.Name) {
                        if ($property -match "status|severity|owner|label|tag|task|classification") {
                            $mutatedFields.Add($property.ToLowerInvariant())
                        }
                    }
                }
            }
        }
    }

    return [pscustomobject]@{
        ActionTypes = @($actionTypes | Sort-Object -Unique)
        MutatedFields = @($mutatedFields | Sort-Object -Unique)
        PlaybookIds = @($playbookIds | Sort-Object -Unique)
        ActionFingerprint = (@($rawTokens | Sort-Object) -join "||")
    }
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [string]$Severity,
        [string]$FindingType,
        [string]$RuleA,
        [AllowNull()][string]$RuleB,
        [string]$Rationale,
        [string]$Recommendation
    )

    $Findings.Add([pscustomobject]@{
        Severity = $Severity
        FindingType = $FindingType
        RuleA = $RuleA
        RuleB = $RuleB
        Rationale = $Rationale
        Recommendation = $Recommendation
    })
}

function ConvertTo-MarkdownCell {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrEmpty($Value)) {
        return ""
    }

    return (($Value -replace "`r?`n", " ") -replace "\|", "\|")
}

function Test-Prerequisites {
    $minimumAzAccountsVersion = [version]"2.13.0"
    $azAccountsModule = Get-Module -ListAvailable -Name Az.Accounts |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if ($null -eq $azAccountsModule) {
        throw "Az.Accounts module is required. Install with: Install-Module Az.Accounts -MinimumVersion $minimumAzAccountsVersion -Scope CurrentUser"
    }

    if ($azAccountsModule.Version -lt $minimumAzAccountsVersion) {
        throw "Az.Accounts $minimumAzAccountsVersion or later is required. Installed version: $($azAccountsModule.Version). Update with: Install-Module Az.Accounts -MinimumVersion $minimumAzAccountsVersion -Scope CurrentUser -Force"
    }

    if ($PSVersionTable.PSVersion -lt [version]"7.0") {
        Write-Warning "PowerShell 7.0 or later is recommended. Current version: $($PSVersionTable.PSVersion)."
    }
}

function Invoke-AzPagedGet {
    param([Parameter(Mandatory = $true)][string]$Path)

    $items = New-Object System.Collections.Generic.List[object]
    $nextPath = $Path

    while (-not [string]::IsNullOrWhiteSpace($nextPath)) {
        $response = Invoke-AzRestMethod -Method GET -Path $nextPath
        if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
            if ($response.StatusCode -eq 403) {
                throw "ARM request returned 403 Forbidden. Confirm the signed-in identity has Microsoft Sentinel Reader or Reader on the workspace/resource group. Response: $($response.Content)"
            }

            throw "ARM request failed with status $($response.StatusCode): $($response.Content)"
        }

        $body = $response.Content | ConvertFrom-Json -Depth 100
        foreach ($item in @($body.value)) {
            $items.Add($item)
        }

        $nextLink = Get-PropertyValue -Object $body -PropertyName "nextLink"
        if ([string]::IsNullOrWhiteSpace($nextLink)) {
            $nextPath = $null
        }
        else {
            $uri = [Uri]$nextLink
            $nextPath = $uri.PathAndQuery
        }
    }

    return @($items)
}

Test-Prerequisites
Import-Module Az.Accounts -ErrorAction Stop

$currentContext = Get-AzContext -ErrorAction SilentlyContinue
if ($null -eq $currentContext -or $null -eq $currentContext.Account) {
    $tenantHint = if ([string]::IsNullOrWhiteSpace($TenantId)) { "" } else { " -Tenant '$TenantId'" }
    throw "No Azure session found. Run Connect-AzAccount$tenantHint before running this script."
}

try {
    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    }
    else {
        Set-AzContext -SubscriptionId $SubscriptionId -Tenant $TenantId -ErrorAction Stop | Out-Null
    }
}
catch {
    $tenantMessage = if ([string]::IsNullOrWhiteSpace($TenantId)) { "" } else { " in tenant '$TenantId'" }
    throw "Unable to set Azure context to subscription '$SubscriptionId'$tenantMessage. Confirm you are signed in with Connect-AzAccount and have at least Reader or Microsoft Sentinel Reader on the target workspace. Original error: $($_.Exception.Message)"
}

$workspaceResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
$automationRulesPath = "$workspaceResourceId/providers/Microsoft.SecurityInsights/automationRules?api-version=$ApiVersion"

New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null

Write-Host "Exporting Sentinel automation rules from $WorkspaceName..."
$rules = Invoke-AzPagedGet -Path $automationRulesPath

$normalizedRules = foreach ($rule in $rules) {
    $properties = Get-PropertyValue -Object $rule -PropertyName "properties"
    $displayName = Get-PropertyValue -Object $properties -PropertyName "displayName"
    $order = Get-PropertyValue -Object $properties -PropertyName "order"
    $triggeringLogic = Get-PropertyValue -Object $properties -PropertyName "triggeringLogic"
    $actions = Get-PropertyValue -Object $properties -PropertyName "actions"
    $conditions = Get-PropertyValue -Object $triggeringLogic -PropertyName "conditions"
    $isEnabled = [bool](Get-PropertyValue -Object $triggeringLogic -PropertyName "isEnabled")
    $triggersOn = Get-PropertyValue -Object $triggeringLogic -PropertyName "triggersOn"
    $triggersWhen = Get-PropertyValue -Object $triggeringLogic -PropertyName "triggersWhen"
    $expirationTimeUtc = Get-PropertyValue -Object $triggeringLogic -PropertyName "expirationTimeUtc"
    $conditionArray = if ($null -eq $conditions) { @() } else { @($conditions) }
    $actionArray = if ($null -eq $actions) { @() } else { @($actions) }
    $conditionTokens = @(Get-ConditionTokens -Conditions $conditionArray)
    $actionSummary = Get-ActionSummary -Actions $actionArray

    [pscustomobject]@{
        Id = Get-PropertyValue -Object $rule -PropertyName "id"
        Name = Get-PropertyValue -Object $rule -PropertyName "name"
        DisplayName = $displayName
        Enabled = $isEnabled
        Order = $order
        TriggersOn = $triggersOn
        TriggersWhen = $triggersWhen
        ExpirationTimeUtc = $expirationTimeUtc
        ConditionCount = $conditionArray.Count
        ActionCount = $actionArray.Count
        ConditionTokens = $conditionTokens
        ConditionFingerprint = ($conditionTokens -join "||")
        ActionTypes = $actionSummary.ActionTypes
        MutatedFields = $actionSummary.MutatedFields
        PlaybookIds = $actionSummary.PlaybookIds
        ActionFingerprint = $actionSummary.ActionFingerprint
        ScopeFingerprint = ("{0}|{1}|{2}" -f $triggersOn, $triggersWhen, ($conditionTokens -join "||")).ToLowerInvariant()
        RawRule = $rule
    }
}

$analysisRules = @($normalizedRules | Where-Object { $IncludeDisabled -or $_.Enabled })
$findings = New-Object System.Collections.Generic.List[object]

foreach ($rule in $analysisRules) {
    if ($rule.Enabled -and -not [string]::IsNullOrWhiteSpace($rule.ExpirationTimeUtc)) {
        $expiration = [datetimeoffset]::Parse($rule.ExpirationTimeUtc, [System.Globalization.CultureInfo]::InvariantCulture).UtcDateTime
        if ($expiration -lt (Get-Date).ToUniversalTime()) {
            Add-Finding -Findings $findings -Severity "High" -FindingType "EnabledExpiredRule" -RuleA $rule.DisplayName -RuleB $null `
                -Rationale "Rule is enabled but expirationTimeUtc is in the past: $($rule.ExpirationTimeUtc)." `
                -Recommendation "Disable or delete the rule, or update the expiration after confirming it is still required."
        }
    }

    if ($rule.ConditionCount -eq 0 -and ($rule.ActionTypes -contains "runplaybook" -or $rule.MutatedFields.Count -gt 0)) {
        Add-Finding -Findings $findings -Severity "Medium" -FindingType "BroadRuleWithActions" -RuleA $rule.DisplayName -RuleB $null `
            -Rationale "Rule has no conditions but performs incident changes or runs automation." `
            -Recommendation "Add narrow conditions, or confirm this is an intentional global policy with clear ownership and monitoring."
    }
}

$sameOrderGroups = $analysisRules |
    Group-Object -Property TriggersOn, TriggersWhen, Order |
    Where-Object { $_.Count -gt 1 -and $null -ne $_.Group[0].Order }

foreach ($group in $sameOrderGroups) {
    $names = @($group.Group.DisplayName) -join "; "
    Add-Finding -Findings $findings -Severity "Medium" -FindingType "SameOrderSameTrigger" -RuleA $names -RuleB $null `
        -Rationale "Multiple rules share the same trigger and order. Execution may still be deterministic internally, but the design is hard to reason about." `
        -Recommendation "Assign unique order values within the same trigger family and document the intended sequencing."
}

for ($i = 0; $i -lt $analysisRules.Count; $i++) {
    for ($j = $i + 1; $j -lt $analysisRules.Count; $j++) {
        $a = $analysisRules[$i]
        $b = $analysisRules[$j]

        if ($a.TriggersOn -ne $b.TriggersOn -or $a.TriggersWhen -ne $b.TriggersWhen) {
            continue
        }

        if ($a.ConditionCount -eq 0 -or $b.ConditionCount -eq 0) {
            continue
        }

        $sameScope = $a.ScopeFingerprint -eq $b.ScopeFingerprint
        $aSubsetB = Test-Subset -CandidateSubset $a.ConditionTokens -CandidateSuperset $b.ConditionTokens
        $bSubsetA = Test-Subset -CandidateSubset $b.ConditionTokens -CandidateSuperset $a.ConditionTokens
        $overlappingScope = $sameScope -or $aSubsetB -or $bSubsetA

        if (-not $overlappingScope) {
            continue
        }

        if ($sameScope -and $a.ActionFingerprint -eq $b.ActionFingerprint) {
            Add-Finding -Findings $findings -Severity "Medium" -FindingType "DuplicateScopeAndActions" -RuleA $a.DisplayName -RuleB $b.DisplayName `
                -Rationale "Rules have the same trigger, conditions, and action fingerprint." `
                -Recommendation "Consolidate duplicate rules or document why both are required."
            continue
        }

        $commonMutatedFields = @($a.MutatedFields | Where-Object { $b.MutatedFields -contains $_ })
        if ($commonMutatedFields.Count -gt 0) {
            Add-Finding -Findings $findings -Severity "High" -FindingType "OverlappingScopeMutatesSameFields" -RuleA $a.DisplayName -RuleB $b.DisplayName `
                -Rationale "Rules can match overlapping incident scope and both mutate: $($commonMutatedFields -join ', ')." `
                -Recommendation "Review priority order, conditions, and whether field updates should be consolidated into one rule or moved into playbook logic."
        }

        if (($a.ActionTypes -contains "runplaybook") -and ($b.ActionTypes -contains "runplaybook") -and $a.ActionFingerprint -ne $b.ActionFingerprint) {
            Add-Finding -Findings $findings -Severity "Medium" -FindingType "OverlappingScopeRunsDifferentPlaybooks" -RuleA $a.DisplayName -RuleB $b.DisplayName `
                -Rationale "Rules can match overlapping incident scope and run different playbooks." `
                -Recommendation "Confirm both playbooks are safe to run together, or use tags/conditions/order to make the paths mutually exclusive."
        }

        if (($a.MutatedFields -contains "status" -and $b.ActionTypes -contains "runplaybook") -or ($b.MutatedFields -contains "status" -and $a.ActionTypes -contains "runplaybook")) {
            Add-Finding -Findings $findings -Severity "Medium" -FindingType "StatusChangeAndPlaybookOverlap" -RuleA $a.DisplayName -RuleB $b.DisplayName `
                -Rationale "One overlapping rule changes status while another runs a playbook." `
                -Recommendation "Ensure status changes do not close, suppress, or reroute incidents before dependent playbooks complete."
        }
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$rawPath = Join-Path $OutputDirectory "sentinel-automation-rules-raw-$timestamp.json"
$normalizedPath = Join-Path $OutputDirectory "sentinel-automation-rules-normalized-$timestamp.json"
$csvPath = Join-Path $OutputDirectory "sentinel-automation-rules-summary-$timestamp.csv"
$findingsJsonPath = Join-Path $OutputDirectory "sentinel-automation-rule-findings-$timestamp.json"
$findingsCsvPath = Join-Path $OutputDirectory "sentinel-automation-rule-findings-$timestamp.csv"
$markdownPath = Join-Path $OutputDirectory "sentinel-automation-rule-analysis-$timestamp.md"

$rules | ConvertTo-Json -Depth 100 | Set-Content -Path $rawPath -Encoding UTF8
$normalizedExport = $normalizedRules | Select-Object Id, Name, DisplayName, Enabled, Order, TriggersOn, TriggersWhen, ExpirationTimeUtc, ConditionCount, ActionCount, ConditionTokens, ConditionFingerprint, ActionTypes, MutatedFields, PlaybookIds, ActionFingerprint, ScopeFingerprint
$normalizedExport | ConvertTo-Json -Depth 100 | Set-Content -Path $normalizedPath -Encoding UTF8

$normalizedRules |
    Select-Object DisplayName, Enabled, Order, TriggersOn, TriggersWhen, ExpirationTimeUtc, ConditionCount, ActionCount,
        @{Name = "ActionTypes"; Expression = { $_.ActionTypes -join ";" }},
        @{Name = "MutatedFields"; Expression = { $_.MutatedFields -join ";" }},
        @{Name = "PlaybookIds"; Expression = { $_.PlaybookIds -join ";" }},
        Id |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$findings | ConvertTo-Json -Depth 20 | Set-Content -Path $findingsJsonPath -Encoding UTF8
$findings | Export-Csv -Path $findingsCsvPath -NoTypeInformation -Encoding UTF8

$severityCounts = $findings | Group-Object Severity | Sort-Object Name
$markdown = New-Object System.Collections.Generic.List[string]
$markdown.Add("# Microsoft Sentinel automation rule analysis")
$markdown.Add("")
$markdown.Add("- Workspace: $WorkspaceName")
$markdown.Add("- Resource group: $ResourceGroupName")
$markdown.Add("- Subscription: $SubscriptionId")
$markdown.Add("- Exported rules: $($normalizedRules.Count)")
$markdown.Add("- Rules analyzed: $($analysisRules.Count)")
$markdown.Add("- Findings: $($findings.Count)")
$markdown.Add("")
$markdown.Add("## Finding counts")
$markdown.Add("")
if ($severityCounts.Count -eq 0) {
    $markdown.Add("No findings generated.")
}
else {
    $markdown.Add("| Severity | Count |")
    $markdown.Add("| --- | ---: |")
    foreach ($count in $severityCounts) {
        $markdown.Add("| $($count.Name) | $($count.Count) |")
    }
}
$markdown.Add("")
$markdown.Add("## Findings")
$markdown.Add("")
if ($findings.Count -eq 0) {
    $markdown.Add("No overlap or conflict candidates found by static analysis.")
}
else {
    $markdown.Add("| Severity | Type | Rule A | Rule B | Rationale | Recommendation |")
    $markdown.Add("| --- | --- | --- | --- | --- | --- |")
    foreach ($finding in $findings) {
        $ruleB = if ([string]::IsNullOrWhiteSpace($finding.RuleB)) { "" } else { $finding.RuleB }
        $markdown.Add("| $(ConvertTo-MarkdownCell $finding.Severity) | $(ConvertTo-MarkdownCell $finding.FindingType) | $(ConvertTo-MarkdownCell $finding.RuleA) | $(ConvertTo-MarkdownCell $ruleB) | $(ConvertTo-MarkdownCell $finding.Rationale) | $(ConvertTo-MarkdownCell $finding.Recommendation) |")
    }
}
$markdown.Add("")
$markdown.Add("## Review guidance")
$markdown.Add("")
$markdown.Add("- Treat findings as candidates for SOC engineering review, not automatic defects.")
$markdown.Add("- Prioritize High findings where overlapping rules mutate the same fields or expired enabled rules remain active.")
$markdown.Add("- Consolidate rules that differ only by small value lists into watchlists, lookup tables, or playbook logic.")
$markdown.Add("- Keep clear, isolated policies as separate rules when that improves ownership and auditability.")
$markdown.Add("- Re-run this export after rule changes and before major incident-routing or playbook updates.")

$markdown | Set-Content -Path $markdownPath -Encoding UTF8

Write-Host ""
Write-Host "Export complete."
Write-Host "Raw rules:        $rawPath"
Write-Host "Normalized rules: $normalizedPath"
Write-Host "Rule summary:     $csvPath"
Write-Host "Findings JSON:    $findingsJsonPath"
Write-Host "Findings CSV:     $findingsCsvPath"
Write-Host "Markdown report:  $markdownPath"
