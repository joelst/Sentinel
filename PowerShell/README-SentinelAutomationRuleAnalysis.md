# Sentinel automation rule export and analysis

Use `Export-SentinelAutomationRuleAnalysis.ps1` to export Microsoft Sentinel automation rules and identify likely overlap or conflict candidates for review.

## Prerequisites

- PowerShell 7 recommended.
- `Az.Accounts` 2.13.0 or later.
- Authenticated Azure session:

```powershell
Install-Module Az.Accounts -MinimumVersion 2.13.0 -Scope CurrentUser
Connect-AzAccount
```

For multi-tenant accounts:

```powershell
Connect-AzAccount -Tenant "<tenant-id>"
```

## Least privilege

The script is read-only. Use **Microsoft Sentinel Reader** or **Reader** scoped to the Log Analytics workspace or its resource group. Contributor, Responder, and Owner are not required.

## Run

```powershell
./Scripts/Export-SentinelAutomationRuleAnalysis.ps1 `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<sentinel-workspace>" `
  -OutputDirectory ".\AutomationRuleAssessment"
```

Optional:

```powershell
./Scripts/Export-SentinelAutomationRuleAnalysis.ps1 `
  -TenantId "<tenant-id>" `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<sentinel-workspace>" `
  -OutputDirectory ".\AutomationRuleAssessment" `
  -IncludeDisabled
```

## Outputs

- Raw rule JSON
- Normalized rule JSON
- Rule summary CSV
- Findings JSON
- Findings CSV
- Markdown report

## Findings generated

- Enabled expired rules
- Broad rules with actions and no conditions
- Multiple rules with the same trigger and order
- Duplicate scope and actions
- Overlapping rules that mutate the same fields
- Overlapping rules that run different playbooks
- Overlapping status changes and playbook execution

## Interpretation

Findings are review candidates, not proof that rules are wrong. The script uses static and syntactic comparison, so it can miss semantic overlaps such as one rule matching `High` severity and another matching `High` or `Medium`. Use the report to prioritize SOC engineering review.
