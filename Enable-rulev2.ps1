<#
.SYNOPSIS
Safely deploy Microsoft Sentinel analytics rules from Rule templates.

.DESCRIPTION
Guided option 0 lists Azure subscriptions and Log Analytics workspaces visible
to the current Azure identity. Discovery is read-only and restores the original
Azure context before returning to the main menu.

The script supports three deployment modes:

  Validate - Read-only preflight and deployment plan. No Sentinel rule is changed.
  Canary   - Create or update only one or two rule resources.
  Full     - Create or update every planned rule. Requires -ApproveFullDeployment.

Activation is controlled separately. The default Preserve mode creates new rules
disabled and preserves the enabled state of existing rules. Enabling rules requires
-ActivationMode Enabled and -ApproveActivation.

Every API operation and deployment checkpoint is written to a JSONL production log.
The plan, journal, and snapshots of existing rules are kept in the output directory.
There is intentionally no automatic rollback because a Sentinel deployment is not
transactional. A stopped run can be resumed safely with -ResumeStatePath.

.EXAMPLE
.\Enable-rules.ps1

Starts the guided production rollout wizard. This is the recommended interactive
entry point and the only command an operator needs to remember.

.EXAMPLE
.\Enable-rules.ps1 -SubscriptionId <SUB-ID> -ResourceGroupName <RG> `
  -WorkspaceName <WORKSPACE> -Prefix SOC -DeploymentMode Validate

.EXAMPLE
.\Enable-rules.ps1 -SubscriptionId <SUB-ID> -ResourceGroupName <RG> `
  -WorkspaceName <WORKSPACE> -Prefix SOC -DeploymentMode Canary -CanaryCount 2 `
  -ActivationMode Preserve -Verbose

.EXAMPLE
.\Enable-rules.ps1 -SubscriptionId <SUB-ID> -ResourceGroupName <RG> `
  -WorkspaceName <WORKSPACE> -Prefix SOC -DeploymentMode Full `
  -ActivationMode Preserve -ApproveFullDeployment

.EXAMPLE
.\Enable-rules.ps1 -SubscriptionId <SUB-ID> -ResourceGroupName <RG> `
  -WorkspaceName <WORKSPACE> -Prefix SOC -DeploymentMode Canary -CanaryCount 2 `
  -ActivationMode Enabled -ApproveActivation

.NOTES
Requires : PowerShell 7.4.x or later
Module   : Az.Accounts
API      : Microsoft Sentinel REST API 2025-09-01
Discovery: Azure Resource Graph REST API 2024-04-01
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Position = 0, HelpMessage = 'Azure Subscription ID')]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Position = 1, HelpMessage = 'Resource Group containing Microsoft Sentinel')]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Position = 2, HelpMessage = 'Log Analytics Workspace name')]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceName,

    [Parameter(Position = 3, HelpMessage = 'Deprecated; all available rule templates are evaluated')]
    [string]$SolutionName,

    [Parameter(Position = 4, HelpMessage = 'Prefix added before the analytics rule display name')]
    [AllowEmptyString()]
    [string]$Prefix = 'SOC',

    [Parameter(HelpMessage = 'Validate is read-only, Canary changes 1-2 rules, Full evaluates all rules')]
    [ValidateSet('Validate', 'Canary', 'Full')]
    [string]$DeploymentMode = 'Validate',

    [Parameter(HelpMessage = 'Maximum number of rule resources changed in Canary mode')]
    [ValidateRange(1, 2)]
    [int]$CanaryCount = 2,

    [Parameter(HelpMessage = 'Maximum entity mappings accepted by the target analytics rule API')]
    [ValidateRange(1, 10)]
    [int]$MaxEntityMappings = 10,

    [Parameter(HelpMessage = 'Optional template IDs to target in Validate or Canary mode')]
    [string[]]$TemplateId,

    [Parameter(HelpMessage = 'Preserve keeps existing state and creates new rules disabled')]
    [ValidateSet('Preserve', 'Disabled', 'Enabled')]
    [string]$ActivationMode = 'Preserve',

    [Parameter(HelpMessage = 'Required before Full mode can write to Sentinel')]
    [switch]$ApproveFullDeployment,

    [Parameter(HelpMessage = 'Required before rules can be enabled')]
    [switch]$ApproveActivation,

    [Parameter(HelpMessage = 'Stop immediately or continue after an individual rule failure')]
    [ValidateSet('Stop', 'Continue')]
    [string]$FailurePolicy = 'Continue',

    [Parameter(HelpMessage = 'Directory for JSONL logs, plan, journal, and snapshots')]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'deployment-logs'),

    [Parameter(HelpMessage = 'Local JSON file for saved non-secret target defaults')]
    [ValidateNotNullOrEmpty()]
    [string]$SettingsPath = (Join-Path $PSScriptRoot '.sentinel-deployment-settings.json'),

    [Parameter(HelpMessage = 'Journal from an interrupted run; successful identical payloads are skipped')]
    [string]$ResumeStatePath,

    [Parameter(HelpMessage = 'Include complete request payloads in logs; queries may contain sensitive data')]
    [switch]$LogPayload,

    [Parameter(HelpMessage = 'Maximum retries for HTTP 429 and 5xx responses')]
    [ValidateRange(0, 10)]
    [int]$MaxRetryCount = 4,

    [Parameter(HelpMessage = 'Microsoft Sentinel REST API version')]
    [ValidateNotNullOrEmpty()]
    [string]$ApiVersion = '2025-09-01',

    [Parameter(HelpMessage = 'Microsoft Sentinel REST API version used for NRT rule list and deployment')]
    [ValidateNotNullOrEmpty()]
    [string]$NrtApiVersion = '2025-07-01-preview',

    [Parameter(HelpMessage = 'Azure Resource Graph API version used for workspace discovery')]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGraphApiVersion = '2024-04-01',

    [Parameter(HelpMessage = 'Deprecated compatibility parameter; prefer -ActivationMode')]
    [ValidateSet('Yes', 'No')]
    [string]$EnableRules
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RunId = [guid]::NewGuid().ToString()
$script:RunStartedUtc = [datetime]::UtcNow
$script:LogPath = $null
$script:JournalPath = $null
$script:PlanPath = $null
$script:DuplicateReportPath = $null
$script:CompatibilityReportPath = $null
$script:SnapshotDirectory = $null
$script:DiscoveryReportPath = $null
$script:Cmdlet = $PSCmdlet
$script:InteractiveSession = $false
$script:SaveSettingsAfterConfirmation = $false
$script:InvocationBoundParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $script:InvocationBoundParameters[$parameterName] = $PSBoundParameters[$parameterName]
}

function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $invalidCharacters = [System.IO.Path]::GetInvalidFileNameChars()
    $escapedCharacters = [regex]::Escape((-join $invalidCharacters))
    return ($Value -replace "[$escapedCharacters]", '_')
}

function Limit-Text {
    param(
        [AllowNull()]
        [string]$Value,

        [int]$MaximumLength = 8000
    )

    if ($null -eq $Value -or $Value.Length -le $MaximumLength) {
        return $Value
    }

    return "$($Value.Substring(0, $MaximumLength))...[truncated]"
}

function Get-ObjectPropertyValue {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Read-RequiredInput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    do {
        $value = Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Host 'A value is required.' -ForegroundColor Yellow
        }
    } while ([string]::IsNullOrWhiteSpace($value))

    return $value.Trim()
}

function Get-SavedTargetSettings {
    if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) {
        return $null
    }

    try {
        $settings = Get-Content -LiteralPath $SettingsPath -Raw | ConvertFrom-Json
        $savedSubscriptionId = Get-ObjectPropertyValue -InputObject $settings -Name 'subscriptionId'
        $savedResourceGroup = Get-ObjectPropertyValue -InputObject $settings -Name 'resourceGroupName'
        $savedWorkspace = Get-ObjectPropertyValue -InputObject $settings -Name 'workspaceName'
        $savedPrefix = Get-ObjectPropertyValue -InputObject $settings -Name 'prefix'

        $parsedSubscriptionId = [guid]::Empty
        if (-not [guid]::TryParse("$savedSubscriptionId", [ref]$parsedSubscriptionId) -or
            [string]::IsNullOrWhiteSpace("$savedResourceGroup") -or
            [string]::IsNullOrWhiteSpace("$savedWorkspace")) {
            throw 'The saved target is incomplete or invalid.'
        }

        return [pscustomobject]@{
            subscriptionId   = "$savedSubscriptionId"
            resourceGroupName = "$savedResourceGroup"
            workspaceName    = "$savedWorkspace"
            prefix           = if ($null -eq $savedPrefix) { 'SOC' } else { "$savedPrefix" }
        }
    }
    catch {
        Write-Host "Saved settings could not be used: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Settings file: $SettingsPath" -ForegroundColor Yellow
        return $null
    }
}

function Save-TargetSettings {
    $fullSettingsPath = [System.IO.Path]::GetFullPath($SettingsPath)
    $settingsDirectory = [System.IO.Path]::GetDirectoryName($fullSettingsPath)
    New-Item -ItemType Directory -Path $settingsDirectory -Force | Out-Null

    $settings = [ordered]@{
        schemaVersion     = 1
        subscriptionId    = $SubscriptionId
        resourceGroupName = $ResourceGroupName
        workspaceName     = $WorkspaceName
        prefix            = $Prefix
        updatedUtc        = [datetime]::UtcNow.ToString('o')
    }

    $temporaryPath = "$fullSettingsPath.$($script:RunId).tmp"
    try {
        $settings | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $temporaryPath -Encoding utf8
        Move-Item -LiteralPath $temporaryPath -Destination $fullSettingsPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }

    Write-Host "Saved target defaults: $fullSettingsPath" -ForegroundColor Green
}

function Set-TargetValuesFromPrompt {
    param(
        [AllowNull()]
        [object]$Defaults
    )

    $defaultSubscriptionId = Get-ObjectPropertyValue -InputObject $Defaults -Name 'subscriptionId'
    $defaultResourceGroup = Get-ObjectPropertyValue -InputObject $Defaults -Name 'resourceGroupName'
    $defaultWorkspace = Get-ObjectPropertyValue -InputObject $Defaults -Name 'workspaceName'
    $defaultPrefix = Get-ObjectPropertyValue -InputObject $Defaults -Name 'prefix'

    do {
        $subscriptionPrompt = if ([string]::IsNullOrWhiteSpace("$defaultSubscriptionId")) {
            'Azure Subscription ID'
        }
        else {
            "Azure Subscription ID [$defaultSubscriptionId]"
        }
        $subscriptionInput = (Read-Host $subscriptionPrompt).Trim()
        if ([string]::IsNullOrWhiteSpace($subscriptionInput)) {
            $subscriptionInput = "$defaultSubscriptionId"
        }

        $parsedSubscriptionId = [guid]::Empty
        $validSubscriptionId = [guid]::TryParse($subscriptionInput, [ref]$parsedSubscriptionId)
        if (-not $validSubscriptionId) {
            Write-Host 'Enter a valid Azure Subscription GUID.' -ForegroundColor Yellow
        }
    } while (-not $validSubscriptionId)
    $script:SubscriptionId = $subscriptionInput

    $resourceGroupPrompt = if ([string]::IsNullOrWhiteSpace("$defaultResourceGroup")) {
        'Resource Group name'
    }
    else {
        "Resource Group name [$defaultResourceGroup]"
    }
    do {
        $resourceGroupInput = (Read-Host $resourceGroupPrompt).Trim()
        if ([string]::IsNullOrWhiteSpace($resourceGroupInput)) {
            $resourceGroupInput = "$defaultResourceGroup"
        }
        if ([string]::IsNullOrWhiteSpace($resourceGroupInput)) {
            Write-Host 'A Resource Group name is required.' -ForegroundColor Yellow
        }
    } while ([string]::IsNullOrWhiteSpace($resourceGroupInput))
    $script:ResourceGroupName = $resourceGroupInput

    $workspacePrompt = if ([string]::IsNullOrWhiteSpace("$defaultWorkspace")) {
        'Log Analytics Workspace name'
    }
    else {
        "Log Analytics Workspace name [$defaultWorkspace]"
    }
    do {
        $workspaceInput = (Read-Host $workspacePrompt).Trim()
        if ([string]::IsNullOrWhiteSpace($workspaceInput)) {
            $workspaceInput = "$defaultWorkspace"
        }
        if ([string]::IsNullOrWhiteSpace($workspaceInput)) {
            Write-Host 'A Log Analytics Workspace name is required.' -ForegroundColor Yellow
        }
    } while ([string]::IsNullOrWhiteSpace($workspaceInput))
    $script:WorkspaceName = $workspaceInput

    if ($null -eq $defaultPrefix) {
        $defaultPrefix = $Prefix
    }
    $prefixInput = (Read-Host "Rule display-name prefix [$defaultPrefix]").Trim()
    $script:Prefix = if ([string]::IsNullOrWhiteSpace($prefixInput)) {
        "$defaultPrefix"
    }
    else {
        $prefixInput
    }
}

function Set-GuidedTargetConfiguration {
    $savedSettings = Get-SavedTargetSettings
    $explicitTargetComplete =
        $script:InvocationBoundParameters.ContainsKey('SubscriptionId') -and
        $script:InvocationBoundParameters.ContainsKey('ResourceGroupName') -and
        $script:InvocationBoundParameters.ContainsKey('WorkspaceName') -and
        -not [string]::IsNullOrWhiteSpace($SubscriptionId) -and
        -not [string]::IsNullOrWhiteSpace($ResourceGroupName) -and
        -not [string]::IsNullOrWhiteSpace($WorkspaceName)

    if ($explicitTargetComplete) {
        Write-Host ''
        Write-Host 'Using target supplied on the command line.' -ForegroundColor Cyan
        if ($null -eq $savedSettings) {
            $script:SaveSettingsAfterConfirmation = $true
        }
        return
    }

    if ($null -ne $savedSettings) {
        Write-Host ''
        Write-Host 'Saved target defaults' -ForegroundColor Cyan
        Write-Host "  Subscription   : $($savedSettings.subscriptionId)"
        Write-Host "  Resource group : $($savedSettings.resourceGroupName)"
        Write-Host "  Workspace      : $($savedSettings.workspaceName)"
        Write-Host "  Rule prefix    : $($savedSettings.prefix)"
        Write-Host "  Settings file  : $SettingsPath"
        Write-Host ''
        Write-Host '  [Enter/U] Use saved defaults'
        Write-Host '  [C]       Change and save new defaults'
        Write-Host '  [O]       Use another target once'

        do {
            $targetChoice = (Read-Host 'Target selection [U]').Trim().ToUpperInvariant()
            if ([string]::IsNullOrWhiteSpace($targetChoice)) {
                $targetChoice = 'U'
            }
            if ($targetChoice -notin @('U', 'C', 'O')) {
                Write-Host 'Enter U, C, or O.' -ForegroundColor Yellow
            }
        } while ($targetChoice -notin @('U', 'C', 'O'))

        if ($targetChoice -eq 'U') {
            if (-not $script:InvocationBoundParameters.ContainsKey('SubscriptionId')) {
                $script:SubscriptionId = $savedSettings.subscriptionId
            }
            if (-not $script:InvocationBoundParameters.ContainsKey('ResourceGroupName')) {
                $script:ResourceGroupName = $savedSettings.resourceGroupName
            }
            if (-not $script:InvocationBoundParameters.ContainsKey('WorkspaceName')) {
                $script:WorkspaceName = $savedSettings.workspaceName
            }
            if (-not $script:InvocationBoundParameters.ContainsKey('Prefix')) {
                $script:Prefix = $savedSettings.prefix
            }
            return
        }

        Set-TargetValuesFromPrompt -Defaults $savedSettings
        $script:SaveSettingsAfterConfirmation = $targetChoice -eq 'C'
        return
    }

    Write-Host ''
    Write-Host 'No saved target defaults were found. Enter the target once; it will be saved after confirmation.' `
        -ForegroundColor Cyan
    $parameterDefaults = [pscustomobject]@{
        subscriptionId   = $SubscriptionId
        resourceGroupName = $ResourceGroupName
        workspaceName    = $WorkspaceName
        prefix           = $Prefix
    }
    Set-TargetValuesFromPrompt -Defaults $parameterDefaults
    $script:SaveSettingsAfterConfirmation = $true
}

function Show-GuidedWorkflow {
    Write-Host ''
    Write-Host 'Microsoft Sentinel Analytics Rule Deployment' -ForegroundColor Cyan
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Recommended production workflow:'
    Write-Host '  1. Validate        Read Azure and generate a plan. No rule is changed.'
    Write-Host '  2. Canary stage   Change one or two rules. New rules stay disabled; existing activation is preserved.'
    Write-Host '  3. Canary enable  Enable only the selected Canary rules after validation.'
    Write-Host '  4. Full stage     Deploy all remaining rules. New rules stay disabled; existing activation is preserved.'
    Write-Host '  5. Full enable    Enable all supported rules only after Canary monitoring is successful.'
    Write-Host ''
    Write-Host 'Recovery model: Azure does not provide a transaction for this rollout.'
    Write-Host 'The script writes a journal before and after every PUT. Re-run this wizard and choose option 6 to resume.'
    Write-Host 'Target defaults are stored locally without Azure credentials or access tokens.'
    Write-Host ''
}

function Set-GuidedStage {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('1', '2', '3', '4', '5')]
        [string]$Choice
    )

    switch ($Choice) {
        '1' {
            $script:DeploymentMode = 'Validate'
            $script:ActivationMode = 'Preserve'
        }
        '2' {
            $script:DeploymentMode = 'Canary'
            $script:ActivationMode = 'Preserve'
        }
        '3' {
            $script:DeploymentMode = 'Canary'
            $script:ActivationMode = 'Enabled'
            $script:ApproveActivation = [switch]$true
        }
        '4' {
            $script:DeploymentMode = 'Full'
            $script:ActivationMode = 'Preserve'
            $script:ApproveFullDeployment = [switch]$true
        }
        '5' {
            $script:DeploymentMode = 'Full'
            $script:ActivationMode = 'Enabled'
            $script:ApproveFullDeployment = [switch]$true
            $script:ApproveActivation = [switch]$true
        }
    }
}

function Confirm-GuidedRisk {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Choice
    )

    if ($Choice -in @('3', '5')) {
        Write-Host ''
        Write-Host 'WARNING: This stage enables analytics rules and can immediately generate alerts and incidents.' `
            -ForegroundColor Yellow
        $activationConfirmation = Read-Host 'Type ENABLE to approve activation'
        if ($activationConfirmation -cne 'ENABLE') {
            Write-Host 'Activation was not approved. No Azure request was sent.' -ForegroundColor Yellow
            return $false
        }
    }

    if ($Choice -in @('4', '5')) {
        Write-Host ''
        Write-Host 'WARNING: Full mode can update every supported analytics rule in the workspace.' `
            -ForegroundColor Yellow
        $fullConfirmation = Read-Host 'Type FULL to approve the full rollout'
        if ($fullConfirmation -cne 'FULL') {
            Write-Host 'Full rollout was not approved. No Azure request was sent.' -ForegroundColor Yellow
            return $false
        }
    }

    return $true
}

function Start-GuidedConfiguration {
    $script:InteractiveSession = $true
    Show-GuidedWorkflow

    while ($true) {
        Write-Host 'Choose an action:'
        Write-Host '  [0] List accessible subscriptions and Log Analytics workspaces'
        Write-Host '  [1] Validate / create a read-only plan (recommended first)'
        Write-Host '  [2] Stage a Canary deployment'
        Write-Host '  [3] Enable selected Canary rules'
        Write-Host '  [4] Stage the full deployment'
        Write-Host '  [5] Enable all rules'
        Write-Host '  [6] Resume an interrupted deployment'
        Write-Host '  [Q] Quit'
        Write-Host ''

        do {
            $choice = (Read-Host 'Selection').Trim().ToUpperInvariant()
            if ($choice -notin @('0', '1', '2', '3', '4', '5', '6', 'Q')) {
                Write-Host 'Enter 0, 1, 2, 3, 4, 5, 6, or Q.' -ForegroundColor Yellow
            }
        } while ($choice -notin @('0', '1', '2', '3', '4', '5', '6', 'Q'))

        if ($choice -ne '0') {
            break
        }

        try {
            Show-AccessibleAzureWorkspaceInventory
        }
        catch {
            if ($script:LogPath) {
                Write-DeploymentError -ErrorRecord $_ `
                    -Operation 'Accessible Azure workspace discovery' -Level 'ERROR'
                Write-Host "Discovery log: $script:LogPath" -ForegroundColor Yellow
            }
            else {
                Write-Host "Workspace discovery failed: $($_.Exception.Message)" `
                    -ForegroundColor Red
            }
        }

        Write-Host ''
        [void](Read-Host 'Press Enter to return to the main menu')
        Write-Host ''
    }

    if ($choice -eq 'Q') {
        Write-Host 'Deployment cancelled. No Azure request was sent.'
        return $false
    }

    if ($choice -eq '6') {
        $script:ResumeStatePath = Read-RequiredInput `
            -Prompt 'Path to the previous *.journal.jsonl file'
        Write-Host ''
        Write-Host 'Which interrupted stage should be resumed?'
        Write-Host '  [2] Canary stage'
        Write-Host '  [3] Canary enable'
        Write-Host '  [4] Full stage'
        Write-Host '  [5] Full enable'
        do {
            $choice = (Read-Host 'Original stage').Trim()
            if ($choice -notin @('2', '3', '4', '5')) {
                Write-Host 'Enter 2, 3, 4, or 5.' -ForegroundColor Yellow
            }
        } while ($choice -notin @('2', '3', '4', '5'))
    }

    Set-GuidedStage -Choice $choice
    if (-not (Confirm-GuidedRisk -Choice $choice)) {
        return $false
    }

    if ($DeploymentMode -eq 'Canary') {
        do {
            $canaryInput = (Read-Host 'Number of Canary rule resources [1-2, default 2]').Trim()
            if ([string]::IsNullOrWhiteSpace($canaryInput)) {
                $script:CanaryCount = 2
                break
            }

            $parsedCanaryCount = 0
            $validCanaryCount = [int]::TryParse($canaryInput, [ref]$parsedCanaryCount) -and
                $parsedCanaryCount -in @(1, 2)
            if (-not $validCanaryCount) {
                Write-Host 'Enter 1 or 2.' -ForegroundColor Yellow
            }
        } while (-not $validCanaryCount)

        if (-not [string]::IsNullOrWhiteSpace($canaryInput)) {
            $script:CanaryCount = $parsedCanaryCount
        }
    }

    Set-GuidedTargetConfiguration

    Write-Host ''
    Write-Host 'Selected configuration:' -ForegroundColor Cyan
    Write-Host "  Stage            : $choice"
    Write-Host "  Deployment mode  : $DeploymentMode"
    Write-Host "  Activation mode  : $ActivationMode"
    Write-Host "  Subscription     : $SubscriptionId"
    Write-Host "  Resource group   : $ResourceGroupName"
    Write-Host "  Workspace        : $WorkspaceName"
    Write-Host "  Rule prefix      : $Prefix"
    Write-Host "  Settings file    : $SettingsPath"
    if ($DeploymentMode -eq 'Canary') {
        Write-Host "  Canary limit     : $CanaryCount rule resource(s)"
    }
    if (-not [string]::IsNullOrWhiteSpace($ResumeStatePath)) {
        Write-Host "  Resume journal   : $ResumeStatePath"
    }
    Write-Host ''

    $runConfirmation = (Read-Host 'Continue? [y/N]').Trim()
    if ($runConfirmation -notmatch '^(?i:y|yes)$') {
        Write-Host 'Deployment cancelled. No Azure request was sent.'
        return $false
    }

    if ($script:SaveSettingsAfterConfirmation) {
        Save-TargetSettings
    }

    return $true
}

function Write-DeploymentLog {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('TRACE', 'INFO', 'WARN', 'ERROR', 'FATAL')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Event,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [AllowNull()]
        [object]$Data
    )

    $callSite = @(Get-PSCallStack)[1]
    $record = [ordered]@{
        timestampUtc = [datetime]::UtcNow.ToString('o')
        runId        = $script:RunId
        level        = $Level
        event        = $Event
        message      = $Message
        source       = [ordered]@{
            script   = $callSite.ScriptName
            function = $callSite.FunctionName
            line     = $callSite.ScriptLineNumber
        }
        data         = $Data
    }

    $json = $record | ConvertTo-Json -Depth 100 -Compress
    if ($script:LogPath) {
        Add-Content -LiteralPath $script:LogPath -Value $json -Encoding utf8
    }

    $consoleMessage = "[$($record.timestampUtc)] [$Level] [$Event] $Message"
    switch ($Level) {
        'WARN'  { Write-Host $consoleMessage -ForegroundColor Yellow }
        'ERROR' { Write-Host $consoleMessage -ForegroundColor Red }
        'FATAL' { Write-Host $consoleMessage -ForegroundColor Red }
        'TRACE' { Write-Verbose $consoleMessage }
        default { Write-Host $consoleMessage }
    }
}

function Get-ProbableCause {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $errorDetailsMessage = Get-ObjectPropertyValue `
        -InputObject $ErrorRecord.ErrorDetails -Name 'Message'
    $message = "$($ErrorRecord.Exception.Message) $errorDetailsMessage"

    switch -Regex ($message) {
        '(?i)\b400\b|bad request|invalid.*payload|deserialize|validation' {
            return 'Likely request schema or template property mismatch. Compare the logged API version, rule kind, and response body with the Sentinel API schema.'
        }
        '(?i)\b401\b|unauthorized|authentication|token' {
            return 'Likely expired Azure token or invalid authentication context. Re-authenticate and verify the selected tenant and subscription.'
        }
        '(?i)\b403\b|forbidden|authorizationfailed|does not have authorization' {
            return 'Likely missing Microsoft.SecurityInsights permissions at the workspace or resource-group scope.'
        }
        '(?i)\b404\b|not found|resourcenotfound' {
            return 'Likely incorrect subscription, resource group, workspace, rule ID, or unsupported API path/version.'
        }
        '(?i)\b409\b|conflict|already exists' {
            return 'Likely resource conflict or concurrent modification. Refresh current rules before retrying.'
        }
        '(?i)\b429\b|too many requests|throttl' {
            return 'Azure throttling is the likely cause. The script retries with backoff; retry the failed checkpoint later if attempts are exhausted.'
        }
        '(?i)\b5\d\d\b|internal server|service unavailable|bad gateway' {
            return 'Likely transient Azure service failure. The request is idempotent and can be retried from the journal.'
        }
        '(?i)timeout|timed out|connection|name resolution|network' {
            return 'Likely network, proxy, DNS, or TLS interruption between PowerShell and Azure Resource Manager.'
        }
        '(?i)convertfrom-json|unexpected character|json' {
            return 'Likely malformed or unexpected JSON in an Azure response or locally generated payload.'
        }
        default {
            return 'Cause is not deterministic from the exception alone. Review the API event immediately before this error, response body, source line, and stack trace.'
        }
    }
}

function Get-ErrorDiagnostic {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $exceptionData = [ordered]@{}
    foreach ($key in $ErrorRecord.Exception.Data.Keys) {
        $exceptionData["$key"] = $ErrorRecord.Exception.Data[$key]
    }

    return [ordered]@{
        operation             = $Operation
        exceptionType         = $ErrorRecord.Exception.GetType().FullName
        exceptionMessage      = $ErrorRecord.Exception.Message
        errorDetails          = Get-ObjectPropertyValue `
            -InputObject $ErrorRecord.ErrorDetails -Name 'Message'
        fullyQualifiedErrorId = $ErrorRecord.FullyQualifiedErrorId
        category              = "$($ErrorRecord.CategoryInfo.Category)"
        targetName            = "$($ErrorRecord.CategoryInfo.TargetName)"
        scriptName            = $ErrorRecord.InvocationInfo.ScriptName
        scriptLineNumber      = $ErrorRecord.InvocationInfo.ScriptLineNumber
        offsetInLine          = $ErrorRecord.InvocationInfo.OffsetInLine
        lineText              = "$(Get-ObjectPropertyValue `
            -InputObject $ErrorRecord.InvocationInfo -Name 'Line')".Trim()
        positionMessage       = $ErrorRecord.InvocationInfo.PositionMessage
        scriptStackTrace      = $ErrorRecord.ScriptStackTrace
        probableCause         = Get-ProbableCause -ErrorRecord $ErrorRecord
        exceptionData         = $exceptionData
    }
}

function Write-DeploymentError {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory = $true)]
        [string]$Operation,

        [ValidateSet('ERROR', 'FATAL')]
        [string]$Level = 'ERROR'
    )

    $diagnostic = Get-ErrorDiagnostic -ErrorRecord $ErrorRecord -Operation $Operation
    Write-DeploymentLog -Level $Level -Event 'Exception' `
        -Message "$Operation failed at line $($diagnostic.scriptLineNumber): $($diagnostic.exceptionMessage)" `
        -Data $diagnostic
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return [System.Convert]::ToHexString($hashBytes).ToLowerInvariant()
}

function Add-ApiVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Version = $ApiVersion
    )

    if ($Path -match '(\?|&)api-version=') {
        return $Path
    }

    if ($Path.Contains('?')) {
        return "$Path&api-version=$Version"
    }

    return "$Path`?api-version=$Version"
}

function Get-ResponseHeader {
    param(
        [AllowNull()]
        [object]$Response,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $headers = Get-ObjectPropertyValue -InputObject $Response -Name 'Headers'
    if ($null -eq $headers) {
        return $null
    }

    if ($headers -is [System.Collections.IDictionary]) {
        foreach ($headerName in @($headers.Keys)) {
            if ("$headerName" -eq $Name) {
                return "$($headers[$headerName])"
            }
        }
    }
    else {
        foreach ($header in @($headers.GetEnumerator())) {
            if ("$($header.Key)" -eq $Name) {
                return "$($header.Value)"
            }
        }
    }

    return $null
}

function New-HttpException {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$RequestPath,

        [Parameter(Mandatory = $true)]
        [int]$StatusCode,

        [AllowNull()]
        [string]$ResponseContent,

        [AllowNull()]
        [string]$CorrelationId,

        [AllowNull()]
        [string]$RequestId
    )

    $exception = [System.InvalidOperationException]::new(
        "$Method failed with HTTP $StatusCode for '$RequestPath'. Response: $(Limit-Text -Value $ResponseContent -MaximumLength 4000)"
    )
    $exception.Data['HttpStatusCode'] = $StatusCode
    $exception.Data['RequestPath'] = $RequestPath
    $exception.Data['CorrelationId'] = $CorrelationId
    $exception.Data['RequestId'] = $RequestId
    $exception.Data['ResponseContent'] = Limit-Text `
        -Value $ResponseContent -MaximumLength 8000
    return $exception
}

function Invoke-SentinelRest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [AllowNull()]
        [object]$Body,

        [string]$Operation = 'Sentinel API request',

        [string]$ApiVersionOverride
    )

    $effectiveApiVersion = if ([string]::IsNullOrWhiteSpace($ApiVersionOverride)) {
        $ApiVersion
    }
    else {
        $ApiVersionOverride
    }
    $requestPath = Add-ApiVersion -Path $Path -Version $effectiveApiVersion
    $payload = $null
    $payloadHash = $null

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $payload = $Body | ConvertTo-Json -EnumsAsStrings -Depth 100 -Compress
        $payloadHash = Get-Sha256 -Value $payload
    }

    for ($attempt = 1; $attempt -le ($MaxRetryCount + 1); $attempt++) {
        $requestData = [ordered]@{
            operation   = $Operation
            method      = $Method
            path        = $requestPath
            attempt     = $attempt
            payloadHash = $payloadHash
            payload     = if ($LogPayload) { $payload } else { $null }
        }
        Write-DeploymentLog -Level 'TRACE' -Event 'ApiRequest' `
            -Message "$Method $requestPath (attempt $attempt)" -Data $requestData

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            if ($null -ne $payload) {
                $response = Invoke-AzRestMethod -Path $requestPath -Method $Method -Payload $payload
            }
            elseif ($requestPath -like 'https://*') {
                $response = Invoke-AzRestMethod -Uri $requestPath -Method $Method
            }
            else {
                $response = Invoke-AzRestMethod -Path $requestPath -Method $Method
            }
        }
        catch {
            $stopwatch.Stop()
            $diagnostic = Get-ErrorDiagnostic -ErrorRecord $_ -Operation $Operation
            $diagnostic['method'] = $Method
            $diagnostic['path'] = $requestPath
            $diagnostic['attempt'] = $attempt
            $diagnostic['durationMs'] = $stopwatch.ElapsedMilliseconds
            Write-DeploymentLog -Level 'ERROR' -Event 'ApiTransportError' `
                -Message "$Method transport failure on attempt $attempt." -Data $diagnostic

            if ($attempt -le $MaxRetryCount) {
                $delaySeconds = [math]::Min([math]::Pow(2, $attempt), 30)
                Write-DeploymentLog -Level 'WARN' -Event 'ApiRetry' `
                    -Message "Retrying in $delaySeconds second(s)." `
                    -Data @{ operation = $Operation; attempt = $attempt; delaySeconds = $delaySeconds }
                Start-Sleep -Seconds $delaySeconds
                continue
            }

            throw
        }

        $stopwatch.Stop()
        $correlationId = Get-ResponseHeader -Response $response -Name 'x-ms-correlation-request-id'
        $requestId = Get-ResponseHeader -Response $response -Name 'x-ms-request-id'
        $responseData = [ordered]@{
            operation     = $Operation
            method        = $Method
            path          = $requestPath
            attempt       = $attempt
            statusCode    = $response.StatusCode
            durationMs    = $stopwatch.ElapsedMilliseconds
            correlationId = $correlationId
            requestId     = $requestId
            response      = if ($response.StatusCode -ge 300) {
                Limit-Text -Value $response.Content -MaximumLength 8000
            }
            else {
                $null
            }
        }
        Write-DeploymentLog -Level $(if ($response.StatusCode -ge 200 -and $response.StatusCode -le 299) { 'TRACE' } else { 'ERROR' }) `
            -Event 'ApiResponse' -Message "$Method returned HTTP $($response.StatusCode)." -Data $responseData

        if ($response.StatusCode -ge 200 -and $response.StatusCode -le 299) {
            return $response
        }

        $retryable = $response.StatusCode -eq 429 -or $response.StatusCode -ge 500
        if ($retryable -and $attempt -le $MaxRetryCount) {
            $delaySeconds = [math]::Min([math]::Pow(2, $attempt), 30)
            Write-DeploymentLog -Level 'WARN' -Event 'ApiRetry' `
                -Message "HTTP $($response.StatusCode); retrying in $delaySeconds second(s)." `
                -Data @{ operation = $Operation; attempt = $attempt; delaySeconds = $delaySeconds }
            Start-Sleep -Seconds $delaySeconds
            continue
        }

        throw (New-HttpException -Method $Method -RequestPath $requestPath `
            -StatusCode $response.StatusCode -ResponseContent $response.Content `
            -CorrelationId $correlationId -RequestId $requestId)
    }
}

function Get-SentinelPagedItems {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ResourceType
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextLink = Add-ApiVersion -Path $Path
    $page = 0

    while ($nextLink) {
        $page++
        $response = Invoke-SentinelRest -Method GET -Path $nextLink `
            -Operation "List $ResourceType page $page"
        $content = $response.Content | ConvertFrom-Json

        foreach ($item in @($content.value)) {
            $items.Add($item)
        }

        $nextLink = Get-ObjectPropertyValue -InputObject $content -Name 'nextLink'
    }

    Write-DeploymentLog -Level 'INFO' -Event 'ResourceListComplete' `
        -Message "Loaded $($items.Count) $ResourceType item(s) across $page page(s)." `
        -Data @{ resourceType = $ResourceType; count = $items.Count; pages = $page }
    return $items
}

function Install-ModuleIfNeeded {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-DeploymentLog -Level 'TRACE' -Event 'ModuleCheck' `
            -Message "Module '$ModuleName' is available." -Data $null
        return
    }

    Write-DeploymentLog -Level 'WARN' -Event 'ModuleInstall' `
        -Message "Installing missing module '$ModuleName' for the current user." -Data $null
    Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
}

function Confirm-AzContext {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetSubscriptionId
    )

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-DeploymentLog -Level 'WARN' -Event 'AzureLogin' `
            -Message 'No Azure context found; interactive sign-in is required.' -Data $null
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }

    $context = Set-AzContext -Subscription $TargetSubscriptionId -ErrorAction Stop
    Write-DeploymentLog -Level 'INFO' -Event 'AzureContext' `
        -Message "Azure context set to subscription '$($context.Subscription.Name)'." `
        -Data @{
            subscriptionId   = $context.Subscription.Id
            subscriptionName = $context.Subscription.Name
            tenantId         = $context.Tenant.Id
            account          = $context.Account.Id
    }
}

function Initialize-DiscoveryFiles {
    $resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null

    $runStamp = [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $baseName = "workspace-discovery-$runStamp-$($script:RunId.Substring(0, 8))"
    $script:LogPath = Join-Path $resolvedOutputDirectory "$baseName.log.jsonl"
    $script:DiscoveryReportPath = Join-Path $resolvedOutputDirectory "$baseName.inventory.json"
    New-Item -ItemType File -Path $script:LogPath -Force | Out-Null
}

function Invoke-AzureResourceGraphWorkspaceQuery {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $skipToken = $null
    $page = 0
    $query = @"
Resources
| where type =~ 'microsoft.operationalinsights/workspaces'
| project subscriptionId, resourceGroup, workspaceName = name, location, id
| order by subscriptionId asc, resourceGroup asc, workspaceName asc
"@

    do {
        $page++
        $options = [ordered]@{
            '$top' = 1000
        }
        if (-not [string]::IsNullOrWhiteSpace("$skipToken")) {
            $options['$skipToken'] = "$skipToken"
        }

        $body = [ordered]@{
            subscriptions = @($SubscriptionIds)
            query         = $query
            options       = $options
        }
        $response = Invoke-SentinelRest -Method POST `
            -Path "/providers/Microsoft.ResourceGraph/resources?api-version=$ResourceGraphApiVersion" `
            -Body $body `
            -Operation "Discover Log Analytics workspaces in tenant '$TenantId' page $page" `
            -ApiVersionOverride $ResourceGraphApiVersion
        $content = $response.Content | ConvertFrom-Json

        foreach ($workspace in @(Get-ObjectPropertyValue -InputObject $content -Name 'data')) {
            if ($null -ne $workspace) {
                $results.Add($workspace)
            }
        }

        $skipToken = Get-ObjectPropertyValue -InputObject $content -Name '$skipToken'
        if ([string]::IsNullOrWhiteSpace("$skipToken")) {
            $skipToken = Get-ObjectPropertyValue -InputObject $content -Name 'skipToken'
        }
    } while (-not [string]::IsNullOrWhiteSpace("$skipToken"))

    Write-DeploymentLog -Level 'INFO' -Event 'WorkspaceDiscoveryTenantComplete' `
        -Message "Discovered $($results.Count) Log Analytics workspace(s) in tenant '$TenantId'." `
        -Data @{
            tenantId         = $TenantId
            subscriptionIds  = @($SubscriptionIds)
            workspaceCount   = $results.Count
            pages            = $page
        }
    return $results
}

function Show-AccessibleAzureWorkspaceInventory {
    Initialize-DiscoveryFiles
    Write-DeploymentLog -Level 'INFO' -Event 'WorkspaceDiscoveryStarted' `
        -Message 'Starting read-only Azure subscription and Log Analytics workspace discovery.' `
        -Data @{
            resourceGraphApiVersion = $ResourceGraphApiVersion
            outputDirectory         = [System.IO.Path]::GetDirectoryName($script:LogPath)
        }

    if ($PSVersionTable.PSVersion -lt [version]'7.4') {
        throw "PowerShell 7.4 or later is required. Current version: $($PSVersionTable.PSVersion)."
    }

    Install-ModuleIfNeeded -ModuleName Az.Accounts
    Import-Module Az.Accounts -ErrorAction Stop

    $originalContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $originalContext) {
        Write-DeploymentLog -Level 'WARN' -Event 'AzureLogin' `
            -Message 'No Azure context found; interactive sign-in is required for discovery.' `
            -Data $null
        Connect-AzAccount -ErrorAction Stop | Out-Null
        $originalContext = Get-AzContext -ErrorAction Stop
    }

    $subscriptions = @(Get-AzSubscription -ErrorAction Stop |
        Sort-Object Id -Unique |
        Sort-Object Name, Id)
    if ($subscriptions.Count -eq 0) {
        Write-Host ''
        Write-Host 'No Azure subscriptions are accessible to the current account.' `
            -ForegroundColor Yellow
        Write-DeploymentLog -Level 'WARN' -Event 'NoAccessibleSubscriptions' `
            -Message 'The current Azure account returned no accessible subscriptions.' `
            -Data @{ account = $originalContext.Account.Id }
        return
    }

    $workspaceRows = [System.Collections.Generic.List[object]]::new()
    $queryStatusBySubscription = @{}
    $queryErrorBySubscription = @{}
    foreach ($subscription in $subscriptions) {
        $subscriptionId = "$(Get-ObjectPropertyValue -InputObject $subscription -Name 'Id')"
        $subscriptionState = "$(Get-ObjectPropertyValue -InputObject $subscription -Name 'State')"
        if ($subscriptionState -eq 'Enabled') {
            $queryStatusBySubscription[$subscriptionId] = 'Pending'
        }
        else {
            $queryStatusBySubscription[$subscriptionId] = "Skipped:$subscriptionState"
        }
    }

    try {
        $enabledSubscriptions = @($subscriptions | Where-Object {
            "$(Get-ObjectPropertyValue -InputObject $_ -Name 'State')" -eq 'Enabled'
        })
        foreach ($tenantGroup in @($enabledSubscriptions | Group-Object TenantId)) {
            $tenantId = "$($tenantGroup.Name)"
            $tenantSubscriptions = @($tenantGroup.Group)
            $contextSubscriptionId = "$(
                Get-ObjectPropertyValue -InputObject $tenantSubscriptions[0] -Name 'Id'
            )"

            try {
                $tenantContext = Set-AzContext -Subscription $contextSubscriptionId `
                    -Tenant $tenantId -Scope Process -ErrorAction Stop
                Write-DeploymentLog -Level 'INFO' -Event 'WorkspaceDiscoveryContext' `
                    -Message "Azure discovery context set to tenant '$tenantId'." `
                    -Data @{
                        tenantId       = $tenantId
                        subscriptionId = $tenantContext.Subscription.Id
                        account        = $tenantContext.Account.Id
                    }

                for ($batchStart = 0; $batchStart -lt $tenantSubscriptions.Count; $batchStart += 1000) {
                    $batchEnd = [math]::Min($batchStart + 999, $tenantSubscriptions.Count - 1)
                    $batchSubscriptions = @($tenantSubscriptions[$batchStart..$batchEnd])
                    $batchSubscriptionIds = @($batchSubscriptions | ForEach-Object {
                        "$(Get-ObjectPropertyValue -InputObject $_ -Name 'Id')"
                    })

                    try {
                        $batchWorkspaces = @(Invoke-AzureResourceGraphWorkspaceQuery `
                            -SubscriptionIds $batchSubscriptionIds -TenantId $tenantId)
                        foreach ($workspace in $batchWorkspaces) {
                            $workspaceSubscriptionId = "$(
                                Get-ObjectPropertyValue -InputObject $workspace -Name 'subscriptionId'
                            )"
                            $workspaceSubscription = @($batchSubscriptions | Where-Object {
                                "$(Get-ObjectPropertyValue -InputObject $_ -Name 'Id')" `
                                    -eq $workspaceSubscriptionId
                            } | Select-Object -First 1)
                            $workspaceRows.Add([pscustomobject]@{
                                SubscriptionName = if ($workspaceSubscription.Count -gt 0) {
                                    "$(Get-ObjectPropertyValue `
                                        -InputObject $workspaceSubscription[0] -Name 'Name')"
                                }
                                else {
                                    $workspaceSubscriptionId
                                }
                                SubscriptionId   = $workspaceSubscriptionId
                                TenantId          = $tenantId
                                ResourceGroupName = "$(
                                    Get-ObjectPropertyValue -InputObject $workspace -Name 'resourceGroup'
                                )"
                                WorkspaceName     = "$(
                                    Get-ObjectPropertyValue -InputObject $workspace -Name 'workspaceName'
                                )"
                                Location          = "$(
                                    Get-ObjectPropertyValue -InputObject $workspace -Name 'location'
                                )"
                                ResourceId        = "$(
                                    Get-ObjectPropertyValue -InputObject $workspace -Name 'id'
                                )"
                            })
                        }

                        foreach ($batchSubscriptionId in $batchSubscriptionIds) {
                            $queryStatusBySubscription[$batchSubscriptionId] = 'Completed'
                        }
                    }
                    catch {
                        $diagnostic = Get-ErrorDiagnostic -ErrorRecord $_ `
                            -Operation "Query workspaces in tenant '$tenantId'"
                        Write-DeploymentLog -Level 'ERROR' -Event 'WorkspaceDiscoveryBatchFailed' `
                            -Message "Workspace discovery failed for $($batchSubscriptionIds.Count) subscription(s) in tenant '$tenantId' at line $($diagnostic.scriptLineNumber)." `
                            -Data $diagnostic
                        foreach ($batchSubscriptionId in $batchSubscriptionIds) {
                            $queryStatusBySubscription[$batchSubscriptionId] = 'Failed'
                            $queryErrorBySubscription[$batchSubscriptionId] = $diagnostic
                        }
                    }
                }
            }
            catch {
                $diagnostic = Get-ErrorDiagnostic -ErrorRecord $_ `
                    -Operation "Set Azure context for tenant '$tenantId'"
                Write-DeploymentLog -Level 'ERROR' -Event 'WorkspaceDiscoveryTenantFailed' `
                    -Message "Discovery could not query tenant '$tenantId' at line $($diagnostic.scriptLineNumber)." `
                    -Data $diagnostic
                foreach ($tenantSubscription in $tenantSubscriptions) {
                    $tenantSubscriptionId = "$(
                        Get-ObjectPropertyValue -InputObject $tenantSubscription -Name 'Id'
                    )"
                    $queryStatusBySubscription[$tenantSubscriptionId] = 'Failed'
                    $queryErrorBySubscription[$tenantSubscriptionId] = $diagnostic
                }
            }
        }
    }
    finally {
        if ($null -ne $originalContext) {
            try {
                Set-AzContext -Context $originalContext -Scope Process -ErrorAction Stop |
                    Out-Null
                Write-DeploymentLog -Level 'INFO' -Event 'AzureContextRestored' `
                    -Message 'Restored the Azure context that was active before discovery.' `
                    -Data @{
                        subscriptionId = $originalContext.Subscription.Id
                        tenantId       = $originalContext.Tenant.Id
                        account        = $originalContext.Account.Id
                    }
            }
            catch {
                $diagnostic = Get-ErrorDiagnostic -ErrorRecord $_ `
                    -Operation 'Restore Azure context after workspace discovery'
                Write-DeploymentLog -Level 'WARN' -Event 'AzureContextRestoreFailed' `
                    -Message "The original Azure context could not be restored at line $($diagnostic.scriptLineNumber)." `
                    -Data $diagnostic
            }
        }
    }

    $subscriptionReport = @($subscriptions | ForEach-Object {
        $subscriptionId = "$(Get-ObjectPropertyValue -InputObject $_ -Name 'Id')"
        [ordered]@{
            subscriptionName = "$(Get-ObjectPropertyValue -InputObject $_ -Name 'Name')"
            subscriptionId   = $subscriptionId
            tenantId          = "$(Get-ObjectPropertyValue -InputObject $_ -Name 'TenantId')"
            state             = "$(Get-ObjectPropertyValue -InputObject $_ -Name 'State')"
            queryStatus       = $queryStatusBySubscription[$subscriptionId]
            workspaceCount    = @($workspaceRows | Where-Object {
                $_.SubscriptionId -eq $subscriptionId
            }).Count
            error             = if ($queryErrorBySubscription.ContainsKey($subscriptionId)) {
                $queryErrorBySubscription[$subscriptionId]
            }
            else {
                $null
            }
        }
    })
    $report = [ordered]@{
        generatedUtc  = [datetime]::UtcNow.ToString('o')
        account       = $originalContext.Account.Id
        subscriptions = $subscriptionReport
        workspaces    = @($workspaceRows | Sort-Object `
            SubscriptionName, ResourceGroupName, WorkspaceName)
    }
    $report | ConvertTo-Json -Depth 100 |
        Set-Content -LiteralPath $script:DiscoveryReportPath -Encoding utf8

    Write-Host ''
    Write-Host 'Accessible Azure inventory' -ForegroundColor Cyan
    Write-Host "  Current account          : $($originalContext.Account.Id)"
    Write-Host "  Accessible subscriptions : $($subscriptions.Count)"
    Write-Host "  Log Analytics workspaces : $($workspaceRows.Count)"

    foreach ($subscription in $subscriptions) {
        $subscriptionId = "$(Get-ObjectPropertyValue -InputObject $subscription -Name 'Id')"
        $subscriptionName = "$(Get-ObjectPropertyValue -InputObject $subscription -Name 'Name')"
        $tenantId = "$(Get-ObjectPropertyValue -InputObject $subscription -Name 'TenantId')"
        $subscriptionState = "$(Get-ObjectPropertyValue -InputObject $subscription -Name 'State')"
        $subscriptionWorkspaces = @($workspaceRows | Where-Object {
            $_.SubscriptionId -eq $subscriptionId
        } | Sort-Object ResourceGroupName, WorkspaceName)

        Write-Host ''
        Write-Host "$subscriptionName" -ForegroundColor Cyan
        Write-Host "  Subscription ID : $subscriptionId"
        Write-Host "  Tenant ID       : $tenantId"
        Write-Host "  State           : $subscriptionState"

        if ($queryStatusBySubscription[$subscriptionId] -eq 'Failed') {
            $diagnostic = $queryErrorBySubscription[$subscriptionId]
            Write-Host "  Discovery       : Failed at line $($diagnostic.scriptLineNumber)" `
                -ForegroundColor Red
            Write-Host "  Probable cause  : $($diagnostic.probableCause)" `
                -ForegroundColor Yellow
            continue
        }
        if ($queryStatusBySubscription[$subscriptionId] -like 'Skipped:*') {
            Write-Host "  Discovery       : $($queryStatusBySubscription[$subscriptionId])" `
                -ForegroundColor Yellow
            continue
        }
        if ($subscriptionWorkspaces.Count -eq 0) {
            Write-Host '  No accessible Log Analytics workspace was found.'
            continue
        }

        $subscriptionWorkspaces |
            Select-Object ResourceGroupName, WorkspaceName, Location |
            Format-Table -AutoSize | Out-Host
    }

    $failedSubscriptionCount = @($subscriptionReport | Where-Object {
        $_.queryStatus -eq 'Failed'
    }).Count
    Write-DeploymentLog -Level 'INFO' -Event 'WorkspaceDiscoveryCompleted' `
        -Message "Discovery completed: $($subscriptions.Count) subscription(s), $($workspaceRows.Count) workspace(s), $failedSubscriptionCount failed subscription query or queries." `
        -Data @{
            account                 = $originalContext.Account.Id
            subscriptionCount       = $subscriptions.Count
            workspaceCount          = $workspaceRows.Count
            failedSubscriptionCount = $failedSubscriptionCount
            reportPath              = $script:DiscoveryReportPath
        }

    Write-Host ''
    Write-Host "Discovery log   : $script:LogPath"
    Write-Host "Inventory report: $script:DiscoveryReportPath"
    Write-Host 'No Azure resource was changed.' -ForegroundColor Green
}

function Copy-Properties {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [string[]]$Exclude = @()
    )

    $copy = [ordered]@{}
    foreach ($property in $InputObject.PSObject.Properties) {
        if ($Exclude -contains $property.Name) {
            continue
        }

        if ($null -ne $property.Value) {
            $copy[$property.Name] = $property.Value
        }
    }

    return $copy
}

function Add-DisplayNamePrefix {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$DisplayName,

        [AllowEmptyString()]
        [string]$RulePrefix
    )

    $cleanPrefix = $RulePrefix.Trim()
    if ([string]::IsNullOrWhiteSpace($cleanPrefix)) {
        return $DisplayName
    }

    if ($DisplayName.StartsWith($cleanPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $DisplayName
    }

    if ($cleanPrefix.EndsWith('-') -or $cleanPrefix.EndsWith(':')) {
        return "$cleanPrefix $DisplayName"
    }

    return "$cleanPrefix - $DisplayName"
}

function Get-TargetEnabledState {
    param(
        [AllowNull()]
        [object]$ExistingRule
    )

    switch ($ActivationMode) {
        'Enabled'  { return $true }
        'Disabled' { return $false }
        'Preserve' {
            if ($null -eq $ExistingRule) {
                return $false
            }

            return [bool](Get-ObjectPropertyValue `
                -InputObject $ExistingRule.properties -Name 'enabled')
        }
    }
}

function New-AlertRulePayloadFromTemplate {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Template,

        [Parameter(Mandatory = $true)]
        [bool]$Enabled,

        [AllowEmptyString()]
        [string]$RulePrefix
    )

    $readOnlyTemplateProperties = @(
        'alertRulesCreatedByTemplateCount',
        'createdDateUTC',
        'lastUpdatedDateUTC',
        'requiredDataConnectors',
        'status',
        'version'
    )

    switch ($Template.kind) {
        'Fusion' {
            $properties = [ordered]@{
                alertRuleTemplateName = $Template.name
                enabled               = $Enabled
            }
        }
        default {
            $properties = Copy-Properties -InputObject $Template.properties -Exclude $readOnlyTemplateProperties
            $properties['alertRuleTemplateName'] = $Template.name
            $properties['enabled'] = $Enabled

            $templateVersion = Get-ObjectPropertyValue `
                -InputObject $Template.properties -Name 'version'
            if ($templateVersion) {
                $properties['templateVersion'] = $templateVersion
            }

            if ($properties.Contains('displayName')) {
                $properties['displayName'] = Add-DisplayNamePrefix `
                    -DisplayName $properties['displayName'] -RulePrefix $RulePrefix
            }

            if ($Template.kind -in @('Scheduled', 'NRT')) {
                if (-not $properties.Contains('suppressionDuration')) {
                    $properties['suppressionDuration'] = 'PT5H'
                }

                if (-not $properties.Contains('suppressionEnabled')) {
                    $properties['suppressionEnabled'] = $false
                }
            }
        }
    }

    return [ordered]@{
        kind       = $Template.kind
        properties = $properties
    }
}

function New-AlertRulePayloadFromExistingRule {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule,

        [Parameter(Mandatory = $true)]
        [bool]$Enabled,

        [AllowEmptyString()]
        [string]$RulePrefix
    )

    if ($Rule.kind -eq 'Fusion') {
        return [ordered]@{
            kind       = $Rule.kind
            properties = [ordered]@{
                alertRuleTemplateName = Get-ObjectPropertyValue `
                    -InputObject $Rule.properties -Name 'alertRuleTemplateName'
                enabled               = $Enabled
            }
        }
    }

    $readOnlyRuleProperties = @('lastModifiedUtc', 'provisioningState')
    $properties = Copy-Properties -InputObject $Rule.properties -Exclude $readOnlyRuleProperties
    $properties['enabled'] = $Enabled

    if ($properties.Contains('displayName')) {
        $properties['displayName'] = Add-DisplayNamePrefix `
            -DisplayName $properties['displayName'] -RulePrefix $RulePrefix
    }

    return [ordered]@{
        kind       = $Rule.kind
        properties = $properties
    }
}

function Get-RuleChanges {
    param(
        [AllowNull()]
        [object]$ExistingRule,

        [Parameter(Mandatory = $true)]
        [object]$Payload
    )

    if ($null -eq $ExistingRule) {
        return @('CreateResource')
    }

    $changes = [System.Collections.Generic.List[string]]::new()
    $currentDisplayName = Get-ObjectPropertyValue `
        -InputObject $ExistingRule.properties -Name 'displayName'
    $targetDisplayName = Get-ObjectPropertyValue `
        -InputObject $Payload.properties -Name 'displayName'
    if ("$currentDisplayName" -cne "$targetDisplayName") {
        $changes.Add('DisplayName')
    }

    $currentEnabled = Get-ObjectPropertyValue `
        -InputObject $ExistingRule.properties -Name 'enabled'
    $targetEnabled = Get-ObjectPropertyValue `
        -InputObject $Payload.properties -Name 'enabled'
    if ([bool]$currentEnabled -ne [bool]$targetEnabled) {
        $changes.Add('EnabledState')
    }

    return @($changes)
}

function Get-EntityMappingCompatibilityIssue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Payload
    )

    $payloadProperties = Get-ObjectPropertyValue -InputObject $Payload -Name 'properties'
    $entityMappings = @(Get-ObjectPropertyValue `
        -InputObject $payloadProperties -Name 'entityMappings' |
        Where-Object { $null -ne $_ })
    if ($entityMappings.Count -le $MaxEntityMappings) {
        return $null
    }

    $mappingTypes = @($entityMappings | ForEach-Object {
        $entityType = Get-ObjectPropertyValue -InputObject $_ -Name 'entityType'
        if ([string]::IsNullOrWhiteSpace("$entityType")) {
            '<unknown>'
        }
        else {
            "$entityType"
        }
    })

    return [pscustomobject]@{
        Code               = 'EntityMappingsLimit'
        Message            = "Payload contains $($entityMappings.Count) entity mappings; the configured API limit is $MaxEntityMappings."
        EntityMappingCount = $entityMappings.Count
        MaximumAllowed     = $MaxEntityMappings
        EntityTypes        = $mappingTypes
        ExcessEntityTypes  = @($mappingTypes | Select-Object -Skip $MaxEntityMappings)
    }
}

function Get-TemplateExclusionReason {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Template
    )

    $status = Get-ObjectPropertyValue -InputObject $Template.properties -Name 'status'
    $displayName = Get-ObjectPropertyValue -InputObject $Template.properties -Name 'displayName'
    $deprecated = Get-ObjectPropertyValue -InputObject $Template.properties -Name 'deprecated'
    $metadata = Get-ObjectPropertyValue -InputObject $Template -Name 'metadata'
    $contentDeprecated = Get-ObjectPropertyValue -InputObject $metadata -Name 'isDeprecated'

    if ([bool]$deprecated -or [bool]$contentDeprecated) {
        return 'DeprecatedFlag'
    }
    if ("$status" -in @('Deprecated', 'NotAvailable')) {
        return "Status:$status"
    }
    if ("$displayName" -match '^\s*\[Deprecated\]') {
        return 'DeprecatedDisplayName'
    }

    return $null
}

function ConvertFrom-InstalledAnalyticsContentTemplate {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ContentTemplate
    )

    $contentProperties = $ContentTemplate.properties
    $mainTemplate = Get-ObjectPropertyValue -InputObject $contentProperties -Name 'mainTemplate'
    if ($null -eq $mainTemplate) {
        return
    }

    $resources = @(Get-ObjectPropertyValue -InputObject $mainTemplate -Name 'resources')
    foreach ($resource in $resources) {
        $resourceType = Get-ObjectPropertyValue -InputObject $resource -Name 'type'
        if ("$resourceType" -notmatch '(?i)^Microsoft\.SecurityInsights/AlertRuleTemplates$') {
            continue
        }

        $contentId = Get-ObjectPropertyValue -InputObject $contentProperties -Name 'contentId'
        $templateName = Get-ObjectPropertyValue -InputObject $resource -Name 'name'
        if ([string]::IsNullOrWhiteSpace("$templateName") -or "$templateName" -match '^\s*\[') {
            $templateName = $contentId
        }
        elseif ("$templateName".Contains('/')) {
            $templateName = @("$templateName" -split '/')[-1]
        }

        $normalizedProperties = Copy-Properties -InputObject $resource.properties
        if (-not $normalizedProperties.Contains('version')) {
            $contentVersion = Get-ObjectPropertyValue -InputObject $contentProperties -Name 'version'
            if (-not [string]::IsNullOrWhiteSpace("$contentVersion")) {
                $normalizedProperties['version'] = $contentVersion
            }
        }

        [pscustomobject]@{
            name       = "$templateName"
            kind       = Get-ObjectPropertyValue -InputObject $resource -Name 'kind'
            properties = [pscustomobject]$normalizedProperties
            metadata   = [pscustomobject]@{
                contentTemplateResourceName = $ContentTemplate.name
                contentId                   = $contentId
                contentProductId            = Get-ObjectPropertyValue `
                    -InputObject $contentProperties -Name 'contentProductId'
                packageId                   = Get-ObjectPropertyValue `
                    -InputObject $contentProperties -Name 'packageId'
                packageName                 = Get-ObjectPropertyValue `
                    -InputObject $contentProperties -Name 'packageName'
                isDeprecated                = Get-ObjectPropertyValue `
                    -InputObject $contentProperties -Name 'isDeprecated'
            }
        }
    }
}

function Select-CanonicalRuleForTemplate {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Rules,

        [Parameter(Mandatory = $true)]
        [string]$TemplateId
    )

    $exactRule = @($Rules | Where-Object {
        "$($_.name)" -eq $TemplateId
    } | Select-Object -First 1)
    if ($exactRule.Count -gt 0) {
        return $exactRule[0]
    }

    return @($Rules | Sort-Object name | Select-Object -First 1)[0]
}

function Select-GuidedCanaryPlan {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Candidates
    )

    $changedCandidates = @($Candidates | Where-Object {
        $_.Action -notin @('NoChange', 'Blocked')
    })
    if ($changedCandidates.Count -eq 0) {
        Write-Host 'No rule requires a change. The Canary plan is empty.' -ForegroundColor Yellow
        return @()
    }

    Write-Host ''
    Write-Host 'Canary rule selection' -ForegroundColor Cyan
    Write-Host 'Search by display name, kind, rule ID, or template ID.'

    while ($true) {
        $filter = (Read-Host 'Search filter [Enter shows the first 30 changes]').Trim()
        if ([string]::IsNullOrWhiteSpace($filter)) {
            $matches = $changedCandidates
        }
        else {
            $matches = @($changedCandidates | Where-Object {
                $_.DisplayName -like "*$filter*" -or
                $_.Kind -like "*$filter*" -or
                $_.RuleId -like "*$filter*" -or
                $_.TemplateId -like "*$filter*"
            })
        }

        if ($matches.Count -eq 0) {
            Write-Host 'No matching rule was found. Try another filter.' -ForegroundColor Yellow
            continue
        }

        $visibleMatches = @($matches | Select-Object -First 30)
        Write-Host ''
        for ($index = 0; $index -lt $visibleMatches.Count; $index++) {
            $item = $visibleMatches[$index]
            Write-Host ('  [{0,2}] [{1,-6}] [{2,-8}] {3}' -f
                ($index + 1), $item.Action, $item.Kind, $item.DisplayName)
            Write-Host "       Rule ID: $($item.RuleId)" -ForegroundColor DarkGray
        }

        if ($matches.Count -gt $visibleMatches.Count) {
            Write-Host "Showing 30 of $($matches.Count) matches. Enter F to refine the filter." `
                -ForegroundColor Yellow
        }

        $selectionInput = (Read-Host "Select up to $CanaryCount number(s), comma-separated; F filters again").Trim()
        if ($selectionInput -match '^(?i:f|filter)$') {
            continue
        }

        $selectionParts = @($selectionInput -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique)

        if ($selectionParts.Count -lt 1 -or $selectionParts.Count -gt $CanaryCount) {
            Write-Host "Select between 1 and $CanaryCount rule(s)." -ForegroundColor Yellow
            continue
        }

        $selectedItems = [System.Collections.Generic.List[object]]::new()
        $validSelection = $true
        foreach ($selectionPart in $selectionParts) {
            $selectedIndex = 0
            if (-not [int]::TryParse($selectionPart, [ref]$selectedIndex) -or
                $selectedIndex -lt 1 -or $selectedIndex -gt $visibleMatches.Count) {
                $validSelection = $false
                break
            }

            $selectedItems.Add($visibleMatches[$selectedIndex - 1])
        }

        if (-not $validSelection) {
            Write-Host 'One or more selected numbers are invalid.' -ForegroundColor Yellow
            continue
        }

        Write-Host ''
        Write-Host 'Selected Canary rules:' -ForegroundColor Cyan
        foreach ($selectedItem in $selectedItems) {
            Write-Host "  - [$($selectedItem.Action)] $($selectedItem.DisplayName)"
        }

        $confirmation = (Read-Host 'Use this Canary selection? [y/N]').Trim()
        if ($confirmation -match '^(?i:y|yes)$') {
            return @($selectedItems)
        }
    }
}

function Add-JournalRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Phase,

        [Parameter(Mandatory = $true)]
        [object]$PlanItem,

        [AllowNull()]
        [object]$AdditionalData
    )

    $record = [ordered]@{
        timestampUtc = [datetime]::UtcNow.ToString('o')
        runId        = $script:RunId
        phase        = $Phase
        subscriptionId = $SubscriptionId
        resourceGroup = $ResourceGroupName
        workspace    = $WorkspaceName
        ruleId       = $PlanItem.RuleId
        templateId   = $PlanItem.TemplateId
        action       = $PlanItem.Action
        payloadHash  = $PlanItem.PayloadHash
        data         = $AdditionalData
    }
    Add-Content -LiteralPath $script:JournalPath `
        -Value ($record | ConvertTo-Json -Depth 100 -Compress) -Encoding utf8
}

function Get-CompletedResumeKeys {
    $completedKeys = @{}
    if ([string]::IsNullOrWhiteSpace($ResumeStatePath)) {
        return $completedKeys
    }

    if (-not (Test-Path -LiteralPath $ResumeStatePath -PathType Leaf)) {
        throw "Resume journal '$ResumeStatePath' does not exist."
    }

    foreach ($line in Get-Content -LiteralPath $ResumeStatePath) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $record = $line | ConvertFrom-Json
        $journalWorkspace = Get-ObjectPropertyValue -InputObject $record -Name 'workspace'
        $journalSubscriptionId = Get-ObjectPropertyValue -InputObject $record -Name 'subscriptionId'
        $journalResourceGroup = Get-ObjectPropertyValue -InputObject $record -Name 'resourceGroup'
        if ($journalWorkspace -ne $WorkspaceName -or
            $journalSubscriptionId -ne $SubscriptionId -or
            $journalResourceGroup -ne $ResourceGroupName) {
            throw "Resume journal '$ResumeStatePath' belongs to a different Sentinel target."
        }

        if ((Get-ObjectPropertyValue -InputObject $record -Name 'phase') -eq 'Succeeded') {
            $journalRuleId = Get-ObjectPropertyValue -InputObject $record -Name 'ruleId'
            $journalPayloadHash = Get-ObjectPropertyValue -InputObject $record -Name 'payloadHash'
            $completedKeys["$journalRuleId|$journalPayloadHash"] = $true
        }
    }

    Write-DeploymentLog -Level 'INFO' -Event 'ResumeJournalLoaded' `
        -Message "Loaded $($completedKeys.Count) successful checkpoint(s)." `
        -Data @{ resumeStatePath = $ResumeStatePath; completedCount = $completedKeys.Count }
    return $completedKeys
}

function Save-ExistingRuleSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [object]$PlanItem
    )

    if ($null -eq $PlanItem.ExistingRule) {
        return $null
    }

    $safeRuleId = ConvertTo-SafeFileName -Value $PlanItem.RuleId
    $snapshotPath = Join-Path $script:SnapshotDirectory "$safeRuleId.before.json"
    $PlanItem.ExistingRule | ConvertTo-Json -Depth 100 |
        Set-Content -LiteralPath $snapshotPath -Encoding utf8
    return $snapshotPath
}

function Initialize-RunFiles {
    $resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null

    $runStamp = $script:RunStartedUtc.ToString('yyyyMMddTHHmmssZ')
    $workspaceFileName = ConvertTo-SafeFileName -Value $WorkspaceName
    $baseName = "$workspaceFileName-$runStamp-$($script:RunId.Substring(0, 8))"

    $script:LogPath = Join-Path $resolvedOutputDirectory "$baseName.log.jsonl"
    $script:JournalPath = Join-Path $resolvedOutputDirectory "$baseName.journal.jsonl"
    $script:PlanPath = Join-Path $resolvedOutputDirectory "$baseName.plan.json"
    $script:DuplicateReportPath = Join-Path $resolvedOutputDirectory "$baseName.duplicates.json"
    $script:CompatibilityReportPath = Join-Path $resolvedOutputDirectory "$baseName.compatibility.json"
    $script:SnapshotDirectory = Join-Path $resolvedOutputDirectory "$baseName.snapshots"
    New-Item -ItemType Directory -Path $script:SnapshotDirectory -Force | Out-Null

    New-Item -ItemType File -Path $script:LogPath -Force | Out-Null
    New-Item -ItemType File -Path $script:JournalPath -Force | Out-Null
}

function Assert-TargetConfiguration {
    $missingParameters = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        $missingParameters.Add('SubscriptionId')
    }
    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        $missingParameters.Add('ResourceGroupName')
    }
    if ([string]::IsNullOrWhiteSpace($WorkspaceName)) {
        $missingParameters.Add('WorkspaceName')
    }

    if ($missingParameters.Count -gt 0) {
        throw "Missing required target parameter(s): $($missingParameters -join ', '). Run '.\Enable-rules.ps1' for the guided wizard."
    }

    $parsedSubscriptionId = [guid]::Empty
    if (-not [guid]::TryParse($SubscriptionId, [ref]$parsedSubscriptionId)) {
        throw "SubscriptionId '$SubscriptionId' is not a valid GUID."
    }
}

function Assert-DeploymentGuards {
    if ($DeploymentMode -eq 'Full' -and -not $ApproveFullDeployment) {
        throw 'Full mode is blocked. Review a Validate/Canary run, then pass -ApproveFullDeployment.'
    }

    if ($DeploymentMode -ne 'Validate' -and $ActivationMode -eq 'Enabled' -and -not $ApproveActivation) {
        throw 'Rule activation is blocked. Pass -ApproveActivation only after reviewing the disabled Canary results.'
    }

    $templateFilterCount = @($TemplateId |
        Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }).Count
    if ($DeploymentMode -eq 'Full' -and $templateFilterCount -gt 0) {
        throw '-TemplateId is only supported in Validate or Canary mode. Full mode always evaluates all templates.'
    }
}

function Start-SentinelRuleDeployment {
    Assert-TargetConfiguration
    Initialize-RunFiles
    Write-DeploymentLog -Level 'INFO' -Event 'RunStarted' `
        -Message "Starting Sentinel rule deployment in '$DeploymentMode' mode." `
        -Data @{
            subscriptionId  = $SubscriptionId
            resourceGroup   = $ResourceGroupName
            workspace       = $WorkspaceName
            deploymentMode  = $DeploymentMode
            activationMode  = $ActivationMode
            canaryCount     = $CanaryCount
            maxEntityMappings = $MaxEntityMappings
            prefix          = $Prefix
            apiVersion      = $ApiVersion
            nrtApiVersion   = $NrtApiVersion
            failurePolicy   = $FailurePolicy
            logPayload      = [bool]$LogPayload
            outputDirectory = [System.IO.Path]::GetDirectoryName($script:LogPath)
        }

    Assert-DeploymentGuards
    if ($PSVersionTable.PSVersion -lt [version]'7.4') {
        throw "PowerShell 7.4 or later is required. Current version: $($PSVersionTable.PSVersion)."
    }

    Install-ModuleIfNeeded -ModuleName Az.Accounts
    Import-Module Az.Accounts -ErrorAction Stop
    Confirm-AzContext -TargetSubscriptionId $SubscriptionId

    if ($script:InvocationBoundParameters.ContainsKey('SolutionName') -and
        -not [string]::IsNullOrWhiteSpace($SolutionName)) {
        Write-DeploymentLog -Level 'WARN' -Event 'DeprecatedParameter' `
            -Message "-SolutionName '$SolutionName' is ignored; all available templates are evaluated." `
            -Data @{ parameter = 'SolutionName'; value = $SolutionName }
    }

    if ($script:InvocationBoundParameters.ContainsKey('EnableRules')) {
        $legacyMessage = if ($script:InteractiveSession) {
            "-EnableRules is deprecated and ignored in guided mode; the wizard selected -ActivationMode '$ActivationMode'."
        }
        else {
            "-EnableRules is deprecated; mapped to -ActivationMode '$ActivationMode'."
        }
        Write-DeploymentLog -Level 'WARN' -Event 'DeprecatedParameter' `
            -Message $legacyMessage `
            -Data @{ parameter = 'EnableRules'; value = $EnableRules; activationMode = $ActivationMode }
    }

    $sentinelBasePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"
    $installedContentTemplates = @(Get-SentinelPagedItems `
        -Path "$sentinelBasePath/contentTemplates?`$expand=properties/mainTemplate" `
        -ResourceType 'installed content template')
    $installedAnalyticsContent = @($installedContentTemplates | Where-Object {
        (Get-ObjectPropertyValue -InputObject $_.properties -Name 'contentKind') -eq 'AnalyticsRule'
    })
    $allTemplates = @($installedAnalyticsContent | ForEach-Object {
        ConvertFrom-InstalledAnalyticsContentTemplate -ContentTemplate $_
    })
    $supportedKindTemplates = @($allTemplates | Where-Object {
        $_.kind -in @('Scheduled', 'NRT', 'Fusion', 'MicrosoftSecurityIncidentCreation')
    })
    $excludedTemplates = @($supportedKindTemplates | Where-Object {
        $null -ne (Get-TemplateExclusionReason -Template $_)
    })
    $templates = @($supportedKindTemplates | Where-Object {
        $null -eq (Get-TemplateExclusionReason -Template $_)
    })
    $contentWithoutAlertTemplateCount = $installedAnalyticsContent.Count - $allTemplates.Count
    $unsupportedKindCount = $allTemplates.Count - $supportedKindTemplates.Count

    Write-Host ''
    Write-Host 'Template inventory' -ForegroundColor Cyan
    Write-Host "  Installed content entries : $($installedAnalyticsContent.Count)"
    Write-Host "  Embedded rule templates   : $($allTemplates.Count)"
    Write-Host "  Eligible for deployment   : $($templates.Count)"
    Write-Host "  Deprecated/unavailable    : $($excludedTemplates.Count) skipped"
    Write-Host "  Missing embedded template : $contentWithoutAlertTemplateCount skipped"
    Write-Host "  Unsupported rule kinds    : $unsupportedKindCount skipped"
    Write-DeploymentLog -Level 'INFO' -Event 'TemplateInventory' `
        -Message "Workspace has $($installedAnalyticsContent.Count) installed analytics content template(s); $($templates.Count) are eligible." `
        -Data @{
            installedContentCount = $installedAnalyticsContent.Count
            embeddedTemplateCount = $allTemplates.Count
            eligibleCount        = $templates.Count
            excludedCount        = $excludedTemplates.Count
            missingEmbeddedTemplateCount = $contentWithoutAlertTemplateCount
            unsupportedKindCount = $unsupportedKindCount
            excludedTemplates    = @($excludedTemplates | ForEach-Object {
                @{
                    templateId = $_.name
                    displayName = Get-ObjectPropertyValue `
                        -InputObject $_.properties -Name 'displayName'
                    reason = Get-TemplateExclusionReason -Template $_
                }
            })
        }

    $requestedTemplateIds = @($TemplateId |
        Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } |
        Select-Object -Unique)
    if ($requestedTemplateIds.Count -gt 0) {
        $requestedExcludedTemplates = @($excludedTemplates | Where-Object {
            $_.name -in $requestedTemplateIds
        })
        if ($requestedExcludedTemplates.Count -gt 0) {
            $excludedNames = @($requestedExcludedTemplates | ForEach-Object {
                "'$($_.name)' ($(Get-TemplateExclusionReason -Template $_))"
            })
            throw "Requested template(s) are deprecated or unavailable and cannot be deployed: $($excludedNames -join ', ')."
        }

        $templates = @($templates | Where-Object { $_.name -in $requestedTemplateIds })
        $foundTemplateIds = @($templates | ForEach-Object {
            Get-ObjectPropertyValue -InputObject $_ -Name 'name'
        })
        $missingTemplateIds = @($requestedTemplateIds | Where-Object { $_ -notin $foundTemplateIds })
        if ($missingTemplateIds.Count -gt 0) {
            throw "Template ID(s) not found or unsupported: $($missingTemplateIds -join ', ')."
        }
    }

    if ($templates.Count -eq 0) {
        throw "No supported Microsoft Sentinel alert rule templates were found in workspace '$WorkspaceName'."
    }

    $existingRules = Get-SentinelPagedItems `
        -Path "$sentinelBasePath/alertRules?api-version=$NrtApiVersion" `
        -ResourceType 'analytics rule'
    $rulesByTemplateName = @{}
    foreach ($rule in $existingRules) {
        $templateName = Get-ObjectPropertyValue `
            -InputObject $rule.properties -Name 'alertRuleTemplateName'
        if ([string]::IsNullOrWhiteSpace($templateName)) {
            continue
        }

        if (-not $rulesByTemplateName.ContainsKey($templateName)) {
            $rulesByTemplateName[$templateName] = [System.Collections.Generic.List[object]]::new()
        }
        $rulesByTemplateName[$templateName].Add($rule)
    }

    $eligibleTemplateIds = @{}
    foreach ($template in $templates) {
        $eligibleTemplateIds[$template.name] = $true
    }
    $managedExistingRules = @($existingRules | Where-Object {
        $existingTemplateName = Get-ObjectPropertyValue `
            -InputObject $_.properties -Name 'alertRuleTemplateName'
        -not [string]::IsNullOrWhiteSpace("$existingTemplateName") -and
            $eligibleTemplateIds.ContainsKey($existingTemplateName)
    })
    $unmanagedExistingRules = @($existingRules | Where-Object {
        $existingTemplateName = Get-ObjectPropertyValue `
            -InputObject $_.properties -Name 'alertRuleTemplateName'
        [string]::IsNullOrWhiteSpace("$existingTemplateName") -or
            -not $eligibleTemplateIds.ContainsKey($existingTemplateName)
    })

    Write-Host ''
    Write-Host 'Existing rule scope' -ForegroundColor Cyan
    Write-Host "  Existing analytics rules : $($existingRules.Count)"
    Write-Host "  Linked to eligible scope : $($managedExistingRules.Count)"
    Write-Host "  Outside eligible scope   : $($unmanagedExistingRules.Count) untouched"
    Write-DeploymentLog -Level 'INFO' -Event 'ExistingRuleScope' `
        -Message "$($managedExistingRules.Count) of $($existingRules.Count) existing rule(s) are linked to eligible installed templates." `
        -Data @{
            existingRuleCount          = $existingRules.Count
            managedExistingRuleCount   = $managedExistingRules.Count
            unmanagedExistingRuleCount = $unmanagedExistingRules.Count
        }

    $candidatePlan = [System.Collections.Generic.List[object]]::new()
    $duplicateRuleReport = [System.Collections.Generic.List[object]]::new()
    foreach ($template in $templates) {
        if ($rulesByTemplateName.ContainsKey($template.name)) {
            $matchingRules = @($rulesByTemplateName[$template.name])
            $existingRule = Select-CanonicalRuleForTemplate `
                -Rules $matchingRules -TemplateId $template.name
            $duplicateRules = @($matchingRules | Where-Object {
                $_.name -ne $existingRule.name
            })

            if ($duplicateRules.Count -gt 0) {
                foreach ($duplicateRule in $duplicateRules) {
                    $duplicateRuleReport.Add([pscustomobject]@{
                        templateId        = $template.name
                        templateDisplayName = Get-ObjectPropertyValue `
                            -InputObject $template.properties -Name 'displayName'
                        canonicalRuleId   = $existingRule.name
                        duplicateRuleId   = $duplicateRule.name
                        duplicateDisplayName = Get-ObjectPropertyValue `
                            -InputObject $duplicateRule.properties -Name 'displayName'
                    })
                }

                Write-DeploymentLog -Level 'TRACE' -Event 'DuplicateRulesSkipped' `
                    -Message "Template '$($template.name)' has $($matchingRules.Count) existing rules; only canonical rule '$($existingRule.name)' will be managed." `
                    -Data @{
                        templateId      = $template.name
                        canonicalRuleId = $existingRule.name
                        skippedRuleIds  = @($duplicateRules.name)
                    }
            }
        }
        else {
            $existingRule = $null
        }

        $targetEnabled = Get-TargetEnabledState -ExistingRule $existingRule
        if ($null -eq $existingRule) {
            $ruleId = $template.name
            $payload = New-AlertRulePayloadFromTemplate -Template $template `
                -Enabled $targetEnabled -RulePrefix $Prefix
            $baseAction = 'Create'
            $currentEnabled = $null
        }
        else {
            $ruleId = $existingRule.name
            $payload = New-AlertRulePayloadFromExistingRule -Rule $existingRule `
                -Enabled $targetEnabled -RulePrefix $Prefix
            $baseAction = 'Update'
            $currentEnabled = [bool](Get-ObjectPropertyValue `
                -InputObject $existingRule.properties -Name 'enabled')
        }

        $changes = @(Get-RuleChanges -ExistingRule $existingRule -Payload $payload)
        $action = if ($changes.Count -eq 0) { 'NoChange' } else { $baseAction }
        $payloadJson = $payload | ConvertTo-Json -EnumsAsStrings -Depth 100 -Compress
        $displayName = Get-ObjectPropertyValue `
            -InputObject $payload.properties -Name 'displayName'
        if ([string]::IsNullOrWhiteSpace("$displayName")) {
            $displayName = Get-ObjectPropertyValue `
                -InputObject $template.properties -Name 'displayName'
        }
        $compatibilityIssue = if ($action -ne 'NoChange') {
            Get-EntityMappingCompatibilityIssue -Payload $payload
        }
        else {
            $null
        }
        $planAction = if ($null -ne $compatibilityIssue) {
            'Blocked'
        }
        else {
            $action
        }
        $planChanges = if ($null -ne $compatibilityIssue) {
            @($changes) + @($compatibilityIssue.Code)
        }
        else {
            $changes
        }

        $candidatePlan.Add([pscustomobject]@{
            TemplateId     = $template.name
            RuleId         = $ruleId
            Kind           = $template.kind
            DisplayName    = $displayName
            Action         = $planAction
            IntendedAction = $action
            Changes        = $planChanges
            CurrentEnabled = $currentEnabled
            TargetEnabled  = $targetEnabled
            ApiVersion     = if ($template.kind -eq 'NRT') { $NrtApiVersion } else { $ApiVersion }
            PayloadHash    = Get-Sha256 -Value $payloadJson
            Payload        = $payload
            ExistingRule   = $existingRule
            CompatibilityIssue = $compatibilityIssue
        })
    }

    ConvertTo-Json -InputObject @($duplicateRuleReport) -Depth 20 |
        Set-Content -LiteralPath $script:DuplicateReportPath -Encoding utf8
    Write-Host "  Existing duplicate rules : $($duplicateRuleReport.Count) skipped"
    if ($duplicateRuleReport.Count -gt 0) {
        Write-Host "  Duplicate report         : $script:DuplicateReportPath" -ForegroundColor Yellow
        Write-DeploymentLog -Level 'WARN' -Event 'DuplicateRuleSummary' `
            -Message "$($duplicateRuleReport.Count) duplicate existing rule resource(s) were excluded from the deployment plan." `
            -Data @{
                duplicateCount = $duplicateRuleReport.Count
                reportPath     = $script:DuplicateReportPath
            }
    }

    $candidatePlan = @($candidatePlan | Sort-Object DisplayName, RuleId)
    if ($candidatePlan.Count -gt $templates.Count) {
        throw "Internal safety check failed: plan count $($candidatePlan.Count) exceeds eligible template count $($templates.Count)."
    }

    $blockedCandidates = @($candidatePlan | Where-Object Action -eq 'Blocked')
    $compatibilityReport = @($blockedCandidates | ForEach-Object {
        [ordered]@{
            templateId          = $_.TemplateId
            ruleId              = $_.RuleId
            kind                = $_.Kind
            displayName         = $_.DisplayName
            intendedAction      = $_.IntendedAction
            code                = $_.CompatibilityIssue.Code
            message             = $_.CompatibilityIssue.Message
            entityMappingCount  = $_.CompatibilityIssue.EntityMappingCount
            maximumAllowed      = $_.CompatibilityIssue.MaximumAllowed
            entityTypes         = $_.CompatibilityIssue.EntityTypes
            excessEntityTypes   = $_.CompatibilityIssue.ExcessEntityTypes
        }
    })
    ConvertTo-Json -InputObject $compatibilityReport -Depth 20 |
        Set-Content -LiteralPath $script:CompatibilityReportPath -Encoding utf8

    if ($blockedCandidates.Count -gt 0) {
        Write-Host ''
        Write-Host 'Compatibility preflight' -ForegroundColor Cyan
        Write-Host "  Blocked rule resources : $($blockedCandidates.Count)"
        Write-Host "  Entity mapping limit   : $MaxEntityMappings"
        Write-Host "  Compatibility report  : $script:CompatibilityReportPath" `
            -ForegroundColor Yellow
        $blockedCandidates |
            Select-Object DisplayName,
                @{n = 'Mappings'; e = { $_.CompatibilityIssue.EntityMappingCount }},
                @{n = 'Limit'; e = { $_.CompatibilityIssue.MaximumAllowed }},
                IntendedAction, RuleId |
            Format-Table -AutoSize | Out-Host
        Write-DeploymentLog -Level 'WARN' -Event 'CompatibilityRulesBlocked' `
            -Message "$($blockedCandidates.Count) rule resource(s) were blocked before PUT because their entity mappings exceed the configured API limit of $MaxEntityMappings." `
            -Data @{
                blockedCount       = $blockedCandidates.Count
                maxEntityMappings  = $MaxEntityMappings
                reportPath         = $script:CompatibilityReportPath
                blockedTemplateIds = @($blockedCandidates.TemplateId)
            }
    }

    if ($DeploymentMode -eq 'Canary') {
        $templateFilterCount = @($TemplateId |
            Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }).Count
        if ($script:InteractiveSession -and $templateFilterCount -eq 0) {
            $deploymentPlan = @(Select-GuidedCanaryPlan -Candidates $candidatePlan)
        }
        else {
            $deploymentPlan = @($candidatePlan |
                Where-Object { $_.Action -notin @('NoChange', 'Blocked') } |
                Select-Object -First $CanaryCount)
        }
    }
    else {
        $deploymentPlan = $candidatePlan
    }

    $exportPlan = @($deploymentPlan | ForEach-Object {
        [ordered]@{
            templateId    = $_.TemplateId
            ruleId        = $_.RuleId
            kind          = $_.Kind
            displayName   = $_.DisplayName
            action        = $_.Action
            intendedAction = $_.IntendedAction
            changes       = $_.Changes
            blockReason   = if ($null -ne $_.CompatibilityIssue) {
                $_.CompatibilityIssue.Message
            }
            else {
                $null
            }
            currentEnabled = $_.CurrentEnabled
            targetEnabled = $_.TargetEnabled
            apiVersion    = $_.ApiVersion
            payloadHash   = $_.PayloadHash
        }
    })
    ConvertTo-Json -InputObject $exportPlan -Depth 20 |
        Set-Content -LiteralPath $script:PlanPath -Encoding utf8

    $createCount = @($deploymentPlan | Where-Object Action -eq 'Create').Count
    $updateCount = @($deploymentPlan | Where-Object Action -eq 'Update').Count
    $noChangeCount = @($deploymentPlan | Where-Object Action -eq 'NoChange').Count
    $blockedCount = @($deploymentPlan | Where-Object Action -eq 'Blocked').Count
    Write-DeploymentLog -Level 'INFO' -Event 'PlanCreated' `
        -Message "Plan contains $($deploymentPlan.Count) rule(s) from $($templates.Count) eligible template(s): $createCount create, $updateCount update, $noChangeCount unchanged, $blockedCount blocked." `
        -Data @{
            planPath      = $script:PlanPath
            candidateCount = $candidatePlan.Count
            selectedCount = $deploymentPlan.Count
            eligibleTemplateCount = $templates.Count
            excludedTemplateCount = $excludedTemplates.Count
            duplicateRulesSkipped = $duplicateRuleReport.Count
            existingRuleCount = $existingRules.Count
            managedExistingRuleCount = $managedExistingRules.Count
            unmanagedExistingRuleCount = $unmanagedExistingRules.Count
            projectedRuleCountAfterFull = $existingRules.Count + $createCount
            createCount   = $createCount
            updateCount   = $updateCount
            noChangeCount = $noChangeCount
            blockedCount  = $blockedCount
            compatibilityReportPath = $script:CompatibilityReportPath
        }

    $deploymentPlan |
        Select-Object Action, Kind, CurrentEnabled, TargetEnabled, DisplayName, RuleId |
        Format-Table -AutoSize | Out-Host

    if ($DeploymentMode -eq 'Validate') {
        Write-Host ''
        Write-Host 'Full rollout projection' -ForegroundColor Cyan
        Write-Host "  Existing rule resources : $($existingRules.Count)"
        Write-Host "  Planned new resources   : $createCount"
        Write-Host "  Projected total         : $($existingRules.Count + $createCount)"
        Write-Host "  Existing outside scope  : $($unmanagedExistingRules.Count) retained"
        Write-Host "  Blocked by preflight    : $blockedCount"
    }

    if ($DeploymentMode -eq 'Validate') {
        Write-DeploymentLog -Level 'INFO' -Event 'ValidationComplete' `
            -Message 'Validate mode completed. No PUT request was sent to Azure.' `
            -Data @{
                planPath               = $script:PlanPath
                blockedCount           = $blockedCount
                compatibilityReportPath = $script:CompatibilityReportPath
            }
        return [pscustomobject]@{
            Mode        = $DeploymentMode
            Created     = 0
            Updated     = 0
            Unchanged   = $noChangeCount
            Blocked     = $blockedCount
            ResumedSkip = 0
            Failed      = 0
        }
    }

    $completedResumeKeys = Get-CompletedResumeKeys
    $created = 0
    $updated = 0
    $unchanged = 0
    $blocked = 0
    $resumedSkip = 0
    $failed = 0

    foreach ($planItem in $deploymentPlan) {
        if ($planItem.Action -eq 'Blocked') {
            $blocked++
            Add-JournalRecord -Phase 'BlockedPreflight' -PlanItem $planItem `
                -AdditionalData @{
                    compatibilityIssue = $planItem.CompatibilityIssue
                    reportPath         = $script:CompatibilityReportPath
                }
            Write-DeploymentLog -Level 'WARN' -Event 'RuleBlockedPreflight' `
                -Message "Blocked '$($planItem.DisplayName)' before PUT: $($planItem.CompatibilityIssue.Message)" `
                -Data @{
                    ruleId              = $planItem.RuleId
                    templateId          = $planItem.TemplateId
                    intendedAction      = $planItem.IntendedAction
                    compatibilityIssue  = $planItem.CompatibilityIssue
                    compatibilityReport = $script:CompatibilityReportPath
                }
            continue
        }

        if ($planItem.Action -eq 'NoChange') {
            $unchanged++
            Write-DeploymentLog -Level 'TRACE' -Event 'RuleUnchanged' `
                -Message "No PUT needed for '$($planItem.DisplayName)'." `
                -Data @{ ruleId = $planItem.RuleId; templateId = $planItem.TemplateId }
            continue
        }

        $resumeKey = "$($planItem.RuleId)|$($planItem.PayloadHash)"
        if ($completedResumeKeys.ContainsKey($resumeKey)) {
            $resumedSkip++
            Add-JournalRecord -Phase 'SkippedFromResume' -PlanItem $planItem `
                -AdditionalData @{ resumeStatePath = $ResumeStatePath }
            Write-DeploymentLog -Level 'INFO' -Event 'RuleSkippedFromResume' `
                -Message "Skipping previously successful identical payload for '$($planItem.DisplayName)'." `
                -Data @{ ruleId = $planItem.RuleId; payloadHash = $planItem.PayloadHash }
            continue
        }

        try {
            $snapshotPath = Save-ExistingRuleSnapshot -PlanItem $planItem
            Add-JournalRecord -Phase 'BeforeRequest' -PlanItem $planItem `
                -AdditionalData @{ snapshotPath = $snapshotPath }

            $target = "$($planItem.DisplayName) [$($planItem.RuleId)]"
            $operation = "$($planItem.Action) Sentinel analytics rule; changes: $($planItem.Changes -join ', ')"
            if ($script:Cmdlet.ShouldProcess($target, $operation)) {
                $rulePath = "$sentinelBasePath/alertRules/$($planItem.RuleId)"
                $result = Invoke-SentinelRest -Path $rulePath -Method PUT `
                    -Body $planItem.Payload -Operation $operation `
                    -ApiVersionOverride $planItem.ApiVersion

                Add-JournalRecord -Phase 'Succeeded' -PlanItem $planItem `
                    -AdditionalData @{
                        httpStatusCode = $result.StatusCode
                        snapshotPath   = $snapshotPath
                    }
                if ($planItem.Action -eq 'Create') {
                    $created++
                }
                else {
                    $updated++
                }

                Write-DeploymentLog -Level 'INFO' -Event 'RuleDeploymentSucceeded' `
                    -Message "$($planItem.Action)d '$($planItem.DisplayName)' successfully." `
                    -Data @{
                        ruleId       = $planItem.RuleId
                        templateId   = $planItem.TemplateId
                        changes      = $planItem.Changes
                        targetEnabled = $planItem.TargetEnabled
                        snapshotPath = $snapshotPath
                    }
            }
            else {
                Add-JournalRecord -Phase 'SkippedByShouldProcess' -PlanItem $planItem `
                    -AdditionalData $null
            }
        }
        catch {
            $failed++
            $diagnostic = Get-ErrorDiagnostic -ErrorRecord $_ `
                -Operation "$($planItem.Action) '$($planItem.DisplayName)'"
            Add-JournalRecord -Phase 'Failed' -PlanItem $planItem `
                -AdditionalData $diagnostic
            Write-DeploymentError -ErrorRecord $_ `
                -Operation "$($planItem.Action) '$($planItem.DisplayName)'" -Level 'ERROR'

            if ($FailurePolicy -eq 'Stop') {
                throw
            }
        }
    }

    return [pscustomobject]@{
        Mode        = $DeploymentMode
        Created     = $created
        Updated     = $updated
        Unchanged   = $unchanged
        Blocked     = $blocked
        ResumedSkip = $resumedSkip
        Failed      = $failed
    }
}

function Show-RecommendedNextStep {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Result
    )

    if (-not $script:InteractiveSession) {
        return
    }

    Write-Host ''
    Write-Host 'Recommended next step' -ForegroundColor Cyan
    if ($Result.Blocked -gt 0) {
        Write-Host "$($Result.Blocked) rule(s) were not deployed because compatibility preflight blocked them." `
            -ForegroundColor Yellow
        Write-Host "Review: $script:CompatibilityReportPath" -ForegroundColor Yellow
    }
    if ($DeploymentMode -eq 'Validate') {
        Write-Host 'Review the generated plan, then run .\Enable-rules.ps1 again and choose [2] Canary stage.'
    }
    elseif ($DeploymentMode -eq 'Canary' -and $ActivationMode -eq 'Preserve') {
        Write-Host 'Validate the staged Canary rules, then run .\Enable-rules.ps1 again and choose [3] Canary enable.'
    }
    elseif ($DeploymentMode -eq 'Canary' -and $ActivationMode -eq 'Enabled') {
        Write-Host 'Monitor Canary alerts and incidents, then run .\Enable-rules.ps1 again and choose [4] Full stage.'
    }
    elseif ($DeploymentMode -eq 'Full' -and $ActivationMode -eq 'Preserve') {
        Write-Host 'Review the full staged rollout, then run .\Enable-rules.ps1 again and choose [5] Full enable.'
    }
    else {
        Write-Host 'Full rollout and activation are complete. Continue monitoring alerts, incidents, and the deployment log.'
    }
}

try {
    if (-not $script:InvocationBoundParameters.ContainsKey('DeploymentMode')) {
        $continueDeployment = Start-GuidedConfiguration
        if (-not $continueDeployment) {
            return
        }
    }
    elseif ($script:InvocationBoundParameters.ContainsKey('EnableRules')) {
        $ActivationMode = if ($EnableRules -eq 'Yes') { 'Enabled' } else { 'Disabled' }
    }

    $result = Start-SentinelRuleDeployment
    $duration = [datetime]::UtcNow - $script:RunStartedUtc
    Write-DeploymentLog -Level 'INFO' -Event 'RunCompleted' `
        -Message "Run completed in $([math]::Round($duration.TotalSeconds, 2)) second(s)." `
        -Data @{
            result      = $result
            durationMs  = [math]::Round($duration.TotalMilliseconds)
            logPath     = $script:LogPath
            planPath    = $script:PlanPath
            journalPath = $script:JournalPath
            duplicateReportPath = $script:DuplicateReportPath
            compatibilityReportPath = $script:CompatibilityReportPath
        }

    Write-Host ''
    Write-Host "Result  : Mode=$($result.Mode), Created=$($result.Created), Updated=$($result.Updated), Unchanged=$($result.Unchanged), Blocked=$($result.Blocked), ResumeSkip=$($result.ResumedSkip), Failed=$($result.Failed)" -ForegroundColor Green
    Write-Host "Log     : $script:LogPath"
    Write-Host "Plan    : $script:PlanPath"
    Write-Host "Journal : $script:JournalPath"
    if (Test-Path -LiteralPath $script:DuplicateReportPath) {
        Write-Host "Duplicates: $script:DuplicateReportPath"
    }
    if (Test-Path -LiteralPath $script:CompatibilityReportPath) {
        Write-Host "Compatibility: $script:CompatibilityReportPath"
    }
    Show-RecommendedNextStep -Result $result
}
catch {
    if ($script:LogPath) {
        Write-DeploymentError -ErrorRecord $_ -Operation 'Sentinel rule deployment' -Level 'FATAL'
        Write-Host "Log     : $script:LogPath" -ForegroundColor Yellow
        Write-Host "Plan    : $script:PlanPath" -ForegroundColor Yellow
        Write-Host "Journal : $script:JournalPath" -ForegroundColor Yellow
        if ($script:DuplicateReportPath) {
            Write-Host "Duplicates: $script:DuplicateReportPath" -ForegroundColor Yellow
        }
        if ($script:CompatibilityReportPath) {
            Write-Host "Compatibility: $script:CompatibilityReportPath" `
                -ForegroundColor Yellow
        }
    }
    else {
        Write-Error $_ -ErrorAction Continue
    }

    exit 1
}
