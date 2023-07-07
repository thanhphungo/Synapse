#---------------------------------------------------------[Global Variables]-----------------------------------------------------
#region
$Global:AuthenticationToken = $null
$Global:Scopes = $null
$Global:SignIn = $null
$Global:SignInName = $null

$resourceManagerEndpointUrl = "https://management.usgovcloudapi.net"     #Endpoint for Azure Resource Manager REST API
$destSynapseDevelopmentEndpointUrl = "https://dev.azuresynapse.usgovcloudapi.net/.default"     #Endpoint for Synapse Rest API

$psGetDocs = "Documentation is available at https://docs.microsoft.com/en-us/powershell/module/powershellget/?view=powershell-7.1"
$azPSDocs = "Documentation is available at https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-5.5.0"
$azSynDocs = "Documentation is available at https://docs.microsoft.com/en-us/powershell/module/az.synapse/?view=azps-5.6.0"
$msalPSDocs = "Documentation is available at https://www.powershellgallery.com/packages/MSAL.PS/4.2.1.3"

#Default App Settings JSON
$defaultConfigContent = '{
        "AzureSettings": {
            "TenantId": "<fill in the Tenant ID from the Azure Portal>",
            "SubscriptionId": "<fill in the Subscription ID from the Azure Portal>",
            "ClientID": "<fill in the Service Principal ID from the Azure Portal>",
            "ClientSecret": "<fill in the Service Principal Secret from the Azure Portal>"
        },
        "srcSynapseWorkspace": {
            "ResourceGroup": "<Resource Group name where source Synapse is located>",
            "Name": "<Source Synapse Workspace Name>",
            "ResourceId": "<Source Synapse Resource ID i.e., /subscriptions/YOURSUBSCRIPTIONID/resourceGroups/RESOURCEGROUPOFSYNAPSEWORKSPACE/providers/Microsoft.Synapse/workspaces/YOURSYNAPSEWORKSPACENAME>",
            "apiVersion": "<api version i.e., 2019-06-01-preview>"
        },
        "destSynapseWorkspace": {
            "ResourceGroup": "<resource group name were synapse is located>",
            "Name": "<Synapse Workspace Name>",
            "ResourceId": "<Destination Synapse Resource ID i.e., /subscriptions/YOURSUBSCRIPTIONID/resourceGroups/RESOURCEGROUPOFSYNAPSEWORKSPACE/providers/Microsoft.Synapse/workspaces/YOURSYNAPSEWORKSPACENAME>",
            "apiVersion": "<api version i.e., 2019-06-01-preview>"
        }
    }'
#endregion

#---------------------------------------------------------[Prerequisites]-----------------------------------------------------
#region
function CheckPrerequisites() {
    CustomWriteHost("[CHECK] Azure PowerShell Module check")
    #Please make sure you have the PowerShellGet Module installed and the minimum version is -MinimumVersion 2.2.5
    #https://www.powershellgallery.com/packages/PowerShellGet/2.2.5
    $azPSGetInstalled = Get-Module -ListAvailable -Name PowerShellGet
    if (-Not $azPSGetInstalled) {
        WriteErrorResponse "  PowerShellGet module is not installed - Install it via 'Install-Module -Name PowerShellGet -RequiredVersion 2.2.5 -Force'. $($psGetDocs)"
        #Install-Module -Name PowerShellGet -RequiredVersion 2.2.5 -Force
        return $False
    }

    #Please make sure you have the Az.Resources Module installed and the minimum version is -MinimumVersion 3.3.0
    #https://www.powershellgallery.com/packages/Az.Resources/3.3.0
    $azResourcesInstalled = Get-Module -ListAvailable -Name Az.Resources
    if (-Not $azResourcesInstalled) {
        WriteErrorResponse "  Az.Resources module is not installed - Install it via 'Install-Module -Name Az.Resources -MinimumVersion 3.3.0 -AllowClobber -Force'. $($azPSDocs)"
        #Install-Module -Name Az.Resources -AllowClobber -Force
        return $False
    }

    #Please make sure you have the Az.Accounts Module installed and the minimum version is -MinimumVersion 2.2.6
    #https://www.powershellgallery.com/packages/Az.Accounts/2.2.6
    $azAccountsInstalled = Get-Module -ListAvailable -Name Az.Accounts
    if (-Not $azAccountsInstalled) {
        WriteErrorResponse "  Az.Accounts module is not installed - Install it via 'Install-Module -Name Az.Accounts -MinimumVersion 2.2.6 -AllowClobber -Force'. $($azPSDocs)"
        #Install-Module -Name Az.Accounts -AllowClobber -Force
        return $False
    }

    #Please make sure you have the Az.Synapse Module installed and the minimum version is -MinimumVersion 0.8.0
    #https://www.powershellgallery.com/packages/Az.Synapse/0.8.0
    $azSynapseInstalled = Get-Module -ListAvailable -Name Az.Synapse
    if (-Not $azSynapseInstalled) {
        WriteErrorResponse "  Az.Synapse module is not installed - Install it via 'Install-Module -Name Az.Synapse -MinimumVersion 0.8.0 -AllowClobber -Force'. $($azSynDocs)"
        #Install-Module -Name Az.Synapse -AllowClobber -Force
        return $False
    }

    return $True
}
#endregion

#---------------------------------------------------------[CheckResources]-----------------------------------------------------
#region
#Check if Synapse Workspaces Exist
function CheckResources() {
    CustomWriteHost("[CHECK] Source and Destination Synapse Workspaces")

    #Check if source Synapse Workspace Exists
    #$srcSyn = Get-AzSynapseWorkspace -ResourceGroupName $config.srcSynapseWorkspace.ResourceGroup -Name $config.srcSynapseWorkspace.Name -ErrorAction Continue
    $srcSyn = Get-AzResource -ResourceGroupName $config.srcSynapseWorkspace.ResourceGroup -Name $config.srcSynapseWorkspace.Name -ExpandProperties -ErrorAction Continue
    $srcSynGitConnected = 0

    if (-Not $srcSyn) {
        WriteError ("[Error] The Synapse Workspace you are trying to access does not exist or you do not have access to it.")
        WriteError ("Migration aborted.")
        return $False
    }
    else {
        try {
            if ($srcSyn.Properties.workspaceRepositoryConfiguration.accountName ) {
                Write-Host("Azure Synapse Analytics is connected to a Git repository")
                Write-Host("Migration will only migrate to Live. ")
                Write-Host("You will need to disconnect your Git repository and resync to get the changes that have been migrated to Synapse live.")
                $srcSynGitConnected = 1
            } 
        }
        catch {
            # do nothing
            
        }
    }

    if ($srcSynGitConnected -eq 0) {
        Write-Host("Azure Synapse Analytics is not connected to a Git repository")
    }

    #Check if destination Synapse Workspace Exists
    #$destSyn = Get-AzSynapseWorkspace -ResourceGroupName $config.destSynapseWorkspace.ResourceGroup -Name $config.destSynapseWorkspace.Name -ErrorAction Continue
    $destSyn = Get-AzResource -ResourceGroupName $config.destSynapseWorkspace.ResourceGroup -Name $config.destSynapseWorkspace.Name -ExpandProperties -ErrorAction Continue
    $destSynGitConnected = 0

    if (-Not $destSyn) {
        WriteError ("[Error] The Synapse Workspace you are trying to access does not exist or you do not have access to it.")
        WriteError ("Migration aborted.")
        return $False
    }
    else {
        try {
            if ($destSyn.Properties.workspaceRepositoryConfiguration.accountName ) {
                Write-Host("Azure Synapse Analytics is connected to a Git repository")
                Write-Host("Migration will only migrate to Live. ")
                Write-Host("You will need to disconnect your Git repository and resync to get the changes that have been migrated to Synapse live.")
                $destSynGitConnected = 1
            } 
        }
        catch {
            # do nothing
            
        }
    }

    if ($destSynGitConnected -eq 0) {
        Write-Host("Azure Synapse Analytics is not connected to a Git repository")
    }

    Write-Host "#--------------------------------------------------------------------------------------------------------";
    CustomWriteHost("[CHECK] Source and destination Synapse Workspace Role Assignment")
    #Get the Role Assignment you have on your source Synapse and Synapse Workspace
    if ($Global:SignIn -eq 'S') {
        $srcSynRole = Get-AzRoleAssignment -ServicePrincipalName $Global:SignInName -ResourceGroupName $config.srcSynapseWorkspace.ResourceGroup -ResourceName $config.srcSynapseWorkspace.Name -ResourceType "Microsoft.Synapse/workspaces"
        $destSynRole = Get-AzRoleAssignment -ServicePrincipalName $Global:SignInName -ResourceGroupName $config.destSynapseWorkspace.ResourceGroup -ResourceName $config.destSynapseWorkspace.Name -ResourceType "Microsoft.Synapse/workspaces"
    }
    else {
        $srcSynRole = Get-AzRoleAssignment -SignInName $Global:SignInName -ResourceGroupName $config.srcSynapseWorkspace.ResourceGroup -ResourceName $config.srcSynapseWorkspace.Name -ResourceType "Microsoft.Synapse/workspaces"
        $destSynRole = Get-AzRoleAssignment -SignInName $Global:SignInName -ResourceGroupName $config.destSynapseWorkspace.ResourceGroup -ResourceName $config.destSynapseWorkspace.Name -ResourceType "Microsoft.Synapse/workspaces"
    }

    if (-Not $srcSynRole) {
        WriteError ("Source Synapse you are trying to access does not exist or you do not have access to it.")
        WriteError ("Migration aborted.")
        return $False
    }
    else {
        Write-Host "Source Synapse Role Assignment for Service Principal/User $($Global:SignInName) is: $($srcSynRole.RoleDefinitionName)" -ForegroundColor Green
    }

    if (-Not $destSynRole) {
        WriteError ("Destination Synapse you are trying to access does not exist or you do not have access to it.")
        WriteError ("Migration aborted.")
        return $False
    }
    else {
        Write-Host "Destination Synapse Role Assignment for Service Principal/User $($Global:SignInName) is: $($destSynRole.RoleDefinitionName)" -ForegroundColor Green
    }

    return $True
}

#endregion

#---------------------------------------------------------[Login]-----------------------------------------------------
#region
function Login {
    Param (
        [object] $config,
        [string] $signIn,
        [string] $tenantId
    )
    try {
        $context = Get-AzContext
        if (!$context -or ($context.Subscription.Id -ne $config.AzureSettings.SubscriptionId)) {
            #Login to Azure (programmatically)
            if ($signIn -eq 's') {
                Write-Host ""
                Write-Host "Logging into Azure" -ForegroundColor Yellow
                Write-Host "Authentication Type: Service Principal (Client ID and Secret) from appSettings.json."
                $pscredential = New-Object -TypeName System.Management.Automation.PSCredential($config.AzureSettings.ClientID, (ConvertTo-SecureString $config.AzureSettings.ClientSecret -AsPlainText -Force))
                Connect-AzAccount -Credential $pscredential -Tenant $config.AzureSettings.TenantId -ServicePrincipal -EnvironmentName "AzureUSGovernment" | Out-null
                Write-Host ""
            }
            #Login to Azure (interactively)
            else {
                Write-Host ""
                Write-Host "Logging into Azure" -ForegroundColor Yellow
                Write-Host "Authentication Type: Interactively"
                    
                # get the subscription info
                if (-NOT [string]::IsNullOrEmpty($tenantId) ) {
                    #Login with Tentant Id
                    Connect-AzAccount -SubscriptionId $config.AzureSettings.SubscriptionId -TenantId $tenantId -EnvironmentName "AzureUSGovernment"
                }
                else {
                    Connect-AzAccount -SubscriptionId $config.AzureSettings.SubscriptionId -EnvironmentName "AzureUSGovernment"

                    # Set the right Tenant ID
                    $subscription = Get-AzSubscription -SubscriptionId $config.AzureSettings.SubscriptionId

                    Write-Host "Setting AzContext "
                    Set-AzContext -SubscriptionId $subscription.Id -TenantId $subscription.TenantId
                }                   
            }

            $context = Get-AzContext
            if ($context.Account.type -eq 'ServicePrincipal') {
                $Global:SignInName = $config.AzureSettings.ClientId
            }
            else {
                $Global:SignInName = $context.Account.Id
            }

            LoginContextDetails -tenantcontext $context.Tenant.Id -subscriptioncontext $config.AzureSettings.SubscriptionId -usercontext $(if ($signIn -eq 'S') { 'ServicePrincipal' } else { 'User' })
        }
        else {
            LoginContextDetails $context.Subscription.Id $context.Tenant.Id $context.Account.type
        }
    }
    catch {
        Write-Host ""
        WriteError $_
        WriteErrorResponse "  You were not able to login. Please check your appsettings.json file or log in interactively via the Connect-AzAccount command"
        throw
    }
}

#-------------------------------------------------------------------
function CheckLogin() {
    $context = Get-AzContext
    if (!$context) {
        Write-Host ""
        WriteErrorResponse "  You are NOT currently logged into Azure."
        Write-Host ""
        return $False
    }

    if ($context.Account.type -eq 'ServicePrincipal') {
        $Global:SignInName = $config.AzureSettings.ClientId
        $Global:SignIn = "S"
    }
    else {
        $Global:SignInName = $context.Account.Id
        $Global:SignIn = "I"
    }

    LoginContextDetails $context.Subscription.Id $context.Tenant.Id $context.Account.type

    return $True
}

#-------------------------------------------------------------------
function LoginContextDetails() {
    Param (
        [string] $tenantcontext,
        [string] $subscriptioncontext,
        [string] $usercontext
    )

    Write-Host ""
    Write-Host "#--------------------------------------------------------------------------------------------------------"
    WriteSuccess "  You are currently logged into the following Subscription: "
    WriteSuccess "   SubscriptionId: '$($subscriptioncontext)' "
    WriteSuccess "   TenantId: '$($tenantcontext)' "
    WriteSuccess "   Context: '$($usercontext)'"
    Write-Host "#--------------------------------------------------------------------------------------------------------"
    Write-Host ""
}

#-------------------------------------------------------------------
function GetAuthenticationToken {
    Param (
        [bool] $armToken,
        [string] $signIn
    )

    try {
        if ($armToken -eq $true) {
            $token = Get-AzAccessToken -ResourceTypeName Arm
            $Global:AuthenticationToken = $token.Token
        }
        else {
            $token = Get-AzAccessToken -ResourceTypeName Synapse
            $Global:AuthenticationToken = $token.Token
        }

        if ($Global:AuthenticationToken) {
            return $Global:AuthenticationToken
        }
        else {
            Write-Host
            Write-Host "Authorization Access Token is null, please stop the script and re-run authentication..." -ForegroundColor Red
            Write-Host
            break
        }
    }
    catch {
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    }
}
#endregion

#---------------------------------------------------------[Load Config File]-----------------------------------------------------
#region
function GetDefaultConfig() {
    $defaultConfig = ConvertFrom-Json($defaultConfigContent)
    return $defaultConfig
}

function LoadConfig(
    [string] $fileLocation,
    [string] $TenantId,
    [string] $SubscriptionId,
    [string] $srcResourceGroupSynapse,
    [string] $srcSynapseName,
    [string] $destResourceGroupSynapse,
    [string] $destSynapseName,
    [string] $ClientID,
    [string] $ClientSecret,
    [string] $srcSynapseResourceId,
    [string] $destSynapseResourceId,
    [string] $srcSynapseAPIVersion,
    [string] $destSynapseAPIVersion
) {

    try {
        if (-NOT [string]::IsNullOrEmpty($fileLocation)) {
            $configFromFile = Get-Content -Path $fileLocation -Raw | ConvertFrom-Json
        }
    }
    catch {
        WriteError("Could not parse config json file at: $fileLocation. Please ensure that it is a valid json file (use a json linter, often a stray comma can make your file invalid)")
        return $null
    }

    $defaultConfig = GetDefaultConfig
    $config = $defaultConfig

    if (-NOT [string]::IsNullOrEmpty($fileLocation)) {
        if ([bool]($configFromFile | get-member -name "AzureSettings")) {
            $configFromFile.AzureSettings.psobject.properties | ForEach-Object {
                $config.AzureSettings | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value -Force
            }
        }

        if ([bool]($configFromFile | get-member -name "srcSynapseWorkspace")) {
            $configFromFile.srcSynapseWorkspace.psobject.properties | ForEach-Object {
                $config.srcSynapseWorkspace | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value -Force
            }
        }

        if ([bool]($configFromFile | get-member -name "destSynapseWorkspace")) {
            $configFromFile.destSynapseWorkspace.psobject.properties | ForEach-Object {
                $config.destSynapseWorkspace | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value -Force
            }
        }
    }

    #Override App Settings Tenant ID
    if (-Not [string]::IsNullOrEmpty($TenantId)) {
        $config.AzureSettings.TenantId = $TenantId
    }

    #Override App Settings Subscription ID
    if (-Not [string]::IsNullOrEmpty($SubscriptionId)) {
        $config.AzureSettings.SubscriptionId = $SubscriptionId
    }

    #Override App Settings source Synapse Resource Group
    if (-Not [string]::IsNullOrEmpty($srcResourceGroupSynapse)) {
        $config.srcSynapseWorkspace.ResourceGroup = $srcResourceGroupSynapse
    }

    #Override App Settings source Synapse Name Entry
    if (-Not [string]::IsNullOrEmpty($srcSynapseName)) {
        $config.srcSynapseWorkspace.Name = $srcSynapseName
    }

    #Override App Settings destination Synapse Resource Group Entry
    if (-Not [string]::IsNullOrEmpty($destResourceGroupSynapse)) {
        $config.destSynapseWorkspace.ResourceGroup = $destResourceGroupSynapse
    }

    #Override App Settings destination Synapse Name Entry
    if (-Not [string]::IsNullOrEmpty($destSynapseName)) {
        $config.destSynapseWorkspace.Name = $destSynapseName
    }

    if (-NOT [string]::IsNullOrEmpty($fileLocation)) {
        $config.srcSynapseWorkspace.ResourceId = "/subscriptions/$($config.AzureSettings.SubscriptionId)/resourceGroups/$($config.srcSynapseWorkspace.ResourceGroup)/providers/Microsoft.Synapse/workspaces/$($config.srcSynapseWorkspace.Name)"
        $config.destSynapseWorkspace.ResourceId = "/subscriptions/$($config.AzureSettings.SubscriptionId)/resourceGroups/$($config.destSynapseWorkspace.ResourceGroup)/providers/Microsoft.Synapse/workspaces/$($config.destSynapseWorkspace.Name)"
    }

    #Override App Settings source Synapse ResourceID Entry
    if (-Not [string]::IsNullOrEmpty($srcSynapseResourceId)) {
        $config.srcSynapseWorkspace.ResourceId = $srcSynapseResourceId
    }

    #Override App Settings destination Synapse ResourceID Entry
    if (-Not [string]::IsNullOrEmpty($destSynapseResourceId)) {
        $config.destSynapseWorkspace.ResourceId = $destSynapseResourceId
    }

    #Override App Settings source Synapse apiVersion
    if (-Not [string]::IsNullOrEmpty($srcSynapseAPIVersion)) {
        $config.srcSynapseWorkspace.apiVersion = $srcSynapseAPIVersion
    }

    #Override App Settings destination Synapse apiVersion
    if (-Not [string]::IsNullOrEmpty($destSynapseAPIVersion)) {
        $config.destSynapseWorkspace.apiVersion = $destSynapseAPIVersion
    }

    return $config
}
#endregion

#---------------------------------------------------------[Format Output Messages]-----------------------------------------------------
#region
function CustomWriteHost($str) {
    Write-Host "$(Get-Date) : $str"
}

function CustomWriteHostError($str) {
    Write-Host "$(Get-Date) : $str" -ForegroundColor Red
}

function WriteError([string] $message) {
    Write-Host -ForegroundColor Red "$(Get-Date) : $message";
}

function WriteSuccess([string] $message) {
    Write-Host -ForegroundColor Green "$(Get-Date) : $message";
}
function WriteSuccessResponse([string] $message) {
    Write-Host -ForegroundColor Green "#--------------------------------------------------------------------------------------------------------";
    WriteInformation("$message")
    Write-Host -ForegroundColor Green "#--------------------------------------------------------------------------------------------------------";
}

function WriteErrorResponse([string] $message) {
    Write-Host -ForegroundColor Red "#--------------------------------------------------------------------------------------------------------";
    WriteInformation("$(Get-Date) : $message")
    Write-Host -ForegroundColor Red "#--------------------------------------------------------------------------------------------------------";
}

function WriteInformation([string] $message) {
    Write-Host -ForegroundColor White "$(Get-Date) : $message";
}

function WriteLine {
    Write-Host `n;
    Write-Host "--------------------------------------------------------------------------------------------------------------------" ;
    Write-Host `n;
}

function WriteProgress($activity, $status) {
    Write-Progress -Activity $activity -Status $status;
}
#endregion