#---------------------------------------------------------[Parameters]-----------------------------------------------------
#region Parameters
[CmdletBinding(DefaultParameterSetName = "ByResourceID")]
Param(
    [Parameter(ParameterSetName = 'ByResourceID')]
    [string]$srcSynapseResourceId,
    [Parameter(ParameterSetName = 'ByResourceID')]
    [string]$destSynapseResourceId,

    [Parameter(ParameterSetName = 'ByConfigFile')]
    [string]$ConfigFile,

    [ValidateSet('Interactive', 'ServicePrincipal')]
    [string]$AuthenticationType = "Interactive",

    [string] $TenantId, #optional override for TenantId in config file
    [string] $SubscriptionId, #optional override for SubscriptionId in config file
    [string] $srcResourceGroupSynapse, #optional override for srcResourceGroupSynapse in config file
    [string] $srcSynapseName, #optional override for srcSynapseName in config file
    [string] $destResourceGroupSynapse, #optional override for destResourceGroupSynapse in config file
    [string] $destSynapseName, #optional override for destSynapseName in config file
    [string] $ClientID, #optional override for ClientID in config file
    [string] $ClientSecret #optional override for ClientSecret in config file
)
#endregion Parameters

Clear-Host
Set-PSDebug -Trace 0 -Strict
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
Set-StrictMode -Version Latest

#---------------------------------------------------------[Load Utility File]-----------------------------------------------------
#region Utility

#Load Utility File
. "$PSScriptRoot\Utils.ps1" #include Utils for Console Messages, Logging, Config parsing

#endregion Utility

#---------------------------------------------------------[Migrate Synapse to Synapse]-----------------------------------------------------
#region MigrateSynapse
function MigrateSynapse {
    #If Config file is specified, use the appsettings.json file
    if ($ConfigFile) {
        Write-Host -ForegroundColor Yellow "Migration Config File: $ConfigFile"

        #Load Config file
        try {
            if (-Not [string]::IsNullOrEmpty($ConfigFile)) {
                $ConfigFile = "$PSScriptRoot\$ConfigFile"

                if ( Test-Path $ConfigFile ) {
                    $config = LoadConfig `
                        -fileLocation $ConfigFile `
                        -TenantId $TenantId `
                        -SubscriptionId $SubscriptionId `
                        -srcResourceGroupSynapse $srcResourceGroupSynapse `
                        -srcSynapseName $srcSynapseName `
                        -destResourceGroupSynapse $destResourceGroupSynapse `
                        -destSynapseName $destSynapseName `
                        -ClientID $ClientID `
                        -ClientSecret $ClientSecret

                    if ($null -eq $config) {
                        WriteError("[Error] reading config file - check the syntax within your config file. Make sure the JSON is properly formatted.")
                        exit 1
                    }
                }
                else {
                    WriteError("[Error] reading config file - File path, file name or directory does not exist: $($ConfigFile)")
                    exit -1
                }
            }
            else {
                WriteError("[Error] reading config file - Please provide the name of your config file (i.e. appsettings.json)")
                exit -1
            }
        }
        catch {
            CustomWriteHostError("[Error] $_.Exception.Message")
            exit -1
        }
    }
    elseif (-NOT [string]::IsNullOrEmpty($srcSynapseResourceId) -and -NOT [string]::IsNullOrEmpty($destSynapseResourceId)) {
        Write-Host "Resource Ids:" -ForegroundColor White
        Write-Host "Source Synapse" -ForegroundColor Gray
        Write-Host "$srcSynapseResourceId" -ForegroundColor Gray

        Write-Host "Azure Synapse Analytics" -ForegroundColor Gray
        Write-Host "$destSynapseResourceId" -ForegroundColor Gray

        Write-Host ""
        Write-Host "#--------------------------------------------------------------------------------------------------------";
        Write-Host "Migration Details" -ForegroundColor Yellow
        Write-Host ""

        #Check whether ResourceID string starts with /
        if ( -Not ( $srcSynapseResourceId.StartsWith("/") ) ) {
            $srcSynapseResourceId = "/" + $srcSynapseResourceId
        }

        if ( -Not ( $destSynapseResourceId.StartsWith("/") ) ) {
            $destSynapseResourceId = "/" + $destSynapseResourceId
        }

        try {
            $match = "$srcSynapseResourceId" | Select-String -Pattern '^\/subscriptions\/(.+)\/resourceGroups\/(\w.+)\/providers\/Microsoft.Synapse\/workspaces\/(\w.+)'
            $SubscriptionId, $srcResourceGroupSynapse, $srcSynapseName = $match.Matches[0].Groups[1..3].Value
            Write-host "From Source Synapse "

            Write-Host "    Source Synapse Subscription Id: $SubscriptionId "
            Write-Host "    Resource Group: $srcResourceGroupSynapse "
            Write-host "    Source Synapse Name: $srcSynapseName"

            Write-Host " "
            Write-host "To Destination Synapse"


            $match = "$destSynapseResourceId" | Select-String -Pattern '^\/subscriptions\/(.+)\/resourceGroups\/(\w.+)\/providers\/Microsoft.Synapse\/workspaces\/(\w.+)'
            $SubscriptionId, $destResourceGroupSynapse, $destSynapseName = $match.Matches[0].Groups[1..3].Value
            Write-Host "    Subscription Id: $SubscriptionId "
            Write-Host "    Resourec Group $destResourceGroupSynapse "
            Write-Host "    Synapse Analytics Workspace Name:  $destSynapseName"
            Write-Host "#--------------------------------------------------------------------------------------------------------";
            Write-Host ""

            $config = LoadConfig `
                -SubscriptionId $SubscriptionId `
                -srcResourceGroupSynapse $srcResourceGroupSynapse `
                -srcSynapseName $srcSynapseName `
                -destResourceGroupSynapse $destResourceGroupSynapse `
                -destSynapseName $destSynapseName `
                -srcSynapseResourceId $srcSynapseResourceId `
                -destSynapseResourceId $destSynapseResourceId `
                -srcSynapseAPIVersion $srcSynapseAPIVersion `
                -destSynapseAPIVersion $destSynapseAPIVersion
        }
        catch {
            CustomWriteHostError("[Error] $_")
            CustomWriteHostError("[Error] Resource ID provided is not correct. Please check and make sure you have the correct Resource ID for both your Source Synapse and Synapse Workspace.")
            CustomWriteHostError("[Error] Resource ID Examples:")
            CustomWriteHostError("   Source Synapse ResourceID: /subscriptions/<SubscriptionID>/resourcegroups/<srcSynapseResourceGroupName>/providers/Microsoft.Synapse/workspaces/<srcSynapseName> ")
            CustomWriteHostError("   Destination Synapse ResourceID: /subscriptions/<SubscriptionID>/resourcegroups/<destSynapseResourceGroupName>/providers/Microsoft.Synapse/workspaces/<destSynapseName> ")
            Write-Host "#--------------------------------------------------------------------------------------------------------";
            exit -1
        }
    }
    else {
        Write-Host "    Synapse Migration PowerShell script did not start correctly" -ForegroundColor Red
        Write-Host "    Please make sure you are using the correct syntax" -ForegroundColor Red
        Write-Host ""
        Write-Host "    Syntax:" -ForegroundColor Red
        Write-Host "        .\importSynapsetoSynapseTool.ps1 [-ConfigFile <Filename>] " -ForegroundColor Red
        Write-Host "        .\importSynapsetoSynapseTool.ps1 [-srcSynapseResourceId <String>] [-destSynapseResourceId <String>] [-TenantId <String>]" -ForegroundColor Red
        Write-Host ""
        Write-Host "    Docs: " -ForegroundColor Blue
        Write-Host "#--------------------------------------------------------------------------------------------------------";
        exit 0
    }

    #At this point, we have the resource ID for both source and destination
    #Disconnect the Azure account connect so it is a clean login
    Disconnect-AzAccount | Out-null

    try {
        #Let's login
        $LoggedIn = CheckLogin
        if ($ConfigFile) {
            #Login with Service Principal or Interactively
            if (-Not $LoggedIn) {
                Write-Host "Migration tool supports authentication using Service Principal (S) or UserName/Password (I)" -ForegroundColor Yellow
                $Global:SignIn = Read-Host -prompt "Choose the Authentication Method: (S)Service Principal (I)Interactively. (S/I)?"
                $(if ($Global:SignIn -eq 'S') { $AuthenticationType = 'ServicePrincipal' } else { $AuthenticationType = 'Interactive' })
                Login $config $Global:SignIn
            }
        }
        elseif (-NOT [string]::IsNullOrEmpty($srcSynapseResourceId) -and -NOT [string]::IsNullOrEmpty($destSynapseResourceId)) {
            #Login Intereactively
            $AuthenticationType = "Interactively"
            $Global:SignIn = "I"

            if (-NOT [string]::IsNullOrEmpty($TenantId) ) {
                Write-Host "Tenant Id provided"
                Login $config $Global:SignIn $TenantId
            }
            else {
                Login $config $Global:SignIn ""
            }
        }
    }
    catch {
        CustomWriteHostError("[Error] $_.Exception.Message")
        CustomWriteHostError("[Error] Connecting to Azure using Authentication Type: $AuthenticationType")
        exit -1
    }

    #Check if Source and Destination Synapse Resources Exist and if you have access to them
    $CheckResources = CheckResources
    if (-Not $CheckResources) {
        WriteError ("Please double check your appsettings.json entries and your RBAC roles within the portal.")
        exit 1
    }

    #Begin Migration
    Write-Host ""
    Write-Host "#--------------------------------------------------------------------------------------------------------";
    Write-Host ""
    CustomWriteHost("[Info] Start Migration")
    StartMigration $config.srcSynapseWorkspace.ResourceId $config.destSynapseWorkspace.ResourceId
    CustomWriteHost("[Info] Migration Completed")
    Write-Host ""
}
#endregion MigrateSynapse

#---------------------------------------------------------[ProcessResource]-----------------------------------------------------
#region
function PollUntilCompletion {
    Param (
        [string] $uri,
        [string] $originalUri,
        [string] $resourceName,
        [bool] $isArmToken
    )

    Write-Output "Waiting for operation to complete..."

    try {
        $token = GetAuthenticationToken -armToken $isArmToken -signIn $signIn
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Get -ContentType "application/json" -Headers @{ Authorization = "Bearer $token" }

        if ($response.StatusCode -ge 203) {
            Write-Error "Error migrating resource $originalUri"
            throw
        }

        if ($response.StatusCode -ne 200) {
            Start-Sleep -Seconds 1
            PollUntilCompletion $uri $originalUri $resourceName $isArmToken
            return;
        }

        if ($response.StatusCode -eq 200) {
            WriteSuccess "Successfully migrated $resourceName"
            return;
        }

        #if ((ConvertFrom-Json -InputObject $response.Content).status -eq 'Failed') {
        #Write-Error "Error on creating resource $originalUri. Details: $response.Content"
        #throw
        #}
    }
    catch [Exception] {
        Write-Error "An occur has occured. Error Message: $($_.Exception.Message)"
        Write-Error "Error Details: $($_.ErrorDetails.Message)"
        throw
    }
}
#endregion

#---------------------------------------------------------[StartMigration]-----------------------------------------------------
#region
function StartMigration {
    [CmdletBinding()]
    Param (
        [string]$srcResourceId,
        [string]$destResourceId
    )

    $allResources = New-Object Collections.Generic.List[String]
    $allResources.Add("integrationRuntimes");
    $allResources.Add("linkedServices");
    $allResources.Add("datasets");
    $allResources.Add("dataflows");
    $allResources.Add("pipelines");
    $allResources.Add("triggers");

    $allResources | ForEach-Object -Process { ProcessResource -srcResourceId $srcResourceId -destResourceId $destResourceId -resourceType $_ }
    Write-Host "#--------------------------------------------------------------------------------------------------------`n"
}
#endregion

#---------------------------------------------------------[ProcessResource]-----------------------------------------------------
#region
function ProcessResource {
    [CmdletBinding()]
    Param (
        [string]$srcResourceId,
        [string]$destResourceId,
        [string]$resourceType
    )

    $numResourcesCopied = 0

    #$srcResource = Get-AzResource -ResourceId $config.srcSynapseWorkspace.ResourceId -ApiVersion $config.srcSynapseWorkspace.apiVersion
    $destResource = Get-AzResource -ResourceId $config.destSynapseWorkspace.ResourceId -ApiVersion $config.destSynapseWorkspace.apiVersion

    $srcUri = "https://management.usgovcloudapi.net" + $config.srcSynapseWorkspace.ResourceId

    if ($resourceType -eq "integrationRuntimes" -or $resourceType -eq "sqlPools" -or $resourceType -eq "sparkPools") {
        $isDestArm = $true;
        $destUri = "https://management.usgovcloudapi.net" + $config.destSynapseWorkspace.ResourceId
    }
    else {
        $isDestArm = $false;
        $destUri = $destResource.Properties.connectivityEndpoints.dev
    }

    $resourcesToBeCopied = New-Object Collections.Generic.List[Object]
    $uri = "$srcUri/$($resourceType)?api-version=$($config.srcSynapseWorkspace.apiVersion)"

    try {
        $token = GetAuthenticationToken -armToken $true -signIn $Global:SignIn
        $srcResponse = Invoke-RestMethod -UseBasicParsing -Uri $uri -Method Get -ContentType "application/json" -Headers @{ Authorization = "Bearer $token" }

        #For future versions of this tool think about deleting all schema entries inside of datasets before running invoke-restmethod

        if ($srcResponse.Value.Length -gt 0) {
            Write-Host ""
            Write-Host "Processing $resourceType" -ForegroundColor White
            $resourcesToBeCopied.AddRange($srcResponse.Value);

            while ($srcResponse.PSobject.Properties.Name.Contains("nextLink")) {
                Write-Host "Processing next page $srcResponse.nextLink"
                $nextLink = $srcResponse.nextLink
                $srcResponse = Invoke-RestMethod -UseBasicParsing -Uri $nextLink -Method Get -ContentType "application/json" -Headers @{ Authorization = "Bearer $token" } 
                if ($srcResponse.Value.Length -gt 0) {
                    $resourcesToBeCopied.AddRange($srcResponse.Value);
                }
            }

            WriteSuccessResponse("  Migrating $($resourcesToBeCopied.Count) $resourceType")
        }
        elseif ($resourcesToBeCopied.Count -le 0) {
            return;
        }
    }
    catch [Exception] {
        Write-Error "[Error] Listing $resourceType : $_"
        throw
    }

    $resourcesToBeCopied | ForEach-Object -Process {
        $uri = "$destUri/$resourceType/$($_.name)?api-version=$($config.destSynapseWorkspace.apiVersion)";
        $jsonBody = ConvertTo-Json $_ -Depth 30
        $name = $_.name

        $destResponse = $null;

        #Check if you have an Azure-SSIS Integration Runtime. Azure-SSIS is currently not supported in Synapse Workspaces
        #Check if you have an Self-Hosted Integration Runtime that is Shared or Linked. Linked IR are currently not supported in this PowerShell script because you of Managed Identity references.
        #Check if you have an Azure Integration Runtime that is using a Managed Virtual Network. Managed VNets are currently not supported in Synapse Workspaces
        $is_ssis = $false
        $is_link = $false
        $is_vnet = $false

        if ($resourceType -eq "integrationRuntimes") {
            $ssisObj = $_.PSObject.Properties["properties"].value.typeProperties | Get-Member -Name "ssisProperties"
            $linkObj = $_.PSObject.Properties["properties"].value.typeProperties | Get-Member -Name "linkedInfo"
            $vnetObj = $_.PSObject.Properties["properties"].value | Get-Member -Name "managedVirtualNetwork"

            if ([bool]$ssisObj) {
                $is_ssis = $true
            }
            else {
                $is_ssis = $false
            }

            if ([bool]$linkObj) {
                $is_link = $true
            }
            else {
                $is_link = $false
            }

            if ([bool]$vnetObj) {
                $is_vnet = $true
            }
            else {
                $is_vnet = $false
            }
        }

        try {
            #If Integration Runtime is SSIS then Skip
            if (-Not $is_ssis) {
                #If Integration Runtime has is a Linked IR then Skip
                if (-Not $is_link) {
                    #If Integration Runtime has a VNet then Skip
                    if (-Not $is_vnet) {
                        $token = GetAuthenticationToken -armToken $isDestArm -signIn $Global:SignIn
                        $destResponse = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Put -ContentType "application/json" -Body $jsonBody -Headers @{ Authorization = "Bearer $token" }
                        $numResourcesCopied = $numResourcesCopied + 1

                        WriteInformation "Started migrating $resourceType : $($name)"

                        if ($destResponse.StatusCode -eq 202) {
                            PollUntilCompletion $destResponse.Headers.Location $uri $name $isDestArm
                        }
                        elseif ($null -eq $destResponse -or $destResponse.StatusCode -ne 200) {
                            Write-Error "Creation failed for $($name). Error: $($_.Exception.Message)"
                            throw
                        }
                    }
                    else {
                        Write-Host "    Managed VNet Integration Runtime with the following name will be filtered and will NOT be migrated: $($name)" -ForegroundColor Yellow
                        Write-Host ""
                    }
                }
                else {
                    Write-Host "    Self-Hosted (Linked) Integration Runtime with the following name will be filtered and will NOT be migrated: $($name)" -ForegroundColor Yellow
                    Write-Host ""
                }
            }
            else {
                Write-Host "    Azure-SSIS Integration Runtime with the following name will be filtered and will NOT be migrated: $($name)" -ForegroundColor Yellow
                Write-Host ""
            }
        }
        catch [Exception] {
            Write-Error "An error occured during migration for $($name). Error: $($_.Exception.Message)"
            throw
        }
    }

    # Show number of resources copied
    WriteInformation "Resources migrated: $numResourcesCopied "
}
#endregion

#---------------------------------------------------------[Entry Point - Execution of Script Starts Here]-----------------------------------------------------
