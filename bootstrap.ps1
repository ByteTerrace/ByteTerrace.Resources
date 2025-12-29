[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Location,
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$ManagedIdentityName,
    [Parameter(Mandatory = $true, Position = 2)]
    [string]$OrganizationName,
    [Parameter(Mandatory = $true, Position = 3)]
    [string]$ProjectName,
    [Parameter(Mandatory = $true, Position = 4)]
    [string]$ResourceGroupName,
    [Parameter(Mandatory = $true, Position = 5)]
    [string]$ServiceConnectionName,
    [Parameter(Mandatory = $true, Position = 6)]
    [string]$SubscriptionNameOrId,
    [Parameter(Mandatory = $true, Position = 7)]
    [string]$TenantId
)

begin {
    $azureDevOpsResourceId = '499b84ac-1321-427f-aa17-267ca6975798';
    $serviceConnectionJsonTemplate = @'
{
    "authorization": {
        "parameters": {
            "scope": "<scope>",
            "serviceprincipalid": "<service-principal-id>",
            "tenantid": "<tenant-id>"
        },
        "scheme": "WorkloadIdentityFederation"
    },
    "data": {
        "creationMode": "Manual",
        "environment": "AzureCloud",
        "identityType": "ManagedIdentity",
        "scopeLevel": "Subscription",
        "subscriptionId": "<subscription-id>",
        "subscriptionName": "<subscription-name>"
    },
    "isShared": false,
    "name": "<name>",
    "owner": "library",
    "serviceEndpointProjectReferences": [
        {
            "name": "<name>",
            "projectReference": {
                "id": "<project-id>"
            }
        }
    ],
    "type": "AzureRM",
    "url": "https://management.azure.com/"
}
'@;
}
process {
    # set subscription
    az account set --subscription $SubscriptionNameOrId;

    $subscription = [Text.Json.Nodes.JsonNode]::Parse((az account show `
        --query '{ id: id, name: name }' `
        --output 'json'
    ));
    $subscriptionId = $subscription["id"].ToString();
    $subscriptionName = $subscription["name"].ToString();

    # create resource group
    $resourceGroupId = (az group create `
        --location $Location `
        --name $ResourceGroupName `
        --output 'tsv' `
        --query 'id'
    );

    # create managed identity
    $managedIdentity = [Text.Json.Nodes.JsonNode]::Parse((az identity create `
        --location $Location `
        --name $ManagedIdentityName `
        --query '{ clientId: clientId, principalId: principalId }' `
        --resource-group $ResourceGroupName
    ));
    $managedIdentityClientId = $managedIdentity["clientId"].ToString();
    $managedIdentityObjectId = $managedIdentity["principalId"].ToString();

    # create role assignments
    az role assignment create `
        --assignee-object-id $managedIdentityObjectId `
        --assignee-principal-type 'ServicePrincipal' `
        --name 'b9fefe22-ace0-4824-ab27-4ca4bdbd6f73' `
        --role 'Contributor' `
        --scope $resourceGroupId;
    az role assignment create `
        --assignee-object-id $managedIdentityObjectId `
        --assignee-principal-type 'ServicePrincipal' `
        --name 'b9fefe22-ace0-436d-9392-6faa218b955f' `
        --role 'Locks Contributor' `
        --scope $resourceGroupId;
    az role assignment create `
        --assignee-object-id $managedIdentityObjectId `
        --assignee-principal-type 'ServicePrincipal' `
        --name 'b9fefe22-ace0-46ea-9d0f-93fec3cbd79c' `
        --role 'Role Based Access Control Administrator' `
        --scope $resourceGroupId;

    # transform service connection JSON template
    $rootNode = [Text.Json.Nodes.JsonNode]::Parse($serviceConnectionJsonTemplate);
    $authorizationNode = $rootNode["authorization"];
    $authorizationParametersNode = $authorizationNode["parameters"];
    $dataNode = $rootNode["data"];
    $serviceEndpointProjectReferenceNode = $rootNode["serviceEndpointProjectReferences"].AsArray()[0];
    $projectReferenceNode = $serviceEndpointProjectReferenceNode["projectReference"];
    $rootNode["name"] = $ServiceConnectionName;
    $authorizationParametersNode["scope"] = $resourceGroupId;
    $authorizationParametersNode["serviceprincipalid"] = $managedIdentityClientId;
    $authorizationParametersNode["tenantid"] = $TenantId;
    $dataNode["subscriptionId"] = $subscriptionId;
    $dataNode["subscriptionName"] = $subscriptionName;
    $serviceEndpointProjectReferenceNode["name"] = $ServiceConnectionName;
    $projectReferenceNode["id"] = (az rest `
        --method 'GET' `
        --output 'tsv' `
        --query 'id' `
        --resource $azureDevOpsResourceId `
        --url "https://dev.azure.com/${OrganizationName}/_apis/projects/${ProjectName}?api-version=7.1"
    );
    $projectReferenceNode["name"] = $ProjectName;

    # create service connection
    $serviceConnection = [Text.Json.Nodes.JsonNode]::Parse(($rootNode.ToJsonString() | az rest `
        --body "@-" `
        --headers 'Content-Type=application/json' `
        --method 'POST' `
        --query '{ id: id, issuer: authorization.parameters.workloadIdentityFederationIssuer, subject: authorization.parameters.workloadIdentityFederationSubject }' `
        --resource $azureDevOpsResourceId `
        --url "https://dev.azure.com/${OrganizationName}/_apis/serviceendpoint/endpoints?api-version=7.1"
    ));
    $serviceConnectionId = $serviceConnection["id"].ToString();
    $serviceConnectionIssuer = $serviceConnection["issuer"].ToString();
    $serviceConnectionSubject = $serviceConnection["subject"].ToString();

    # create federated credential
    az identity federated-credential create `
        --audiences 'api://AzureADTokenExchange' `
        --identity-name $ManagedIdentityName `
        --issuer $serviceConnectionIssuer `
        --name $serviceConnectionId `
        --resource-group $resourceGroupName `
        --subject $serviceConnectionSubject;

    # add https://graph.microsoft.com/Application.ReadWrite.OwnedBy permission to managed identity.
    $graphResourceId = (az ad sp show `
        --id '00000003-0000-0000-c000-000000000000' `
        --output 'tsv' `
        --query 'id'
    );
    $applicationReadWriteOwnedByPermissionJsonTemplate = @"
{
    "appRoleId": "18a4783c-866b-4cc7-a460-3d5e5662c884",
    "principalId": "${managedIdentityObjectId}",
    "resourceId": "${graphResourceId}"
}
"@;

    $applicationReadWriteOwnedByPermissionJsonTemplate | az rest `
        --body "@-" `
        --method 'POST' `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${managedIdentityObjectId}/appRoleAssignments";
}
end {}
