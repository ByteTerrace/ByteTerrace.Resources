# ByteTerrace.Resources

Infrastructure-as-code for Azure resources.

## Prerequisites

- An Azure subscription with the permissions required to create a resource group and assign roles.
- An Azure DevOps project with permissions to create a service connection.
- Azure CLI v2.70 (or greater) installed.
- PowerShell v7.2 (or greater) installed.

## Getting Started

1) Clone this repository into your Azure DevOps project.
2) Create a new branch and adjust the `resources` parameter in `./main.bicepparam`.
3) Follow the bootstrap process outlined below.
4) Create a new pipeline that points to `.azure-devops/pipelines/deploy-infrastructure.yaml`.
5) Run the pipeline created in the previous step.

## Bootstrap Process

### *Automated*

1) Download `./bootstrap.ps1` from repository.
2) Run `bootstrap.ps1` via PowerShell.
3) Follow script prompts.

### *Manual*

### 1) Create a Resource Group
<details>
<summary>Azure CLI (PowerShell)</summary>

```powershell
$location = '<location>';
$resourceGroupName = '<resource-group-name>';
$subscriptionNameOrId = '<subscription-name-or-id>';

az account set --subscription $subscriptionNameOrId;
az group create `
    --location $location `
    --name $resourceGroupName;
```

</details>

### 2) Create a User-Assigned Managed Identity
<details>
<summary>Azure CLI (PowerShell)</summary>

```powershell
$location = '<location>';
$managedIdentityName = '<managed-identity-name>';
$resourceGroupName = '<resource-group-name>';

az identity create `
    --location $location `
    --name $managedIdentityName `
    --resource-group $resourceGroupName;
```

</details>

### 3) Assign Roles to User-Assigned Managed Identity

Use the **objectId** value from the previous step.

<details>
<summary>Azure CLI (PowerShell)</summary>

```powershell
$managedIdentityObjectId = '<managed-identity-object-id>';
$resourceGroupName = '<resource-group-name>';
$subscriptionId = '<subscription-id>';

az role assignment create `
    --assignee-object-id $managedIdentityObjectId `
    --assignee-principal-type 'ServicePrincipal' `
    --name 'b9fefe22-ace0-4824-ab27-4ca4bdbd6f73' `
    --role 'Contributor' `
    --scope "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}";

az role assignment create `
    --assignee-object-id $managedIdentityObjectId `
    --assignee-principal-type 'ServicePrincipal' `
    --name 'b9fefe22-ace0-436d-9392-6faa218b955f' `
    --role 'Locks Contributor' `
    --scope "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}";

az role assignment create `
    --assignee-object-id $managedIdentityObjectId `
    --assignee-principal-type 'ServicePrincipal' `
    --name 'b9fefe22-ace0-46ea-9d0f-93fec3cbd79c' `
    --role 'Role Based Access Control Administrator' `
    --scope "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}";
```

</details>

### 4) Create an Azure DevOps Service Connection

Use the **clientId/tenantId** values from the previous step.

<details>
<summary>Azure CLI (PowerShell)</summary>

```powershell
$managedIdentityClientId = '<managed-identity-client-id>';
$organizationName = '<organization-name>';
$projectName = '<project-name>';
$resourceGroupName = '<resource-group-name>';
$serviceConnectionName = '<service-connection-name>';
$subscriptionName = '<subscription-name>';
$tenantId = '<tenant-id>';

# hard-coded values
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

# get property references
$rootNode = [Text.Json.Nodes.JsonNode]::Parse($serviceConnectionJsonTemplate);
$authorizationNode = $rootNode["authorization"];
$authorizationParametersNode = $authorizationNode["parameters"];
$dataNode = $rootNode["data"];
$serviceEndpointProjectReferenceNode = $rootNode["serviceEndpointProjectReferences"].AsArray()[0];
$projectReferenceNode = $serviceEndpointProjectReferenceNode["projectReference"];

# set property values
$subscriptionId = (az account list `
    --query "[?name=='${subscriptionName}'] | [0].id" `
    --output 'tsv'
);
$rootNode["name"] = $serviceConnectionName;
$authorizationParametersNode["scope"] = "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}";
$authorizationParametersNode["serviceprincipalid"] = $managedIdentityClientId;
$authorizationParametersNode["tenantid"] = $tenantId;
$dataNode["subscriptionId"] = $subscriptionId;
$dataNode["subscriptionName"] = $subscriptionName;
$serviceEndpointProjectReferenceNode["name"] = $serviceConnectionName;
$projectReferenceNode["id"] = (az rest `
    --method 'GET' `
    --output 'tsv' `
    --query 'id' `
    --resource $azureDevOpsResourceId `
    --url "https://dev.azure.com/${organizationName}/_apis/projects/${projectName}?api-version=7.1"
);
$projectReferenceNode["name"] = $projectName;

# send REST API request
$rootNode.ToJsonString() | az rest `
    --body "@-" `
    --headers 'Content-Type=application/json' `
    --method 'POST' `
    --resource $azureDevOpsResourceId `
    --url "https://dev.azure.com/${organizationName}/_apis/serviceendpoint/endpoints?api-version=7.1";
```

</details>

### 5) Add Federated Credentials to User-Assigned Managed Identity

Use the **audience/issuer/subject** values from the previous step.

<details>
<summary>Azure CLI (PowerShell)</summary>

```powershell
$audience = '<audience>';
$federatedCredentialName = '<federated-credential-name>';
$identityName = '<identity-name>';
$issuer = '<issuer>';
$resourceGroupName = '<resource-group-name>';
$subject = '<subject>';

az identity federated-credential create `
    --audiences $audience `
    --identity-name $identityName `
    --issuer $issuer `
    --name $federatedCredentialName `
    --resource-group $resourceGroupName `
    --subject $subject;
```

</details>

### 6) Assign API permissions to User-Assigned Managed Identity

Use the **objectId** value from step 2.

<details>
<summary>Azure CLI (PowerShell)</summary>

```powershell
$managedIdentityObjectId = '';
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
```

</details>
