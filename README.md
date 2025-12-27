# ByteTerrace.Resources

Infrastructure-as-code for Azure resources.

## Prerequisites

- An Azure subscription with the permissions required to create a resource group and assign roles.
- An Azure DevOps project with permissions to create a service connection.
- One of:
	- Azure CLI (`az`) with Bicep support
	- Azure PowerShell (`Az` module)

## Getting Started (Manual)

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
<details>
<summary>Azure PowerShell</summary>

```powershell
$location = '<location>';
$resourceGroupName = '<resource-group-name>';
$subscriptionId = '<subscription-id>';

Set-AzContext -SubscriptionId $subscriptionId;
New-AzResourceGroup `
	-Location $location `
    -Name $resourceGroupName;
```

</details>

### 2) Create a User-Assigned Managed Identity
<details>
<summary>Azure CLI (PowerShell)</summary>

```powershell
$location = '<location>';
$resourceGroupName = '<resource-group-name>';
$identityName = '<identity-name>';

az identity create `
    --location $location `
    --name $identityName `
    --resource-group $resourceGroupName;
```

</details>
<details>
<summary>Azure PowerShell</summary>

```powershell
$location = '<location>';
$resourceGroupName = '<resource-group-name>';
$identityName = '<identity-name>';

$identity = New-AzUserAssignedIdentity `
	-Location $location `
	-Name $identityName `
	-ResourceGroupName $resourceGroupName;
```

</details>

### 3) Create an Azure DevOps Service Connection

TODO: Implement PowerShell scripts.

### 4) Add Federated Credentials to User-Assigned Managed Identity

Use the **audience/issuer/subject** values from step 3.

<details>
<summary>Azure CLI (PowerShell)</summary>

```powershell
$audience = '<audience>';
$identityName = '<identity-name>';
$issuer = '<issuer>';
$resourceGroupName = '<resource-group-name>';
$federatedCredentialName = '<federated-credential-name>';
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
<details>
<summary>Azure PowerShell</summary>

```powershell
$audience = '<audience>';
$identityName = '<identity-name>';
$issuer = '<issuer>';
$resourceGroupName = '<resource-group-name>';
$federatedCredentialName = '<federated-credential-name>';
$subject = '<subject>';

New-AzFederatedIdentityCredential `
    -Audience $audience ` 
    -IdentityName $identityName `
    -Issuer $issuer  `
    -Name $federatedCredentialName `
    -ResourceGroupName $resourceGroupName `
    -Subject $subject;
```

</details>
