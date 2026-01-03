using './main.bicep'

param deployOwnerRoleAssignments = true
param lockKind = 'CanNotDelete'
param resources = {
  applicationInsights: {
    name: 'bytrcappip000'
  }
  applicationRegistration: {
    identifierUri: 'https://api.byteterrace.com'
    name: 'ByteTerrace'
    requiredResourceAccess: [
      {
        resourceAppId: '00000003-0000-0000-c000-000000000000' // Microsoft Graph
        resourceAccess: [
          {
            id: '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0' // https://graph.microsoft.com/email
            type: 'Scope'
          }
          {
            id: '7427e0e9-2fba-42fe-b0c0-848c9e6a8182' // https://graph.microsoft.com/offline_access
            type: 'Scope'
          }
          {
            id: '37f7f235-527c-4136-accd-4a02d197296e' // https://graph.microsoft.com/openid
            type: 'Scope'
          }
          {
            id: '14dad69e-099b-42c9-810b-d002981feec1' // https://graph.microsoft.com/profile
            type: 'Scope'
          }
          {
            id: 'e1fe6dd8-ba31-4d61-89e7-88639da4683d' // https://graph.microsoft.com/User.Read
            type: 'Scope'
          }
        ]
      }
    ]
    spa: {
      redirectUris: ['https://byteterrace.com']
    }
    web: {
      homePageUrl: 'https://byteterrace.com'
      implicitGrantSettings: {
        enableAccessTokenIssuance: false
        enableIdTokenIssuance: true
      }
      logoutUrl: null
      redirectUris: []
    }
  }
  applicationServicePlan: {
    name: 'bytrcaspp000'
  }
  configurationStore: {
    name: 'bytrcappcsp000'
  }
  devOps: {
    agentPool: {
      concurrency: 2
      images: [
        {
          ephemeralType: 'Automatic'
          wellKnownImageName: 'ubuntu-24.04'
        }
        {
          ephemeralType: 'Automatic'
          wellKnownImageName: 'windows-2025'
        }
      ]
      name: 'bytrcmdopp000'
      vmSkuName: 'Standard_D2ads_v5'
    }
    organizationName: 'byteterrace'
    projectName: 'Koholint'
  }
  dns: {
    secondLevelDomainName: 'byteterrace'
    topLevelDomainName: 'com'
  }
  frontDoor: {
    name: 'bytrcfdp000'
    webApplicationFirewallPolicy: {
      name: 'bytrcfdfpp000'
    }
  }
  functionApplication: {
    name: 'bytrcfuncp000'
  }
  keyVault: {
    name: 'bytrckvp000'
  }
  logAnalyticsWorkspace: {
    name: 'bytrclogp000'
  }
  monitorPrivateLinkScope: {
    name: 'bytrcmplsp000'
  }
  natGateway: {
    name: 'bytrcngp000'
    publicIpPrefix: {
      name: 'bytrcipprep000'
    }
  }
  networkSecurityPerimeter: {
    name: 'bytrcnspp000'
  }
  /*postgresFlexibleServer: {
    administrators: [
      {
        objectId: '<PLACEHOLDER>'
        principalType: 'ServicePrincipal'
        principalName: '<PLACEHOLDER>'
      }
    ]
    name: 'bytrcpsqlp000'
    skuName: 'Standard_B1ms'
    storageSizeGB: 64
    tier: 'Burstable'
    version: '18'
  }*/
  redisCache: {
    capacity: 2
    evictionPolicy: 'VolatileLRU'
    name: 'bytrcamrp000'
    skuName: 'Balanced_B0'
  }
  storageAccountFunction: {
    name: 'bytrcstp000'
  }
  storageAccountPublic: {
    name: 'bytrcstp001'
  }
  userAssignedIdentityApplicationRegistration: {
    name: 'bytrcidp000'
  }
  userAssignedIdentityCustomerManagedEncryption: {
    name: 'bytrcidp001'
  }
  userAssignedIdentityFunctionApplication: {
    name: 'bytrcidp002'
  }
  userAssignedIdentityFrontDoor: {
    name: 'bytrcidp003'
  }
  virtualNetwork: {
    addressPrefixes: ['10.64.0.0/20']
    name: 'bytrcvnetp000'
    subnets: [
      {
        addressPrefixes: ['10.64.0.0/24']
        defaultOutboundAccess: false
        delegation: null
        name: 'bytrcsnetp000'
        privateEndpointNetworkPolicies: 'Enabled'
        privateLinkServiceNetworkPolicies: 'Enabled'
      }
      {
        addressPrefixes: ['10.64.1.0/26']
        defaultOutboundAccess: false
        delegation: 'Microsoft.App/environments'
        name: 'bytrcsnetp001'
        natGatewayResourceId: 'bytrcngp000'
        privateEndpointNetworkPolicies: 'Disabled'
        privateLinkServiceNetworkPolicies: 'Disabled'
      }
      {
        addressPrefixes: ['10.64.1.64/26']
        defaultOutboundAccess: false
        delegation: 'Microsoft.DevOpsInfrastructure/pools'
        name: 'bytrcsnetp002'
        natGatewayResourceId: 'bytrcngp000'
        privateEndpointNetworkPolicies: 'Disabled'
        privateLinkServiceNetworkPolicies: 'Disabled'
        serviceEndpoints: ['Microsoft.Web']
      }
    ]
  }
}
