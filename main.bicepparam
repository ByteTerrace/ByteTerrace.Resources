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
            // NOTE: Admin consent required.
            id: 'e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20' // https://graph.microsoft.com/AuditLog.Read.All
            type: 'Scope'
          }
          {
            id: '38826093-1258-4dea-98f0-00003be2b8d0' // https://graph.microsoft.com/Chat.Create
            type: 'Scope'
          }
          {
            id: '116b7235-7cc6-461e-b163-8e55691d839e' // https://graph.microsoft.com/ChatMessage.Send
            type: 'Scope'
          }
          {
            id: 'e383f46e-2787-4529-855e-0e479a3ffac0' // https://graph.microsoft.com/Mail.Send
            type: 'Scope'
          }
          {
            // NOTE: Admin consent required.
            id: 'fc30e98b-8810-4501-81f5-c20a3196387b' // https://graph.microsoft.com/User.RevokeSessions.All
            type: 'Scope'
          }
        ]
      }
    ]
    spa: {
      redirectUris: [
        'https://byteterrace.app'
      ]
    }
    web: {
      homePageUrl: 'https://byteterrace.com'
      implicitGrantSettings: {
        enableAccessTokenIssuance: false
        enableIdTokenIssuance: true
      }
      logoutUrl: null
      redirectUris: [
        'https://byteterrace.com'
        'https://byteterrace.org'
      ]
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
      }
    ]
  }
}
