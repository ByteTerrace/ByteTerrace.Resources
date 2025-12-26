extension graph

import {
  imageType
} from 'br/public:avm/res/dev-ops-infrastructure/pool:0.7.0'

import {
  subnetType
} from 'br/public:avm/res/network/virtual-network:0.7.2'

import {
  diagnosticSettingFullType
} from 'br/public:avm/utl/types/avm-common-types:0.6.1'

import {
  publicDnsZoneType
} from './publicDnsZones.bicep'

type resourceType = {
  applicationInsights: {
    name: string
    tags: tagsType?
  }
  applicationRegistration: {
    identifierUri: string
    name: string
    requiredResourceAccess: {
      resourceAppId: string
      resourceAccess: {
        id: string
        type: 'Scope'
      }[]
    }[]?
    spa: {
      redirectUris: string[]
    }?
    web: {
      homePageUrl: string?
      implicitGrantSettings: {
        enableAccessTokenIssuance: bool
        enableIdTokenIssuance: bool
      }
      logoutUrl: string?
      redirectUris: string[]
    }?
  }
  applicationServicePlan: {
    name: string
    tags: tagsType?
  }
  containerRegistry: {
    name: string
    tags: tagsType?
  }
  devOpsAgentPool: {
    @minValue(1)
    @maxValue(10000)
    concurrency: int
    images: imageType[]
    name: string
    organizationProfile: {
      organizations: {
        parallelism: int
        projects: string[]
        url: string
      }[]
    }
    tags: tagsType?
    vmSkuName: string
  }
  frontDoor: {
    name: string
    tags: tagsType?
    webApplicationFirewallPolicy: {
      name: string
      tags: tagsType?
    }
  }
  functionApplication: {
    name: string
    tags: tagsType?
  }
  keyVault: {
    name: string
    tags: tagsType?
  }
  logAnalyticsWorkspace: {
    name: string
    tags: tagsType?
  }
  monitorPrivateLinkScope: {
    name: string
    tags: tagsType?
  }
  natGateway: {
    name: string
    publicIpPrefix: {
      name: string
      tags: tagsType?
    }
    tags: tagsType?
  }
  networkSecurityPerimeter: {
    name: string
    tags: tagsType?
  }
  publicDnsZones: {
    *: publicDnsZoneType
  }
  storageAccountFunction: {
    name: string
    tags: tagsType?
  }
  storageAccountPublic: {
    name: string
    tags: tagsType?
  }
  userAssignedIdentityApplicationRegistration: {
    name: string
    tags: tagsType?
  }
  userAssignedIdentityCustomerManagedEncryption: {
    name: string
    tags: tagsType?
  }
  userAssignedIdentityFunctionApplication: {
    name: string
    tags: tagsType?
  }
  virtualNetwork: {
    addressPrefixes: string[]
    diagnosticSettings: diagnosticSettingFullType[]?
    dnsServers: string[]?
    name: string
    @maxLength(3)
    @minLength(3)
    subnets: subnetType[]
    tags: tagsType?
  }
}
type tagsType = { *: string }

param deployOwnerRoleAssignments bool = false
param location string = resourceGroup().location
param lockKind ('CanNotDelete' | 'None' | 'ReadOnly') = 'CanNotDelete'
param resources resourceType = {
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
  containerRegistry: {
    name: 'bytrccrp000'
  }
  devOpsAgentPool: {
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
    organizationProfile: {
      organizations: [
        {
          parallelism: 2
          projects: ['Koholint']
          url: 'https://dev.azure.com/byteterrace'
        }
      ]
    }
    vmSkuName: 'Standard_D2ads_v5'
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
  publicDnsZones: {
    'api.byteterrace.com': {}
    'byteterrace.app': {}
    'byteterrace.com': {}
    'byteterrace.dev': {}
    'byteterrace.net': {}
    'byteterrace.org': {}
    'byteterrace.us': {}
    'byteterrace.xyz': {}
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

var apiPublicDnsZone = first(filter(objectKeys(resources.publicDnsZones), zone => startsWith(zone, 'api.')))! // TODO: Refactor to be more robust.
var applicationRegistrationUniqueName = guid(resources.applicationRegistration.name)
var defaultCustomerManagedKey = {
  name: 'CustomerManagedEncryption'
}
var functionAppContainerName = '${resources.functionApplication.name}-${uniqueString(resourceId('Microsoft.Web/sites', resources.functionApplication.name))}'
var natGatewayResourceIdMap = {
  '${resources.natGateway.name}': natGateway.outputs.resourceId
}
var owner = {
  name: deployer().userPrincipalName
  principalId: deployer().objectId
}
var publicIpPrefixResourceIdMap = {
  '${resources.natGateway.publicIpPrefix.name}': natGateway_publicIpPrefix.outputs.resourceId
}
var subnetResourceIdMap = {
  devOpsAgentPool: virtualNetwork.outputs.subnetResourceIds[2]
  flexConsumptionApplicationServicePlan: virtualNetwork.outputs.subnetResourceIds[1]
  privateEndpoints: virtualNetwork.outputs.subnetResourceIds[0]
}

resource applicationRegistration 'Microsoft.Graph/applications@v1.0' = {
  api: {
    acceptMappedClaims: false
    knownClientApplications: []
    oauth2PermissionScopes: []
    preAuthorizedApplications: []
    requestedAccessTokenVersion: 2
  }
  authenticationBehaviors: {
    blockAzureADGraphAccess: true
    removeUnverifiedEmailClaim: true
  }
  defaultRedirectUri: null
  description: null
  displayName: resources.applicationRegistration.name
  groupMembershipClaims: 'SecurityGroup'
  identifierUris: [resources.applicationRegistration.identifierUri]
  info: {
    marketingUrl: null
    privacyStatementUrl: null
    supportUrl: null
    termsOfServiceUrl: null
  }
  isDeviceOnlyAuthSupported: false
  nativeAuthenticationApisEnabled: 'none'
  optionalClaims: {
    accessToken: []
    idToken: []
    saml2Token: []
  }
  owners: {
    relationships: [owner.principalId]
    relationshipSemantics: 'append' // TODO: Change to 'replace' after Microsoft resolves issue with replication delay.
  }
  publicClient: {
    redirectUris: []
  }
  requiredResourceAccess: resources.applicationRegistration.?requiredResourceAccess
  servicePrincipalLockConfiguration: {
    allProperties: true
    credentialsWithUsageSign: true
    credentialsWithUsageVerify: true
    isEnabled: true
    tokenEncryptionKeyId: true
  }
  signInAudience: 'AzureADMyOrg'
  spa: resources.applicationRegistration.?spa
  tags: []
  uniqueName: applicationRegistrationUniqueName
  web: resources.applicationRegistration.?web

  resource applicationRegistration_federatedIdentityCredential 'federatedIdentityCredentials@v1.0' = {
    audiences: ['api://AzureADTokenExchange']
    description: 'Federated identity credential for authentication to Azure Function App using "Easy Auth".'
    issuer: '${environment().authentication.loginEndpoint}${tenant().tenantId}/v2.0'
    name: '${applicationRegistrationUniqueName}/${userAssignedIdentityApplicationRegistration.outputs.clientId}'
    subject: userAssignedIdentityApplicationRegistration.outputs.principalId
  }
}
resource applicationRegistration_servicePrincipal 'Microsoft.Graph/servicePrincipals@v1.0' = {
  appId: applicationRegistration.appId
}
resource devOpsInfrastructure_servicePrincipal 'Microsoft.Graph/servicePrincipals@v1.0' existing = {
  appId: '31687f79-5e43-4c1e-8c63-d9f4bff5cf8b'
}

@onlyIfNotExists() // NOTE: This bootstrap step was added to address a cyclic dependency between the Front Door and Function Application.
resource frontDoor_bootstrap 'Microsoft.Cdn/profiles@2025-06-01' = {
  location: 'global'
  name: resources.frontDoor.name
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
}

module applicationInsights 'br/public:avm/res/insights/component:0.7.1' = {
  params: {
    applicationType: 'web'
    diagnosticSettings: []
    disableIpMasking: true
    disableLocalAuth: true
    enableTelemetry: false
    ingestionMode: 'LogAnalytics'
    kind: 'web'
    location: location
    lock: {
      kind: lockKind
    }
    name: resources.applicationInsights.name
    publicNetworkAccessForIngestion: 'Disabled'
    publicNetworkAccessForQuery: 'Enabled' // TODO: Set to 'Disabled' when done with initial testing.
    retentionInDays: 30
    roleAssignments: [
      {
        principalId: userAssignedIdentityFunctionApplication.outputs.principalId
        principalType: 'ServicePrincipal'
        roleDefinitionIdOrName: 'Monitoring Metrics Publisher'
      }
    ]
    samplingPercentage: 100
    tags: resources.applicationInsights.?tags
    workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
  }
}
module applicationServicePlan 'br/public:avm/res/web/serverfarm:0.5.0' = {
  params: {
    appServiceEnvironmentResourceId: null
    diagnosticSettings: []
    enableTelemetry: false
    kind: 'functionapp'
    location: location
    lock: {
      kind: lockKind
    }
    name: resources.applicationServicePlan.name
    reserved: true
    roleAssignments: []
    skuCapacity: 1
    skuName: 'FC1'
    tags: resources.applicationServicePlan.?tags
    zoneRedundant: false
  }
}
/*module containerRegistry 'br/public:avm/res/container-registry/registry:0.9.3' = {
  params: {
    acrAdminUserEnabled: false
    acrSku: 'Premium'
    anonymousPullEnabled: false
    azureADAuthenticationAsArmPolicyStatus: 'enabled'
    cacheRules: []
    credentialSets: []
    customerManagedKey: {
      autoRotationEnabled: true
      keyName: defaultCustomerManagedKey.name
      keyVaultResourceId: keyVault.outputs.resourceId
      userAssignedIdentityResourceId: userAssignedIdentityCustomerManagedEncryption.outputs.resourceId
    }
    dataEndpointEnabled: true
    diagnosticSettings: [
      {
        logCategoriesAndGroups: [
          {
            categoryGroup: 'audit'
          }
        ]
        workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
      }
    ]
    enableTelemetry: false
    exportPolicyStatus: 'disabled'
    location: location
    lock: {
      kind: lockKind
    }
    managedIdentities: {
      systemAssigned: false
      userAssignedResourceIds: [userAssignedIdentityCustomerManagedEncryption.outputs.resourceId]
    }
    name: resources.containerRegistry.name
    networkRuleBypassOptions: 'None'
    networkRuleSetDefaultAction: 'Deny'
    networkRuleSetIpRules: []
    privateEndpoints: [
      {
        enableTelemetry: false
        privateDnsZoneGroup: {
          privateDnsZoneGroupConfigs: [
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.containerRegistry
            }
          ]
        }
        subnetResourceId: subnetMap.privateEndpoints
      }
    ]
    publicNetworkAccess: 'Disabled'
    retentionPolicyDays: 13
    retentionPolicyStatus: 'enabled'
    roleAssignments: (deployOwnerRoleAssignments ? [
      {
        principalId: owner.principalId
        principalType: 'ServicePrincipal'
        roleDefinitionIdOrName: 'AcrPush'
      }
    ] : [])
    softDeletePolicyDays: 13
    softDeletePolicyStatus: 'disabled'
    tags: resources.containerRegistry.?tags
    zoneRedundancy: 'Enabled'
  }
}*/
module devCenter 'br/public:avm/res/dev-center/devcenter:0.1.0' = {
  params: {
    enableTelemetry: false
    location: location
    lock: {
      kind: lockKind
    }
    name: 'bytrcadcp000'
    roleAssignments: []
    tags: {}
  }
}
module devCenter_project 'br/public:avm/res/dev-center/project:0.1.1' = {
  params: {
    devCenterResourceId: devCenter.outputs.resourceId
    enableTelemetry: false
    location: location
    lock: {
      kind: lockKind
    }
    name: 'bytrcadcpp000'
    roleAssignments: []
    tags: {}
  }
}
module devOpsAgentPool 'br/public:avm/res/dev-ops-infrastructure/pool:0.7.0' = {
  params: {
    agentProfile: {
      kind: 'Stateless'
      resourcePredictionsProfile: {
        kind: 'Automatic'
        predictionPreference: 'MostCostEffective'
      }
    }
    concurrency: resources.devOpsAgentPool.concurrency
    devCenterProjectResourceId: devCenter_project.outputs.resourceId
    diagnosticSettings: [
      {
        logCategoriesAndGroups: [
          {
            category: 'ProvisioningLogs'
          }
        ]
        workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
      }
    ]
    enableTelemetry: false
    fabricProfileSkuName: resources.devOpsAgentPool.vmSkuName
    images: resources.devOpsAgentPool.images
    location: location
    lock: {
      kind: lockKind
    }
    managedIdentities: {
      systemAssigned: false
      userAssignedResourceIds: []
    }
    name: resources.devOpsAgentPool.name
    organizationProfile: {
      kind: 'AzureDevOps'
      organizations: resources.devOpsAgentPool.organizationProfile.organizations
      permissionProfile: {
        kind: 'CreatorOnly'
      }
    }
    osProfile: {
      logonType: 'Interactive'
    }
    roleAssignments: []
    subnetResourceId: subnetResourceIdMap.devOpsAgentPool
    tags: resources.devOpsAgentPool.?tags
  }
}
module frontDoor 'br/public:avm/res/cdn/profile:0.16.1' = {
  params: {
    afdEndpoints: [
      {
        autoGeneratedDomainNameLabelScope: 'NoReuse'
        enabledState: 'Enabled'
        name: 'default'
        routes: [
          {
            cacheConfiguration: null
            customDomainNames: [replace(apiPublicDnsZone, '.', '-')]
            enabledState: 'Enabled'
            forwardingProtocol: 'HttpsOnly'
            httpsRedirect: 'Enabled'
            linkToDefaultDomain: 'Disabled'
            name: 'api'
            originGroupName: 'api'
            originPath: null
            patternsToMatch: []
            ruleSets: []
            supportedProtocols: ['Https']
          }
        ]
      }
    ]
    customDomains: [
      {
        azureDnsZoneResourceId: publicDnsZones.outputs.dnsZoneMap[apiPublicDnsZone]
        certificateType: 'ManagedCertificate'
        cipherSuiteSetType: 'TLS12_2023'
        hostName: apiPublicDnsZone
        minimumTlsVersion: 'TLS12'
        name: replace(apiPublicDnsZone, '.', '-')
      }
    ]
    diagnosticSettings: [
      {
        logCategoriesAndGroups: [
          {
            categoryGroup: 'audit'
          }
        ]
        workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
      }
    ]
    enableTelemetry: false
    location: 'global'
    lock: {
      kind: lockKind
    }
    managedIdentities: {
      systemAssigned: false
      userAssignedResourceIds: []
    }
    originGroups: [
      {
        healthProbeSettings: {
          probeIntervalInSeconds: 127
          probePath: '/api/health-check'
          probeProtocol: 'Https'
          probeRequestType: 'GET'
        }
        loadBalancingSettings: {
          sampleSize: 5
          successfulSamplesRequired: 3
        }
        name: 'api'
        origins: [
          {
            enabledState: 'Enabled'
            enforceCertificateNameCheck: true
            hostName: functionApplication.outputs.defaultHostname
            httpPort: 80
            httpsPort: 443
            name: replace(functionApplication.outputs.defaultHostname, '.', '-')
            originHostHeader: functionApplication.outputs.defaultHostname
          }
        ]
        sessionAffinityState: 'Disabled'
      }
    ]
    name: resources.frontDoor.name
    roleAssignments: []
    ruleSets: []
    securityPolicies: [
      {
        associations: [
          {
            domains: [
              {
                id: resourceId(
                  'Microsoft.Cdn/profiles/customDomains',
                  resources.frontDoor.name,
                  replace(apiPublicDnsZone, '.', '-')
                )
              }
            ]
            patternsToMatch: ['/*']
          }
        ]
        name: 'rate-limit'
        wafPolicyResourceId: frontDoor_waf.outputs.resourceId
      }
    ]
    sku: 'Standard_AzureFrontDoor'
    tags: resources.frontDoor.?tags
  }
}
module frontDoor_dns 'br/public:avm/res/network/dns-zone:0.5.4' = {
  params: {
    a: [
      {
        name: '@'
        targetResourceId: '${frontDoor.outputs.resourceId}/afdEndpoints/default'
        ttl: 3600
      }
    ]
    enableTelemetry: false
    location: 'global'
    name: join(skip(split(frontDoor.outputs.dnsValidation[0].dnsTxtRecordName!, '.'), 1), '.')
    txt: [
      {
        name: first(split(frontDoor.outputs.dnsValidation[0].dnsTxtRecordName!, '.'))
        ttl: 3600
        txtRecords: [
          {
            value: [frontDoor.outputs.dnsValidation[0].dnsTxtRecordValue!]
          }
        ]
      }
    ]
  }
}
module frontDoor_waf 'br/public:avm/res/network/front-door-web-application-firewall-policy:0.3.3' = {
  params: {
    customRules: {
      rules: [
        {
          action: 'Block'
          enabledState: 'Enabled'
          matchConditions: [
            {
              matchValue: ['0']
              matchVariable: 'RequestHeader'
              negateCondition: false
              operator: 'GreaterThanOrEqual'
              selector: 'Host'
              transforms: []
            }
          ]
          name: 'RateLimit'
          priority: 1
          rateLimitDurationInMinutes: 5
          rateLimitThreshold: 1500
          ruleType: 'RateLimitRule'
        }
      ]
    }
    enableTelemetry: false
    location: 'global'
    lock: {
      kind: lockKind
    }
    managedRules: {
      managedRuleSets: []
    }
    name: resources.frontDoor.webApplicationFirewallPolicy.name
    policySettings: {
      customBlockResponseBody: null
      customBlockResponseStatusCode: null
      enabledState: 'Enabled'
      logScrubbing: null
      mode: 'Prevention'
      redirectUrl: null
      requestBodyCheck: 'Disabled'
    }
    roleAssignments: []
    sku: 'Standard_AzureFrontDoor'
    tags: resources.frontDoor.webApplicationFirewallPolicy.?tags
  }
}
module functionApplication 'br/public:avm/res/web/site:0.19.4' = {
  params: {
    basicPublishingCredentialsPolicies: [
      {
        allow: false
        name: 'ftp'
      }
      {
        allow: false
        name: 'scm'
      }
    ]
    clientAffinityEnabled: false
    clientAffinityPartitioningEnabled: false
    clientAffinityProxyEnabled: false
    clientCertEnabled: false
    clientCertExclusionPaths: null
    clientCertMode: 'Optional'
    configs: [
      {
        applicationInsightResourceId: applicationInsights.outputs.resourceId
        name: 'appsettings'
        properties: {
          APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'Authorization=AAD;ClientId=${userAssignedIdentityFunctionApplication.outputs.clientId}'
          AzureWebJobsStorage__clientId: userAssignedIdentityFunctionApplication.outputs.clientId
          AzureWebJobsStorage__credential: 'managedidentity'
          AZURE_CLIENT_ID: userAssignedIdentityApplicationRegistration.outputs.clientId
          OVERRIDE_USE_MI_FIC_ASSERTION_CLIENTID: userAssignedIdentityApplicationRegistration.outputs.clientId
          WEBSITE_AUTH_AAD_ALLOWED_TENANTS: tenant().tenantId
        }
        retainCurrentAppSettings: false
        storageAccountResourceId: storageAccountFunction.outputs.resourceId
        storageAccountUseIdentityAuthentication: true
      }
      {
        name: 'authsettingsV2'
        properties: {
          globalValidation: {
            redirectToProvider: null
            requireAuthentication: true
            unauthenticatedClientAction: 'Return401'
          }
          httpSettings: {
            forwardProxy: {
              convention: 'NoProxy'
            }
            requireHttps: true
          }
          identityProviders: {
            azureActiveDirectory: {
              enabled: true
              login: {
                loginParameters: []
              }
              registration: {
                clientId: applicationRegistration.appId
                clientSecretSettingName: 'OVERRIDE_USE_MI_FIC_ASSERTION_CLIENTID'
                openIdIssuer: '${environment().authentication.loginEndpoint}${tenant().tenantId}/v2.0'
              }
              validation: {
                allowedAudiences: []
                defaultAuthorizationPolicy: {
                  allowedApplications: [applicationRegistration.appId]
                  allowedPrincipals: {
                    groups: []
                    identities: []
                  }
                }
                jwtClaimChecks: {
                  allowedClientApplications: []
                  allowedGroups: []
                }
              }
            }
          }
          login: {
            tokenStore: {
              enabled: true
            }
          }
          platform: {
            enabled: true
            runtimeVersion: '~1'
          }
        }
      }
    ]
    diagnosticSettings: [
      {
        logCategoriesAndGroups: [
          {
            category: 'FunctionAppLogs'
          }
        ]
        workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
      }
    ]
    enableTelemetry: false
    functionAppConfig: {
      deployment: {
        storage: {
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: userAssignedIdentityFunctionApplication.outputs.resourceId
          }
          type: 'blobContainer'
          value: '${storageAccountFunction.outputs.primaryBlobEndpoint}${functionAppContainerName}'
        }
      }
      runtime: {
        name: 'dotnet-isolated'
        version: '10.0'
      }
      scaleAndConcurrency: {
        instanceMemoryMB: 512
        maximumInstanceCount: 40
      }
    }
    httpsOnly: true
    keyVaultAccessIdentityResourceId: userAssignedIdentityFunctionApplication.outputs.resourceId
    kind: 'functionapp,linux'
    location: location
    lock: {
      kind: lockKind
    }
    managedIdentities: {
      systemAssigned: false
      userAssignedResourceIds: [
        userAssignedIdentityApplicationRegistration.outputs.resourceId
        userAssignedIdentityFunctionApplication.outputs.resourceId
      ]
    }
    name: resources.functionApplication.name
    outboundVnetRouting: {
      allTraffic: true
      applicationTraffic: true
      backupRestoreTraffic: true
      contentShareTraffic: true
      imagePullTraffic: true
    }
    privateEndpoints: []
    publicNetworkAccess: 'Enabled'
    roleAssignments: []
    serverFarmResourceId: applicationServicePlan.outputs.resourceId
    siteConfig: {
      alwaysOn: false
      cors: {
        allowedOrigins: ['https://portal.azure.com']
        supportCredentials: false
      }
      ftpsState: 'Disabled'
      healthCheckPath: '/api/health-check'
      http20Enabled: true
      ipSecurityRestrictions: [
        {
          action: 'Allow'
          description: 'Allows a specific Azure Front Door instance to access the site.'
          headers: {
            'x-azure-fdid': [frontDoor_bootstrap.properties.frontDoorId]
          }
          ipAddress: 'AzureFrontDoor.Backend'
          name: 'AllowAzureFrontDoor'
          priority: 1
          tag: 'ServiceTag'
        }
      ]
      ipSecurityRestrictionsDefaultAction: 'Deny'
      keyVaultReferenceIdentity: userAssignedIdentityFunctionApplication.outputs.resourceId
      localMySqlEnabled: false
      minTlsCipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
      minTlsVersion: '1.2'
      remoteDebuggingEnabled: false
      scmIpSecurityRestrictions: []
      scmIpSecurityRestrictionsDefaultAction: 'Deny'
      scmIpSecurityRestrictionsUseMain: true
      scmMinTlsVersion: '1.2'
      scmType: 'None'
      use32BitWorkerProcess: false
      webSocketsEnabled: false
    }
    slots: []
    storageAccountRequired: true
    tags: resources.functionApplication.?tags
    virtualNetworkSubnetResourceId: subnetResourceIdMap.flexConsumptionApplicationServicePlan
  }
}
module keyVault 'br/public:avm/res/key-vault/vault:0.13.3' = {
  params: {
    createMode: 'default'
    diagnosticSettings: [
      {
        logCategoriesAndGroups: [
          {
            categoryGroup: 'audit'
          }
        ]
        workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
      }
    ]
    enablePurgeProtection: true
    enableRbacAuthorization: true
    enableSoftDelete: true
    enableTelemetry: false
    enableVaultForDeployment: false
    enableVaultForDiskEncryption: false
    enableVaultForTemplateDeployment: true
    keys: [
      {
        keyOps: [
          'unwrapKey'
          'wrapKey'
        ]
        keySize: 4096
        kty: 'RSA-HSM'
        name: defaultCustomerManagedKey.name
        rotationPolicy: {
          lifetimeActions: [
            {
              action: {
                type: 'notify'
              }
              trigger: {
                timeBeforeExpiry: 'P30D'
              }
            }
            {
              action: {
                type: 'rotate'
              }
              trigger: {
                timeAfterCreate: 'P60D'
              }
            }
          ]
        }
        roleAssignments: [
          {
            principalId: userAssignedIdentityCustomerManagedEncryption.outputs.principalId
            principalType: 'ServicePrincipal'
            roleDefinitionIdOrName: 'Key Vault Crypto Service Encryption User'
          }
        ]
      }
    ]
    location: location
    lock: {
      kind: lockKind
    }
    name: resources.keyVault.name
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      ipRules: []
      virtualNetworkRules: []
    }
    privateEndpoints: [
      {
        enableTelemetry: false
        privateDnsZoneGroup: {
          privateDnsZoneGroupConfigs: [
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.keyVault
            }
          ]
        }
        subnetResourceId: subnetResourceIdMap.privateEndpoints
      }
    ]
    publicNetworkAccess: 'Disabled' // TODO: Set to 'SecuredByPerimeter' when AVM for Key Vault is updated.
    roleAssignments: (deployOwnerRoleAssignments
      ? [
          {
            principalId: owner.principalId
            principalType: 'ServicePrincipal'
            roleDefinitionIdOrName: 'Key Vault Administrator'
          }
        ]
      : [])
    secrets: []
    softDeleteRetentionInDays: 90
    sku: 'premium'
  }
}
module logAnalyticsWorkspace 'br/public:avm/res/operational-insights/workspace:0.14.2' = {
  params: {
    dataRetention: 30
    diagnosticSettings: []
    enableTelemetry: false
    features: {
      disableLocalAuth: true
      enableDataExport: false
      enableLogAccessUsingOnlyResourcePermissions: true
      immediatePurgeDataOn30Days: false
    }
    forceCmkForQuery: false
    location: location
    lock: {
      kind: lockKind
    }
    managedIdentities: {
      systemAssigned: false
      userAssignedResourceIds: []
    }
    name: resources.logAnalyticsWorkspace.name
    publicNetworkAccessForIngestion: 'SecuredByPerimeter'
    publicNetworkAccessForQuery: 'Enabled' // TODO: Set to 'SecuredByPerimeter' when done with initial testing.
    roleAssignments: []
    skuName: 'PerGB2018'
    tags: resources.logAnalyticsWorkspace.?tags
  }
}
module monitorPrivateLinkScope 'br/public:avm/res/insights/private-link-scope:0.7.2' = {
  params: {
    accessModeSettings: {
      exclusions: []
      ingestionAccessMode: 'PrivateOnly'
      queryAccessMode: 'Open' // TODO: Set to 'PrivateOnly' when done with initial testing.
    }
    enableTelemetry: false
    location: 'global'
    lock: {
      kind: lockKind
    }
    name: resources.monitorPrivateLinkScope.name
    privateEndpoints: [
      {
        enableTelemetry: false
        privateDnsZoneGroup: {
          privateDnsZoneGroupConfigs: [
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.monitor.agentService
            }
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.monitor.core
            }
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.monitor.insightsOds
            }
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.monitor.insightsOms
            }
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.storageAccount.blob
            }
          ]
        }
        subnetResourceId: subnetResourceIdMap.privateEndpoints
      }
    ]
    roleAssignments: []
    scopedResources: [
      {
        linkedResourceId: applicationInsights.outputs.resourceId
        name: applicationInsights.outputs.applicationId
      }
      {
        linkedResourceId: logAnalyticsWorkspace.outputs.resourceId
        name: logAnalyticsWorkspace.outputs.logAnalyticsWorkspaceId
      }
    ]
    tags: resources.monitorPrivateLinkScope.?tags
  }
}
module natGateway 'br/public:avm/res/network/nat-gateway:2.0.0' = {
  params: {
    availabilityZone: -1
    enableTelemetry: false
    location: location
    lock: {
      kind: lockKind
    }
    name: resources.natGateway.?name
    publicIPPrefixResourceIds: [publicIpPrefixResourceIdMap[resources.natGateway.publicIpPrefix.name]]
    roleAssignments: []
    tags: resources.natGateway.?tags
  }
}
module natGateway_publicIpPrefix 'br/public:avm/res/network/public-ip-prefix:0.7.2' = {
  params: {
    availabilityZones: [
      1
      2
      3
    ]
    enableTelemetry: false
    location: location
    lock: {
      kind: lockKind
    }
    name: resources.natGateway.publicIpPrefix.name
    prefixLength: 31
    publicIPAddressVersion: 'IPv4'
    roleAssignments: []
    tags: resources.natGateway.publicIpPrefix.?tags
    tier: 'Regional'
  }
}
module networkSecurityGroups 'br/public:avm/res/network/network-security-group:0.5.2' = [
  for subnet in resources.virtualNetwork.subnets: {
    params: {
      diagnosticSettings: []
      enableTelemetry: false
      flushConnection: false
      location: location
      lock: {
        kind: lockKind
      }
      name: replace(subnet.name, 'snet', 'nsg')
      roleAssignments: []
      securityRules: []
    }
  }
]
module networkSecurityPerimeter 'br/public:avm/res/network/network-security-perimeter:0.1.3' = {
  params: {
    diagnosticSettings: []
    enableTelemetry: false
    location: location
    lock: {
      kind: lockKind
    }
    name: resources.networkSecurityPerimeter.name
    profiles: [
      {
        accessRules: []
        name: 'default'
      }
    ]
    resourceAssociations: [
      /* TODO: Uncomment with Azure Container Registry is onboarded.
      {
        accessMode: 'Enforced'
        privateLinkResource: containerRegistry.outputs.resourceId
        profile: 'default'
      }
      */
      /* TODO: Uncomment with Azure Web App is onboarded.
      {
        accessMode: 'Enforced'
        privateLinkResource: functionApp.outputs.resourceId
        profile: 'default'
      }
      */
      {
        accessMode: 'Learning' // TODO: Set to 'Enforced' when dependencies are onboarded.
        privateLinkResource: keyVault.outputs.resourceId
        profile: 'default'
      }
      {
        accessMode: 'Learning' // TODO: Set to 'Enforced' when done with initial testing.
        privateLinkResource: logAnalyticsWorkspace.outputs.resourceId
        profile: 'default'
      }
      {
        accessMode: 'Learning' // TODO: Set to 'Enforced' when dependencies are onboarded.
        privateLinkResource: storageAccountFunction.outputs.resourceId
        profile: 'default'
      }
      {
        accessMode: 'Learning'
        privateLinkResource: storageAccountPublic.outputs.resourceId
        profile: 'default'
      }
    ]
    roleAssignments: []
    tags: resources.networkSecurityPerimeter.?tags
  }
}
module privateEndpointDnsZones './privateEndpointDnsZones.bicep' = {
  params: {
    lockKind: lockKind
    virtualNetworkResourceIds: [virtualNetwork.outputs.resourceId]
  }
}
module publicDnsZones './publicDnsZones.bicep' = {
  params: {
    lockKind: lockKind
    zones: resources.publicDnsZones
  }
}
module storageAccountFunction 'br/public:avm/res/storage/storage-account:0.31.0' = {
  params: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowedCopyScope: 'PrivateLink'
    allowSharedKeyAccess: false
    azureFilesIdentityBasedAuthentication: {
      defaultSharePermission: 'None'
      directoryServiceOptions: 'None'
      smbOAuthSettings: {
        isSmbOAuthEnabled: true
      }
    }
    blobServices: {
      automaticSnapshotPolicyEnabled: false
      changeFeedEnabled: false
      changeFeedRetentionInDays: null
      containerDeleteRetentionPolicyAllowPermanentDelete: false
      containerDeleteRetentionPolicyDays: 13
      containerDeleteRetentionPolicyEnabled: true
      containers: [
        {
          name: functionAppContainerName
        }
      ]
      corsRules: []
      deleteRetentionPolicyAllowPermanentDelete: false
      deleteRetentionPolicyDays: 13
      deleteRetentionPolicyEnabled: true
      diagnosticSettings: [
        {
          logCategoriesAndGroups: [
            {
              categoryGroup: 'audit'
            }
          ]
          workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        }
      ]
      isVersioningEnabled: true
      lastAccessTimeTrackingPolicyEnabled: true
      restorePolicyDays: null
      restorePolicyEnabled: false
      versionDeletePolicyDays: null
    }
    customerManagedKey: {
      autoRotationEnabled: true
      keyName: defaultCustomerManagedKey.name
      keyVaultResourceId: keyVault.outputs.resourceId
      userAssignedIdentityResourceId: userAssignedIdentityCustomerManagedEncryption.outputs.resourceId
    }
    defaultToOAuthAuthentication: true
    diagnosticSettings: []
    enableSftp: false
    enableTelemetry: false
    fileServices: {
      corsRules: []
      diagnosticSettings: [
        {
          logCategoriesAndGroups: [
            {
              categoryGroup: 'audit'
            }
          ]
          workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        }
      ]
      protocolSettings: {
        smb: {
          authenticationMethods: 'Kerberos'
          channelEncryption: 'AES-256-GCM'
          kerberosTicketEncryption: 'AES-256'
          versions: 'SMB3.1.1'
        }
      }
      shareDeleteRetentionPolicy: {
        days: 13
        enabled: true
      }
      shares: []
    }
    isLocalUserEnabled: false
    keyType: 'Account'
    kind: 'StorageV2'
    location: location
    lock: {
      kind: lockKind
    }
    managedIdentities: {
      systemAssigned: false
      userAssignedResourceIds: [userAssignedIdentityCustomerManagedEncryption.outputs.resourceId]
    }
    minimumTlsVersion: 'TLS1_2'
    name: resources.storageAccountFunction.name
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
      ipRules: []
      resourceAccessRules: []
      virtualNetworkRules: []
    }
    privateEndpoints: [
      {
        enableTelemetry: false
        name: 'pep-${resources.storageAccountFunction.name}-blob-0'
        privateDnsZoneGroup: {
          privateDnsZoneGroupConfigs: [
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.storageAccount.blob
            }
          ]
        }
        privateLinkServiceConnectionName: '${resources.storageAccountFunction.name}-blob-0'
        service: 'blob'
        subnetResourceId: subnetResourceIdMap.privateEndpoints
      }
      {
        enableTelemetry: false
        name: 'pep-${resources.storageAccountFunction.name}-queue-0'
        privateDnsZoneGroup: {
          privateDnsZoneGroupConfigs: [
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.storageAccount.queue
            }
          ]
        }
        privateLinkServiceConnectionName: '${resources.storageAccountFunction.name}-queue-0'
        service: 'queue'
        subnetResourceId: subnetResourceIdMap.privateEndpoints
      }
      {
        enableTelemetry: false
        name: 'pep-${resources.storageAccountFunction.name}-table-0'
        privateDnsZoneGroup: {
          privateDnsZoneGroupConfigs: [
            {
              privateDnsZoneResourceId: privateEndpointDnsZones.outputs.dnsZoneMap.storageAccount.table
            }
          ]
        }
        privateLinkServiceConnectionName: '${resources.storageAccountFunction.name}-table-0'
        service: 'table'
        subnetResourceId: subnetResourceIdMap.privateEndpoints
      }
    ]
    publicNetworkAccess: 'Disabled' // TODO: Set to 'SecuredByPerimeter' when dependencies are onboarded to NSP.
    queueServices: {
      corsRules: []
      diagnosticSettings: [
        {
          logCategoriesAndGroups: [
            {
              categoryGroup: 'audit'
            }
          ]
          workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        }
      ]
      queues: []
    }
    requireInfrastructureEncryption: true
    roleAssignments: [
      ...(deployOwnerRoleAssignments
        ? [
            {
              principalId: owner.principalId
              principalType: 'ServicePrincipal'
              roleDefinitionIdOrName: 'Storage Blob Data Owner'
            }
          ]
        : [])
      {
        principalId: userAssignedIdentityFunctionApplication.outputs.principalId
        principalType: 'ServicePrincipal'
        roleDefinitionIdOrName: 'Storage Blob Data Owner'
      }
      {
        principalId: userAssignedIdentityFunctionApplication.outputs.principalId
        principalType: 'ServicePrincipal'
        roleDefinitionIdOrName: 'Storage Queue Data Contributor'
      }
      {
        principalId: userAssignedIdentityFunctionApplication.outputs.principalId
        principalType: 'ServicePrincipal'
        roleDefinitionIdOrName: 'Storage Table Data Contributor'
      }
    ]
    skuName: 'Standard_RAGRS'
    supportsHttpsTrafficOnly: true
    tableServices: {
      corsRules: []
      diagnosticSettings: [
        {
          logCategoriesAndGroups: [
            {
              categoryGroup: 'audit'
            }
          ]
          workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        }
      ]
      tables: []
    }
    tags: resources.storageAccountFunction.?tags
  }
}
module storageAccountPublic 'br/public:avm/res/storage/storage-account:0.31.0' = {
  params: {
    accessTier: 'Hot'
    allowBlobPublicAccess: true
    allowCrossTenantReplication: false
    allowedCopyScope: 'PrivateLink'
    allowSharedKeyAccess: false
    azureFilesIdentityBasedAuthentication: {
      defaultSharePermission: 'None'
      directoryServiceOptions: 'None'
      smbOAuthSettings: {
        isSmbOAuthEnabled: true
      }
    }
    blobServices: {
      automaticSnapshotPolicyEnabled: false
      changeFeedEnabled: false
      changeFeedRetentionInDays: null
      containerDeleteRetentionPolicyAllowPermanentDelete: false
      containerDeleteRetentionPolicyDays: 13
      containerDeleteRetentionPolicyEnabled: true
      containers: []
      corsRules: []
      deleteRetentionPolicyAllowPermanentDelete: false
      deleteRetentionPolicyDays: 13
      deleteRetentionPolicyEnabled: true
      diagnosticSettings: [
        {
          logCategoriesAndGroups: [
            {
              categoryGroup: 'audit'
            }
          ]
          workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        }
      ]
      isVersioningEnabled: true
      lastAccessTimeTrackingPolicyEnabled: true
      restorePolicyDays: null
      restorePolicyEnabled: false
      versionDeletePolicyDays: null
    }
    customerManagedKey: {
      autoRotationEnabled: true
      keyName: defaultCustomerManagedKey.name
      keyVaultResourceId: keyVault.outputs.resourceId
      userAssignedIdentityResourceId: userAssignedIdentityCustomerManagedEncryption.outputs.resourceId
    }
    defaultToOAuthAuthentication: true
    diagnosticSettings: []
    enableSftp: false
    enableTelemetry: false
    fileServices: {
      corsRules: []
      diagnosticSettings: [
        {
          logCategoriesAndGroups: [
            {
              categoryGroup: 'audit'
            }
          ]
          workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        }
      ]
      protocolSettings: {
        smb: {
          authenticationMethods: 'Kerberos'
          channelEncryption: 'AES-256-GCM'
          kerberosTicketEncryption: 'AES-256'
          versions: 'SMB3.1.1'
        }
      }
      shareDeleteRetentionPolicy: {
        days: 13
        enabled: true
      }
      shares: []
    }
    isLocalUserEnabled: false
    keyType: 'Account'
    kind: 'StorageV2'
    location: location
    lock: {
      kind: lockKind
    }
    managedIdentities: {
      systemAssigned: false
      userAssignedResourceIds: [userAssignedIdentityCustomerManagedEncryption.outputs.resourceId]
    }
    minimumTlsVersion: 'TLS1_2'
    name: resources.storageAccountPublic.name
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Allow'
      ipRules: []
      resourceAccessRules: []
      virtualNetworkRules: []
    }
    privateEndpoints: []
    publicNetworkAccess: 'Enabled'
    queueServices: {
      corsRules: []
      diagnosticSettings: [
        {
          logCategoriesAndGroups: [
            {
              categoryGroup: 'audit'
            }
          ]
          workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        }
      ]
      queues: []
    }
    requireInfrastructureEncryption: true
    roleAssignments: []
    skuName: 'Standard_RAGRS'
    supportsHttpsTrafficOnly: true
    tableServices: {
      corsRules: []
      diagnosticSettings: [
        {
          logCategoriesAndGroups: [
            {
              categoryGroup: 'audit'
            }
          ]
          workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        }
      ]
      tables: []
    }
    tags: resources.storageAccountPublic.?tags
  }
}
module userAssignedIdentityApplicationRegistration 'br/public:avm/res/managed-identity/user-assigned-identity:0.4.3' = {
  params: {
    enableTelemetry: false
    federatedIdentityCredentials: []
    location: location
    lock: {
      kind: lockKind
    }
    name: resources.userAssignedIdentityApplicationRegistration.name
    roleAssignments: []
    tags: resources.userAssignedIdentityApplicationRegistration.?tags
  }
}
module userAssignedIdentityCustomerManagedEncryption 'br/public:avm/res/managed-identity/user-assigned-identity:0.4.3' = {
  params: {
    enableTelemetry: false
    federatedIdentityCredentials: []
    location: location
    lock: {
      kind: lockKind
    }
    name: resources.userAssignedIdentityCustomerManagedEncryption.name
    roleAssignments: []
    tags: resources.userAssignedIdentityCustomerManagedEncryption.?tags
  }
}
module userAssignedIdentityFunctionApplication 'br/public:avm/res/managed-identity/user-assigned-identity:0.4.3' = {
  params: {
    enableTelemetry: false
    federatedIdentityCredentials: []
    location: location
    lock: {
      kind: lockKind
    }
    name: resources.userAssignedIdentityFunctionApplication.name
    roleAssignments: []
    tags: resources.userAssignedIdentityFunctionApplication.?tags
  }
}
module virtualNetwork 'br/public:avm/res/network/virtual-network:0.7.2' = {
  params: {
    addressPrefixes: resources.virtualNetwork.addressPrefixes
    diagnosticSettings: resources.virtualNetwork.?diagnosticSettings
    dnsServers: resources.virtualNetwork.?dnsServers
    enableTelemetry: false
    enableVmProtection: true
    location: location
    lock: {
      kind: 'None' // NOTE: Lock is not set in order to allow subnet delegation modifications (example: Azure Managed DevOps Pools).
    }
    name: resources.virtualNetwork.name
    peerings: []
    roleAssignments: (0 != length(filter(
        resources.virtualNetwork.subnets,
        subnet => ('microsoft.devopsinfrastructure/pools' == toLower(subnet.?delegation ?? ''))
      ))
      ? [
          {
            principalId: devOpsInfrastructure_servicePrincipal.id
            principalType: 'ServicePrincipal'
            roleDefinitionIdOrName: 'Reader'
          }
        ]
      : [])
    subnets: [
      for (subnet, index) in resources.virtualNetwork.subnets: {
        ...subnet
        natGatewayResourceId: (contains(subnet, 'natGatewayResourceId')
          ? (contains(subnet.natGatewayResourceId!, '/')
              ? subnet.natGatewayResourceId!
              : natGatewayResourceIdMap[subnet.natGatewayResourceId!])
          : null)
        networkSecurityGroupResourceId: networkSecurityGroups[index].outputs.resourceId
        roleAssignments: (('microsoft.devopsinfrastructure/pools' == toLower(subnet.?delegation ?? ''))
          ? [
              {
                principalId: devOpsInfrastructure_servicePrincipal.id
                principalType: 'ServicePrincipal'
                roleDefinitionIdOrName: 'Network Contributor'
              }
            ]
          : [])
      }
    ]
    vnetEncryption: true
    vnetEncryptionEnforcement: 'AllowUnencrypted'
    tags: resources.virtualNetwork.?tags
  }
}
