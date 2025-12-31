targetScope = 'resourceGroup'

type dnsZoneMapType = {
  configurationStore: string
  containerRegistry: string
  keyVault: string
  monitor: {
    agentService: string
    core: string
    insightsOds: string
    insightsOms: string
  }
  postgresFlexibleServer: string
  redisCache: string
  storageAccount: {
    blob: string
    dfs: string
    file: string
    queue: string
    table: string
    web: string
  }
  webApp: string
}

param lockKind ('CanNotDelete' | 'None' | 'ReadOnly') = 'CanNotDelete'
param virtualNetworkResourceIds string[] = []

var dnsZoneMap dnsZoneMapType = {
  configurationStore: 'privatelink.azconfig.io'
  containerRegistry: 'privatelink.azurecr.io'
  keyVault: 'privatelink.vaultcore.azure.net'
  monitor: {
    agentService: 'privatelink.agentsvc.azure-automation.net'
    core: 'privatelink.monitor.azure.com'
    insightsOds: 'privatelink.ods.opinsights.azure.com'
    insightsOms: 'privatelink.oms.opinsights.azure.com'
  }
  postgresFlexibleServer: 'privatelink.postgres.database.azure.com'
  redisCache: 'privatelink.redis.azure.net'
  storageAccount: {
    blob: 'privatelink.blob.${environment().suffixes.storage}'
    dfs: 'privatelink.dfs.${environment().suffixes.storage}'
    file: 'privatelink.file.${environment().suffixes.storage}'
    queue: 'privatelink.queue.${environment().suffixes.storage}'
    table: 'privatelink.table.${environment().suffixes.storage}'
    web: 'privatelink.web.${environment().suffixes.storage}'
  }
  webApp: 'privatelink.azurewebsites.net'
}
var dnsZoneResourceIds = [for i in range(0, length(dnsZones)): privateDnsZones[i].id]
var dnsZones {
  category: string
  index: int
  subCategory: string?
  value: string
}[] = map(
  flatten(map(
    items(dnsZoneMap),
    category =>
      (contains(category.value, 'privatelink.')
        ? [
            {
              category: category.key
              subCategory: null
              value: category.value
            }
          ]
        : map(items(category.value), subCategory => {
            category: category.key
            subCategory: subCategory.key
            value: subCategory.value
          }))
  )),
  (zone, index) => {
    ...zone
    index: index
  }
)
var storageAccountBlobDnsZoneIndex = first(filter(dnsZones, zone => (dnsZoneMap.storageAccount.blob == zone.value)))!.index

@onlyIfNotExists()
resource privateDnsZones 'Microsoft.Network/privateDnsZones@2024-06-01' = [
  for zone in dnsZones: {
    location: 'global'
    name: zone.value
  }
]
resource privateDnsZones_lock 'Microsoft.Authorization/locks@2020-05-01' = [
  for zone in dnsZones: if ('None' != lockKind) {
    name: 'lock-${zone.value}'
    properties: {
      level: lockKind
      notes: ((lockKind == 'CanNotDelete')
        ? 'Cannot delete resource or child resources.'
        : 'Cannot delete or modify the resource or child resources.')
    }
    scope: privateDnsZones[zone.index]
  }
]
@onlyIfNotExists() // NOTE: This virtual network link was added to fix an issue where Azure Functions Flex Consumption plans cannot access private endpoints.
resource storageAccountBlobDnsZone_virtualNetworkLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [
  for id in virtualNetworkResourceIds: {
    location: 'global'
    name: '${last(split(id, '/'))}-${uniqueString(privateDnsZones[storageAccountBlobDnsZoneIndex].id, id)}'
    parent: privateDnsZones[storageAccountBlobDnsZoneIndex]
    properties: {
      registrationEnabled: false
      resolutionPolicy: 'Default'
      virtualNetwork: {
        id: id
      }
    }
  }
]

output dnsZoneMap dnsZoneMapType = reduce(dnsZones, {}, (result, zone) => {
  ...result
  '${zone.category}': (empty(zone.?subCategory)
    ? dnsZoneResourceIds[zone.index]
    : {
        ...(result[?zone.category] ?? {})
        '${zone.subCategory!}': dnsZoneResourceIds[zone.index]
      })
})
