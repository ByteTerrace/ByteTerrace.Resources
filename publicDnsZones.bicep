@export()
type publicDnsZoneType = {
  enableDnssec: bool?
}

param lockKind ('CanNotDelete' | 'None' | 'ReadOnly') = 'CanNotDelete'
param zones { *: publicDnsZoneType }

var zoneKeys = objectKeys(zones)
var zoneResourceIds = [for i in range(0, length(zoneKeys)): publicDnsZones[i].id]

@onlyIfNotExists()
resource publicDnsZones 'Microsoft.Network/dnsZones@2018-05-01' = [
  for key in zoneKeys: {
    location: 'global'
    name: key
  }
]
@onlyIfNotExists()
resource publicDnsZones_dnssecConfigs 'Microsoft.Network/dnsZones/dnssecConfigs@2023-07-01-preview' = [
  for (key, index) in zoneKeys: if (zones[key].?enableDnssec ?? true) {
    dependsOn: [publicDnsZones]
    name: 'default'
    parent: publicDnsZones[index]
  }
]
resource publicDnsZones_lock 'Microsoft.Authorization/locks@2020-05-01' = [
  for (key, index) in zoneKeys: if ('None' != lockKind) {
    name: 'lock-${key}'
    properties: {
      level: lockKind
      notes: ((lockKind == 'CanNotDelete')
        ? 'Cannot delete resource or child resources.'
        : 'Cannot delete or modify the resource or child resources.')
    }
    scope: publicDnsZones[index]
  }
]

output dnsZoneMap { *: string } = reduce(
  map(zoneKeys, (key, index) => {
    key: key
    index: index
  }),
  {},
  (result, zone) => {
    ...result
    '${zone.key}': zoneResourceIds[zone.index]
  }
)
