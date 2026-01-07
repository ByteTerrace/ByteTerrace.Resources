extension graph

@export()
type groupType = {
  classification: string?
  description: string
  mailEnabled: bool
  mailNickname: string
  name: string
  uniqueName: string?
}
@export()
type roleAssignmentType = {
  description: string?
  groupName: string?
  principalId: string?
  principalType: ('' | 'Device' | 'ForeignGroup' | 'Group' | 'ServicePrincipal' | 'User')
  resourceGroupName: string?
  resourceId: string?
  resourcePath: string?
  resourceProvider: string?
  roleDefinitionName: string
  subscriptionId: string?
}
@export()
type roleDefinitionType = {
  actions: string[]?
  assignableScopes: string[]?
  dataActions: string[]?
  description: string
  location: string?
  name: string
  notActions: string[]?
  notDataActions: string[]?
  roleName: string?
}

param groups groupType[] = []
param roleAssignments roleAssignmentType[] = []
param roleDefinitions roleDefinitionType[] = []

var groupsMap { *: int } = toObject(range(0, length(groups)), i => groups[i].name, i => i)
var roleAssignmentResourceIds = map(
  map(roleAssignments, assignment => {
    resourceGroupName: (assignment.?resourceGroupName ?? resourceGroup().name)
    resourceId: assignment.?resourceId
    resourcePathParts: split(assignment.?resourcePath ?? '', '/')
    resourceProviderParts: split(assignment.?resourceProvider ?? '', '/')
    subscriptionId: (assignment.?subscriptionId ?? subscription().subscriptionId)
  }),
  assignment =>
    (assignment.?resourceId ?? '/subscriptions/${assignment.subscriptionId}/resourceGroups/${assignment.resourceGroupName}/providers/${first(assignment.resourceProviderParts)}/${join(map(skip(assignment.resourceProviderParts, 1), (s, i) => '${s}/${assignment.resourcePathParts[i]}'), '/')}')
)
var roleDefinitionsMap { *: int } = toObject(range(0, length(roleDefinitions)), i => roleDefinitions[i].name, i => i)

@onlyIfNotExists()
resource groupsResource 'Microsoft.Graph/groups@v1.0' = [
  for group in groups: {
    classification: group.?classification
    description: group.?description
    displayName: group.name
    isAssignableToRole: false
    mailEnabled: group.mailEnabled
    mailNickname: group.mailNickname
    securityEnabled: true
    uniqueName: (group.?uniqueName ?? guid(tenant().tenantId, group.name))
    visibility: 'Private'
  }
]
resource roleDefinitionsResource 'Microsoft.Authorization/roleDefinitions@2022-04-01' = [
  for definition in roleDefinitions: {
    name: guid(definition.name)
    properties: {
      assignableScopes: (definition.?assignableScopes ?? [])
      description: definition.description
      permissions: [
        {
          actions: definition.?actions
          dataActions: definition.?dataActions
          notActions: definition.?notActions
          notDataActions: definition.?notDataActions
        }
      ]
      roleName: (definition.?roleName ?? definition.name)
      type: 'CustomRole'
    }
  }
]
module resourceRoleAssignmentModule 'br/public:avm/ptn/authorization/resource-role-assignment:0.1.2' = [
  for (assignment, index) in roleAssignments: {
    params: {
      description: assignment.?description
      enableTelemetry: false
      principalId: (assignment.?principalId ?? groupsResource[groupsMap[assignment.groupName!]].id)
      principalType: assignment.principalType
      resourceId: roleAssignmentResourceIds[index]
      roleDefinitionId: roleDefinitionsResource[roleDefinitionsMap[assignment.roleDefinitionName]].id
    }
  }
]
