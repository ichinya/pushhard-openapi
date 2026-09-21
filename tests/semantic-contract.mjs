import { readFileSync } from 'node:fs'

const [, , bundlePath] = process.argv
const logLevel = process.env.LOG_LEVEL ?? 'info'

function log(level, event, context = {}) {
  const ranks = { debug: 10, info: 20, warning: 30, error: 40 }
  if ((ranks[level] ?? 20) < (ranks[logLevel] ?? 20)) return

  const target = level === 'error' ? console.error : console.log
  target(JSON.stringify({ level, event, ...context }))
}

function invariant(condition, message) {
  if (!condition) {
    log('error', 'semantic_contract_failed', { rule: message })
    throw new Error(message)
  }
}

function equal(actual, expected, message) {
  invariant(JSON.stringify(actual) === JSON.stringify(expected), message)
}

function schema(spec, name) {
  const value = spec.components?.schemas?.[name]
  invariant(value && typeof value === 'object', `missing schema: ${name}`)
  return value
}

function assertClosedObject(value, name) {
  invariant(value.type === 'object', `${name} must be an object`)
  invariant(value.additionalProperties === false, `${name} must reject additional properties`)
}

function propertyNames(value) {
  return Object.keys(value.properties ?? {}).sort()
}

invariant(bundlePath, 'bundle path argument is required')
log('info', 'semantic_contract_started', { bundle: 'openapi.json' })

const spec = JSON.parse(readFileSync(bundlePath, 'utf8'))
const capabilityIds = schema(spec, 'ServerCapabilityId')
equal(
  capabilityIds.enum,
  ['git', 'docker_engine', 'docker_compose_v2', 'rsync', 'php', 'composer', 'node'],
  'capability catalog must stay fixed and ordered',
)

const context = schema(spec, 'ServerCapabilityCheckContext')
assertClosedObject(context, 'ServerCapabilityCheckContext')
equal(
  propertyNames(context),
  ['build_server_id', 'image_transport', 'recipe', 'server_role', 'target_server_id'],
  'capability context exposes unexpected fields',
)
equal(
  [...context.required].sort(),
  ['recipe', 'server_role', 'target_server_id'],
  'capability context required fields drifted',
)
equal(context.properties.recipe.enum, ['docker_compose', 'go'], 'recipe enum drifted')
equal(context.properties.server_role.enum, ['target', 'build'], 'server role enum drifted')
equal(
  context.properties.image_transport.enum,
  ['archive_copy'],
  'image transport enum drifted',
)

for (const forbidden of [
  'transfer_required',
  'command',
  'commands',
  'package',
  'packages',
  'path',
  'capabilities',
]) {
  invariant(!(forbidden in context.properties), `forbidden context field: ${forbidden}`)
}

const request = schema(spec, 'ServerCapabilityCheckRequest')
assertClosedObject(request, 'ServerCapabilityCheckRequest')
equal(propertyNames(request), ['context'], 'capability request must contain only optional context')
invariant(!request.required, 'capability request context must remain optional')

const probe = schema(spec, 'ServerCapabilityProbe')
const evaluation = schema(spec, 'ServerCapabilityEvaluation')
const check = schema(spec, 'ServerCapabilityCheck')
const installHint = schema(spec, 'ServerCapabilityInstallHint')
for (const [name, value] of [
  ['ServerCapabilityProbe', probe],
  ['ServerCapabilityEvaluation', evaluation],
  ['ServerCapabilityCheck', check],
  ['ServerCapabilityInstallHint', installHint],
]) {
  assertClosedObject(value, name)
}

equal(probe.properties.status.enum, ['checked', 'unavailable'], 'probe status enum drifted')
equal(
  probe.properties.error_code.enum,
  ['ssh_unavailable', 'authentication_failed', 'probe_timeout', 'probe_failed'],
  'probe error code enum drifted',
)
equal(
  evaluation.properties.status.enum,
  ['ready', 'missing_capabilities', 'unavailable'],
  'evaluation status enum drifted',
)
equal(
  evaluation.properties.error_code.enum,
  ['probe_unavailable', 'probe_timeout'],
  'evaluation error code enum drifted',
)
invariant(probe.properties.available.maxItems === 7, 'probe inventory must be bounded')
invariant(evaluation.properties.required.maxItems === 4, 'required capabilities must be bounded')
invariant(evaluation.properties.missing.maxItems === 4, 'missing capabilities must be bounded')
invariant(evaluation.properties.install_hints.maxItems === 4, 'install hints must be bounded')
invariant(installHint.properties.command.maxLength === 200, 'static install command must be bounded')
invariant(check.properties.server_name.maxLength === 255, 'server display name must be bounded')

const participant = schema(spec, 'DeploymentCapabilityPreflightParticipant')
const preflight = schema(spec, 'DeploymentCapabilityPreflight')
assertClosedObject(participant, 'DeploymentCapabilityPreflightParticipant')
assertClosedObject(preflight, 'DeploymentCapabilityPreflight')
equal(participant.properties.role.enum, ['target', 'build', 'runner'], 'participant role enum drifted')
equal(
  participant.properties.status.enum,
  ['ready', 'missing_capabilities', 'unavailable'],
  'participant status enum drifted',
)
equal(
  participant.properties.error_code.enum,
  ['capability_missing', 'probe_unavailable', 'probe_timeout'],
  'participant error code enum drifted',
)
equal(
  preflight.properties.error_code.enum,
  ['capability_missing', 'probe_unavailable', 'probe_timeout'],
  'preflight error code enum drifted',
)
invariant(participant.properties.required.maxItems === 4, 'participant required list must be bounded')
invariant(participant.properties.missing.maxItems === 4, 'participant missing list must be bounded')
invariant(preflight.properties.participants.minItems === 1, 'preflight requires a participant')
invariant(preflight.properties.participants.maxItems === 3, 'preflight participants must be bounded')
invariant(preflight.properties.required_count.maximum === 12, 'required count must be bounded')
invariant(preflight.properties.missing_count.maximum === 12, 'missing count must be bounded')

const sensitiveNames = new Set([
  'host',
  'ip',
  'user',
  'username',
  'password',
  'credentials',
  'stdout',
  'stderr',
  'output',
  'command',
  'environment',
  'compose',
])
for (const [name, value] of [
  ['ServerCapabilityProbe', probe],
  ['ServerCapabilityEvaluation', evaluation],
  ['ServerCapabilityCheck', check],
  ['DeploymentCapabilityPreflightParticipant', participant],
  ['DeploymentCapabilityPreflight', preflight],
]) {
  for (const property of propertyNames(value)) {
    invariant(!sensitiveNames.has(property), `${name} exposes sensitive field: ${property}`)
  }
}

const operation = spec.paths?.['/servers/{server}/capabilities/check']?.post
invariant(operation, 'capability check operation is missing')
invariant(operation.operationId === 'checkServerCapabilities', 'operationId drifted')
invariant(operation['x-required-ability'] === 'read', 'required ability must be read')
invariant(
  operation.parameters?.some(
    (p) => p?.$ref === '#/components/parameters/ServerId',
  ),
  'operation must use the canonical required ServerId path parameter',
)
invariant(
  operation.parameters?.some(
    (p) => p?.$ref === '#/components/parameters/WorkspaceSelector',
  ),
  'workspace-scoped operation must accept the X-Workspace-Id selector',
)
invariant(operation.requestBody?.required === false, 'request body must remain optional')
invariant(
  operation.requestBody?.content?.['application/json']?.schema?.$ref ===
    '#/components/schemas/ServerCapabilityCheckRequest',
  'request schema ref drifted',
)
invariant(
  operation.responses?.['200']?.content?.['application/json']?.schema?.$ref ===
    '#/components/schemas/ServerCapabilityCheck',
  'success schema ref drifted',
)
for (const status of ['401', '403', '404', '422', '429']) {
  invariant(operation.responses?.[status], `missing protocol response: ${status}`)
}

const serverId = spec.components?.parameters?.ServerId
invariant(serverId?.in === 'path' && serverId.required === true, 'ServerId must be a required path parameter')
invariant(
  serverId.schema?.pattern === '^[0-9A-HJKMNP-TV-Z]{26}$',
  'ServerId must retain the canonical ULID pattern',
)

invariant(
  schema(spec, 'Server').properties?.capability_check?.$ref ===
    '#/components/schemas/ServerCapabilityCheck',
  'Server mutation advisory shape is missing',
)
const bindingChecks = schema(spec, 'ServerBindingContract').properties?.capability_checks
invariant(bindingChecks?.maxItems === 2, 'binding capability checks must be bounded to target/build')
invariant(
  bindingChecks?.items?.$ref === '#/components/schemas/ServerCapabilityCheck',
  'binding advisory schema ref drifted',
)
invariant(
  schema(spec, 'DeploymentExecutionPlan').properties?.preflight?.$ref ===
    '#/components/schemas/DeploymentCapabilityPreflight',
  'deployment execution plan preflight ref is missing',
)

// ---------------------------------------------------------------------------
// Workspace management contract (plan 89-workspace-roles, Tasks 2–3, D1/D2/D3)
// ---------------------------------------------------------------------------

const ULID_PATTERN = '^[0-9A-HJKMNP-TV-Z]{26}$'

// Effective permission = membership role ∩ PAT abilities; '*' never bypasses role.
equal(schema(spec, 'WorkspaceRole').enum, ['admin', 'devops', 'viewer'], 'workspace role enum drifted')

for (const name of [
  'Workspace',
  'WorkspaceMember',
  'WorkspaceCapabilities',
  'WorkspaceWriteRequest',
  'WorkspaceMemberRoleRequest',
  'WorkspaceError',
]) {
  assertClosedObject(schema(spec, name), name)
}

for (const name of ['Workspace', 'WorkspaceMember']) {
  const value = schema(spec, name)
  invariant(value.properties?.id?.pattern === ULID_PATTERN, `${name}.id must expose the public ULID pattern`)
}

const workspaceStatus = schema(spec, 'Workspace').properties?.status
invariant(
  JSON.stringify(workspaceStatus?.enum) === JSON.stringify(['active', 'archived']),
  'workspace status lifecycle drifted',
)
const workspaceKind = schema(spec, 'Workspace').properties?.kind
invariant(
  JSON.stringify(workspaceKind?.enum) === JSON.stringify(['personal', 'shared']),
  'workspace kind drifted',
)

const workspaceCapabilities = schema(spec, 'WorkspaceCapabilities')
equal(
  propertyNames(workspaceCapabilities),
  [
    'can_deploy',
    'can_edit_resources',
    'can_export_audit',
    'can_manage_members',
    'can_manage_servers',
    'can_view_audit',
    'role',
    'workspace_id',
  ],
  'workspace capabilities expose unexpected fields',
)

const workspaceErrorCodes = schema(spec, 'WorkspaceError').properties?.code?.enum
invariant(
  JSON.stringify(workspaceErrorCodes) ===
    JSON.stringify([
      'workspace_not_found',
      'workspace_archived',
      'workspace_not_archived',
      'workspace_not_empty',
      'running_deployment',
      'last_admin',
      'personal_workspace_restricted',
      'workspace_selector_conflict',
      'member_not_found',
      'invitation_not_found',
      'invitation_not_pending',
      'invitation_email_mismatch',
      'membership_exists',
    ]),
  'workspace error code catalog drifted',
)

// Public workspace selector: public ULID header, never numeric IDs.
const selector = spec.components?.parameters?.WorkspaceSelector
invariant(selector?.in === 'header' && selector?.name === 'X-Workspace-Id', 'selector must be the X-Workspace-Id header')
invariant(selector?.required === false, 'selector omission must keep legacy personal-only calls working')
invariant(selector?.schema?.pattern === ULID_PATTERN, 'selector must be a public ULID')

const workspaceIdParam = spec.components?.parameters?.WorkspaceId
invariant(workspaceIdParam?.in === 'path' && workspaceIdParam?.required === true, 'WorkspaceId must be a required path parameter')
invariant(workspaceIdParam?.schema?.pattern === ULID_PATTERN, 'WorkspaceId must retain the canonical ULID pattern')

// Management operations: path parameter is the only selector (D1);
// x-required-ability is the PAT ceiling, x-required-roles is the D2 role matrix.
const managementOps = [
  ['listWorkspaces', '/workspaces', 'get', 'read', ['admin', 'devops', 'viewer']],
  ['createWorkspace', '/workspaces', 'post', 'admin', ['admin', 'devops', 'viewer']],
  ['getWorkspace', '/workspaces/{workspace}', 'get', 'read', ['admin', 'devops', 'viewer']],
  ['renameWorkspace', '/workspaces/{workspace}', 'patch', 'admin', ['admin']],
  ['deleteWorkspace', '/workspaces/{workspace}', 'delete', 'admin', ['admin']],
  ['archiveWorkspace', '/workspaces/{workspace}/archive', 'post', 'admin', ['admin']],
  ['restoreWorkspace', '/workspaces/{workspace}/restore', 'post', 'admin', ['admin']],
  ['getWorkspaceCapabilities', '/workspaces/{workspace}/capabilities', 'get', 'read', ['admin', 'devops', 'viewer']],
  ['listWorkspaceMembers', '/workspaces/{workspace}/members', 'get', 'admin', ['admin']],
  ['changeWorkspaceMemberRole', '/workspaces/{workspace}/members/{member}', 'patch', 'admin', ['admin']],
  ['removeWorkspaceMember', '/workspaces/{workspace}/members/{member}', 'delete', 'admin', ['admin']],
  ['leaveWorkspace', '/workspaces/{workspace}/leave', 'post', 'read', ['admin', 'devops', 'viewer']],
  ['createWorkspaceInvitation', '/workspaces/{workspace}/invitations', 'post', 'admin', ['admin']],
  ['listWorkspaceInvitations', '/workspaces/{workspace}/invitations', 'get', 'admin', ['admin']],
  ['resendWorkspaceInvitation', '/workspaces/{workspace}/invitations/{invitation}/resend', 'post', 'admin', ['admin']],
  ['revokeWorkspaceInvitation', '/workspaces/{workspace}/invitations/{invitation}/revoke', 'post', 'admin', ['admin']],
  ['listWorkspaceAudit', '/workspaces/{workspace}/audit', 'get', 'read', ['admin', 'devops']],
  ['exportWorkspaceAudit', '/workspaces/{workspace}/audit/export', 'get', 'admin', ['admin']],
]

// Recipient self-service outside membership: no workspace selector at all;
// acceptance raises access, so the conservative PAT ceiling is admin.
const recipientOps = [
  ['acceptInvitation', '/invitations/{invitation}/accept', 'post', 'admin'],
  ['declineInvitation', '/invitations/{invitation}/decline', 'post', 'read'],
]

const specOperationIds = new Set()
for (const [path, methods] of Object.entries(spec.paths ?? {})) {
  for (const [method, op] of Object.entries(methods)) {
    if (op?.operationId) specOperationIds.add(op.operationId)
  }
}

for (const [operationId, path, method, ability, roles] of managementOps) {
  const op = spec.paths?.[path]?.[method]
  invariant(op, `workspace management operation is missing: ${path} ${method}`)
  invariant(op.operationId === operationId, `operationId drifted for ${path} ${method}`)
  invariant(op['x-required-ability'] === ability, `${operationId}: PAT ability ceiling drifted (expected ${ability})`)
  if (roles) {
    invariant(
      JSON.stringify([...(op['x-required-roles'] ?? [])].sort()) === JSON.stringify([...roles].sort()),
      `${operationId}: D2 role matrix drifted (expected ${roles.join('/')})`,
    )
  }
  const usesPathSelector = (op.parameters ?? []).some((p) => p?.$ref === '#/components/parameters/WorkspaceId')
  const usesHeaderSelector = (op.parameters ?? []).some((p) => p?.$ref === '#/components/parameters/WorkspaceSelector')
  if (path === '/workspaces') {
    invariant(!usesPathSelector && !usesHeaderSelector, `${operationId} addresses the user, not a selected workspace`)
  } else {
    invariant(usesPathSelector, `${operationId} must address the workspace via the path parameter`)
    invariant(!usesHeaderSelector, `${operationId} must not mix the header selector with the path selector`)
  }
}

for (const [operationId, path, method, ability] of recipientOps) {
  const op = spec.paths?.[path]?.[method]
  invariant(op, `recipient operation is missing: ${path} ${method}`)
  invariant(op.operationId === operationId, `operationId drifted for ${path} ${method}`)
  invariant(op['x-required-ability'] === ability, `${operationId}: PAT ability ceiling drifted (expected ${ability})`)
  const params = op.parameters ?? []
  invariant(
    params.some((p) => p?.$ref === '#/components/parameters/InvitationId'),
    `${operationId} must address the invitation via the path parameter`,
  )
  invariant(
    !params.some((p) => p?.$ref === '#/components/parameters/WorkspaceId' || p?.$ref === '#/components/parameters/WorkspaceSelector'),
    `${operationId} is recipient-scoped and must not take a workspace selector`,
  )
}

// The selector table covers every existing workspace-scoped endpoint;
// required:false keeps context-less legacy calls on the personal workspace.
const resourceOps = [
  'listProjects', 'createProject', 'validateProjectRepository', 'getProject', 'updateProject', 'deleteProject',
  'getProjectDeployHook', 'createProjectDeployHook',
  'upsertProjectWebhook', 'upsertProjectWebhookPut', 'listProjectWebhooks',
  'createProjectProviderWebhook', 'updateProjectProviderWebhook', 'deleteProjectProviderWebhook',
  'listProjectServers', 'createProjectServerBinding', 'updateProjectServerBinding', 'deleteProjectServerBinding',
  'mutateProjectServerEnv', 'updateProjectServerEnv', 'listAvailableServers',
  'triggerProjectDeploy', 'previewProjectDeploymentVariables', 'listProjectDeployments',
  'getProjectDeployment', 'cancelProjectDeployment',
  'listServers', 'createServer', 'getServer', 'updateServer', 'deleteServer',
  'checkServerCapabilities', 'getServerMetrics',
  'legacyTriggerDeploy', 'listGlobalDeployments', 'getGlobalDeployment',
  'retryDeployment', 'rollbackDeployment', 'restoreDeploymentBackup',
  'listProjectReleases', 'activateProjectRelease',
]

function findOperationById(operationId) {
  for (const methods of Object.values(spec.paths ?? {})) {
    for (const op of Object.values(methods)) {
      if (op?.operationId === operationId) return op
    }
  }
  return null
}

for (const operationId of resourceOps) {
  const op = findOperationById(operationId)
  invariant(op, `workspace-scoped resource operation is missing: ${operationId}`)
  invariant(
    (op.parameters ?? []).some((p) => p?.$ref === '#/components/parameters/WorkspaceSelector'),
    `${operationId} must accept the explicit X-Workspace-Id selector`,
  )
  invariant(
    !(op.requestBody?.content?.['application/json']?.schema?.properties?.workspace_id),
    `${operationId} must not accept raw workspace_id in the resource body`,
  )
}

for (const operationId of [
  'getCurrentUser', 'updateProfile', 'updatePassword', 'listTokens', 'createToken', 'deleteToken',
]) {
  const op = findOperationById(operationId)
  invariant(op, `user-level operation is missing: ${operationId}`)
  invariant(
    !(op.parameters ?? []).some((p) => p?.$ref === '#/components/parameters/WorkspaceSelector'),
    `${operationId} is user-level and must not take a workspace selector`,
  )
}

// Raw ownership fields are forbidden in every request body of the spec
// (mass assignment / transfer rejection, D4).
const forbiddenBodyFields = ['workspace_id', 'personal_owner_user_id']
for (const [path, methods] of Object.entries(spec.paths ?? {})) {
  for (const [method, op] of Object.entries(methods)) {
    const props = op?.requestBody?.content?.['application/json']?.schema?.properties
    if (!props) continue
    for (const field of forbiddenBodyFields) {
      invariant(!(field in props), `${method} ${path}: raw ${field} in request body is forbidden`)
    }
  }
}

// Non-disclosure envelope: unknown and foreign workspace share one safe 404 schema.
equal(
  spec.paths?.['/workspaces/{workspace}']?.get?.responses?.['404']?.content?.['application/json']?.schema?.$ref,
  '#/components/schemas/WorkspaceError',
  'workspace 404 must use the safe non-disclosing envelope',
)

// ---------------------------------------------------------------------------
// Invitations and safe audit (plan 89-workspace-roles, Task 3, D5/D6)
// ---------------------------------------------------------------------------

assertClosedObject(schema(spec, 'Invitation'), 'Invitation')
assertClosedObject(schema(spec, 'InvitationCreateRequest'), 'InvitationCreateRequest')
assertClosedObject(schema(spec, 'WorkspaceAuditEvent'), 'WorkspaceAuditEvent')

const invitation = schema(spec, 'Invitation')
invariant(invitation.properties?.id?.pattern === ULID_PATTERN, 'Invitation.id must expose the public ULID pattern')
invariant(invitation.properties?.workspace_id?.pattern === ULID_PATTERN, 'Invitation.workspace_id must be a public ULID')
invariant(
  JSON.stringify(invitation.properties?.status?.enum) ===
    JSON.stringify(['pending', 'accepted', 'expired', 'revoked', 'declined']),
  'invitation state machine drifted',
)
// Raw invitation token/hash/tokenized URL are never part of the API surface (D5).
for (const forbidden of ['token', 'token_hash', 'hash', 'url', 'accept_url', 'invite_url']) {
  invariant(!(forbidden in invitation.properties), `Invitation exposes forbidden delivery field: ${forbidden}`)
}

// Audit allowlist: exact field set, nothing more (D6).
const auditEvent = schema(spec, 'WorkspaceAuditEvent')
equal(
  propertyNames(auditEvent),
  ['action', 'actor_id', 'actor_type', 'diff', 'id', 'occurred_at', 'resource_id', 'resource_type', 'retained_until', 'workspace_id'],
  'audit event exposes fields outside the D6 allowlist',
)
invariant(
  JSON.stringify(auditEvent.properties?.actor_type?.enum) === JSON.stringify(['user', 'system']),
  'audit actor type drifted',
)
invariant(auditEvent.properties?.action?.maxLength === 64, 'audit action must stay bounded')
invariant(auditEvent.properties?.retained_until?.format === 'date-time', 'audit retention target must be present')
for (const forbidden of ['email', 'token', 'hash', 'url', 'ip', 'secret', 'password']) {
  invariant(!(forbidden in auditEvent.properties), `audit event exposes forbidden field: ${forbidden}`)
}
const auditDiff = auditEvent.properties?.diff?.additionalProperties
invariant(auditDiff?.additionalProperties === false, 'audit diff entries must be closed objects')
equal(propertyNames(auditDiff), ['from', 'to'], 'audit diff entry fields drifted')

// Audit list is bounded-paginated; export is a bounded NDJSON stream.
const auditPage = schema(spec, 'WorkspaceAuditPage')
for (const part of ['data', 'links', 'meta']) {
  invariant(part in auditPage.properties, `audit page must expose ${part}`)
}
const exportOp = spec.paths?.['/workspaces/{workspace}/audit/export']?.get
invariant(exportOp, 'audit export operation is missing')
const exportLimit = (exportOp.parameters ?? []).find((p) => p?.name === 'limit')
invariant(exportLimit?.schema?.maximum === 1000, 'audit export limit must stay bounded')
invariant(
  Boolean(exportOp.responses?.['200']?.content?.['application/x-ndjson']),
  'audit export must be an NDJSON stream',
)

// Invitation creation is idempotent for an active pending duplicate (D5).
const inviteCreate = spec.paths?.['/workspaces/{workspace}/invitations']?.post
invariant(inviteCreate?.responses?.['200'] && inviteCreate?.responses?.['201'], 'invite create must document both create and idempotent replay')
// Generation rotation: resend returns the same token-free view.
equal(
  spec.paths?.['/workspaces/{workspace}/invitations/{invitation}/resend']?.post?.responses?.['200']?.content?.['application/json']?.schema?.$ref,
  '#/components/schemas/Invitation',
  'resend response must use the token-free Invitation schema',
)
// Resource transfer is unsupported (D4): no transfer endpoint exists.
for (const path of Object.keys(spec.paths ?? {})) {
  invariant(!/transfer/i.test(path), `transfer endpoints are forbidden: ${path}`)
}
// SSE stays an HTTP surface outside OpenAPI paths (docs/sse.md), never an MCP tool.
for (const path of Object.keys(spec.paths ?? {})) {
  invariant(!/(sse|stream)/i.test(path), `SSE/stream endpoints must not enter the spec: ${path}`)
}

log('info', 'semantic_contract_passed', {
  operation_id: operation.operationId,
  capability_count: capabilityIds.enum.length,
  bounded_participants: preflight.properties.participants.maxItems,
  workspace_operations: managementOps.length + recipientOps.length,
  resource_operations_with_selector: resourceOps.length,
  audit_allowlist_fields: propertyNames(auditEvent).length,
})
