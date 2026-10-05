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
// D3 account deletion is self-service, password confirmed and guarded by
// last-admin/personal-workspace lifecycle policy. It never accepts a selector.
const deleteAccount = spec.paths?.['/profile']?.delete
invariant(deleteAccount?.operationId === 'deleteAccount', 'guarded DELETE /profile is required')
invariant(deleteAccount['x-required-ability'] === 'admin', 'account deletion requires the admin PAT ceiling')
equal(deleteAccount['x-required-roles'], [], 'account deletion must not require a selected workspace role')
invariant(deleteAccount['x-self-service'] === true, 'account deletion must be self-service')
invariant(!deleteAccount.parameters?.length, 'account deletion must not accept a workspace selector')
invariant(deleteAccount.requestBody?.required === true, 'account deletion requires password confirmation')
const deleteAccountBody = deleteAccount.requestBody?.content?.['application/json']?.schema
assertClosedObject(deleteAccountBody, 'DeleteAccountRequest')
equal(propertyNames(deleteAccountBody), ['current_password'], 'account deletion body must contain only current_password')
equal(deleteAccountBody.required, ['current_password'], 'account deletion password is required')
invariant(deleteAccountBody.properties.current_password.format === 'password', 'account deletion password must be marked sensitive')
for (const status of ['204', '401', '403', '409', '422', '429']) {
  invariant(deleteAccount.responses?.[status], `account deletion response ${status} is required`)
}
invariant(!deleteAccount.responses['204'].content, 'deleted accounts must return no response body')

const verifyEmail = spec.paths?.['/email/verify/{user}/{hash}']?.get
invariant(verifyEmail?.operationId === 'verifyEmail', 'verifyEmail operation is required')
for (const name of ['expires', 'signature']) {
  const parameter = verifyEmail.parameters?.find((value) => value.name === name)
  invariant(parameter?.in === 'query' && parameter.required === true, `verifyEmail must declare required ${name} query input`)
  if (name === 'expires') {
    invariant(parameter.schema.type === 'integer' && parameter.schema.minimum > 0, 'signed expiry must be a positive integer')
  } else {
    invariant(parameter.schema.type === 'string' && parameter.schema.minLength === 64 && parameter.schema.maxLength === 64,
      'signed verification signature must be exactly64 characters')
  }
}

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
equal(context.properties.recipe.enum, ['docker_compose', 'go', 'laravel', 'php', 'node'], 'recipe enum drifted')
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
      'workspace_forbidden',
      'unverified_email',
      'throttled',
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
  invariant(
    JSON.stringify(op['x-required-roles'] ?? null) === '[]',
    `${operationId}: recipient self-service must declare an empty role list`,
  )
  invariant(
    op['x-self-service'] === true,
    `${operationId}: recipient self-service marker (x-self-service) is required`,
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
  'sendEmailVerificationNotification', 'verifyEmail',
]) {
  const op = findOperationById(operationId)
  invariant(op, `user-level operation is missing: ${operationId}`)
  invariant(
    !(op.parameters ?? []).some((p) => p?.$ref === '#/components/parameters/WorkspaceSelector'),
    `${operationId} is user-level and must not take a workspace selector`,
  )
}

// Account self-service operations: no membership role applies — empty role
// list plus the explicit self-service marker (same shape as recipient ops).
// Email verification ops are access-elevating (D5 admission) and therefore
// additionally carry the admin PAT ceiling like recipient acceptance.
for (const operationId of [
  'logoutUser', 'getCurrentUser', 'updateProfile', 'updatePassword',
  'listTokens', 'createToken', 'getCurrentTokenAbilities', 'deleteToken',
  'sendEmailVerificationNotification', 'verifyEmail',
]) {
  const op = findOperationById(operationId)
  invariant(op, `account self-service operation is missing: ${operationId}`)
  invariant(
    JSON.stringify(op['x-required-roles'] ?? null) === '[]',
    `${operationId}: account self-service must declare an empty role list`,
  )
  invariant(
    op['x-self-service'] === true,
    `${operationId}: account self-service marker (x-self-service) is required`,
  )
}

for (const operationId of ['sendEmailVerificationNotification', 'verifyEmail']) {
  const op = findOperationById(operationId)
  invariant(op, `email verification operation is missing: ${operationId}`)
  invariant(
    op['x-required-ability'] === 'admin',
    `${operationId}: access-elevating self-service must carry the admin PAT ceiling`,
  )
}

// Raw ownership fields are forbidden in every request body of the spec
// (mass assignment / transfer rejection, D4). The scan resolves $refs and
// composition branches, so a named request schema cannot reopen the surface.
const forbiddenBodyFields = ['workspace_id', 'personal_owner_user_id']

function resolveSchemaRef(node, depth = 0) {
  if (!node || typeof node !== 'object' || depth > 8) return node
  const ref = node.$ref
  if (typeof ref !== 'string' || !ref.startsWith('#/components/schemas/')) return node
  return resolveSchemaRef(spec.components?.schemas?.[ref.slice('#/components/schemas/'.length)], depth + 1)
}

function assertClosedRequestSchema(node, label, depth = 0) {
  const resolved = resolveSchemaRef(node, depth)
  invariant(resolved && typeof resolved === 'object', `${label}: request schema must resolve`)
  if (resolved.additionalProperties === false) return
  const combinators = ['oneOf', 'anyOf'].filter((kw) => Array.isArray(resolved[kw]))
  if (combinators.length === 1) {
    for (const branch of resolved[combinators[0]]) {
      assertClosedRequestSchema(branch, label, depth + 1)
    }
    return
  }
  invariant(false, `${label}: request body must reject unknown fields (additionalProperties: false)`)
}

function collectForbiddenFields(node, depth = 0) {
  if (depth > 4) return []
  const resolved = resolveSchemaRef(node, depth)
  if (!resolved || typeof resolved !== 'object') return []
  const found = []
  for (const kw of ['oneOf', 'anyOf', 'allOf']) {
    if (Array.isArray(resolved[kw])) {
      for (const branch of resolved[kw]) found.push(...collectForbiddenFields(branch, depth + 1))
    }
  }
  for (const [field, prop] of Object.entries(resolved.properties ?? {})) {
    if (forbiddenBodyFields.includes(field)) found.push(field)
    found.push(...collectForbiddenFields(prop, depth + 1))
  }
  return found
}

let closedRequestBodies = 0
for (const [path, methods] of Object.entries(spec.paths ?? {})) {
  for (const [method, op] of Object.entries(methods)) {
    const bodySchema = op?.requestBody?.content?.['application/json']?.schema
    if (!bodySchema) continue
    closedRequestBodies += 1
    assertClosedRequestSchema(bodySchema, `${method} ${path}`)
    const forbidden = [...new Set(collectForbiddenFields(bodySchema))]
    invariant(
      forbidden.length === 0,
      `${method} ${path}: raw ownership fields in request body are forbidden: ${forbidden.join(', ')}`,
    )
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
// Audit diff is a CLOSED domain-field allowlist: keys come from a fixed
// enum-like property set, entry shape stays from/to, and event metadata
// (event id, retained_until) is event-level — never diff keys.
const auditDiff = auditEvent.properties?.diff
invariant(auditDiff?.additionalProperties === false, 'audit diff must be a closed allowlist (additionalProperties: false)')
equal(
  propertyNames(auditDiff),
  ['build_server_id', 'expires_at', 'name', 'role', 'server_id', 'status'],
  'audit diff field allowlist drifted',
)
const auditDiffEntry = schema(spec, 'WorkspaceAuditDiffEntry')
assertClosedObject(auditDiffEntry, 'WorkspaceAuditDiffEntry')
equal(propertyNames(auditDiffEntry), ['from', 'to'], 'audit diff entry fields drifted')
for (const field of propertyNames(auditDiff)) {
  invariant(
    auditDiff.properties?.[field]?.$ref === '#/components/schemas/WorkspaceAuditDiffEntry',
    `audit diff field ${field} must use the closed entry schema`,
  )
}
for (const forbidden of ['email', 'token', 'hash', 'url']) {
  invariant(!(forbidden in (auditDiff.properties ?? {})), `audit diff exposes forbidden field: ${forbidden}`)
}
// Event metadata must be explicit event-level fields, not diff entries.
equal(
  [...(auditEvent.required ?? [])].sort(),
  ['action', 'actor_type', 'id', 'occurred_at', 'retained_until', 'workspace_id'],
  'audit event metadata (event id, retained_until) must be required event-level fields',
)

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

// ---------------------------------------------------------------------------
// Review hardening: role matrix on every authenticated operation, closed
// request schemas, one-time invitation token, public user identifiers.
// ---------------------------------------------------------------------------

// F1: every authenticated operation carries the D2 role matrix. The only
// exempt surface is the public signed-payload/no-auth set (no authenticated
// actor to authorize).
const publicOperationIds = []
let authenticatedOperationCount = 0
for (const [path, methods] of Object.entries(spec.paths ?? {})) {
  for (const [method, op] of Object.entries(methods)) {
    if (!op?.operationId) continue
    const security = op.security ?? spec.security ?? []
    if (security.length === 0) {
      publicOperationIds.push(op.operationId)
      continue
    }
    authenticatedOperationCount += 1
    invariant(
      Array.isArray(op['x-required-roles']),
      `${op.operationId}: x-required-roles (D2 matrix) is required on every authenticated operation`,
    )
  }
}
equal(
  publicOperationIds.sort(),
  [
    'getMeta',
    'loginUser',
    'receiveDeployWebhookGet',
    'receiveDeployWebhookPost',
    'receiveGithubWebhook',
    'receiveGitlabWebhook',
    'registerUser',
  ],
  'public (unauthenticated) operation set drifted',
)

// F1: the 41 legacy workspace-scoped resource operations carry the same D2
// matrix (read = viewer-safe; writes = Admin/DevOps; server create/delete =
// Admin-only; server visibility stops at DevOps because hosts are infra-,
// not viewer-safe).
const legacyRoleMatrix = {
  listProjects: ['admin', 'devops', 'viewer'],
  createProject: ['admin', 'devops'],
  validateProjectRepository: ['admin', 'devops'],
  getProject: ['admin', 'devops', 'viewer'],
  updateProject: ['admin', 'devops'],
  deleteProject: ['admin', 'devops'],
  getProjectDeployHook: ['admin', 'devops'],
  createProjectDeployHook: ['admin', 'devops'],
  upsertProjectWebhook: ['admin', 'devops'],
  upsertProjectWebhookPut: ['admin', 'devops'],
  listProjectWebhooks: ['admin', 'devops', 'viewer'],
  createProjectProviderWebhook: ['admin', 'devops'],
  updateProjectProviderWebhook: ['admin', 'devops'],
  deleteProjectProviderWebhook: ['admin', 'devops'],
  listProjectServers: ['admin', 'devops', 'viewer'],
  createProjectServerBinding: ['admin', 'devops'],
  updateProjectServerBinding: ['admin', 'devops'],
  deleteProjectServerBinding: ['admin', 'devops'],
  mutateProjectServerEnv: ['admin', 'devops'],
  updateProjectServerEnv: ['admin', 'devops'],
  listAvailableServers: ['admin', 'devops', 'viewer'],
  triggerProjectDeploy: ['admin', 'devops'],
  previewProjectDeploymentVariables: ['admin', 'devops'],
  listProjectDeployments: ['admin', 'devops', 'viewer'],
  getProjectDeployment: ['admin', 'devops', 'viewer'],
  cancelProjectDeployment: ['admin', 'devops'],
  listServers: ['admin', 'devops'],
  createServer: ['admin'],
  getServer: ['admin', 'devops'],
  updateServer: ['admin', 'devops'],
  deleteServer: ['admin'],
  checkServerCapabilities: ['admin', 'devops'],
  getServerMetrics: ['admin', 'devops'],
  legacyTriggerDeploy: ['admin', 'devops'],
  listGlobalDeployments: ['admin', 'devops', 'viewer'],
  getGlobalDeployment: ['admin', 'devops', 'viewer'],
  retryDeployment: ['admin', 'devops'],
  rollbackDeployment: ['admin', 'devops'],
  restoreDeploymentBackup: ['admin', 'devops'],
  listProjectReleases: ['admin', 'devops', 'viewer'],
  activateProjectRelease: ['admin', 'devops'],
}
invariant(
  Object.keys(legacyRoleMatrix).length === resourceOps.length,
  'legacy role matrix must cover exactly the workspace-scoped resource operations',
)
for (const [operationId, roles] of Object.entries(legacyRoleMatrix)) {
  const op = findOperationById(operationId)
  invariant(op, `legacy operation is missing: ${operationId}`)
  invariant(
    JSON.stringify([...(op['x-required-roles'] ?? [])].sort()) === JSON.stringify([...roles].sort()),
    `${operationId}: legacy D2 role matrix drifted (expected ${roles.join('/')})`,
  )
}

// F1: updateServer is role-gated with a field-level metadata allowlist for
// DevOps; credential/connection fields stay Admin-only, buckets partition
// the closed request body, and denial is documented as 403.
const updateServerOp = findOperationById('updateServer')
invariant(updateServerOp, 'updateServer operation is missing')
equal(
  [...(updateServerOp['x-required-roles'] ?? [])].sort(),
  ['admin', 'devops'],
  'updateServer role matrix drifted',
)
const updateServerFieldRoles = updateServerOp['x-field-roles']
invariant(updateServerFieldRoles && typeof updateServerFieldRoles === 'object', 'updateServer must declare the x-field-roles allowlist')
const devopsFields = updateServerFieldRoles.devops ?? []
const adminOnlyFields = updateServerFieldRoles.admin ?? []
equal(
  [...devopsFields].sort(),
  ['http_group', 'http_user', 'name'],
  'DevOps server metadata allowlist drifted',
)
for (const field of ['host', 'port', 'user', 'server_type', 'auth_type', 'ssh_key_path', 'ssh_key_content', 'password']) {
  invariant(adminOnlyFields.includes(field), `credential/connection field ${field} must be admin-only`)
  invariant(!devopsFields.includes(field), `DevOps allowlist must not contain credential field ${field}`)
}
const updateServerBody = resolveSchemaRef(updateServerOp.requestBody?.content?.['application/json']?.schema)
const updateServerBodyFields = Object.keys(updateServerBody?.properties ?? {})
invariant(updateServerBodyFields.length > 0, 'updateServer request body fields missing')
for (const field of updateServerBodyFields) {
  invariant(
    devopsFields.includes(field) || adminOnlyFields.includes(field),
    `updateServer field ${field} is not covered by the field-roles allowlist`,
  )
}
invariant(devopsFields.every((f) => !adminOnlyFields.includes(f)), 'updateServer field-roles buckets must be disjoint')
invariant(
  updateServerOp.responses?.['403'] && updateServerOp.responses?.['422'],
  'updateServer must document role denial (403) and validation (422)',
)

// F2: accept/decline require the one-time invitation token (server-side
// digest check against the current generation) on top of the InvitationId.
const invitationResolveRequest = schema(spec, 'InvitationResolveRequest')
assertClosedObject(invitationResolveRequest, 'InvitationResolveRequest')
equal(propertyNames(invitationResolveRequest), ['token'], 'invitation resolve request drifted')
equal([...(invitationResolveRequest.required ?? [])].sort(), ['token'], 'one-time token must be required')
const invitationToken = invitationResolveRequest.properties?.token
invariant(invitationToken?.type === 'string', 'invitation token must be a string')
invariant((invitationToken?.minLength ?? 0) >= 16, 'invitation token must have a lower bound')
invariant((invitationToken?.maxLength ?? Infinity) <= 256, 'invitation token must have an upper bound')
for (const [operationId, path] of [
  ['acceptInvitation', '/invitations/{invitation}/accept'],
  ['declineInvitation', '/invitations/{invitation}/decline'],
]) {
  const op = spec.paths?.[path]?.post
  invariant(op, `recipient operation is missing: ${path}`)
  invariant(op.requestBody?.required === true, `${operationId}: one-time token body is required`)
  invariant(
    op.requestBody?.content?.['application/json']?.schema?.$ref === '#/components/schemas/InvitationResolveRequest',
    `${operationId}: token body schema ref drifted`,
  )
  invariant(op.responses?.['409'], `${operationId}: selector-conflict 409 is missing`)
  invariant(op.responses?.['422'], `${operationId}: body validation 422 is missing`)
}

// F6: user/actor identities are stable public ULIDs — numeric user IDs never
// leave the API (WorkspaceMember.user_id, WorkspaceAuditEvent.actor_id).
const memberSchema = schema(spec, 'WorkspaceMember')
invariant(memberSchema.properties?.user_id?.type === 'string', 'WorkspaceMember.user_id must be a public ULID string, not a numeric id')
invariant(memberSchema.properties?.user_id?.pattern === ULID_PATTERN, 'WorkspaceMember.user_id must use the canonical ULID pattern')
const auditActorId = auditEvent.properties?.actor_id
invariant(auditActorId?.type === 'string' && auditActorId?.nullable === true, 'WorkspaceAuditEvent.actor_id must be a nullable public ULID string')
invariant(auditActorId?.pattern === ULID_PATTERN, 'WorkspaceAuditEvent.actor_id must use the canonical ULID pattern')

// F5: unified precedence — PAT-ceiling 403 on role-open operations and
// structural selector-conflict 409 on every path-selector operation.
equal(
  spec.paths?.['/workspaces']?.get?.responses?.['403']?.content?.['application/json']?.schema?.$ref,
  '#/components/schemas/WorkspaceError',
  'listWorkspaces PAT ceiling must surface the safe 403 envelope',
)
equal(
  spec.paths?.['/workspaces/{workspace}/leave']?.post?.responses?.['403']?.content?.['application/json']?.schema?.$ref,
  '#/components/schemas/WorkspaceError',
  'leaveWorkspace PAT ceiling must surface the safe 403 envelope',
)
for (const path of [
  '/workspaces/{workspace}',
  '/workspaces/{workspace}/capabilities',
  '/workspaces/{workspace}/members',
  '/workspaces/{workspace}/invitations',
  '/workspaces/{workspace}/audit',
  '/workspaces/{workspace}/audit/export',
]) {
  invariant(spec.paths?.[path]?.get?.responses?.['409'], `selector-conflict 409 is missing on ${path}`)
}
for (const op of [
  spec.paths?.['/workspaces/{workspace}']?.patch,
  spec.paths?.['/workspaces/{workspace}']?.delete,
  spec.paths?.['/workspaces/{workspace}/archive']?.post,
  spec.paths?.['/workspaces/{workspace}/restore']?.post,
  spec.paths?.['/workspaces/{workspace}/members/{member}']?.patch,
  spec.paths?.['/workspaces/{workspace}/members/{member}']?.delete,
  spec.paths?.['/workspaces/{workspace}/leave']?.post,
  spec.paths?.['/workspaces/{workspace}/invitations']?.post,
  spec.paths?.['/workspaces/{workspace}/invitations/{invitation}/resend']?.post,
  spec.paths?.['/workspaces/{workspace}/invitations/{invitation}/revoke']?.post,
]) {
  invariant(op?.responses?.['409'], `${op?.operationId ?? 'management operation'}: 409 state/conflict response is missing`)
}

// The shared hook upsert handler returns 201 on creation and 200 on update.
// All public aliases must describe both results with the same safe schema.
for (const [path, method] of [
  ['/projects/{project}/deploy-hook', 'post'],
  ['/projects/{project}/webhook', 'post'],
  ['/projects/{project}/webhook', 'put'],
]) {
  const op = spec.paths?.[path]?.[method]
  invariant(op?.responses?.['200'], `${op?.operationId}: existing hook 200 response is missing`)
  invariant(op?.responses?.['201'], `${op?.operationId}: new hook 201 response is missing`)
  equal(
    op.responses['201'].content?.['application/json']?.schema,
    op.responses['200'].content?.['application/json']?.schema,
    `${op.operationId}: creation and update must share WebhookSettings schema`,
  )
}

// Response contracts are distinct from request inputs. Collections must match
// the established paginator/provider-array wire format consumed by Web.
const projectListResponse = spec.paths['/projects'].get.responses['200'].content['application/json'].schema
invariant(projectListResponse.type === 'object', 'project list must use the documented paginated envelope')
equal([...projectListResponse.required].sort(), ['data', 'links', 'meta'], 'project pagination fields are required')
invariant(projectListResponse.properties.data.type === 'array', 'project pagination data must be an array')
equal(projectListResponse.properties.data.items, { $ref: '#/components/schemas/Project' }, 'project pagination item contract drifted')
for (const field of ['links', 'meta']) {
  invariant(projectListResponse.properties[field].type === 'object', `project pagination ${field} must be an object`)
}
const webhookListResponse = spec.paths['/projects/{project}/webhooks'].get.responses['200'].content['application/json'].schema
invariant(webhookListResponse.type === 'array', 'provider webhook list must be an array')
equal(webhookListResponse.items, { $ref: '#/components/schemas/WebhookSettings' }, 'webhook list item contract drifted')

// OAS 3.0 nullable does not override an allOf reference. A null-only branch
// preserves validation of every non-null value against the original reference.
function assertNullableResponseRef(value, name, referencedSchema, nullBranchType) {
  invariant(Array.isArray(value.oneOf) && value.oneOf.length === 2, `${name} must accept the unchanged reference or null`)
  equal(value.oneOf[0], { $ref: `#/components/schemas/${referencedSchema}` }, `${name} non-null validation must remain referenced`)
  equal(value.oneOf[1], { type: nullBranchType, nullable: true, not: { type: nullBranchType } }, `${name} fallback must accept only actual null`)
}
function assertNullableResponseEnum(value, name, allowedValues) {
  invariant(value.type === 'string' && value.nullable === true, `${name} must retain its explicit nullable string type`)
  equal(value.oneOf, [{ enum: allowedValues }, { type: 'string', nullable: true, not: { type: 'string' } }], `${name} must accept its closed values or actual null`)
}
const responseBinding = schema(spec, 'ServerBindingContract')
assertNullableResponseRef(responseBinding.properties.build_server, 'binding build_server', 'ServerSummary', 'object')
assertNullableResponseRef(responseBinding.properties.recipe_options, 'binding recipe_options', 'ServerBindingRecipeOptions', 'object')
const options = schema(spec, 'ServerBindingRecipeOptions')
assertClosedObject(options, 'ServerBindingRecipeOptions')
invariant(!options.anyOf && !options.oneOf, 'options must have one closed object shape')
const createBinding = spec.paths['/projects/{project}/servers'].post.requestBody.content['application/json'].schema
const updateBinding = schema(spec, 'UpdateProjectServerBindingRequest')
for (const [name, body] of [['create', createBinding], ['update', updateBinding]]) {
  assertNullableResponseRef(body.properties.recipe_options, `${name} recipe_options`, 'ServerBindingRecipeOptions', 'object')
  invariant(!body.properties.recipe_options_compatibility, 'compatibility diagnostics must not be writable')
}
equal(responseBinding.properties.recipe_options_compatibility, { $ref: '#/components/schemas/RecipeOptionsCompatibility' }, 'binding must expose compatibility diagnostics')
const compatibility = schema(spec, 'RecipeOptionsCompatibility')
const conflictOptions = schema(spec, 'ManagedEnvRevisionConflict').properties
assertNullableResponseRef(conflictOptions.recipe_options, 'conflict recipe_options', 'ServerBindingRecipeOptions', 'object')
equal(conflictOptions.recipe_options_compatibility, { $ref: '#/components/schemas/RecipeOptionsCompatibility' }, 'conflict must expose the same compatibility diagnostics')
assertClosedObject(compatibility, 'RecipeOptionsCompatibility')
equal(compatibility.required, ['status', 'issues', 'issues_truncated'], 'compatibility diagnostics must be complete')
invariant(compatibility.readOnly === true && compatibility.properties.issues.maxItems === 100, 'compatibility diagnostics must be read-only and bounded')
assertClosedObject(compatibility.properties.issues.items, 'compatibility issue')
equal(propertyNames(compatibility.properties.issues.items), ['code', 'field'], 'diagnostics must omit raw values')
for (const field of ['shared_dirs', 'shared_files', 'writable_dirs', 'upload_paths']) {
  equal(options.properties[field].items, { $ref: '#/components/schemas/RecipeRelativePath' }, `${field} must use the common path policy`)
  invariant(options.properties[field].type === 'array' && options.properties[field].maxItems === 100 && !options.properties[field].nullable, `${field} must remain bounded and non-nullable`)
}
for (const field of ['build_cmd', 'test_cmd', 'migrate_cmd', 'before_activate_cmd', 'after_activate_cmd', 'health_check_cmd']) {
  equal(options.properties[field], { $ref: '#/components/schemas/RecipeScript' }, `${field} must use the whole-script contract`)
}
const relativePath = schema(spec, 'RecipeRelativePath')
invariant(relativePath.minLength === 1 && relativePath.maxLength === 500, 'relative path bounds drifted')
const pathPattern = new RegExp(relativePath.pattern)
for (const value of ['.env', 'storage', 'public/uploads', 'bin/my-app']) invariant(pathPattern.test(value), 'safe literal path rejected')
for (const value of ['', '/', '../data', 'data/../x', 'data/./x', '-rf', 'a//b', 'a/', 'C:/data', 'a\\b', 'a b', '{{release_path}}', 'a;id']) invariant(!pathPattern.test(value), 'unsafe relative path admitted')
const script = schema(spec, 'RecipeScript')
invariant(script.type === 'string' && script.nullable === true && script.maxLength === 16384, 'script bounds/type drifted')
invariant(new RegExp(script.pattern).test('printf ok\nexit 1') && !new RegExp(script.pattern).test('echo\0bad'), 'whole multiline script / NUL policy drifted')
for (const field of ['before_symlink_cmd', 'stop_cmd', 'after_symlink_cmd', 'start_cmd', 'restart_cmd']) invariant(options.properties[field].deprecated === true, 'legacy aliases must remain explicitly deprecated')
for (const field of ['compose_file', 'backup_policy', 'backup_type', 'backup_retention_days', 'backup_database', 'backup_credentials_file', 'migration_policy', 'migration_down_command', 'critical_changed_files']) invariant(options.properties[field], 'known recipe-specific option removed')
const lifecycle = schema(spec, 'DeploymentExecutionPlan').properties.lifecycle.properties
for (const field of ['has_before_activate_cmd', 'has_after_activate_cmd', 'has_health_check_cmd', 'shared_dirs_count', 'shared_files_count', 'writable_dirs_count']) invariant(lifecycle[field], 'v3 safe lifecycle field missing')
for (const field of ['build_cmd', 'test_cmd', 'migrate_cmd', 'before_activate_cmd', 'after_activate_cmd', 'health_check_cmd']) invariant(!lifecycle[field], 'script leaked into public lifecycle')
const responseDeployment = schema(spec, 'DeploymentSummary')
assertNullableResponseRef(responseDeployment.properties.project, 'deployment project', 'DeploymentProjectSummary', 'object')
assertNullableResponseRef(responseDeployment.properties.server, 'deployment server', 'ServerSummary', 'object')
const responseBackup = schema(spec, 'PreDeployBackupExecutionSummary')
assertNullableResponseRef(responseBackup.properties.type, 'backup type', 'PreDeployBackupType', 'string')
invariant(responseBackup.required.includes('credentials_file_configured'), 'safe backup configuration flag must remain required')
invariant(responseBackup.properties.credentials_file_configured.type === 'boolean', 'safe backup configuration flag must remain boolean')
for (const field of ['provider', 'external_id', 'started_at']) {
  const value = responseDeployment.properties[field]
  invariant(value.type === 'string' && value.nullable === true, `queued deployment ${field} must accept null without changing its non-null type`)
}
invariant(responseDeployment.properties.started_at.format === 'date-time', 'started_at must preserve date-time validation')
assertNullableResponseEnum(schema(spec, 'DockerComposeMigrationTiming'), 'migration timing', ['before_up', 'after_up'])
assertNullableResponseEnum(responseDeployment.properties.initiator_type, 'initiator type', ['manual_ui', 'pat', 'webhook', 'schedule', 'retry', 'rollback', 'restore'])
assertNullableResponseEnum(schema(spec, 'WorkspaceAuditEvent').properties.resource_type, 'audit resource type', ['workspace', 'membership', 'invitation', 'project', 'server', 'binding', 'deployment'])
const releaseDisabledReason = spec.paths['/projects/{project}/releases'].get.responses['200'].content['application/json'].schema.properties.data.items.properties.disabled_reason
assertNullableResponseEnum(releaseDisabledReason, 'release disabled reason', ['deployment_not_successful', 'deploy_path_invalid', 'inventory_unavailable', 'inventory_timeout', 'inventory_invalid', 'current_release_unknown', 'current_release_unrecorded', 'release_missing', 'already_current', 'rollback_unsupported', 'release_compatibility_unknown', 'release_environment_mismatch', 'release_configuration_mismatch'])

log('info', 'semantic_contract_passed', {
  operation_id: operation.operationId,
  capability_count: capabilityIds.enum.length,
  bounded_participants: preflight.properties.participants.maxItems,
  workspace_operations: managementOps.length + recipientOps.length,
  resource_operations_with_selector: resourceOps.length,
  authenticated_operations_role_gated: authenticatedOperationCount,
  closed_request_bodies: closedRequestBodies,
  audit_allowlist_fields: propertyNames(auditEvent).length,
  audit_diff_allowlist_fields: propertyNames(auditDiff).length,
})
