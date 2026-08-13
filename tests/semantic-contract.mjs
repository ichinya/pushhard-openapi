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
  ['git', 'docker_engine', 'docker_compose_v2', 'rsync'],
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
invariant(probe.properties.available.maxItems === 4, 'probe inventory must be bounded')
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
equal(
  operation.parameters,
  [{ $ref: '#/components/parameters/ServerId' }],
  'operation must use the canonical required ServerId path parameter',
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

log('info', 'semantic_contract_passed', {
  operation_id: operation.operationId,
  capability_count: capabilityIds.enum.length,
  bounded_participants: preflight.properties.participants.maxItems,
})
