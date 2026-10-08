# PushHard OpenAPI Specification
Single source of truth for api (PHP), web (Vue), and MCP server.

Spec-first contract: changes to the API must update this spec FIRST.

`POST /projects/{project}/servers/{binding_id}/commands/validate`
(`validateProjectServerCommands`) describes a nonpersisting preview for an existing
binding, limited to 10 requests per minute. The selected workspace must allow
resource editing (Admin or DevOps) and the PAT must allow `admin`; wildcard PATs
still respect workspace roles. Session calls use the same role gate. Authorization
and binding ownership precede SSH/source probes; missing and inaccessible bindings
share a safe 404.

The optional closed draft accepts only `recipe`, `recipe_options`,
`build_server_id`, `source_ref`, `deploy_path`, and `php_path`. Omission uses current
configured values. An options object replaces the whole object, without merging;
`{}` uses release defaults and `null` resets release options. Compose still
requires `compose_file`. Null clears the build server or PHP override; null source
ref uses the project's branch. Recipe and deployment path cannot be null. Existing
recipe applicability, field bounds and binding validation remain authoritative.
Preview executes no submitted scripts, saves no draft or inventory, creates no
deployment/audit, and grants no deployment permission.

`CommandValidationReport` is a closed version-1 report with `ready`, `warning`, or
`blocked` aggregate status, a timestamp, a 64-hex input signature, nullable exact
40-hex source revision, and at most 100 checks. Each check identifies an existing
command field and nullable Compose list index, phase, actual execution role
(`target`, `build`, `container`, or `unknown`), kind, status and closed code.
Static Russian summaries/hints are limited to 500/1000 characters; nullable
version tokens are validated and limited to 64 characters. No scripts, arbitrary
binary names, argv, policy text, URLs, credentials or remote output are returned.
Sudo authentication is explicit (`not_required`, `required`, or `unverified`);
non-sudo checks use null. Policy listing permission and authentication readiness
are separate: an allowed listing does not prove noninteractive execution readiness.
Partial/unsupported context and exhausted budgets remain explicit diagnostics.
The signature establishes freshness only; runtime must recheck before commands.

Deployment `meta.command_validation` optionally exposes the same reconstructed
safe report or null, inherited by deployment detail; older absent/null metadata
remains compatible. It is independent of the five-code diagnosis below. Existing
binding `lifecycle_command_warnings` describes limited cached binary advice, which
can be empty for unsupported commands or unavailable inventory and historically
uses Node facts for npm/npx. It grants no command or deployment authorization.
The seven capability IDs and the recipe execution identity below remain unchanged.

Semantic tests freeze the request/auth/nullable/closed-result shape. Their exported
`commandValidationFixtures` are independent literal positive/hostile cases for a
JSON Schema validator against a freshly bundled document; they do not assert
runtime authorization, storage purity, SSH safety or hosted acceptance.

Deployment responses expose optional nullable `error_code`, `error_summary` (up to
500 characters), and `error_hint` (up to 1000 characters). Codes are limited to
`missing_rsync`, `disk_full`, `ssh_authentication`, `repository_access`, and
`deployment_locked` (up to 64 characters), plus actual `null`. Known failed causes
use a static Russian catalog; unknown, ambiguous, and nonfailed deployments return
three nulls. Consumers must also accept older responses that omit these fields.
Hints are operator advice; lock advice asks operators to check active deployments
and wait before considering manual unlock. No recovery commands are executed.

`DeploymentDetail`, including MCP `getGlobalDeployment`, inherits the summary
contract; server recent deployments use the same fields in a separate projection.
Summaries and recent entries use valid persisted diagnoses without reading logs.
Only authorized legacy detail may use a pure fallback from already loaded masked
error/log with a 65536-byte primary-output bound; uncertain cleanup provenance
returns null. Reads preserve storage and audit state. Raw `error_message` and
detail `log` remain available unchanged. Existing `meta` may be null; its optional
diagnosis namespace is reconstructed from closed version/code/role values without
internal fingerprints, stored free text, or reflected evidence.

This output-only schema change preserves the recipe execution contract identity
`b520965c3eb576a8a3b909baea83326d2fb4c418` and resolver version 2 for existing v3
queued jobs, release receipts, and measured Composer metadata. A new OpenAPI Git
revision does not change recipe, SSH, or PHAR policy.

All five deployment recipes use the closed `ServerBindingRecipeOptions` object.
OpenAPI defines types/bounds; the API validates applicability against the effective
recipe under the binding lock, including options-only PATCH requests.

| Recipe | Paths | Build / migration | Host |
| --- | --- | --- | --- |
| Laravel | storage/.env and writable storage/bootstrap/cache + extras | Native Composer plus optional build; tracked Artisan migrations | Target |
| PHP | .env + extras | Native Composer plus optional build/migration | Target |
| Node | .env + extras | Native npm install; optional build replaces guarded npm build | Target |
| Go | Extras; managed .env protected | Default go build; ordered uploads inherit [app] when empty | Build/test on selected build host; activation on target |
| Docker Compose | Volumes; nonempty shared/writable/upload lists rejected | Native build; custom build rejected; common migration exclusive with service mode | Existing build/target contexts |

Path extras are additive and deduplicated. Safe literal relative paths and runtime
symlink containment are required. Commands remain whole multiline scripts; Compose
command arrays run separately and stop at the first failure. Common activation hooks
surround symlink activation (release recipes) or compose up; health runs afterwards.
Laravel rejects a custom migration script. Nonempty upload overrides are Go-only.
Laravel/PHP/Node capability contexts use target role without build/transport selectors;
invalid selectors are rejected before SSH. Native runtime preflight remains authoritative.

On create, omitted/null options use release defaults. PATCH omission preserves raw
stored JSON, an object fully replaces it, `{}` uses release presets, and `null`
explicitly resets. Compose still requires `compose_file` and rejects null/empty options.
New writes reject unknown keys and invalid types/bounds instead of ignoring them.

Reads return schema-valid configured fields plus read-only
`recipe_options_compatibility`. Invalid legacy fields are excluded from the projection;
stored JSON, revision identity and legacy execution provenance remain unchanged.
Diagnostics contain field names/codes only. A metadata-only save must omit options
when repair is required. Explicit removal/re-entry/reset repairs the configuration;
sending a partial read projection as an unchanged full replacement would lose data.
Deprecated Go aliases retain legacy cwd; explicitly editing a canonical activation
hook changes that phase to the target release cwd. Differing active aliases conflict
on new writes; equal values are accepted. Empty options remain `{}`, never `[]`.

Execution plan v3 carries resolver/contract identity and safe counts/presence flags,
without script bodies. Changes after queue admission fail closed before rendering.
Existing v2 release receipts retain their exact comparison rules; pending v2 jobs
must be replanned before executing the new resolver semantics.
