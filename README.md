# PushHard OpenAPI Specification
Single source of truth for api (PHP), web (Vue), and MCP server.

Spec-first contract: changes to the API must update this spec FIRST.

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
