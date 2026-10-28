# permkit

Generic Rust permission primitives, a permission enum derive macro, and an
async guard macro.

`permkit` stays out of application concerns: authentication, tenancy, storage,
request context, and HTTP errors remain your responsibility.

## Install

```toml
[dependencies]
permkit = "0.4"
```

Enable OpenAPI schema support with:

```toml
[dependencies]
permkit = { version = "0.4", features = ["utoipa"] }
```

## Define Permissions

Derive `Permission` on an enum and give every variant a stable name.
Enum-level roles are defaults; variant-level roles override them.

```rust
use permkit::Permission;

#[derive(Permission)]
#[permission(roles = ["owner", "operator"])]
enum CompanyPermission {
    #[permission(name = "Companies.List")]
    List,

    #[permission(name = "Companies.Delete", roles = ["owner"])]
    Delete,
}
```

Names have at most one `.` or `:` separator and no `*`.

The derive macro provides:

- `AsRef<str>` for the permission name.
- The `Permission` trait, whose `resource()` returns the variant's resource.
- `serde::Serialize` as a string.
- `inventory` registration through `PermissionEntry`, including its resource
  kind.
- `utoipa` schema implementations when the `utoipa` feature is enabled.

### Resource Permissions

A variant may have one field: the resource the permission is checked against,
such as the company in a request path. Mark it with
`#[permission(resource = "kind")]`; its `Display` output is the resource id.

```rust
use permkit::Permission;

#[derive(Permission)]
#[permission(roles = ["companyOwner"])]
enum CompanyUserPermission {
    #[permission(name = "CompanyUser.ListCompanies")]
    ListCompanies,

    #[permission(name = "CompanyUser.ListUsers")]
    ListUsers(#[permission(resource = "company")] CompanyId),
}
```

A passing check only proves access to that resource. Scope the data you load by
the same id.

## Check Permissions

`EffectivePermissions` evaluates in-memory grants. A grant has a scope, a
pattern, an effect, and an optional resource. Deny wins within a scope; the
check passes when any scope allows.

```rust
use permkit::{
    EffectivePermissions,
    PermissionEffect,
    PermissionGrant,
};

let permissions = EffectivePermissions::from_grants([
    PermissionGrant::try_new("role:operator", "Companies.*", PermissionEffect::Allow, None)?,
    PermissionGrant::try_new("role:operator", "Companies.Delete", PermissionEffect::Deny, None)?,
]);

assert!(permissions.allows("Companies.List", None));
assert!(!permissions.allows("Companies.Delete", None));
```

Patterns are a name, `Prefix.*`, `*.Suffix` (or with `:`), or `*`. Checks take concrete names
only; a wildcard name is never allowed.

A grant without a resource applies to every resource; one on a resource applies
only to it, and only to permissions of its kind, so `*` on a company never
grants a permission without a resource. `PermissionGrant::try_new` rejects a
grant that could never apply:

- A deny must match at least one registered permission, so a misspelled deny
  isn't silently ignored.
- On a resource, a deny must match only permissions of the resource's kind.
- On a resource, an allow must match at least one permission of that kind.

Validation reads the registered permissions, so the permission enums must be
linked into the binary that loads grants. Resource ids are compared exactly, so
store them as their `Display` output.

- `allows(name, resource)` passes when, in some scope, a grant without a
  resource or on `resource` allows the name and none denies it. `resource` must
  be of the permission's kind, and `None` when it has none; otherwise the check
  fails. Unregistered names take no resource.
- `allows_permission(&permission)` checks a permission value on its resource.
- `resource_access(name, kind)` returns the resources of `kind` the name is
  allowed on: `ResourceAccess::All`, `AllExcept(ids)`, or `Only(ids)`. A `kind`
  other than the permission's gets no access. Use it to list, for example, the
  companies an account can list users in; `is_empty()` tells whether the name is
  allowed on any resource.

A check covers one resource. For nested resources, such as a customer in a
company, load the child and check the permission on the parent it belongs to.

To connect permissions to your app, implement `HasPermission<Context>` for your
permission enum or expression type.

```rust
use permkit::{
    EffectivePermissions,
    HasPermission,
    PermissionCheckError,
};

struct Context {
    permissions: EffectivePermissions,
}

impl HasPermission<Context> for CompanyPermission {
    type Error = PermissionCheckError;

    async fn has_permission(&self, context: &Context) -> Result<bool, Self::Error> {
        Ok(context.permissions.allows_permission(self))
    }
}
```

Permission checks can be composed with `and` and `or`.

```rust
use permkit::HasPermission;

let permission = CompanyPermission::List.or(CompanyPermission::Delete);
```

## Guard Async Functions

Use `#[permissions(...)]` to run checks before an async function body. Pass the
request context with `context = ...`.

```rust
use permkit::permissions;

#[permissions(CompanyPermission::List, context = context)]
async fn list_companies(context: Context) -> Result<(), PermissionCheckError> {
    Ok(())
}
```

Denied requests return `PermissionDenied::permission_denied()` by default. Use
`error = ...` to return an application-specific error.

```rust
#[permissions(
    CompanyPermission::Delete,
    context = context,
    error = PermissionCheckError::Forbidden
)]
async fn delete_company(context: Context) -> Result<(), PermissionCheckError> {
    Ok(())
}
```

If `context = ...` is omitted, the macro looks for or inserts a
`crate::database::Database` argument named `db`.

## OpenAPI Permission Names

With the `utoipa` feature, use `PermissionName` when a DTO contains arbitrary
permission name strings and the schema should expose collected permission names
as enum values.

```rust
use permkit::PermissionName;
use utoipa::ToSchema;

#[derive(ToSchema)]
struct PermissionsResponse {
    #[schema(value_type = Vec<PermissionName>)]
    permissions: Vec<String>,
}
```
