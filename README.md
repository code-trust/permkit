# permkit

Generic Rust permission primitives, a permission enum derive macro, and an
async guard macro.

`permkit` stays out of application concerns: authentication, tenancy, storage,
request context, and HTTP errors remain your responsibility.

## Install

```toml
[dependencies]
permkit = "0.1"
```

Enable OpenAPI schema support with:

```toml
[dependencies]
permkit = { version = "0.1", features = ["utoipa"] }
```

## Define Permissions

Derive `Permission` on a unit-only enum and give every variant a stable name.
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

The derive macro provides:

- `AsRef<str>` for the permission name.
- `serde::Serialize` as a string.
- `inventory` registration through `PermissionEntry`.
- `utoipa` schema implementations when the `utoipa` feature is enabled.

## Check Permissions

`EffectivePermissions` evaluates in-memory grants. Grants have a scope, pattern,
and effect. Deny wins over allow within the same scope.

```rust
use permkit::{
    EffectivePermissions,
    PermissionEffect,
    PermissionGrant,
};

let permissions = EffectivePermissions::from_grants([
    PermissionGrant {
        scope: "role:operator".to_owned(),
        pattern: "Companies.*".to_owned(),
        effect: PermissionEffect::Allow,
    },
    PermissionGrant {
        scope: "role:operator".to_owned(),
        pattern: "Companies.Delete".to_owned(),
        effect: PermissionEffect::Deny,
    },
]);

assert!(permissions.allows("Companies.List"));
assert!(!permissions.allows("Companies.Delete"));
```

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
        Ok(context.permissions.allows(self.as_ref()))
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
