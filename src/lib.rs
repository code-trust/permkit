//! Generic permission primitives.
//!
//! This crate intentionally avoids application-specific authentication,
//! database, tenant, account, or HTTP error types. Applications provide a
//! request-specific context type and implement [`HasPermission`] for their own
//! permission expressions.

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;

#[cfg(feature = "macros")]
pub use auth_macros::permissions;
pub use inventory;
use itertools::Itertools as _;
#[cfg(feature = "macros")]
pub use permission_macros::Permission;
pub use serde;
#[cfg(feature = "utoipa")]
pub use utoipa;

/// Static metadata about a single permission variant.
///
/// Every `#[derive(Permission)]` enum emits one `inventory::submit!` per variant
/// pointing at this type, so the full set of permissions linked into the final
/// binary can be discovered via [`all_permissions`].
#[derive(Debug, Clone)]
pub struct PermissionEntry {
    pub name: Cow<'static, str>,
    pub enum_name: &'static str,
    pub roles: &'static [&'static str],
}

inventory::collect!(PermissionEntry);

/// Iterate over every registered permission.
///
/// Entries are yielded in linker order, which is not guaranteed stable. Sort the
/// result if deterministic output matters. For every `Domain.Action` permission,
/// this also adds a synthetic `Domain.*` wildcard entry without role grants.
pub fn all_permissions() -> Vec<PermissionEntry> {
    let all: Vec<PermissionEntry> = inventory::iter::<PermissionEntry>().cloned().collect();

    let wildcards: Vec<PermissionEntry> = all
        .iter()
        .filter_map(|entry| {
            let (prefix, _) = entry.name.split_once('.')?;
            Some(PermissionEntry {
                name: Cow::Owned(format!("{prefix}.*")),
                enum_name: entry.enum_name,
                roles: &[],
            })
        })
        .unique_by(|entry| entry.name.clone())
        .collect();

    all.into_iter().chain(wildcards).collect()
}

pub fn all_permission_names() -> Vec<Cow<'static, str>> {
    all_permissions()
        .into_iter()
        .map(|entry| entry.name)
        .sorted()
        .dedup()
        .collect()
}

/// Schema marker for a permission name string.
///
/// Use this with Utoipa field overrides such as
/// `#[schema(value_type = Vec<PermissionName>)]`.
#[cfg(feature = "utoipa")]
pub enum PermissionName {}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for PermissionName {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        let names = all_permission_names();

        utoipa::openapi::RefOr::T(utoipa::openapi::schema::Schema::Object(
            utoipa::openapi::schema::ObjectBuilder::new()
                .schema_type(utoipa::openapi::schema::SchemaType::Type(
                    utoipa::openapi::schema::Type::String,
                ))
                .enum_values(Some(names))
                .description(Some("Identifier of permissions."))
                .build(),
        ))
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for PermissionName {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("PermissionName")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGrant {
    pub scope: String,
    pub pattern: String,
    pub effect: PermissionEffect,
}

#[derive(Debug, Clone, Default)]
pub struct EffectivePermissions {
    scopes: HashMap<String, Vec<ScopedPermission>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopedPermission {
    pattern: String,
    effect: PermissionEffect,
}

impl EffectivePermissions {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_grants(grants: impl IntoIterator<Item = PermissionGrant>) -> Self {
        let scopes = grants
            .into_iter()
            .map(|grant| {
                (
                    grant.scope,
                    ScopedPermission {
                        pattern: grant.pattern,
                        effect: grant.effect,
                    },
                )
            })
            .into_group_map();

        Self { scopes }
    }

    pub fn allows(&self, permission_key: &str) -> bool {
        self.scopes
            .values()
            .any(|grants| allows_in_scope(grants, permission_key))
    }
}

fn allows_in_scope(grants: &[ScopedPermission], permission_key: &str) -> bool {
    let denied = grants.iter().any(|permission| {
        permission.effect == PermissionEffect::Deny
            && permission_pattern_matches(&permission.pattern, permission_key)
    });
    if denied {
        return false;
    }

    grants.iter().any(|permission| {
        permission.effect == PermissionEffect::Allow
            && permission_pattern_matches(&permission.pattern, permission_key)
    })
}

pub fn permission_pattern_matches(pattern: &str, concrete: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let Some((module, action)) = concrete.split_once('.') else {
        return false;
    };

    match pattern.split_once('.') {
        None => false,
        Some(("*", a)) => action == a,
        Some((m, "*")) => module == m,
        Some((m, a)) => m == module && a == action,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionCheckError {
    Forbidden,
}

pub trait PermissionDenied {
    fn permission_denied() -> Self;
}

impl PermissionDenied for PermissionCheckError {
    fn permission_denied() -> Self {
        Self::Forbidden
    }
}

pub struct And<L, R> {
    left: L,
    right: R,
}

pub struct Or<L, R> {
    left: L,
    right: R,
}

impl<Context, L, R> HasPermission<Context> for And<L, R>
where
    Context: Sync,
    L: HasPermission<Context>,
    R: HasPermission<Context, Error = L::Error>,
{
    type Error = L::Error;

    async fn has_permission(&self, context: &Context) -> Result<bool, Self::Error> {
        Ok(self.left.has_permission(context).await? && self.right.has_permission(context).await?)
    }
}

impl<Context, L, R> HasPermission<Context> for Or<L, R>
where
    Context: Sync,
    L: HasPermission<Context>,
    R: HasPermission<Context, Error = L::Error>,
{
    type Error = L::Error;

    async fn has_permission(&self, context: &Context) -> Result<bool, Self::Error> {
        Ok(self.left.has_permission(context).await? || self.right.has_permission(context).await?)
    }
}

pub trait HasPermission<Context>: Send + Sync {
    type Error;

    fn has_permission(
        &self,
        context: &Context,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    fn and<R>(self, right: R) -> And<Self, R>
    where
        Self: Sized,
        R: HasPermission<Context, Error = Self::Error>,
    {
        And { left: self, right }
    }

    fn or<R>(self, right: R) -> Or<Self, R>
    where
        Self: Sized,
        R: HasPermission<Context, Error = Self::Error>,
    {
        Or { left: self, right }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EffectivePermissions,
        PermissionEffect,
        PermissionGrant,
        permission_pattern_matches,
    };

    #[test]
    fn matches_wildcard_patterns() {
        assert!(permission_pattern_matches("*", "Companies.List"));
        assert!(permission_pattern_matches("Companies.*", "Companies.List"));
        assert!(permission_pattern_matches("*.List", "Companies.List"));
        assert!(permission_pattern_matches(
            "Companies.List",
            "Companies.List"
        ));
        assert!(!permission_pattern_matches("Products.*", "Companies.List"));
    }

    #[test]
    fn deny_wins_inside_scope() {
        let permissions = EffectivePermissions::from_grants([
            PermissionGrant {
                scope: "role".to_owned(),
                pattern: "Companies.*".to_owned(),
                effect: PermissionEffect::Allow,
            },
            PermissionGrant {
                scope: "role".to_owned(),
                pattern: "Companies.Delete".to_owned(),
                effect: PermissionEffect::Deny,
            },
        ]);

        assert!(permissions.allows("Companies.List"));
        assert!(!permissions.allows("Companies.Delete"));
    }
}
