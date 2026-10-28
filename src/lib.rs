//! Generic permission primitives.
//!
//! This crate intentionally avoids application-specific authentication,
//! database, tenant, account, or HTTP error types. Applications provide a
//! request-specific context type and implement [`HasPermission`] for their own
//! permission expressions.

use std::borrow::Cow;
use std::collections::{
    HashMap,
    HashSet,
};
use std::fmt::Display;
use std::future::Future;
use std::sync::OnceLock;

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
    pub resource: Option<&'static str>,
}

inventory::collect!(PermissionEntry);

struct PermissionKey {
    prefix: String,
    suffix: String,
    separator: char,
}

impl PermissionKey {
    fn parse(permission: &str) -> Option<Self> {
        permission
            .char_indices()
            .find(|(_, separator)| matches!(separator, '.' | ':'))
            .map(|(index, separator)| Self {
                prefix: permission[..index].to_owned(),
                suffix: permission[index + separator.len_utf8()..].to_owned(),
                separator,
            })
    }
}

/// Iterate over every registered permission.
///
/// Entries are yielded in linker order, which is not guaranteed stable. Sort the
/// result if deterministic output matters. For every two-part permission name,
/// this also adds a synthetic `<prefix><separator>*` wildcard entry without
/// role grants.
pub fn all_permissions() -> Vec<PermissionEntry> {
    let all: Vec<PermissionEntry> = inventory::iter::<PermissionEntry>().cloned().collect();

    let wildcards: Vec<PermissionEntry> = all
        .iter()
        .filter_map(|entry| {
            let parts = PermissionKey::parse(entry.name.as_ref())?;
            Some(PermissionEntry {
                name: Cow::Owned(format!("{}{}*", parts.prefix, parts.separator)),
                enum_name: entry.enum_name,
                roles: &[],
                resource: None,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidGrant {
    /// The pattern matches no registered permission.
    UnknownPermission,
    /// A matched permission takes another resource kind, or none.
    ResourceKindMismatch {
        permission: Cow<'static, str>,
        expected: Option<&'static str>,
    },
}

impl Display for InvalidGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPermission => write!(f, "grant pattern matches no registered permission"),
            Self::ResourceKindMismatch {
                permission,
                expected: Some(kind),
            } => write!(f, "{permission} is checked against a {kind} resource"),
            Self::ResourceKindMismatch {
                permission,
                expected: None,
            } => write!(f, "{permission} is checked without a resource"),
        }
    }
}

impl std::error::Error for InvalidGrant {}

fn validate_grant(
    pattern: &str,
    effect: PermissionEffect,
    resource: Option<&Resource>,
) -> Result<(), InvalidGrant> {
    let matched: Vec<&PermissionEntry> = inventory::iter::<PermissionEntry>()
        .filter(|entry| permission_pattern_matches(pattern, &entry.name))
        .collect();

    let Some(resource) = resource else {
        return match (effect, matched.is_empty()) {
            (PermissionEffect::Deny, true) => Err(InvalidGrant::UnknownPermission),
            _ => Ok(()),
        };
    };

    let on_kind = |entry: &&PermissionEntry| entry.resource == Some(resource.kind.as_ref());
    let mismatch = |entry: &PermissionEntry| InvalidGrant::ResourceKindMismatch {
        permission: entry.name.clone(),
        expected: entry.resource,
    };

    match (effect, matched.first()) {
        (_, None) => Err(InvalidGrant::UnknownPermission),
        (PermissionEffect::Allow, Some(first)) if !matched.iter().any(on_kind) => {
            Err(mismatch(first))
        }
        (PermissionEffect::Allow, Some(_)) => Ok(()),
        (PermissionEffect::Deny, Some(_)) => match matched.iter().find(|entry| !on_kind(entry)) {
            Some(entry) => Err(mismatch(entry)),
            None => Ok(()),
        },
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Resource {
    pub kind: Cow<'static, str>,
    pub id: String,
}

impl Resource {
    pub fn new(kind: impl Into<Cow<'static, str>>, id: impl Display) -> Self {
        Self {
            kind: kind.into(),
            id: id.to_string(),
        }
    }
}

/// Implemented by `#[derive(Permission)]`.
pub trait Permission: AsRef<str> {
    fn resource(&self) -> Option<Resource>;
}

/// Construct with [`PermissionGrant::try_new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGrant {
    scope: String,
    pattern: String,
    effect: PermissionEffect,
    resource: Option<Resource>,
}

impl PermissionGrant {
    /// `None` applies to every resource. A deny must match a registered
    /// permission. On a resource, a deny must match only permissions of its
    /// kind, an allow at least one.
    pub fn try_new(
        scope: impl Into<String>,
        pattern: impl Into<String>,
        effect: PermissionEffect,
        resource: Option<Resource>,
    ) -> Result<Self, InvalidGrant> {
        let pattern = pattern.into();
        validate_grant(&pattern, effect, resource.as_ref())?;
        Ok(Self {
            scope: scope.into(),
            pattern,
            effect,
            resource,
        })
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn effect(&self) -> PermissionEffect {
        self.effect
    }

    pub fn resource(&self) -> Option<&Resource> {
        self.resource.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceAccess {
    All,
    AllExcept(HashSet<String>),
    Only(HashSet<String>),
}

impl ResourceAccess {
    pub fn contains(&self, id: &str) -> bool {
        match self {
            Self::All => true,
            Self::AllExcept(ids) => !ids.contains(id),
            Self::Only(ids) => ids.contains(id),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Only(ids) if ids.is_empty())
    }

    fn all_except(ids: HashSet<String>) -> Self {
        if ids.is_empty() {
            Self::All
        } else {
            Self::AllExcept(ids)
        }
    }

    fn union(self, other: Self) -> Self {
        match (self, other) {
            (Self::All, _) | (_, Self::All) => Self::All,
            (Self::AllExcept(mut denied), Self::AllExcept(other)) => {
                denied.retain(|id| other.contains(id));
                Self::all_except(denied)
            }
            (Self::AllExcept(mut denied), Self::Only(allowed))
            | (Self::Only(allowed), Self::AllExcept(mut denied)) => {
                denied.retain(|id| !allowed.contains(id));
                Self::all_except(denied)
            }
            (Self::Only(mut allowed), Self::Only(other)) => {
                allowed.extend(other);
                Self::Only(allowed)
            }
        }
    }
}

/// Deny wins within a scope; any scope that allows passes.
#[derive(Debug, Clone, Default)]
pub struct EffectivePermissions {
    scopes: HashMap<String, Scope>,
}

#[derive(Debug, Clone, Default)]
struct Scope {
    grants: Vec<ScopedPermission>,
    resources: HashMap<Resource, Vec<ScopedPermission>>,
}

impl Scope {
    fn denies(&self, permission_key: &str) -> bool {
        grants_match(&self.grants, PermissionEffect::Deny, permission_key)
    }

    /// Expects `resource`, if any, to be of the permission's kind.
    fn allows(&self, permission_key: &str, resource: Option<&Resource>) -> bool {
        let mut grants = std::iter::once(&self.grants)
            .chain(resource.and_then(|resource| self.resources.get(resource)));
        !grants
            .clone()
            .any(|grants| grants_match(grants, PermissionEffect::Deny, permission_key))
            && grants.any(|grants| grants_match(grants, PermissionEffect::Allow, permission_key))
    }

    fn resource_access(&self, permission_key: &str, kind: &str) -> ResourceAccess {
        if self.denies(permission_key) {
            return ResourceAccess::Only(HashSet::new());
        }

        let ids = |matches: fn(&[ScopedPermission], &str) -> bool| {
            self.resources
                .iter()
                .filter(|(resource, grants)| {
                    resource.kind == kind && matches(grants, permission_key)
                })
                .map(|(resource, _)| resource.id.clone())
                .collect()
        };

        if grants_match(&self.grants, PermissionEffect::Allow, permission_key) {
            ResourceAccess::all_except(ids(|grants, permission_key| {
                grants_match(grants, PermissionEffect::Deny, permission_key)
            }))
        } else {
            ResourceAccess::Only(ids(allows_in_scope))
        }
    }
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
        let mut scopes = HashMap::<String, Scope>::new();
        for grant in grants {
            let scope = scopes.entry(grant.scope).or_default();
            let permission = ScopedPermission {
                pattern: grant.pattern,
                effect: grant.effect,
            };
            match grant.resource {
                None => scope.grants.push(permission),
                Some(resource) => scope
                    .resources
                    .entry(resource)
                    .or_default()
                    .push(permission),
            }
        }

        Self { scopes }
    }

    /// `resource` must be of the permission's registered kind, and `None` when
    /// it has none; otherwise the check fails. Wildcard keys are never allowed.
    pub fn allows(&self, permission_key: &str, resource: Option<&Resource>) -> bool {
        is_concrete(permission_key)
            && takes_resource(
                permission_key,
                resource.map(|resource| resource.kind.as_ref()),
            )
            && self.grants_allow(permission_key, resource)
    }

    fn grants_allow(&self, permission_key: &str, resource: Option<&Resource>) -> bool {
        self.scopes
            .values()
            .any(|scope| scope.allows(permission_key, resource))
    }

    pub fn allows_permission(&self, permission: &impl Permission) -> bool {
        self.allows(permission.as_ref(), permission.resource().as_ref())
    }

    pub fn resources(&self) -> HashSet<&Resource> {
        self.scopes
            .values()
            .flat_map(|scope| scope.resources.keys())
            .collect()
    }

    /// Allows, in `scope`, each concrete name on each resource both sides allow
    /// it on.
    pub fn intersect<'a>(
        &self,
        other: &Self,
        permission_names: impl IntoIterator<Item = &'a str>,
        scope: &str,
    ) -> Self {
        let resources: HashSet<&Resource> = self
            .resources()
            .into_iter()
            .chain(other.resources())
            .collect();

        let mut grants = Vec::new();
        for name in permission_names
            .into_iter()
            .filter(|name| is_concrete(name))
        {
            let both_allow = |on: Option<&Resource>| {
                self.grants_allow(name, on) && other.grants_allow(name, on)
            };
            let grant = |effect, resource: Option<&Resource>| PermissionGrant {
                scope: scope.to_owned(),
                pattern: name.to_owned(),
                effect,
                resource: resource.cloned(),
            };

            // Resources without grants on either side get the result without one.
            let everywhere = both_allow(None);
            if everywhere {
                grants.push(grant(PermissionEffect::Allow, None));
            }
            for &resource in resources
                .iter()
                .filter(|resource| takes_resource(name, Some(&resource.kind)))
            {
                match (everywhere, both_allow(Some(resource))) {
                    (true, false) => grants.push(grant(PermissionEffect::Deny, Some(resource))),
                    (false, true) => grants.push(grant(PermissionEffect::Allow, Some(resource))),
                    _ => {}
                }
            }
        }

        Self::from_grants(grants)
    }

    /// The ids of `kind` the name is allowed on; no access unless `kind` is the
    /// permission's registered kind. Wildcard keys get no access.
    pub fn resource_access(&self, permission_key: &str, kind: &str) -> ResourceAccess {
        if !is_concrete(permission_key) || !takes_resource(permission_key, Some(kind)) {
            return ResourceAccess::Only(HashSet::new());
        }

        self.scopes
            .values()
            .map(|scope| scope.resource_access(permission_key, kind))
            .fold(ResourceAccess::Only(HashSet::new()), ResourceAccess::union)
    }
}

fn is_concrete(permission_key: &str) -> bool {
    !permission_key.contains('*')
}

/// Whether the permission is checked against a resource of `kind`. Unregistered
/// names take no resource.
fn takes_resource(permission_key: &str, kind: Option<&str>) -> bool {
    static KINDS: OnceLock<HashMap<&'static str, Vec<Option<&'static str>>>> = OnceLock::new();

    let kinds = KINDS.get_or_init(|| {
        inventory::iter::<PermissionEntry>()
            .map(|entry| (entry.name.as_ref(), entry.resource))
            .into_group_map()
    });
    match kinds.get(permission_key) {
        Some(kinds) => kinds.contains(&kind),
        None => kind.is_none(),
    }
}

fn allows_in_scope(grants: &[ScopedPermission], permission_key: &str) -> bool {
    !grants_match(grants, PermissionEffect::Deny, permission_key)
        && grants_match(grants, PermissionEffect::Allow, permission_key)
}

fn grants_match(
    grants: &[ScopedPermission],
    effect: PermissionEffect,
    permission_key: &str,
) -> bool {
    grants.iter().any(|permission| {
        permission.effect == effect
            && permission_pattern_matches(&permission.pattern, permission_key)
    })
}

pub fn permission_pattern_matches(pattern: &str, concrete: &str) -> bool {
    if pattern == "*" || pattern == concrete {
        return true;
    }

    let Some(concrete) = PermissionKey::parse(concrete) else {
        return false;
    };

    let Some(pattern) = PermissionKey::parse(pattern) else {
        return false;
    };

    pattern.separator == concrete.separator
        && match (pattern.prefix.as_str(), pattern.suffix.as_str()) {
            ("*", suffix) => suffix == concrete.suffix,
            (prefix, "*") => prefix == concrete.prefix,
            (prefix, suffix) => prefix == concrete.prefix && suffix == concrete.suffix,
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
    use std::borrow::Cow;

    use super::{
        EffectivePermissions,
        PermissionEffect,
        PermissionEntry,
        PermissionGrant,
        Resource,
        ResourceAccess,
        permission_pattern_matches,
    };

    macro_rules! company_permissions {
        ($($name:literal),*) => {$(
            inventory::submit! {
                PermissionEntry {
                    name: Cow::Borrowed($name),
                    enum_name: "UserPermission",
                    roles: &[],
                    resource: Some("company"),
                }
            }
        )*};
    }

    company_permissions!("Users.List", "Users.Create", "Users.Delete", "Users.Remove");

    fn grant(
        scope: &str,
        pattern: &str,
        effect: PermissionEffect,
        resource: Option<Resource>,
    ) -> PermissionGrant {
        PermissionGrant {
            scope: scope.to_owned(),
            pattern: pattern.to_owned(),
            effect,
            resource,
        }
    }

    fn company(id: &str) -> Resource {
        Resource::new("company", id)
    }

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
        assert!(permission_pattern_matches("update:*", "update:companies"));
        assert!(permission_pattern_matches(
            "*:companies",
            "update:companies"
        ));
        assert!(permission_pattern_matches(
            "update:companies",
            "update:companies"
        ));
        assert!(!permission_pattern_matches("update:*", "Companies.List"));
    }

    #[test]
    fn matches_names_without_separator_exactly() {
        assert!(permission_pattern_matches("Audit", "Audit"));
        assert!(permission_pattern_matches("*", "Audit"));
        assert!(!permission_pattern_matches("Aud", "Audit"));
        assert!(!permission_pattern_matches("Audit.*", "Audit"));
        assert!(!permission_pattern_matches("*.Audit", "Audit"));

        let permissions = EffectivePermissions::from_grants([grant(
            "role",
            "Audit",
            PermissionEffect::Allow,
            None,
        )]);
        assert!(permissions.allows("Audit", None));
        assert!(!permissions.allows("Auditor", None));
    }

    #[test]
    fn wildcard_keys_are_never_allowed() {
        let permissions = EffectivePermissions::from_grants([
            grant("role", "*", PermissionEffect::Allow, None),
            grant("role", "Users.*", PermissionEffect::Allow, None),
            grant("role", "Users.Delete", PermissionEffect::Deny, None),
            grant("role", "*", PermissionEffect::Allow, Some(company("a"))),
        ]);

        for key in ["*", "Users.*", "*.Delete"] {
            assert!(!permissions.allows(key, None));
            assert!(!permissions.allows(key, Some(&company("a"))));
            assert_eq!(
                permissions.resource_access(key, "company"),
                ResourceAccess::Only([].into())
            );
        }
        assert!(permissions.allows("Users.List", Some(&company("b"))));
    }

    #[test]
    fn deny_wins_inside_scope() {
        let permissions = EffectivePermissions::from_grants([
            grant("role", "Companies.*", PermissionEffect::Allow, None),
            grant("role", "Companies.Delete", PermissionEffect::Deny, None),
        ]);

        assert!(permissions.allows("Companies.List", None));
        assert!(!permissions.allows("Companies.Delete", None));
    }

    #[test]
    fn resource_grants_apply_only_to_their_resource() {
        let permissions = EffectivePermissions::from_grants([grant(
            "role",
            "Users.List",
            PermissionEffect::Allow,
            Some(company("a")),
        )]);

        assert!(permissions.allows("Users.List", Some(&company("a"))));
        assert!(!permissions.allows("Users.List", Some(&company("b"))));
        assert!(!permissions.resource_access("Users.List", "company").is_empty());
    }

    #[test]
    fn grants_without_resource_apply_to_every_resource() {
        let permissions = EffectivePermissions::from_grants([grant(
            "role",
            "Users.List",
            PermissionEffect::Allow,
            None,
        )]);

        assert!(permissions.allows("Users.List", Some(&company("a"))));
        assert!(permissions.allows("Users.List", Some(&company("b"))));
    }

    #[test]
    fn checks_need_the_permissions_resource_kind() {
        let permissions = EffectivePermissions::from_grants([
            grant("role", "*", PermissionEffect::Allow, None),
            grant(
                "role",
                "Users.Delete",
                PermissionEffect::Deny,
                Some(company("a")),
            ),
        ]);

        assert!(!permissions.allows("Users.Delete", None));
        assert!(!permissions.allows("Users.Delete", Some(&Resource::new("customer", "a"))));
        assert!(!permissions.allows("Admin.Run", Some(&company("a"))));
        assert!(permissions.allows("Users.Delete", Some(&company("b"))));
        assert!(permissions.allows("Admin.Run", None));
        assert_eq!(
            permissions.resource_access("Users.Delete", "customer"),
            ResourceAccess::Only([].into())
        );
    }

    #[test]
    fn resource_grants_apply_only_to_permissions_of_their_kind() {
        let permissions = EffectivePermissions::from_grants([grant(
            "owner",
            "*",
            PermissionEffect::Allow,
            Some(company("a")),
        )]);

        assert!(!permissions.allows("Admin.Run", None));
        assert!(!permissions.allows("Admin.Run", Some(&company("a"))));
        assert_eq!(
            permissions.resource_access("Admin.Run", "company"),
            ResourceAccess::Only([].into())
        );
        assert!(!permissions.resource_access("Users.List", "company").is_empty());
        assert!(permissions.allows("Users.List", Some(&company("a"))));
    }

    #[test]
    fn deny_on_resource_stays_on_that_resource() {
        let permissions = EffectivePermissions::from_grants([
            grant(
                "role",
                "Users.*",
                PermissionEffect::Allow,
                Some(company("a")),
            ),
            grant(
                "role",
                "Users.*",
                PermissionEffect::Allow,
                Some(company("b")),
            ),
            grant(
                "role",
                "Users.Remove",
                PermissionEffect::Deny,
                Some(company("a")),
            ),
        ]);

        assert!(!permissions.allows("Users.Remove", Some(&company("a"))));
        assert!(permissions.allows("Users.Remove", Some(&company("b"))));
    }

    #[test]
    fn deny_on_resource_wins_over_allow_without_resource() {
        let permissions = EffectivePermissions::from_grants([
            grant("role", "Users.*", PermissionEffect::Allow, None),
            grant(
                "role",
                "Users.Delete",
                PermissionEffect::Deny,
                Some(company("a")),
            ),
        ]);

        assert!(!permissions.allows("Users.Delete", Some(&company("a"))));
        assert!(permissions.allows("Users.Delete", Some(&company("b"))));
        assert!(permissions.allows("Users.List", Some(&company("a"))));

        let access = permissions.resource_access("Users.Delete", "company");
        assert_eq!(access, ResourceAccess::AllExcept(["a".to_owned()].into()));
        assert!(!access.contains("a"));
        assert!(access.contains("b"));
        assert_eq!(
            permissions.resource_access("Users.List", "company"),
            ResourceAccess::All
        );
    }

    #[test]
    fn deny_stays_in_its_scope() {
        let permissions = EffectivePermissions::from_grants([
            grant("role", "Users.*", PermissionEffect::Allow, None),
            grant(
                "role",
                "Users.Delete",
                PermissionEffect::Deny,
                Some(company("a")),
            ),
            grant(
                "admin",
                "Users.Delete",
                PermissionEffect::Allow,
                Some(company("a")),
            ),
        ]);

        assert!(permissions.allows("Users.Delete", Some(&company("a"))));
        assert_eq!(
            permissions.resource_access("Users.Delete", "company"),
            ResourceAccess::All
        );
    }

    #[test]
    fn resource_access_combines_scopes() {
        let permissions = EffectivePermissions::from_grants([
            grant("role", "Users.List", PermissionEffect::Allow, None),
            grant(
                "role",
                "Users.List",
                PermissionEffect::Deny,
                Some(company("a")),
            ),
            grant(
                "role",
                "Users.List",
                PermissionEffect::Deny,
                Some(company("b")),
            ),
            grant("other", "Users.List", PermissionEffect::Allow, None),
            grant(
                "other",
                "Users.List",
                PermissionEffect::Deny,
                Some(company("b")),
            ),
            grant(
                "other",
                "Users.List",
                PermissionEffect::Deny,
                Some(company("c")),
            ),
            grant(
                "third",
                "Users.List",
                PermissionEffect::Allow,
                Some(company("b")),
            ),
        ]);

        assert_eq!(
            permissions.resource_access("Users.List", "company"),
            ResourceAccess::All
        );

        let permissions = EffectivePermissions::from_grants([
            grant("role", "Users.List", PermissionEffect::Allow, None),
            grant(
                "role",
                "Users.List",
                PermissionEffect::Deny,
                Some(company("a")),
            ),
            grant(
                "role",
                "Users.List",
                PermissionEffect::Deny,
                Some(company("b")),
            ),
            grant(
                "other",
                "Users.List",
                PermissionEffect::Allow,
                Some(company("a")),
            ),
        ]);

        assert_eq!(
            permissions.resource_access("Users.List", "company"),
            ResourceAccess::AllExcept(["b".to_owned()].into())
        );
    }

    #[test]
    fn deny_without_resource_covers_resource_grants_in_its_scope() {
        let permissions = EffectivePermissions::from_grants([
            grant("role", "Users.*", PermissionEffect::Allow, None),
            grant("role", "Users.Delete", PermissionEffect::Deny, None),
            grant(
                "role",
                "Users.*",
                PermissionEffect::Allow,
                Some(company("a")),
            ),
            grant(
                "other",
                "Users.Delete",
                PermissionEffect::Allow,
                Some(company("b")),
            ),
        ]);

        assert!(!permissions.allows("Users.Delete", Some(&company("a"))));
        assert!(permissions.allows("Users.Delete", Some(&company("b"))));
        assert!(permissions.allows("Users.List", Some(&company("a"))));
        assert_eq!(
            permissions.resource_access("Users.Delete", "company"),
            ResourceAccess::Only(["b".to_owned()].into())
        );
    }

    #[test]
    fn resource_access_lists_allowed_resources() {
        let permissions = EffectivePermissions::from_grants([
            grant(
                "role",
                "Users.List",
                PermissionEffect::Allow,
                Some(company("a")),
            ),
            grant(
                "role",
                "Users.List",
                PermissionEffect::Allow,
                Some(company("b")),
            ),
            grant(
                "role",
                "Users.List",
                PermissionEffect::Allow,
                Some(Resource::new("customer", "x")),
            ),
        ]);

        assert_eq!(
            permissions.resource_access("Users.List", "company"),
            ResourceAccess::Only(["a".to_owned(), "b".to_owned()].into())
        );
        assert_eq!(
            permissions.resource_access("Users.Remove", "company"),
            ResourceAccess::Only([].into())
        );
    }

    #[test]
    fn intersect_keeps_specific_denies_under_wildcard_allows() {
        let account = EffectivePermissions::from_grants([
            grant("role", "Users.*", PermissionEffect::Allow, None),
            grant("role", "Users.Delete", PermissionEffect::Deny, None),
            grant("role", "*", PermissionEffect::Allow, Some(company("a"))),
            grant(
                "role",
                "Admin.Run",
                PermissionEffect::Deny,
                Some(company("a")),
            ),
        ]);
        let allowlist = EffectivePermissions::from_grants([grant(
            "surface",
            "*",
            PermissionEffect::Allow,
            None,
        )]);

        let clipped = account.intersect(
            &allowlist,
            [
                "*",
                "Users.*",
                "*.Delete",
                "Users.List",
                "Users.Delete",
                "Admin.*",
                "Admin.Run",
            ],
            "clipped",
        );

        assert!(clipped.allows("Users.List", Some(&company("b"))));
        assert!(!clipped.allows("Users.Delete", Some(&company("b"))));
        assert!(!clipped.allows("Users.Delete", Some(&company("a"))));
        assert!(!clipped.allows("Users.Create", Some(&company("b"))));
        assert!(!clipped.allows("Admin.Run", None));
    }

    #[test]
    fn intersect_keeps_resources() {
        let account = EffectivePermissions::from_grants([
            grant(
                "role",
                "Users.*",
                PermissionEffect::Allow,
                Some(company("a")),
            ),
            grant("tenant", "Messages.Send", PermissionEffect::Allow, None),
            grant("tenant", "Admin.Run", PermissionEffect::Allow, None),
        ]);
        let allowlist = EffectivePermissions::from_grants([
            grant("surface", "Users.*", PermissionEffect::Allow, None),
            grant("surface", "Messages.*", PermissionEffect::Allow, None),
        ]);

        let clipped = account.intersect(
            &allowlist,
            ["Users.List", "Messages.Send", "Admin.Run"],
            "clipped",
        );

        assert!(clipped.allows("Users.List", Some(&company("a"))));
        assert!(!clipped.allows("Users.List", Some(&company("b"))));
        assert!(clipped.allows("Messages.Send", None));
        assert!(!clipped.allows("Admin.Run", None));
    }

    #[test]
    fn intersect_keeps_denies_on_resources() {
        let account = EffectivePermissions::from_grants([
            grant("role", "Users.*", PermissionEffect::Allow, None),
            grant(
                "role",
                "Users.Delete",
                PermissionEffect::Deny,
                Some(company("a")),
            ),
        ]);
        let allowlist = EffectivePermissions::from_grants([
            grant("surface", "*", PermissionEffect::Allow, None),
            grant(
                "surface",
                "Users.Delete",
                PermissionEffect::Deny,
                Some(company("b")),
            ),
        ]);

        let clipped = account.intersect(&allowlist, ["Users.Delete"], "clipped");

        assert!(!clipped.allows("Users.Delete", Some(&company("a"))));
        assert!(!clipped.allows("Users.Delete", Some(&company("b"))));
        assert!(clipped.allows("Users.Delete", Some(&company("c"))));
        assert_eq!(
            clipped.resource_access("Users.Delete", "company"),
            ResourceAccess::AllExcept(["a".to_owned(), "b".to_owned()].into())
        );
    }

    #[test]
    fn intersect_ignores_denies_in_scopes_that_never_allow() {
        let account = EffectivePermissions::from_grants([
            grant(
                "role",
                "Users.Delete",
                PermissionEffect::Allow,
                Some(company("a")),
            ),
            grant(
                "blocked",
                "Users.Delete",
                PermissionEffect::Deny,
                Some(company("a")),
            ),
        ]);
        let allow_all = EffectivePermissions::from_grants([grant(
            "surface",
            "*",
            PermissionEffect::Allow,
            None,
        )]);

        let clipped = account.intersect(&allow_all, ["Users.Delete"], "clipped");

        assert!(account.allows("Users.Delete", Some(&company("a"))));
        assert!(clipped.allows("Users.Delete", Some(&company("a"))));
        assert!(!clipped.allows("Users.Delete", Some(&company("b"))));
    }

    #[test]
    fn resource_access_is_all_with_grant_without_resource() {
        let permissions = EffectivePermissions::from_grants([
            grant(
                "role",
                "Users.List",
                PermissionEffect::Allow,
                Some(company("a")),
            ),
            grant("tenant", "Users.*", PermissionEffect::Allow, None),
        ]);

        let access = permissions.resource_access("Users.List", "company");
        assert_eq!(access, ResourceAccess::All);
        assert!(access.contains("anything"));
    }
}
