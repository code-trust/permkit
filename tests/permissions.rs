use futures::executor::block_on;
use itertools::Itertools as _;
use permkit::{
    EffectivePermissions,
    HasPermission,
    InvalidGrant,
    Permission,
    PermissionCheckError,
    PermissionEffect,
    PermissionGrant,
    Resource,
    all_permissions,
    permissions,
};

#[derive(Permission)]
#[permission(roles = ["owner", "operator"])]
enum CompanyPermission {
    #[permission(name = "Companies.List")]
    List,
    #[permission(name = "Companies.Delete", roles = ["owner"])]
    Delete,
}

#[derive(Permission)]
enum CompanyActionPermission {
    #[permission(name = "update:companies")]
    UpdateCompanies,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompanyId(u32);

impl std::fmt::Display for CompanyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Permission)]
#[permission(roles = ["companyOwner"])]
enum CompanyUserPermission {
    #[permission(name = "CompanyUser.ListCompanies")]
    ListCompanies,
    #[permission(name = "CompanyUser.ListUsers")]
    ListUsers(#[permission(resource = "company")] CompanyId),
    #[permission(name = "CompanyUser.RemoveUser")]
    RemoveUser {
        #[permission(resource = "company")]
        company_id: CompanyId,
    },
}

#[derive(Permission)]
enum AuditPermission {
    #[permission(name = "Audit")]
    Audit(#[permission(resource = "company")] CompanyId),
}

impl HasPermission<Context> for CompanyUserPermission {
    type Error = PermissionCheckError;

    async fn has_permission(&self, context: &Context) -> Result<bool, Self::Error> {
        Ok(context.permissions.allows_permission(self))
    }
}

struct Context {
    permissions: EffectivePermissions,
}

impl HasPermission<Context> for CompanyPermission {
    type Error = PermissionCheckError;

    async fn has_permission(&self, context: &Context) -> Result<bool, Self::Error> {
        Ok(context.permissions.allows_permission(self))
    }
}

#[permissions(CompanyPermission::List, context = context)]
async fn guarded(context: Context) -> Result<(), PermissionCheckError> {
    let _ = context;
    Ok(())
}

#[permissions(CompanyUserPermission::ListUsers(company_id), context = context)]
async fn guarded_company(
    context: Context,
    company_id: CompanyId,
) -> Result<(), PermissionCheckError> {
    let _ = (context, company_id);
    Ok(())
}

fn company_grant(pattern: &str, company_id: Option<CompanyId>) -> PermissionGrant {
    PermissionGrant::try_new(
        "role",
        pattern,
        PermissionEffect::Allow,
        company_id.map(|id| Resource::new("company", id)),
    )
    .expect("valid grant")
}

#[test]
fn inventory_collects_derived_permissions() {
    let _ = CompanyPermission::Delete;
    let _ = CompanyActionPermission::UpdateCompanies;

    let entries = all_permissions();
    let mut company_permissions: Vec<_> = entries
        .iter()
        .filter(|entry| entry.enum_name == "CompanyPermission")
        .map(|entry| (entry.name.as_ref(), entry.roles))
        .collect();
    company_permissions.sort_unstable_by(|left, right| left.0.cmp(right.0));

    assert_eq!(
        company_permissions,
        vec![
            ("Companies.*", &[][..]),
            ("Companies.Delete", &["owner"][..]),
            ("Companies.List", &["owner", "operator"][..]),
        ]
    );

    let action_permissions: Vec<_> = entries
        .iter()
        .filter(|entry| entry.enum_name == "CompanyActionPermission")
        .map(|entry| entry.name.as_ref())
        .sorted()
        .collect();

    assert_eq!(action_permissions, vec!["update:*", "update:companies"]);

    let _ = CompanyUserPermission::ListCompanies;
    let resources: Vec<_> = entries
        .iter()
        .filter(|entry| entry.enum_name == "CompanyUserPermission")
        .map(|entry| (entry.name.as_ref(), entry.resource))
        .sorted()
        .collect();

    assert_eq!(
        resources,
        vec![
            ("CompanyUser.*", None),
            ("CompanyUser.ListCompanies", None),
            ("CompanyUser.ListUsers", Some("company")),
            ("CompanyUser.RemoveUser", Some("company")),
        ]
    );
}

#[test]
fn deny_on_resource_must_cover_only_its_kind() {
    let deny = |pattern: &str, kind: &'static str| {
        PermissionGrant::try_new(
            "role",
            pattern,
            PermissionEffect::Deny,
            Some(Resource::new(kind, "1")),
        )
        .map(|_| ())
    };

    assert_eq!(deny("CompanyUser.ListUsers", "company"), Ok(()));
    assert_eq!(deny("*.ListUsers", "company"), Ok(()));
    assert_eq!(
        deny("CompanyUser.ListUsers", "Company"),
        Err(InvalidGrant::ResourceKindMismatch {
            permission: "CompanyUser.ListUsers".into(),
            expected: Some("company"),
        })
    );
    assert_eq!(
        deny("CompanyUser.*", "company"),
        Err(InvalidGrant::ResourceKindMismatch {
            permission: "CompanyUser.ListCompanies".into(),
            expected: None,
        })
    );
    assert!(deny("*", "company").is_err());
    assert_eq!(
        deny("Unknown.Thing", "company"),
        Err(InvalidGrant::UnknownPermission)
    );
}

#[test]
fn allow_on_resource_must_cover_its_kind() {
    let allow = |pattern: &str, kind: &'static str| {
        PermissionGrant::try_new(
            "role",
            pattern,
            PermissionEffect::Allow,
            Some(Resource::new(kind, "1")),
        )
        .map(|_| ())
    };

    assert_eq!(allow("CompanyUser.*", "company"), Ok(()));
    assert_eq!(allow("*", "company"), Ok(()));
    assert!(allow("CompanyUser.*", "Company").is_err());
    assert_eq!(
        allow("Companies.List", "company"),
        Err(InvalidGrant::ResourceKindMismatch {
            permission: "Companies.List".into(),
            expected: None,
        })
    );
    assert_eq!(
        allow("Unknown.Thing", "company"),
        Err(InvalidGrant::UnknownPermission)
    );
}

#[test]
fn grant_without_resource_is_valid_unless_deny_matches_nothing() {
    for effect in [PermissionEffect::Allow, PermissionEffect::Deny] {
        for pattern in ["CompanyUser.ListUsers", "CompanyUser.*", "*"] {
            assert!(PermissionGrant::try_new("role", pattern, effect, None).is_ok());
        }
    }

    assert!(
        PermissionGrant::try_new("role", "Unknown.Thing", PermissionEffect::Allow, None).is_ok()
    );
    for pattern in ["Unknown.Thing", "CompanyUser.ListUser", "Unknown.*"] {
        assert_eq!(
            PermissionGrant::try_new("role", pattern, PermissionEffect::Deny, None),
            Err(InvalidGrant::UnknownPermission)
        );
    }
}

#[test]
fn derived_permissions_carry_their_resource() {
    assert_eq!(CompanyUserPermission::ListCompanies.resource(), None);
    assert_eq!(
        CompanyUserPermission::ListUsers(CompanyId(7)).as_ref(),
        "CompanyUser.ListUsers"
    );
    assert_eq!(
        CompanyUserPermission::ListUsers(CompanyId(7)).resource(),
        Some(Resource::new("company", "7"))
    );
    assert_eq!(
        CompanyUserPermission::RemoveUser {
            company_id: CompanyId(8)
        }
        .resource(),
        Some(Resource::new("company", "8"))
    );
}

#[test]
fn resource_permissions_check_their_resource() {
    let permissions =
        EffectivePermissions::from_grants([company_grant("CompanyUser.*", Some(CompanyId(1)))]);

    assert!(permissions.allows_permission(&CompanyUserPermission::ListUsers(CompanyId(1))));
    assert!(!permissions.allows_permission(&CompanyUserPermission::ListUsers(CompanyId(2))));
    assert!(!permissions.allows_permission(&CompanyUserPermission::ListCompanies));
    assert!(
        !permissions
            .resource_access(
                CompanyUserPermission::ListUsers(CompanyId(1)).as_ref(),
                "company"
            )
            .is_empty()
    );
}

#[test]
fn auth_macro_checks_permission_resource() {
    let allowed = || Context {
        permissions: EffectivePermissions::from_grants([company_grant(
            "CompanyUser.ListUsers",
            Some(CompanyId(1)),
        )]),
    };

    assert_eq!(block_on(guarded_company(allowed(), CompanyId(1))), Ok(()));
    assert_eq!(
        block_on(guarded_company(allowed(), CompanyId(2))),
        Err(PermissionCheckError::Forbidden)
    );

    let everywhere = Context {
        permissions: EffectivePermissions::from_grants([company_grant(
            "CompanyUser.ListUsers",
            None,
        )]),
    };
    assert_eq!(block_on(guarded_company(everywhere, CompanyId(2))), Ok(()));
}

#[test]
fn auth_macro_allows_request_when_permission_passes() {
    let context = Context {
        permissions: EffectivePermissions::from_grants([PermissionGrant::try_new(
            "role",
            "Companies.List",
            PermissionEffect::Allow,
            None,
        )
        .expect("valid grant")]),
    };

    assert_eq!(block_on(guarded(context)), Ok(()));
}

#[test]
fn auth_macro_denies_request_when_permission_fails() {
    let context = Context {
        permissions: EffectivePermissions::empty(),
    };

    assert_eq!(
        block_on(guarded(context)),
        Err(PermissionCheckError::Forbidden)
    );
}

#[test]
fn names_without_separator_match_exact_grants() {
    let permissions = EffectivePermissions::from_grants([PermissionGrant::try_new(
        "role",
        "Audit",
        PermissionEffect::Allow,
        Some(Resource::new("company", CompanyId(1))),
    )
    .expect("valid grant")]);

    assert!(permissions.allows_permission(&AuditPermission::Audit(CompanyId(1))));
    assert!(!permissions.allows_permission(&AuditPermission::Audit(CompanyId(2))));
}
