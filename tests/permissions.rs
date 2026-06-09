use futures::executor::block_on;
use itertools::Itertools as _;
use permkit::{
    EffectivePermissions,
    HasPermission,
    Permission,
    PermissionCheckError,
    PermissionEffect,
    PermissionGrant,
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

struct Context {
    permissions: EffectivePermissions,
}

impl HasPermission<Context> for CompanyPermission {
    type Error = PermissionCheckError;

    async fn has_permission(&self, context: &Context) -> Result<bool, Self::Error> {
        Ok(context.permissions.allows(self.as_ref()))
    }
}

#[permissions(CompanyPermission::List, context = context)]
async fn guarded(context: Context) -> Result<(), PermissionCheckError> {
    let _ = context;
    Ok(())
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
}

#[test]
fn auth_macro_allows_request_when_permission_passes() {
    let context = Context {
        permissions: EffectivePermissions::from_grants([PermissionGrant {
            scope: "role".to_owned(),
            pattern: "Companies.List".to_owned(),
            effect: PermissionEffect::Allow,
        }]),
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
