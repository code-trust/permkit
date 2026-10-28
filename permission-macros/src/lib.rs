//! Derive macro for permission enums.
//!
//! Annotate an enum with `#[derive(Permission)]` and use the
//! `#[permission(...)]` helper attribute to declare the permission string for
//! each variant and the roles that should hold it by default.
//!
//! A variant may have one field: the resource the permission is checked
//! against. Mark it with `#[permission(resource = "kind")]`; the field's
//! `Display` output is the resource id.
//!
//! ```ignore
//! use permkit::Permission;
//!
//! #[derive(Permission)]
//! #[permission(roles = ["owner", "operator"])]
//! pub enum CompanyPermission {
//!     #[permission(name = "Companies.List")]
//!     List,
//!     #[permission(name = "Companies.Create", roles = ["owner"])]
//!     Create,
//!     #[permission(name = "Companies.Update")]
//!     Update(#[permission(resource = "company")] CompanyId),
//! }
//! ```

use std::collections::HashMap;

use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned as _;
use syn::{
    Attribute,
    Data,
    DeriveInput,
    Expr,
    ExprArray,
    ExprLit,
    Fields,
    Lit,
    LitStr,
    Variant,
    parse_macro_input,
};

#[proc_macro_derive(Permission, attributes(permission))]
pub fn derive_permission(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[derive(Default)]
struct EnumAttrs {
    default_roles: Vec<String>,
}

struct VariantInfo {
    ident: syn::Ident,
    name: String,
    roles: Vec<String>,
    resource: Option<ResourceField>,
}

struct ResourceField {
    member: syn::Member,
    kind: String,
}

fn expand(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let enum_ident = &input.ident;

    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            enum_ident,
            "Permission can only be derived for enums",
        ));
    };

    let enum_attrs = parse_enum_attrs(&input.attrs)?;

    let mut variants: Vec<VariantInfo> = Vec::with_capacity(data.variants.len());
    let mut seen_names = HashMap::<String, proc_macro2::Span>::new();

    for variant in &data.variants {
        let info = parse_variant_info(variant, &enum_attrs)?;

        if let Some(prev_span) = seen_names.insert(info.name.clone(), variant.span()) {
            let mut err = syn::Error::new(
                variant.span(),
                format!("duplicate permission name {:?}", info.name),
            );

            err.combine(syn::Error::new(
                prev_span,
                format!("note: previous use of {:?}", info.name),
            ));

            return Err(err);
        }

        variants.push(info);
    }

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let as_ref_arms = variants.iter().map(|variant| {
        let ident = &variant.ident;
        let name = &variant.name;
        quote! { Self::#ident { .. } => #name }
    });

    let resource_arms = variants.iter().map(|variant| {
        let ident = &variant.ident;
        match &variant.resource {
            None => quote! { Self::#ident { .. } => ::core::option::Option::None },
            Some(ResourceField { member, kind }) => quote! {
                Self::#ident { #member: __resource } => ::core::option::Option::Some(
                    ::permkit::Resource::new(#kind, __resource)
                )
            },
        }
    });

    let enum_name_str = enum_ident.to_string();

    let utoipa_impls = if cfg!(feature = "utoipa") {
        let all_names = variants.iter().map(|variant| variant.name.as_str());

        quote! {
            impl #impl_generics ::permkit::utoipa::PartialSchema for #enum_ident #ty_generics #where_clause {
                fn schema() -> ::permkit::utoipa::openapi::RefOr<::permkit::utoipa::openapi::schema::Schema> {
                    ::permkit::utoipa::openapi::RefOr::T(::permkit::utoipa::openapi::schema::Schema::Object(
                        ::permkit::utoipa::openapi::schema::ObjectBuilder::new()
                            .schema_type(::permkit::utoipa::openapi::schema::SchemaType::Type(
                                ::permkit::utoipa::openapi::schema::Type::String,
                            ))
                            .enum_values(::core::option::Option::Some([
                                #(#all_names),*
                            ]))
                            .build(),
                    ))
                }
            }

            impl #impl_generics ::permkit::utoipa::ToSchema for #enum_ident #ty_generics #where_clause {
                fn name() -> ::std::borrow::Cow<'static, str> {
                    ::std::borrow::Cow::Borrowed(#enum_name_str)
                }
            }
        }
    } else {
        quote! {}
    };

    let inventory_submits = variants
        .iter()
        .map(|variant| {
            let name = &variant.name;
            let roles = variant.roles.iter();
            let resource = if let Some(ResourceField { kind, .. }) = &variant.resource {
                quote! { ::core::option::Option::Some(#kind) }
            } else {
                quote! { ::core::option::Option::None }
            };
            quote! {
                ::permkit::inventory::submit! {
                    ::permkit::PermissionEntry {
                        name: ::std::borrow::Cow::Borrowed(#name),
                        enum_name: #enum_name_str,
                        roles: &[#(#roles),*],
                        resource: #resource,
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    Ok(quote! {
        impl #impl_generics ::core::convert::AsRef<str> for #enum_ident #ty_generics #where_clause {
            #[inline]
            fn as_ref(&self) -> &str {
                match self {
                    #(#as_ref_arms),*
                }
            }
        }

        impl #impl_generics ::permkit::Permission for #enum_ident #ty_generics #where_clause {
            fn resource(&self) -> ::core::option::Option<::permkit::Resource> {
                match self {
                    #(#resource_arms),*
                }
            }
        }

        impl #impl_generics ::permkit::serde::Serialize for #enum_ident #ty_generics #where_clause {
            fn serialize<__S>(&self, serializer: __S) -> ::core::result::Result<__S::Ok, __S::Error>
            where
                __S: ::permkit::serde::Serializer,
            {
                serializer.serialize_str(::core::convert::AsRef::<str>::as_ref(self))
            }
        }

        #utoipa_impls

        #(#inventory_submits)*
    })
}

fn parse_enum_attrs(attrs: &[Attribute]) -> syn::Result<EnumAttrs> {
    let mut out = EnumAttrs::default();

    for attr in attrs {
        if !attr.path().is_ident("permission") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("roles") {
                let expr: Expr = meta.value()?.parse()?;
                out.default_roles = parse_string_array(&expr)?;
                Ok(())
            } else if meta.path.is_ident("resource") {
                Err(meta.error("`resource = \"..\"` belongs on a variant's field"))
            } else {
                Err(meta.error(
                    "unsupported `#[permission(...)]` key on enum (expected `roles = [..]`)",
                ))
            }
        })?;
    }

    Ok(out)
}

fn parse_variant_info(variant: &Variant, enum_attrs: &EnumAttrs) -> syn::Result<VariantInfo> {
    let mut name: Option<String> = None;
    let mut roles: Option<Vec<String>> = None;
    let mut saw_permission_attr = false;

    for attr in &variant.attrs {
        if !attr.path().is_ident("permission") {
            continue;
        }
        saw_permission_attr = true;

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                let lit: LitStr = meta.value()?.parse()?;
                validate_name(&lit)?;
                name = Some(lit.value());
                Ok(())
            } else if meta.path.is_ident("roles") {
                let expr: Expr = meta.value()?.parse()?;
                roles = Some(parse_string_array(&expr)?);
                Ok(())
            } else if meta.path.is_ident("resource") {
                Err(meta.error("`resource = \"..\"` belongs on the variant's field"))
            } else {
                Err(meta.error(
                    "unsupported `#[permission(...)]` key on variant (expected `name = \"..\"` or `roles = [..]`)",
                ))
            }
        })?;
    }

    let Some(name) = name else {
        return Err(syn::Error::new(
            variant.span(),
            if saw_permission_attr {
                "missing `name = \"..\"` in `#[permission(...)]`"
            } else {
                "expected `#[permission(name = \"..\")]` on variant"
            },
        ));
    };

    let roles = roles.unwrap_or_else(|| enum_attrs.default_roles.clone());

    Ok(VariantInfo {
        ident: variant.ident.clone(),
        name,
        roles,
        resource: parse_resource_field(&variant.fields)?,
    })
}

/// Patterns split at the first separator, so `A.B.*` couldn't match `A.B.C`.
fn validate_name(lit: &LitStr) -> syn::Result<()> {
    let name = lit.value();
    if name.contains('*') {
        return Err(syn::Error::new_spanned(
            lit,
            "permission name cannot contain `*`",
        ));
    }
    if name.matches(['.', ':']).count() > 1 {
        return Err(syn::Error::new_spanned(
            lit,
            "permission name can have at most one `.` or `:` separator",
        ));
    }
    Ok(())
}

fn parse_resource_field(fields: &Fields) -> syn::Result<Option<ResourceField>> {
    let mut iter = fields.iter();
    let Some(field) = iter.next() else {
        return Ok(None);
    };
    if let Some(extra) = iter.next() {
        return Err(syn::Error::new(
            extra.span(),
            "a permission variant has at most one field, its resource",
        ));
    }

    let mut kind: Option<String> = None;
    for attr in &field.attrs {
        if !attr.path().is_ident("permission") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("resource") {
                return Err(meta.error(
                    "unsupported `#[permission(...)]` key on field (expected `resource = \"..\"`)",
                ));
            }
            if kind.is_some() {
                return Err(meta.error("duplicate `resource = \"..\"`"));
            }
            let lit: LitStr = meta.value()?.parse()?;
            if lit.value().is_empty() {
                return Err(syn::Error::new_spanned(
                    lit,
                    "resource kind cannot be empty",
                ));
            }
            kind = Some(lit.value());
            Ok(())
        })?;
    }

    let Some(kind) = kind else {
        return Err(syn::Error::new(
            field.span(),
            "a permission field is its resource; mark it with `#[permission(resource = \"kind\")]`",
        ));
    };

    let member = match &field.ident {
        Some(ident) => syn::Member::Named(ident.clone()),
        None => syn::Member::Unnamed(syn::Index::from(0)),
    };

    Ok(Some(ResourceField { member, kind }))
}

fn parse_string_array(expr: &Expr) -> syn::Result<Vec<String>> {
    let Expr::Array(ExprArray { elems, .. }) = expr else {
        return Err(syn::Error::new(
            expr.span(),
            "expected a string array like `[\"owner\", \"operator\"]`",
        ));
    };

    elems
        .iter()
        .map(|expr| match expr {
            Expr::Lit(ExprLit {
                lit: Lit::Str(s), ..
            }) => Ok(s.value()),
            other => Err(syn::Error::new(
                other.span(),
                "expected a string literal inside the role array",
            )),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use proc_macro2::TokenStream;
    use quote::quote;

    fn try_expand(input: TokenStream) -> syn::Result<TokenStream> {
        let parsed: syn::DeriveInput = syn::parse2(input)?;
        super::expand(&parsed)
    }

    fn expand_ok(input: TokenStream) -> String {
        try_expand(input).expect("should expand").to_string()
    }

    #[test]
    fn expands_basic_enum_with_default_roles() {
        let input = quote! {
            #[permission(roles = ["owner", "operator"])]
            pub enum CompanyPermission {
                #[permission(name = "Companies.List")]
                List,
                #[permission(name = "Companies.Create", roles = ["owner"])]
                Create,
            }
        };

        let expanded = expand_ok(input);

        assert!(expanded.contains("Self :: List { .. } => \"Companies.List\""));
        assert!(expanded.contains("Self :: Create { .. } => \"Companies.Create\""));
        assert!(expanded.contains("roles : & [\"owner\" , \"operator\"]"));
        assert!(expanded.contains("roles : & [\"owner\"]"));
        assert_eq!(
            expanded.contains(":: permkit :: utoipa :: ToSchema for CompanyPermission"),
            cfg!(feature = "utoipa")
        );
        assert!(expanded.contains(":: permkit :: serde :: Serialize for CompanyPermission"));
        assert!(expanded.contains(":: core :: convert :: AsRef < str > for CompanyPermission"));
        assert!(expanded.contains(":: permkit :: inventory :: submit"));
        assert!(expanded.contains(":: permkit :: PermissionEntry"));
        assert!(expanded.contains("Cow :: Borrowed (\"Companies.List\")"));
        assert!(expanded.contains("enum_name : \"CompanyPermission\""));
        assert!(expanded.contains("resource : :: core :: option :: Option :: None"));
        assert!(expanded.contains(":: permkit :: Permission for CompanyPermission"));
    }

    #[test]
    fn expands_resource_fields() {
        let input = quote! {
            pub enum P {
                #[permission(name = "Users.List")]
                List(#[permission(resource = "company")] CompanyId),
                #[permission(name = "Users.Remove")]
                Remove {
                    #[permission(resource = "customer")]
                    customer_id: CustomerId,
                },
            }
        };

        let expanded = expand_ok(input);

        assert!(expanded.contains("Self :: List { .. } => \"Users.List\""));
        assert!(expanded.contains(
            "Self :: List { 0 : __resource } => :: core :: option :: Option :: Some (:: permkit :: Resource :: new (\"company\" , __resource))"
        ));
        assert!(expanded.contains("Self :: Remove { customer_id : __resource }"));
        assert!(expanded.contains("resource : :: core :: option :: Option :: Some (\"company\")"));
        assert!(expanded.contains("resource : :: core :: option :: Option :: Some (\"customer\")"));
    }

    #[test]
    fn rejects_more_than_one_field() {
        let input = quote! {
            pub enum P {
                #[permission(name = "Users.Remove")]
                Remove {
                    #[permission(resource = "customer")]
                    customer_id: CustomerId,
                    #[permission(resource = "company")]
                    company_id: CompanyId,
                },
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("at most one field"));
    }

    #[test]
    fn rejects_fields_without_resource_kind() {
        let input = quote! {
            pub enum P {
                #[permission(name = "A.B")]
                Variant(String),
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("#[permission(resource"));
    }

    #[test]
    fn rejects_resource_on_variant() {
        let input = quote! {
            pub enum P {
                #[permission(name = "A.B", resource = "company")]
                Variant,
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("belongs on the variant's field"));
    }

    #[test]
    fn rejects_resource_on_enum() {
        let input = quote! {
            #[permission(resource = "company")]
            pub enum P {
                #[permission(name = "A.B")]
                Variant,
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("belongs on a variant's field"));
    }

    #[test]
    fn rejects_unknown_keys_on_field() {
        let input = quote! {
            pub enum P {
                #[permission(name = "A.B")]
                Variant(#[permission(name = "A.C")] CompanyId),
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("key on field"));
    }

    #[test]
    fn rejects_duplicate_resource() {
        let input = quote! {
            pub enum P {
                #[permission(name = "A.B")]
                Variant(
                    #[permission(resource = "company")]
                    #[permission(resource = "customer")]
                    CompanyId
                ),
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("duplicate `resource"));
    }

    #[test]
    fn rejects_empty_resource_kind() {
        let input = quote! {
            pub enum P {
                #[permission(name = "A.B")]
                Variant(#[permission(resource = "")] CompanyId),
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn variant_without_roles_inherits_default() {
        let input = quote! {
            #[permission(roles = ["owner"])]
            pub enum P {
                #[permission(name = "A.B")]
                Variant,
            }
        };

        let expanded = expand_ok(input);
        assert!(expanded.contains("roles : & [\"owner\"]"));
    }

    #[test]
    fn no_default_roles_means_empty_slice() {
        let input = quote! {
            pub enum P {
                #[permission(name = "A.B")]
                Variant,
            }
        };

        let expanded = expand_ok(input);
        assert!(expanded.contains("roles : & []"));
    }

    #[test]
    fn rejects_non_enums() {
        let input = quote! {
            pub struct Foo;
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("can only be derived for enums"));
    }

    #[test]
    fn rejects_missing_name() {
        let input = quote! {
            pub enum P {
                Variant,
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("permission(name"));
    }

    #[test]
    fn rejects_duplicate_names() {
        let input = quote! {
            pub enum P {
                #[permission(name = "A.B")]
                X,
                #[permission(name = "A.B")]
                Y,
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("duplicate permission name"));
    }

    #[test]
    fn rejects_wildcard_names() {
        let input = quote! {
            pub enum P {
                #[permission(name = "Users.*")]
                X,
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("cannot contain `*`"));
    }

    #[test]
    fn rejects_names_with_several_separators() {
        let input = quote! {
            pub enum P {
                #[permission(name = "Users.Admin:Delete")]
                X,
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("at most one"));
    }

    #[test]
    fn rejects_unknown_keys_on_variant() {
        let input = quote! {
            pub enum P {
                #[permission(name = "A.B", description = "nope")]
                X,
            }
        };
        let err = try_expand(input).expect_err("should fail");
        assert!(err.to_string().contains("unsupported"));
    }
}
