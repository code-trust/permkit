use proc_macro::TokenStream;
use quote::{
    format_ident,
    quote,
};
use syn::punctuated::Punctuated;
use syn::{
    Expr,
    ExprAssign,
    ExprPath,
    FnArg,
    Ident,
    ItemFn,
    Pat,
    PatType,
    Path,
    Token,
    Type,
    TypePath,
    parse_macro_input,
    parse_quote,
};

#[proc_macro_attribute]
pub fn permissions(args: TokenStream, input: TokenStream) -> TokenStream {
    let exprs = parse_macro_input!(args with Punctuated::<Expr, Token![,]>::parse_terminated);
    let func = parse_macro_input!(input as ItemFn);

    match expand_permissions_impl(func, &exprs) {
        Ok(expanded) => quote!(#expanded).into(),
        Err(error) => error.to_compile_error().into(),
    }
}

#[derive(Default)]
struct PermissionArgs {
    context: Option<Expr>,
    error: Option<Expr>,
    permissions: Vec<Expr>,
}

fn expand_permissions_impl(
    mut func: ItemFn,
    exprs: &Punctuated<Expr, Token![,]>,
) -> syn::Result<ItemFn> {
    let args = parse_args(exprs)?;
    let context = if let Some(context) = args.context {
        context
    } else {
        let db_ident = ensure_typed_arg(
            &mut func,
            &syn::parse_quote!(crate::database::Database),
            "db",
        )?;
        parse_quote!(#db_ident)
    };
    let denied_error = args.error.map_or_else(
        || quote!(::permkit::PermissionDenied::permission_denied()),
        |error| quote!(::core::convert::Into::into(#error)),
    );

    let checks = args.permissions.iter().map(|permission| {
        quote! {
            if !::permkit::HasPermission::has_permission(&(#permission), &(#context)).await? {
                return Err(#denied_error);
            }
        }
    });

    let body = func.block;
    func.block = Box::new(syn::parse_quote!({
        #(#checks)*
        #body
    }));

    Ok(func)
}

fn ensure_typed_arg(func: &mut ItemFn, ty: &Type, fallback: &str) -> syn::Result<Ident> {
    let Type::Path(TypePath { path: expected, .. }) = ty else {
        return Err(syn::Error::new_spanned(ty, "expected a path type"));
    };

    let expected_last = expected.segments.last().map(|segment| &segment.ident);
    let matches_expected = |path: &Path| {
        path == expected || path.segments.last().map(|segment| &segment.ident) == expected_last
    };

    if let Some(ident) = func.sig.inputs.iter().find_map(|arg| match arg {
        FnArg::Typed(PatType { pat, ty, .. }) => {
            let (Pat::Ident(pat), Type::Path(TypePath { path, .. })) = (pat.as_ref(), ty.as_ref())
            else {
                return None;
            };

            matches_expected(path).then_some(pat.ident.clone())
        }
        _ => None,
    }) {
        return Ok(ident);
    }

    let ident = format_ident!("{fallback}");
    func.sig.inputs.insert(0, parse_quote! { #ident: #ty });
    Ok(ident)
}

fn parse_args(exprs: &Punctuated<Expr, Token![,]>) -> syn::Result<PermissionArgs> {
    let mut args = PermissionArgs::default();

    for expr in exprs {
        match expr {
            Expr::Assign(assign) if is_assignment_to(assign, "context") => {
                if args.context.replace((*assign.right).clone()).is_some() {
                    return Err(syn::Error::new_spanned(expr, "duplicate `context = ...`"));
                }
            }
            Expr::Assign(assign) if is_assignment_to(assign, "error") => {
                if args.error.replace((*assign.right).clone()).is_some() {
                    return Err(syn::Error::new_spanned(expr, "duplicate `error = ...`"));
                }
            }
            Expr::Assign(assign) => {
                return Err(syn::Error::new_spanned(
                    assign,
                    "unsupported assignment in `#[permissions(...)]`",
                ));
            }
            _ => args.permissions.push(expr.clone()),
        }
    }

    Ok(args)
}

fn is_assignment_to(assign: &ExprAssign, ident: &str) -> bool {
    let Expr::Path(ExprPath { path, .. }) = assign.left.as_ref() else {
        return false;
    };

    path.is_ident(ident)
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse::Parser as _;
    use syn::punctuated::Punctuated;
    use syn::{
        Expr,
        ItemFn,
        Token,
    };

    fn expand_permissions(
        args: proc_macro2::TokenStream,
        input: proc_macro2::TokenStream,
    ) -> ItemFn {
        let exprs = Punctuated::<Expr, Token![,]>::parse_terminated
            .parse2(args)
            .expect("attribute args should parse");
        let func = syn::parse2::<ItemFn>(input).expect("function should parse");
        super::expand_permissions_impl(func, &exprs).expect("failed to expand")
    }

    #[test]
    fn inserts_permission_checks_before_handler_body() {
        let input = quote! {
            async fn sample(context: Context) -> Result<(), Error> {
                Ok(())
            }
        };

        let expanded = expand_permissions(
            quote! {
                Permission::Read,
                context = context,
                error = Error::Forbidden
            },
            input,
        );
        let block_tokens = {
            let block = &expanded.block;
            quote! { #block }.to_string()
        };

        assert!(block_tokens.contains("HasPermission :: has_permission"));
        assert!(block_tokens.contains("Permission :: Read"));
        assert!(block_tokens.contains("Error :: Forbidden"));
        assert!(block_tokens.contains("Ok (())"));
    }

    #[test]
    fn infers_database_context_and_backend_error() {
        let input = quote! {
            async fn sample() -> Result<(), Error> {
                Ok(())
            }
        };

        let expanded = expand_permissions(quote! { Permission::Read }, input);
        let inputs = quote! { #expanded }.to_string();
        let block_tokens = {
            let block = &expanded.block;
            quote! { #block }.to_string()
        };

        assert!(inputs.contains("db : crate :: database :: Database"));
        assert!(block_tokens.contains("Permission :: Read"));
        assert!(block_tokens.contains("PermissionDenied :: permission_denied"));
    }
}
