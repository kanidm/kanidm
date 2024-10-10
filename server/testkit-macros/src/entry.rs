use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use syn::{parse::Parser, punctuated::Punctuated, spanned::Spanned, ExprAssign, Token};

use quote::{quote, quote_spanned, ToTokens};

// for now we only allow a subset of the configuration to be tweaked, but it can be expanded in the future as needed

const ALLOWED_ATTRIBUTES: &[&str] = &[
    "threads",
    "db_path",
    "maximum_request",
    "trust_x_forward_for",
    "cors_allowed_origins",
    "role",
    "output_mode",
    "log_level",
];

fn parse_knobs(
    input: &syn::ItemFn,
    server_config: &Punctuated<ExprAssign, syn::token::Comma>,
) -> TokenStream {
    // If type mismatch occurs, the current rustc points to the last statement.
    let (last_stmt_start_span, _last_stmt_end_span) = {
        let mut last_stmt = input
            .block
            .stmts
            .last()
            .map(ToTokens::into_token_stream)
            .unwrap_or_default()
            .into_iter();
        // `Span` on stable Rust has a limitation that only points to the first
        // token, not the whole tokens. We can work around this limitation by
        // using the first/last span of the tokens like
        // `syn::Error::new_spanned` does.
        let start = last_stmt.next().map_or_else(Span::call_site, |t| t.span());
        let end = last_stmt.last().map_or(start, |t| t.span());
        (start, end)
    };

    // here we gather all the provided configuration in a struct like declaration
    // By now we have already checked that the configurations provided belong to the allowed subset
    let mut field_modifications = quote! {};
    server_config.pairs().for_each(|p| {
        let field_name = p.value().left.to_token_stream(); // here we can use to_token_stream as we know we're iterating over ExprAssigns
        let field_value = p.value().right.to_token_stream();
        field_modifications.extend(quote! {
        #field_name: #field_value,})
    });

    // Setup the config filling the remaining fields with the default values
    let default_config_struct = quote!(kanidmd_core::config::Configuration {
        #field_modifications
        ..kanidmd_core::config::Configuration::new_for_test()
    });

    let rt = quote_spanned! {last_stmt_start_span=>
        tokio::runtime::Builder::new_current_thread()
    };

    let header = quote! {
        #[::core::prelude::v1::test]
    };

    let fn_name = &input.sig.ident;
    let test_driver = Ident::new(&format!("tk_{}", fn_name), input.sig.span());

    // Effectively we are just injecting a real test function around this which we will
    // call.

    let result = quote! {
        #input

        #header
        fn #test_driver() {
            let body = async {
                let (rsclient, mut core_handle) = kanidmd_testkit::setup_async_test(#default_config_struct).await;
                #fn_name(rsclient).await;
                core_handle.shutdown().await;
            };
            #[allow(clippy::expect_used, clippy::diverging_sub_expression)]
            {
                return #rt
                    .enable_all()
                    .build()
                    .expect("Failed building the Runtime")
                    .block_on(body);
            }
        }
    };

    result.into()
}

fn token_stream_with_error(mut tokens: TokenStream, error: syn::Error) -> TokenStream {
    tokens.extend(TokenStream::from(error.into_compile_error()));
    tokens
}

pub(crate) fn test(args: TokenStream, item: TokenStream) -> TokenStream {
    // If any of the steps for this macro fail, we still want to expand to an item that is as close
    // to the expected output as possible. This helps out IDEs such that completions and other
    // related features keep working.
    let input: syn::ItemFn = match syn::parse(item.clone()) {
        Ok(it) => it,
        Err(e) => return token_stream_with_error(item, e),
    };

    if let Some(attr) = input.attrs.iter().find(|attr| attr.path().is_ident("test")) {
        let msg = "second test attribute is supplied";
        return token_stream_with_error(item, syn::Error::new_spanned(attr, msg));
    };

    if input.sig.asyncness.is_none() {
        let msg = "the `async` keyword is missing from the function declaration";
        return token_stream_with_error(item, syn::Error::new_spanned(input.sig.fn_token, msg));
    }
    let args: Punctuated<ExprAssign, syn::token::Comma> =
        match Punctuated::<ExprAssign, Token![,]>::parse_terminated.parse(args.clone()) {
            Ok(it) => it,
            Err(e) => return token_stream_with_error(args, e),
        };
    let args_are_allowed = args.pairs().all(|p| {
        ALLOWED_ATTRIBUTES.to_vec().contains(
            &p.value()
                .left
                .span()
                .source_text()
                .unwrap_or_default()
                .as_str(),
        )
    });
    if !args_are_allowed {
        let msg =
            "Currently only a subset of all the server configs can be set. Here is the full list";
        return token_stream_with_error(
            item,
            syn::Error::new_spanned(
                input.sig.fn_token,
                format!("{}: {}", msg, ALLOWED_ATTRIBUTES.join(", ")),
            ),
        );
    }
    parse_knobs(&input, &args)
}
