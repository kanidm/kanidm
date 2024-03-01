use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::{quote, quote_spanned, ToTokens};
use syn::{parse::Parser, punctuated::Punctuated, spanned::Spanned, ExprAssign, Token};

fn token_stream_with_error(mut tokens: TokenStream, error: syn::Error) -> TokenStream {
    tokens.extend(TokenStream::from(error.into_compile_error()));
    tokens
}

const ALLOWED_ATTRIBUTES: &[&str] = &["audit", "domain_level"];

#[derive(Default)]
struct Flags {
    audit: bool,
}

fn parse_attributes(
    args: &TokenStream,
    input: &syn::ItemFn,
) -> Result<(proc_macro2::TokenStream, Flags), syn::Error> {
    let args: Punctuated<ExprAssign, syn::token::Comma> =
        match Punctuated::<ExprAssign, Token![,]>::parse_terminated.parse(args.clone()) {
            Ok(it) => it,
            Err(e) => return Err(e),
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
        let msg = "Invalid test config attribute. The following are allow";
        return Err(syn::Error::new_spanned(
            input.sig.fn_token,
            format!("{}: {}", msg, ALLOWED_ATTRIBUTES.join(", ")),
        ));
    }

    let mut flags = Flags::default();
    let mut field_modifications = quote! {};

    args.pairs().for_each(|p| {
        match p
            .value()
            .left
            .span()
            .source_text()
            .unwrap_or_default()
            .as_str()
        {
            "audit" => flags.audit = true,
            _ => {
                let field_name = p.value().left.to_token_stream(); // here we can use to_token_stream as we know we're iterating over ExprAssigns
                let field_value = p.value().right.to_token_stream();
                field_modifications.extend(quote! {
                #field_name: #field_value,})
            }
        }
    });

    let ts = quote!(crate::testkit::TestConfiguration {
        #field_modifications
        ..crate::testkit::TestConfiguration::default()
    });

    Ok((ts, flags))
}

pub(crate) fn qs_test(args: TokenStream, item: TokenStream) -> TokenStream {
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

    // Setup the config filling the remaining fields with the default values
    let (default_config_struct, _flags) = match parse_attributes(&args, &input) {
        Ok(dc) => dc,
        Err(e) => return token_stream_with_error(args, e),
    };

    let rt = quote_spanned! {last_stmt_start_span=>
        tokio::runtime::Builder::new_current_thread()
    };

    let header = quote! {
        #[::core::prelude::v1::test]
    };

    let test_fn = &input.sig.ident;
    let test_driver = Ident::new(&format!("qs_{}", test_fn), input.sig.span());

    // Effectively we are just injecting a real test function around this which we will
    // call.

    let result = quote! {
        #input

        #header
        fn #test_driver() {
            let body = async {
                let test_config = #default_config_struct;

                let test_server = crate::testkit::setup_test(test_config).await;

                #test_fn(&test_server).await;

                // Any needed teardown?
                // Clear the cache before we verify.
                assert!(test_server.clear_cache().await.is_ok());
                // Make sure there are no errors.
                let verifications = test_server.verify().await;
                trace!("Verification result: {:?}", verifications);
                assert!(verifications.len() == 0);
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

pub(crate) fn qs_pair_test(args: &TokenStream, item: TokenStream) -> TokenStream {
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

    let rt = quote_spanned! {last_stmt_start_span=>
        tokio::runtime::Builder::new_current_thread()
    };

    let header = quote! {
        #[::core::prelude::v1::test]
    };

    // Setup the config filling the remaining fields with the default values
    let (default_config_struct, _flags) = match parse_attributes(args, &input) {
        Ok(dc) => dc,
        Err(e) => return token_stream_with_error(args.clone(), e),
    };

    let test_fn = &input.sig.ident;
    let test_driver = Ident::new(&format!("qs_{}", test_fn), input.sig.span());

    // Effectively we are just injecting a real test function around this which we will
    // call.

    let result = quote! {
        #input

        #header
        fn #test_driver() {
            let body = async {
                let test_config = #default_config_struct;

                let (server_a, server_b) = crate::testkit::setup_pair_test(test_config).await;

                #test_fn(&server_a, &server_b).await;

                // Any needed teardown?
                assert!(server_a.clear_cache().await.is_ok());
                assert!(server_b.clear_cache().await.is_ok());
                // Make sure there are no errors.
                let verifications_a = server_a.verify().await;
                let verifications_b = server_b.verify().await;
                trace!("Verification result: {:?}, {:?}", verifications_a, verifications_b);
                assert!(verifications_a.len() + verifications_b.len() == 0);
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

pub(crate) fn idm_test(args: &TokenStream, item: TokenStream) -> TokenStream {
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

    // Setup the config filling the remaining fields with the default values
    let (default_config_struct, flags) = match parse_attributes(args, &input) {
        Ok(dc) => dc,
        Err(e) => return token_stream_with_error(args.clone(), e),
    };

    let rt = quote_spanned! {last_stmt_start_span=>
        tokio::runtime::Builder::new_current_thread()
    };

    let header = quote! {
        #[::core::prelude::v1::test]
    };

    let test_fn = &input.sig.ident;
    let test_driver = Ident::new(&format!("idm_{}", test_fn), input.sig.span());

    let test_fn_args = if flags.audit {
        quote! {
            &test_server, &mut idms_delayed, &mut idms_audit
        }
    } else {
        quote! {
            &test_server, &mut idms_delayed
        }
    };

    // Effectively we are just injecting a real test function around this which we will
    // call.

    let result = quote! {
        #input

        #header
        fn #test_driver() {
            let body = async {
                let test_config = #default_config_struct;

                let (test_server, mut idms_delayed, mut idms_audit)  = crate::testkit::setup_idm_test(test_config).await;

                #test_fn(#test_fn_args).await;

                // Any needed teardown?
                // assert!(test_server.clear_cache().await.is_ok());
                // Make sure there are no errors.
                let mut idm_read_txn = test_server.proxy_read().await;
                let verifications = idm_read_txn.qs_read.verify();
                trace!("Verification result: {:?}", verifications);
                assert!(verifications.len() == 0);

                idms_delayed.check_is_empty_or_panic();
                idms_audit.check_is_empty_or_panic();
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
