use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::{quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;

fn token_stream_with_error(mut tokens: TokenStream, error: syn::Error) -> TokenStream {
    tokens.extend(TokenStream::from(error.into_compile_error()));
    tokens
}

pub(crate) fn qs_test(_args: &TokenStream, item: TokenStream, with_init: bool) -> TokenStream {
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

    let init = if with_init {
        quote! {
            test_server.initialise_helper(duration_from_epoch_now())
                .await
                .expect("init failed!");
        }
    } else {
        quote! {}
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
                let test_server = crate::testkit::setup_test().await;

                #init

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

pub(crate) fn qs_pair_test(_args: &TokenStream, item: TokenStream, with_init: bool) -> TokenStream {
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

    let init = if with_init {
        quote! {
            server_a.initialise_helper(duration_from_epoch_now())
                .await
                .expect("init_a failed!");
            server_b.initialise_helper(duration_from_epoch_now())
                .await
                .expect("init_b failed!");
        }
    } else {
        quote! {}
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
                let (server_a, server_b) = crate::testkit::setup_pair_test().await;

                #init

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
    let audit = args.to_string() == "audit";

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

    let test_fn = &input.sig.ident;
    let test_driver = Ident::new(&format!("idm_{}", test_fn), input.sig.span());

    let test_fn_args = if audit {
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
                let (test_server, mut idms_delayed, mut idms_audit)  = crate::testkit::setup_idm_test().await;

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
