use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use syn::spanned::Spanned;

use quote::{quote, quote_spanned, ToTokens};

fn parse_knobs(input: &syn::ItemFn) -> TokenStream {
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

    let fn_name = &input.sig.ident;
    let test_driver = Ident::new(&format!("tk_{}", fn_name), input.sig.span());

    // Effectively we are just injecting a real test function around this which we will
    // call.

    let result = quote! {
        #input

        #header
        fn #test_driver() {
            let body = async {
                let rsclient = kanidmd_testkit::setup_async_test().await;
                #fn_name(rsclient).await
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

pub(crate) fn test(_args: &TokenStream, item: TokenStream) -> TokenStream {
    // If any of the steps for this macro fail, we still want to expand to an item that is as close
    // to the expected output as possible. This helps out IDEs such that completions and other
    // related features keep working.
    let input: syn::ItemFn = match syn::parse(item.clone()) {
        Ok(it) => it,
        Err(e) => return token_stream_with_error(item, e),
    };

    if let Some(attr) = input.attrs.iter().find(|attr| attr.path.is_ident("test")) {
        let msg = "second test attribute is supplied";
        return token_stream_with_error(item, syn::Error::new_spanned(attr, msg));
    };

    if input.sig.asyncness.is_none() {
        let msg = "the `async` keyword is missing from the function declaration";
        return token_stream_with_error(item, syn::Error::new_spanned(input.sig.fn_token, msg));
    }

    parse_knobs(&input)
}
