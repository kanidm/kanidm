#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

mod entry;

#[allow(unused_extern_crates)]
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;

#[proc_macro_attribute]
pub fn test(args: TokenStream, item: TokenStream) -> TokenStream {
    entry::test(args, item)
}

#[proc_macro]
/// used in testkit to run the kanidm client with the correct environment variables
pub fn cli_kanidm(_input: TokenStream) -> TokenStream {
    let code = quote! {
        {
        let mut kanidm = Command::cargo_bin("kanidm").unwrap();
        kanidm.env("KANIDM_URL", &rsclient.get_url().to_string());
        kanidm.env("KANIDM_TOKEN_CACHE_PATH", &token_cache_path);
        kanidm
        }
    };

    code.into()
}
