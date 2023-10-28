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
/// used in testkit to build and run the kanidm binary with the correct environment variables
pub fn cli_kanidm(_input: TokenStream) -> TokenStream {
    let code = quote! {
        {
        // get the manifest path for the kanidm binary
        let cli_manifest_file_path =
            format!("{}/../../tools/cli/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
        let cli_manifest_file = std::path::Path::new(&cli_manifest_file_path)
            .canonicalize()
            .unwrap();

        // make sure we're building/running the current version
        let mut kanidm = escargot::CargoBuild::new()
            .bin("kanidm")
            .current_release()
            .current_target()
            .manifest_path(&cli_manifest_file)
            .run()
            .unwrap();
        let mut kanidm = kanidm.command();
        kanidm.env("KANIDM_URL", &rsclient.get_url().to_string());
        kanidm.env("KANIDM_TOKEN_CACHE_PATH", &token_cache_path);
        kanidm
        }
    };

    code.into()
}
