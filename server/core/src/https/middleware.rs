use regex::Regex;

///! Custom tide middleware for Kanidm
use crate::https::JavaScriptFile;

/// This is for the tide_compression middleware so that we only compress certain content types.
///
/// ```
/// use kanidmd_core::https::middleware::compression_content_type_checker;
/// let these_should_match = vec![
///     "application/wasm",
///     "application/x-javascript",
///     "application/x-javascript; charset=utf-8",
///     "image/svg+xml",
///     "text/json",
///     "text/javascript",
/// ];
/// for test_value in these_should_match {
///     eprintln!("checking {:?}", test_value);
///     assert!(compression_content_type_checker().is_match(test_value));
/// }
/// assert!(compression_content_type_checker().is_match("application/wasm"));
/// let these_should_be_skipped = vec![
///     "application/manifest+json",
///     "image/jpeg",
///     "image/wasm",
///     "text/html",
/// ];
/// for test_value in these_should_be_skipped {
///     eprintln!("checking {:?}", test_value);
///     assert!(!compression_content_type_checker().is_match(test_value));
/// }
/// ```
pub fn compression_content_type_checker() -> Regex {
    Regex::new(r"^(?:(image/svg\+xml)|(?:application|text)/(?:css|javascript|json|text|x-javascript|xml|wasm))(|; charset=utf-8)$")
    .expect("regex matcher for tide_compress content-type check failed to compile")
}

#[derive(Default)]
pub struct CacheableMiddleware;

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> tide::Middleware<State> for CacheableMiddleware {
    async fn handle(
        &self,
        request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        let mut response = next.run(request).await;
        response.insert_header("Cache-Control", "max-age=300,must-revalidate,private");
        Ok(response)
    }
}

#[derive(Default)]
pub struct NoCacheMiddleware;

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> tide::Middleware<State> for NoCacheMiddleware {
    async fn handle(
        &self,
        request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        let mut response = next.run(request).await;
        response.insert_header("Cache-Control", "no-store, max-age=0");
        response.insert_header("Pragma", "no-cache");
        Ok(response)
    }
}

#[derive(Default)]
/// Sets Cache-Control headers on static content endpoints
pub struct StaticContentMiddleware;

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> tide::Middleware<State> for StaticContentMiddleware {
    async fn handle(
        &self,
        request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        let mut response = next.run(request).await;
        response.insert_header("Cache-Control", "max-age=3600,private");
        Ok(response)
    }
}

#[derive(Default)]
/// Adds the following headers to responses
/// - x-frame-options
/// - x-content-type-options
/// - cross-origin-resource-policy
/// - cross-origin-embedder-policy
/// - cross-origin-opener-policy
pub struct StrictResponseMiddleware;

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> tide::Middleware<State> for StrictResponseMiddleware {
    async fn handle(
        &self,
        request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        let mut response = next.run(request).await;
        response.insert_header("cross-origin-embedder-policy", "require-corp");
        response.insert_header("cross-origin-opener-policy", "same-origin");
        response.insert_header("cross-origin-resource-policy", "same-origin");
        response.insert_header("x-content-type-options", "nosniff");
        Ok(response)
    }
}

// unused
// #[derive(Default)]
// struct StrictRequestMiddleware;

// #[async_trait::async_trait]
// impl<State: Clone + Send + Sync + 'static> tide::Middleware<State> for StrictRequestMiddleware {
//     async fn handle(
//         &self,
//         request: tide::Request<State>,
//         next: tide::Next<'_, State>,
//     ) -> tide::Result {
//         let proceed = request
//             .header("sec-fetch-site")
//             .map(|hv| {
//                 matches!(hv.as_str(), "same-origin" | "same-site" | "none")
//                     || (request.header("sec-fetch-mode").map(|v| v.as_str()) == Some("navigate")
//                         && request.method() == tide::http::Method::Get
//                         && request.header("sec-fetch-dest").map(|v| v.as_str()) != Some("object")
//                         && request.header("sec-fetch-dest").map(|v| v.as_str()) != Some("embed"))
//             })
//             .unwrap_or(true);

//         if proceed {
//             Ok(next.run(request).await)
//         } else {
//             Err(tide::Error::from_str(
//                 tide::StatusCode::MethodNotAllowed,
//                 "StrictRequestViolation",
//             ))
//         }
//     }
// }

#[derive(Default)]
/// This tide MiddleWare adds headers like Content-Security-Policy
/// and similar families. If it keeps adding more things then
/// probably rename the middleware :)
pub struct UIContentSecurityPolicyResponseMiddleware {
    // The sha384 hash of /pkg/wasmloader.js
    pub hashes: Vec<JavaScriptFile>,
}
impl UIContentSecurityPolicyResponseMiddleware {
    pub fn new(hashes: Vec<JavaScriptFile>) -> Self {
        Self { hashes }
    }
}

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> tide::Middleware<State>
    for UIContentSecurityPolicyResponseMiddleware
{
    // This updates the UI body with the integrity hash value for the wasmloader.js file, and adds content-security-policy headers.
    async fn handle(
        &self,
        request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        let mut response = next.run(request).await;

        // a list of hashes of js files that we're sending to the user
        let hashes: Vec<String> = self
            .hashes
            .iter()
            .map(|j| format!("'{}'", j.hash))
            .collect();

        response.insert_header(
            /* content-security-policy headers tell the browser what to trust
                https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

                In this case we're only trusting the same server that the page is
                loaded from, and adding a hash of wasmloader.js, which is the main script
                we should be loading, and should be really secure about that!

            */
            "content-security-policy",
            vec![
                "default-src 'self'",
                // TODO: #912 have a dev/test mode where we can rebuild the hashes on page load, so when doing constant JS changes/rebuilds we don't have to restart the server every time. It'd be *terrible* to run in prod because of the constant disk thrashing, but nicer for devs.
                // we need unsafe-eval because of WASM things
                format!("script-src 'self' {} 'unsafe-eval'", hashes.join(" ")).as_str(),
                "form-action https: 'self'", // to allow for OAuth posts
                // we are not currently using workers so it can be blocked
                "worker-src 'none'",
                // TODO: Content-Security-Policy-Report-Only https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
                // "report-to 'none'", // unsupported by a lot of things still, but mozilla's saying report-uri is deprecated?
                // Commented because when violated this attempts to post to "'none'" as a url
                // "report-uri 'none'",
                "base-uri 'self'",
                // nobody wants to be in a frame
                "frame-ancestors 'none'",
                // allow inline images because bootstrap
                "img-src 'self' data:",
            ]
            .join(";"),
        );

        Ok(response)
    }
}

const KANIDM_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct VersionHeaderMiddleware;

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> tide::Middleware<State> for VersionHeaderMiddleware {
    async fn handle(
        &self,
        request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        let mut response = next.run(request).await;
        response.insert_header("X-KANIDM-VERSION", KANIDM_VERSION);
        Ok(response)
    }
}
