///! Middleware for the tide web server

#[derive(Default)]
/// Injects the domain_display_name where it needs to
pub struct KanidmDisplayNameMiddleware {
    domain_display_name: String,
}

// TODO: finish this for #860
#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> tide::Middleware<State> for KanidmDisplayNameMiddleware {
    async fn handle(
        &self,
        request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        let mut response = next.run(request).await;
        // grab the body we're intending to return at this point
        let body_str = response.take_body().into_string().await?;
        // update it with the hash
        // TODO: #860 make this a const so we can change it and not typo it later
        response.set_body(body_str.replace(
            "===DOMAIN_DISPLAY_NAME===",
            self.domain_display_name.as_str(),
        ));
        Ok(response)
    }
}

impl KanidmDisplayNameMiddleware {
    /// Pulls the domain_display_name from the qs on web server start, so we can
    /// set it in pages
    pub fn new(domain_display_name: String) -> Self {
        KanidmDisplayNameMiddleware {
            // TODO: #860 work out how to get this out :D
            domain_display_name: domain_display_name,
        }
    }
}

#[derive(Default)]
/// This tide MiddleWare adds headers like Content-Security-Policy
/// and similar families. If it keeps adding more things then
/// probably rename the middlewre :)
pub struct UIContentSecurityPolicyResponseMiddleware {
    // The sha384 hash of /pkg/wasmloader.js
    pub integrity_wasmloader: String,
}
impl UIContentSecurityPolicyResponseMiddleware {
    pub fn new(integrity_wasmloader: String) -> Self {
        return Self {
            integrity_wasmloader,
        };
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

        // grab the body we're intending to return at this point
        let body_str = response.take_body().into_string().await?;
        // update it with the hash
        response.set_body(body_str.replace("==WASMHASH==", self.integrity_wasmloader.as_str()));
        response.insert_header(
            /* content-security-policy headers tell the browser what to trust
                https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

                In this case we're only trusting the same server that the page is
                loaded from, and adding a hash of wasmloader.js, which is the main script
                we should be loading, and should be really secure about that!

            */
            // TODO: consider scraping the other js files that wasm-pack builds and including them too
            "content-security-policy",
            vec![
                "default-src 'self'",
                // we need unsafe-eval because of WASM things
                format!(
                    "script-src 'self' 'sha384-{}' 'unsafe-eval'",
                    self.integrity_wasmloader.as_str()
                )
                .as_str(),
                "form-action https: 'self'", // to allow for OAuth posts
                // we are not currently using workers so it can be blocked
                "worker-src 'none'",
                // TODO: Content-Security-Policy-Report-Only https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
                // "report-to 'none'", // unsupported by a lot of things still, but mozilla's saying report-uri is deprecated?
                "report-uri 'none'",
                "base-uri 'self'",
            ]
            .join(";"),
        );

        Ok(response)
    }
}
