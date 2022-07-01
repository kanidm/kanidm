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
