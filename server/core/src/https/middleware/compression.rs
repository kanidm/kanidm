/*
    Let's build a compression middleware!

    The threat of the TLS BREACH attack [1] was considered as part of adding
    the CompressMiddleware configuration.

    The attack targets secrets compressed and encrypted in flight with the intent
    to infer their content.

    This is not a concern for the paths covered by this configuration
    ( /, /ui/<and all sub-paths>, /pkg/<and all sub-paths> ),
    as they're all static content with no secrets in transit - all that data should
    come from Kanidm's REST API, which is on a different path and not covered by
    the compression middleware.


    [1] - https://resources.infosecinstitute.com/topic/the-breach-attack/
*/

use tower_http::compression::CompressionLayer;
pub fn new() -> CompressionLayer {
    CompressionLayer::new()
        .no_br()
        .quality(tower_http::CompressionLevel::Best)
}
