use std::{any::Any, collections::HashMap, sync::LazyLock};

use askama::Template;
use axum::{
    body::Body,
    http::HeaderValue,
    response::{IntoResponse as _, Response},
};
use bytes::Bytes;
use fluent::{concurrent::FluentBundle, FluentResource};
use hyper::{header::CONTENT_TYPE, StatusCode};
use unic_langid::{langid, LanguageIdentifier};

use crate::https::middleware::i18n::I18nCtx;

/// One of the options, seemed like a good fit with askama, but a build script can do this without an
/// extra dependency too
#[derive(rust_embed::Embed)]
#[folder = "i18n/"]
struct I18nAssets;

pub(crate) const DEFAULT_LANGUAGE: LanguageIdentifier = langid!("en-AU");
/// tl;dr: quickly thrown together, needs to be done better in the final implementation
///
/// This is a bit messy, LazyLock because this is accessed from async code, but
/// `fluent::concurrent::FluentBundle` also has an internal Mutex because it uses a cache for
/// formatters (which is generally not a great idea for a web server imo). Keeping this static, it
/// could be moved to a thread local to lose both the LazyLock and internal Mutex at the cost of
/// memory usage (not much though, FluentBundle can take references to FluentResource and resources
/// are not modified).
/// Alternatively, this could be put in the server state, but due to how askama works we'd need to
/// either:
/// - put the bundle into every template struct; or
/// - put the bundle into askama::Values instead of the language code
/// The first is going to make a mess of the code, the second is doable (probably following the the
/// singletons already in the state) but more effort than a poc should get
pub(crate) static I18N_BUNDLES: LazyLock<
    HashMap<LanguageIdentifier, FluentBundle<FluentResource>>,
> = LazyLock::new(|| {
    let mut bundles = HashMap::new();

    for path in I18nAssets::iter() {
        let (lang, _) = path.split_once('/').unwrap();
        let lang: LanguageIdentifier = lang.parse().unwrap();

        if !bundles.contains_key(&lang) {
            bundles.insert(
                lang.clone(),
                FluentBundle::new_concurrent(vec![lang.clone()]),
            );
        }

        let cont = I18nAssets::get(&path).unwrap().data;
        let cont = String::from_utf8(cont.to_vec()).unwrap();
        let res = FluentResource::try_new(cont).unwrap();
        bundles.get_mut(&lang).unwrap().add_resource(res).unwrap();
    }

    bundles
});

/// This is intended to replace `#[derive(WebTemplate)]` since that doesn't render with environment
/// variables. I think it can be done without having every render call `into_response_with_i18n`
/// manually, but I didn't want to spend too much time on it now.
pub trait IntoResponseWithI18n {
    fn into_response_with_i18n(self, ctx: I18nCtx) -> Response;
}

impl<T> IntoResponseWithI18n for T
where
    T: Template,
{
    fn into_response_with_i18n(self, ctx: I18nCtx) -> Response {
        let mut values = HashMap::<&str, Box<dyn Any>>::new();
        values.insert("lang", Box::new(ctx.lang));
        let (status, content_type, body) = match self.render_with_values(&values) {
            Ok(body) => (StatusCode::OK, HTML, Bytes::from_owner(body)),
            Err(err) => {
                error!(?err, "Error rendering with i18n");
                (StatusCode::INTERNAL_SERVER_ERROR, TEXT, FAIL)
            }
        };

        let mut resp = Body::from(body).into_response();
        *resp.status_mut() = status;
        resp.headers_mut().insert(CONTENT_TYPE, content_type);
        resp
    }
}

const HTML: HeaderValue = HeaderValue::from_static("text/html");
const TEXT: HeaderValue = HeaderValue::from_static("text/plain");
const FAIL: Bytes = Bytes::from_static("INTERNAL SERVER ERROR".as_bytes());
