//! Builds a Progressive Web App Manifest page.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use http::header::CONTENT_TYPE;
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::middleware::KOpId;
// Thanks to the webmanifest crate for a lot of this code
use super::ServerState;

/// The MIME type for `.webmanifest` files.
const MIME_TYPE_MANIFEST: &str = "application/manifest+json;charset=utf-8";

/// Create a new manifest builder.

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    name: String,
    short_name: String,
    start_url: String,
    #[serde(rename = "display")]
    display_mode: DisplayMode,
    background_color: String,
    description: Option<String>,
    #[serde(rename = "dir")]
    direction: Direction,
    // direction: Option<Direction>,
    orientation: Option<String>,
    // orientation: Option<Orientation>,
    lang: Option<String>,
    scope: Option<String>,
    //
    theme_color: String,
    prefer_related_applications: Option<bool>,
    // #[serde(borrow)]
    //
    icons: Vec<ManifestIcon>,
    // icons: Vec<Icon<'i>>,
    // #[serde(borrow)]
    related_applications: Option<Vec<String>>,
    // related_applications: Vec<Related<'r>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ManifestIcon {
    src: String,
    #[serde(rename = "type")]
    mime_type: String,
    sizes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Direction {
    /// left-to-right
    #[serde(rename = "ltr")]
    Ltr,
    /// right-to-left
    #[serde(rename = "rtl")]
    Rtl,
    /// Hints to the browser to use the [Unicode bidirectional
    /// algorithm](https://developer.mozilla.org/en-US/docs/Web/Localization/Unicode_Bidirectional_Text_Algorithm)
    /// to make a best guess about the text's direction.
    #[serde(rename = "auto")]
    Auto,
}

/// Display modes from the Web app manifest definition
///
/// Ref: <https://developer.mozilla.org/en-US/docs/Web/Manifest/display>
#[derive(Debug, Clone, Serialize, Deserialize)]
enum DisplayMode {
    /// All of the available display area is used and no user agent chrome is
    /// shown.
    #[serde(rename = "full-screen")]
    FullScreen,
    /// The application will look and feel like a standalone application. This can
    /// include the application having a different window, its own icon in the
    /// application launcher, etc. In this mode, the user agent will exclude UI
    /// elements for controlling navigation, but can include other UI elements
    /// such as a status bar.
    #[serde(rename = "standalone")]
    Standalone,
    /// The application will look and feel like a standalone application, but will
    /// have a minimal set of UI elements for controlling navigation. The elements
    /// will vary by browser.
    #[serde(rename = "minimal-ui")]
    MinimalUi,
    /// The application opens in a conventional browser tab or new window,
    /// depending on the browser and platform. This is the default.
    #[serde(rename = "browser")]
    Browser,
}

pub fn manifest_data(host_req: Option<&str>, domain_display_name: String) -> Manifest {
    let icons = vec![
        ManifestIcon {
            sizes: String::from("512x512"),
            src: String::from("/pkg/img/logo-square.svg"),
            mime_type: String::from("image/svg+xml"),
            purpose: None,
        },
        ManifestIcon {
            sizes: String::from("512x512"),
            src: String::from("/pkg/img/logo-512.png"),
            mime_type: String::from("image/png"),
            purpose: Some(String::from("maskable")),
        },
        ManifestIcon {
            sizes: String::from("192x192"),
            src: String::from("/pkg/img/logo-192.png"),
            mime_type: String::from("image/png"),
            purpose: Some(String::from("maskable")),
        },
        ManifestIcon {
            sizes: String::from("256x156"),
            src: String::from("/pkg/img/logo-256.png"),
            mime_type: String::from("image/png"),
            purpose: Some(String::from("maskable")),
        },
    ];

    let start_url = match host_req {
        Some(value) => format!("https://{}/", value),
        None => String::from("/"),
    };

    Manifest {
        short_name: "Kanidm".to_string(),
        name: domain_display_name,
        start_url,
        display_mode: DisplayMode::MinimalUi,
        description: None,
        orientation: None,
        lang: Some("en".to_string()),
        theme_color: "white".to_string(),
        background_color: "white".to_string(),
        direction: Direction::Auto,
        scope: None,
        prefer_related_applications: None,
        icons,
        related_applications: None,
    }
}

/// Generates a manifest.json file for progressive web app usage
pub(crate) async fn manifest(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let domain_display_name = state.qe_r_ref.get_domain_display_name(kopid.eventid).await;
    // TODO: fix the None here to make it the request host
    let manifest_string =
        match serde_json::to_string_pretty(&manifest_data(None, domain_display_name)) {
            Ok(val) => val,
            Err(_) => String::from(""),
        };
    let mut res = Response::new(manifest_string);

    res.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_MANIFEST));

    res
}
