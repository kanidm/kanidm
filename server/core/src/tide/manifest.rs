use serde::{Deserialize, Serialize};

///! Builds a Progressive Web App Manifest page.
// Thanks to the webmanifest crate for a lot of this code
use crate::tide::{AppState, RequestExtensions};

/// The MIME type for `.webmanifest` files.
const MIME_TYPE_MANIFEST: &str = "application/manifest+json;charset=utf-8";

/// Create a new manifest builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest<'s> {
    name: &'s str,
    short_name: &'s str,
    start_url: &'s str,
    #[serde(rename = "display")]
    display_mode: DisplayMode,
    background_color: &'s str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'s str>,
    #[serde(rename = "dir")]
    direction: Direction,
    // direction: Option<Direction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    orientation: Option<String>,
    // orientation: Option<Orientation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lang: Option<&'s str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'s str>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    theme_color: &'s str,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefer_related_applications: Option<bool>,
    // #[serde(borrow)]
    // #[serde(skip_serializing_if = "Option::is_none")]
    icons: Vec<ManifestIcon>,
    // icons: Vec<Icon<'i>>,
    // #[serde(borrow)]
    #[serde(skip_serializing_if = "Option::is_none")]
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

/// Generates a manifest.json file for progressive web app usage
pub async fn manifest(req: tide::Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);
    let (eventid, _) = req.new_eventid();
    let domain_display_name = req.state().qe_r_ref.get_domain_display_name(eventid).await;

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

    let start_url = match req.host() {
        Some(value) => format!("https://{}/", value),
        None => String::from("/"),
    };

    let manifest_struct = Manifest {
        short_name: "Kanidm",
        name: domain_display_name.as_str(),
        start_url: start_url.as_str(),
        display_mode: DisplayMode::MinimalUi,
        description: None,
        orientation: None,
        lang: Some("en"),
        theme_color: "white",
        background_color: "white",
        direction: Direction::Auto,
        scope: None,
        prefer_related_applications: None,
        icons,
        related_applications: None,
    };

    let manifest_string = serde_json::to_string_pretty(&manifest_struct)?;

    res.set_content_type(MIME_TYPE_MANIFEST);
    res.set_body(manifest_string);

    Ok(res)
}
