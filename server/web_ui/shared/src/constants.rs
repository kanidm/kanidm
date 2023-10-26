//! Constants

pub const CONTENT_TYPE: &str = "content-type";

// CSS classes that get applied to full-page forms
pub const CSS_CLASSES_BODY_FORM: &[&str] = &["flex-column", "d-flex", "h-100"];

// when you want to put big text at the top of the page
pub const CSS_PAGE_HEADER: &str = "d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-0 pb-0 mb-3 border-bottom";

// the HTML element ID that the signout modal dialogue box has
pub const ID_SIGNOUTMODAL: &str = "signoutModal";

// the HTML element ID that the unix password dialog box has
pub const ID_UNIX_PASSWORDCHANGE: &str = "unixPasswordModal";
pub const ID_IDENTITY_VERIFICATION_SYSTEM_TOTP_MODAL: &str = "identityVerificationSystemTotpModal";
pub const ID_CRED_RESET_CODE: &str = "credResetCodeModal";
pub const ID_NAVBAR_COLLAPSE: &str = "navbarCollapse";
// classes for buttons
pub const CLASS_BUTTON_DARK: &str = "btn btn-dark";
pub const CLASS_BUTTON_SUCCESS: &str = "btn btn-success";

// the CSS classes to apply to the div which a login field sits inside
pub const CLASS_DIV_LOGIN_FIELD: &str = "input-group mb-3";
// the CSS classes to apply to the div which a login button sits inside
pub const CLASS_DIV_LOGIN_BUTTON: &str = "input-group mb-3 justify-content-md-center";

pub const CSS_LINK_DARK_STRETCHED: &str = "link-dark stretched-link";
// default table classes
pub const CSS_TABLE: &str = "table table-striped table-hover";
// default table cell class
pub const CSS_CELL: &str = "p-1";

pub const CSS_DT: &str = "col-6";

// pub const CSS_BREADCRUMB_ITEM: &str = "breadcrumb-item";
// pub const CSS_BREADCRUMB_ITEM_ACTIVE: &str = "breadcrumb-item active";

// used in the UI for ... cards
pub const CSS_CARD: &str = "card text-center";
pub const CSS_CARD_BODY: &str = "card-body text-center";

pub const CSS_NAV_LINK: &str = "nav-link";

pub const CSS_ALERT_WARNING: &str = "alert alert-warning";
pub const CSS_ALERT_DANGER: &str = "alert alert-danger";

pub const CSS_NAVBAR_NAV: &str = "navbar navbar-expand-md navbar-dark bg-dark mb-4";
pub const CSS_NAVBAR_BRAND: &str = "navbar-brand navbar-dark";
pub const CSS_NAVBAR_LINKS_UL: &str = "navbar-nav me-auto mb-2 mb-md-0";

pub const URL_ADMIN: &str = "/ui/admin";
pub const URL_OAUTH2: &str = "/ui/oauth2";
pub const URL_USER_HOME: &str = "/ui/apps";
pub const URL_USER_PROFILE: &str = "/ui/profile";
pub const URL_LOGIN: &str = "/ui/login";
pub const URL_REAUTH: &str = "/ui/reauth";
pub const URL_RESET: &str = "/ui/reset";

pub const IMG_FAVICON: &str = "/pkg/img/favicon.png";
pub const IMG_LOGO_SQUARE: &str = "/pkg/img/logo-square.svg";
