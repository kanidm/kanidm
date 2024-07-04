use askama::Template;
use uuid::Uuid;

#[derive(Template)]
#[template(path = "recoverable_error_partial.html")]
pub struct ErrorPartialView {
    pub(crate) error_message: String,
    pub(crate) operation_id: Uuid,
    pub(crate) recovery_path: String,
    pub(crate) recovery_boosted: bool,
}