use std::collections::HashMap;

use fluent::{FluentArgs, FluentValue};
use unic_langid::LanguageIdentifier;

use crate::https::i18n::I18N_BUNDLES;

/// Option 1: arguments passed as an optional filter argument
/// This basically needs the macro below to be usable (afaik askama doesn't
/// let you run random code in the template to fill out a HashMap, and doesn't have variadic
/// functions/macros), which means copying the variables from scope:
///
/// ```
/// (% arg1 = arg1_var %)
/// (% arg2 = obj.arg2 %)
/// (( "translation-key" | trans_args(fl_args!("arg1" => arg1, "arg2" => arg2)) ))
/// ```
#[askama::filter_fn]
pub fn trans_args(
    input: &'static str,
    env: &dyn askama::Values,
    #[optional(None)] args: Option<HashMap<&'static str, FluentValue<'static>>>,
) -> askama::Result<String> {
    let lang = env.get_value("lang").ok_or(askama::Error::ValueMissing)?;
    let lang: &LanguageIdentifier = lang.downcast_ref().ok_or(askama::Error::ValueType)?;

    let bundle = I18N_BUNDLES.get(lang).ok_or(askama::Error::ValueMissing)?;
    let (msg_id, attr_id) = input.split_once('.').unwrap_or((input, ""));

    let message = bundle
        .get_message(msg_id)
        .ok_or(askama::Error::ValueMissing)?;
    let message = if attr_id.is_empty() {
        message.value()
    } else {
        message.get_attribute(attr_id).map(|attr| attr.value())
    };
    let pattern = message.ok_or(askama::Error::ValueMissing)?;

    let mut errors = Vec::new();
    let value = bundle.format_pattern(
        &pattern,
        args.map(FluentArgs::from_iter).as_ref(),
        &mut errors,
    );

    if !errors.is_empty() {
        return Err(askama::Error::custom(errors.remove(0)));
    }

    Ok(value.into())
}

#[allow(unused)]
macro_rules! fl_args {
    ($var:ident, $key:literal => $val:expr) => {
        $var.insert($key, $val.to_string().into());
    };
    ($var:ident, $key:literal => $val:expr, $($rest:tt)*) => {{
        fl_args!($var, $key => $val);
        fl_args!($var, $($rest)*);
    }};
    ($key:literal => $val:expr) => {{
        let mut args = ::std::collections::HashMap::<&str, ::fluent::FluentValue>::new();
        fl_args!(args, $key => $val);
        Some(args)
    }};
    ($key:literal => $val:expr, $($rest:tt)*) => {{
        let mut args = ::std::collections::HashMap::<&str, ::fluent::FluentValue>::new();
        fl_args!(args, $key => $val, $($rest)*);
        Some(args)
    }};
}

/// Option 2: no macro, arguments composed with another filter
///
/// ```
/// (( "translation-key" | with_arg("arg1", arg1_var) | with_arg("arg2", obj.arg2) | trans ))
/// ```
#[askama::filter_fn]
pub fn trans_with(input: impl MsgId, env: &dyn askama::Values) -> askama::Result<String> {
    let lang = env.get_value("lang").ok_or(askama::Error::ValueMissing)?;
    let lang: &LanguageIdentifier = lang.downcast_ref().ok_or(askama::Error::ValueType)?;

    let bundle = I18N_BUNDLES.get(lang).ok_or(askama::Error::ValueMissing)?;
    let (msg_id, args) = input.take();
    let (msg_id, attr_id) = msg_id.split_once('.').unwrap_or((msg_id.as_str(), ""));

    let message = bundle
        .get_message(msg_id)
        .ok_or(askama::Error::ValueMissing)?;
    let message = if attr_id.is_empty() {
        message.value()
    } else {
        message.get_attribute(attr_id).map(|attr| attr.value())
    };
    let pattern = message.ok_or(askama::Error::ValueMissing)?;

    let mut errors = Vec::new();
    let value = bundle.format_pattern(&pattern, Some(&FluentArgs::from_iter(args)), &mut errors);

    if !errors.is_empty() {
        return Err(askama::Error::custom(errors.remove(0)));
    }

    Ok(value.into())
}

pub struct MsgIdWithArgs {
    msg_id: String,
    args: HashMap<&'static str, FluentValue<'static>>,
}

pub(crate) trait MsgId {
    fn take(self) -> (String, HashMap<&'static str, FluentValue<'static>>);
}

impl MsgId for &str {
    fn take(self) -> (String, HashMap<&'static str, FluentValue<'static>>) {
        (self.to_string(), HashMap::new())
    }
}

impl MsgId for MsgIdWithArgs {
    fn take(self) -> (String, HashMap<&'static str, FluentValue<'static>>) {
        (self.msg_id, self.args)
    }
}

#[askama::filter_fn]
pub fn with_arg<T>(
    msg_id: impl MsgId,
    _env: &dyn askama::Values,
    name: &'static str,
    value: &T,
) -> askama::Result<MsgIdWithArgs>
where
    T: Clone + TryInto<FluentValue<'static>>,
    <T as TryInto<FluentValue<'static>>>::Error: std::fmt::Debug,
{
    let (msg_id, mut args) = msg_id.take();
    args.insert(
        name,
        value
            .clone()
            .try_into()
            .expect("couldn't convert to FluentValue"),
    );
    Ok(MsgIdWithArgs { msg_id, args })
}

/// Option 3: no macro, no with_arg, no having to reassign variables
/// Code is generated in build.rs, but it's a huge mess since I just wanted to get something
/// working. It could also potentially be made to make clippy error out for unused translations.
///
/// Since askama has no way of calling `.into` on filter arguments I had to use `&dyn ToString` to
/// avoid having to call `.into` manually in templates, or wrapping every used value in `Some()`.
///
/// One funny thing I could also try is making most of this compile-time - instead of generating the
/// functions that use a static FluentBundle reference just use the AST to make them output strings.
/// The formatters would have to stay as statics.
mod option_3 {
    use super::*;
    include!(concat!(env!("OUT_DIR"), "/gen_fluent_i18n.rs"));
}

pub use option_3::trans;
