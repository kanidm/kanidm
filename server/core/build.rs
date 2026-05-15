use std::{
    collections::{HashMap, HashSet},
    io::Write as _,
    path::PathBuf,
    str::FromStr,
};

use fluent::FluentResource;
use fluent_syntax::ast::{Identifier, Pattern, PatternElement};

fn get_args(resource: &FluentResource, value: &Pattern<&str>) -> Vec<String> {
    let mut res = Vec::new();

    for element in &value.elements {
        if let PatternElement::Placeable { expression } = element {
            let inner = match expression {
                fluent_syntax::ast::Expression::Select { selector, .. } => selector,
                fluent_syntax::ast::Expression::Inline(inline_expression) => inline_expression,
            };
            match inner {
                fluent_syntax::ast::InlineExpression::FunctionReference { .. } => {
                    todo!()
                }
                // TODO: mark referenced message as used to make clippy happy
                fluent_syntax::ast::InlineExpression::MessageReference { id, attribute } => {
                    for entry in resource.entries() {
                        if let fluent_syntax::ast::Entry::Message(msg) = entry {
                            if &msg.id == id {
                                if let Some(attr) = attribute {
                                    let mut args = get_args(
                                        resource,
                                        &msg.attributes
                                            .iter()
                                            .find(|attribute| attribute.id.name == attr.name)
                                            .unwrap()
                                            .value,
                                    );
                                    res.append(&mut args);
                                }
                            }
                        }
                    }
                }
                fluent_syntax::ast::InlineExpression::TermReference { .. } => {}
                fluent_syntax::ast::InlineExpression::VariableReference { id } => {
                    res.push(id.name.to_owned());
                }
                fluent_syntax::ast::InlineExpression::Placeable { .. } => todo!(),
                _ => {}
            }
        }
    }

    res
}

fn gen_i18n_fn(
    resource: &FluentResource,
    prefix: Option<&Identifier<&str>>,
    id: &Identifier<&str>,
    value: &Pattern<&str>,
) -> (String, Vec<String>, String) {
    let gen_prefix = prefix
        .map(|id| format!("{}_", id.name))
        .unwrap_or_default()
        .replace('-', "_");
    let gen_id = id.name.replace('-', "_");
    let args = get_args(resource, value);
    let name = format!(
        "i18n_message_{prefix}{id}",
        prefix = gen_prefix,
        id = gen_id
    );

    let body_msg = if let Some(prefix) = prefix {
        format!(
            r#"    let message = bundle.get_message("{prefix}").ok_or(::askama::Error::ValueMissing)?;
    let pattern = message.get_attribute("{id}").ok_or(::askama::Error::ValueMissing)?.value();
        "#,
            prefix = prefix.name,
            id = id.name
        )
    } else {
        format!(
            r#"    let pattern = bundle.get_message("{id}").ok_or(::askama::Error::ValueMissing)?.value().ok_or(::askama::Error::ValueMissing)?;
        "#,
            id = id.name
        )
    };
    let body_args = if args.is_empty() {
        "   let args = None;".to_owned()
    } else {
        format!(
            r#"
    let mut args = HashMap::new();
{args}
    let args = Some(&::fluent::FluentArgs::from_iter(args));
        "#,
            args = args
                .iter()
                .map(|arg| format!(r#"    args.insert("{arg}", {arg});"#, arg = arg))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    let body = format!(
        r#"{message}
{args}

    let mut _errors = Vec::new();
    let value = bundle.format_pattern(&pattern, args, &mut _errors);
    Ok(value.into())"#,
        message = body_msg,
        args = body_args,
    );

    let out = format!(
        r#"fn {name}(bundle: &::fluent::concurrent::FluentBundle<::fluent::FluentResource>, {args}) -> ::askama::Result<String> {{
{body}
}}"#,
        name = name,
        args = args
            .iter()
            .map(|arg| format!("{}: FluentValue<'static>", arg))
            .collect::<Vec<_>>()
            .join(", ")
    );

    (name, args, out)
}

fn main() {
    profiles::apply_profile();
    println!("cargo:rerun-if-changed=build.rs");

    let src_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut fallback_lang_file = PathBuf::from_str(&src_dir).unwrap();
    fallback_lang_file.push("i18n");
    fallback_lang_file.push("en-AU");
    fallback_lang_file.push("kanidmd_core.ftl");
    let fallback_lang = std::fs::read_to_string(fallback_lang_file).unwrap();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let mut out_file_name = PathBuf::from_str(&out_dir).unwrap();
    out_file_name.push("gen_fluent_i18n.rs");
    let mut out_file = std::fs::File::create(out_file_name).unwrap();
    let resource = FluentResource::try_new(fallback_lang).unwrap();
    let mut all_args = HashSet::new();
    let mut all_fns = HashMap::new();
    for entry in resource.entries() {
        match entry {
            fluent_syntax::ast::Entry::Message(message) => {
                let (name, args, out) = gen_i18n_fn(
                    &resource,
                    None,
                    &message.id,
                    message.value.as_ref().unwrap(),
                );
                writeln!(out_file, "{}", out).unwrap();
                all_fns.insert(message.id.name.to_owned(), (name, args.clone()));
                all_args.extend(args);
                for attr in &message.attributes {
                    let (name, args, out) =
                        gen_i18n_fn(&resource, Some(&message.id), &attr.id, &attr.value);
                    writeln!(out_file, "{}", out).unwrap();
                    all_fns.insert(
                        format!("{}.{}", message.id.name, attr.id.name),
                        (name, args.clone()),
                    );
                    all_args.extend(args);
                }
            }
            fluent_syntax::ast::Entry::Term(_term) => {}
            _ => {} // ↓ can be used to generate docs
                    // fluent_syntax::ast::Entry::Comment(comment) => todo!(),
                    // fluent_syntax::ast::Entry::GroupComment(comment) => todo!(),
                    // fluent_syntax::ast::Entry::ResourceComment(comment) => todo!(),
                    // fluent_syntax::ast::Entry::Junk { content } => todo!(),
        }
    }
    write!(out_file,
        r#"
#[::askama::filter_fn]
pub fn trans(
    input: &'static str,
    env: &dyn ::askama::Values,
{args}
) -> ::askama::Result<String> {{
    let lang = env.get_value("lang").ok_or(::askama::Error::ValueMissing)?;
    let lang: &::unic_langid::LanguageIdentifier = lang.downcast_ref().ok_or(::askama::Error::ValueType)?;

    let bundle = I18N_BUNDLES.get(lang).ok_or(askama::Error::ValueMissing)?;

    match input {{
{match_arms}
        _ => unimplemented!()
    }}
}}"#,
        args = all_args
            .iter()
            .map(|arg| format!(r#"    #[optional(&0)] {}: &dyn ToString"#, arg))
            .collect::<Vec<_>>()
            .join(",\n"),
        match_arms = all_fns
            .iter()
            .map(|(id, (fun, args))| format!(
                r#"        "{}" => {}(bundle, {args}),"#,
                id,
                fun,
                args = args.iter().map(|arg| format!("ToString::to_string({}).try_into().unwrap()", arg)).collect::<Vec<_>>().join(", ")
            ))
            .collect::<Vec<_>>()
            .join("\n")
    ).unwrap();
}
