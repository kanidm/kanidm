use std::str::FromStr;

peg::parser! {
    grammar template() for str {
        pub rule parse<A: FromStr, C: FromStr + Default, O: FromStr>() -> Vec<TemplateIntermediate<A, C, O>> =
            s:(element()*) { s }

        rule element<A: FromStr, C: FromStr + Default, O: FromStr>() -> TemplateIntermediate<A, C, O> = precedence!{
            start_template() o:operand::<A, C, O>() end_template()
                { o }
            --
            s:(literal())
                {  TemplateIntermediate::Literal (s) }
        }

        rule operand<A: FromStr, C: FromStr + Default, O: FromStr>() -> TemplateIntermediate<A, C, O> =
            separator()* a:attrname::<A>() c:condition::<C>() separator()* o:option::<O>()? separator()*
                { TemplateIntermediate::Operand {
                    attribute: a,
                    condition: c,
                    options: o }
                }

        rule condition<C: FromStr + Default>() -> C =
            separator()+ start_condition() separator()+ c:condition_str()
                { c }
            / condition_default()

        rule condition_default<C: Default>() -> C =
            { C::default() }

        rule condition_str<C: FromStr>() -> C =
            s:$(['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '(' | ')']+)
                {? C::from_str(s).or(Err("invalid condition")) }

        rule option<O: FromStr>() -> O =
            start_option() separator()+ os:option_str()
                { os }

        rule option_str<O: FromStr>() -> O =
            s:$(['a'..='z']+)
                {? O::from_str(s).or(Err("invalid option")) }

        rule literal() -> String =
            s:$((!start_template()[_])+)
            { s.to_string() }

        rule attrname<A: FromStr>() -> A =
            s:$([ 'a'..='z' | 'A'..='Z']['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_']*)
                {? A::from_str(s).or(Err("invalid attribute name")) }

        rule start_condition() =
            ['i']['f']

        rule start_option() =
            ['|']

        rule start_template() =
            ['{']['{']

        rule end_template() =
            ['}']['}']

        rule separator() =
            ['\n' | ' ' | '\t' ]
    }
}

#[derive(Debug)]
enum TemplateOption {
    FormatJson,
}

impl FromStr for TemplateOption {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::FormatJson),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Default)]
enum TemplateCondition {
    #[default]
    None,
    Abc,
}

impl FromStr for TemplateCondition {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "memberof(abc)" => Ok(Self::Abc),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
enum TemplateAttribute {
    Ident,
}

impl FromStr for TemplateAttribute {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ident" => Ok(Self::Ident),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
enum TemplateIntermediate<A, C, O> {
    Literal(String),
    Operand {
        attribute: A,
        condition: C,
        options: Option<O>,
    },
}

#[cfg(test)]
mod tests {
    use super::{template, TemplateAttribute, TemplateCondition, TemplateIntermediate};

    type TemplateTest = Vec<TemplateIntermediate<TemplateAttribute, TemplateCondition, String>>;

    #[test]
    fn single_literal() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("foo").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn single_operand() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("{{ ident }}").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn literal_operand() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("some_literal {{ ident }}").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn literal_operand_literal() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("some_literal {{ ident }} another_literal").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn operand_literal() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("{{ ident }} another_literal").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn literal_operand_literal_operand() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest =
            template::parse("some_literal {{ ident }} another_literal {{ ident }}").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn operand_operand() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("{{ ident }}{{ ident }}").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn operand_option_json() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("{{ ident | json }}").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn operand_condition_option_json() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("{{ ident if memberof(abc) | json }}").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn operand_condition() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("{{ ident if memberof(abc) }}").unwrap();

        tracing::trace!(?x);
    }
}
