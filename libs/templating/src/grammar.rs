use std::str::FromStr;

peg::parser! {
    grammar template() for str {
        pub rule parse<A: FromStr>() -> Vec<TemplateIntermediate<A>> =
            s:(element()*) { s }

        rule element<A: FromStr>() -> TemplateIntermediate<A> = precedence!{
            start_template() o:operand::<A>() end_template()
                { o }
            --
            s:(literal())
                {  TemplateIntermediate::Literal (s) }
        }

        rule operand<A: FromStr>() -> TemplateIntermediate<A> =
            separator()* a:attrname::<A>() separator()* c:condition()? separator()* o:option()? separator()*
                { TemplateIntermediate::Operand {
                    attribute: a,
                    condition: c,
                    options: o }
                }

        rule condition() -> TemplateCondition =
            start_condition() separator()+ c:condition_str()
                { c }

        rule condition_str() -> TemplateCondition = precedence!{
            "A"
            { TemplateCondition::A }
        }

        rule option() -> TemplateOption =
            start_option() separator()+ os:option_str()
                { os }

        rule option_str() -> TemplateOption = precedence!{
            "json"
            { TemplateOption::FormatJson }
        }


        rule literal() -> String =
            s:$((!start_template()[_])+)
            { s.to_string() }

        rule attrname<A: FromStr>() -> A =
            s:$([ 'a'..='z' | 'A'..='Z']['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' ]*) {? A::from_str(s).or(Err("invalid attribute name")) }

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

#[derive(Debug)]
enum TemplateCondition {
    A,
}

#[derive(Debug)]
enum TemplateIntermediate<A> {
    // None,
    Literal(String),
    // Join(Self, Self),
    Operand {
        attribute: A,
        condition: Option<TemplateCondition>,
        options: Option<TemplateOption>,
    },
}

#[cfg(test)]
mod tests {
    use super::{template, TemplateIntermediate};

    type TemplateTest = Vec<TemplateIntermediate<String>>;

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
}
