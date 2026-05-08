peg::parser! {
    grammar template() for str {
        pub rule parse() -> Vec<TemplateIntermediate> =
            s:(element()*) { s }

        rule element() -> TemplateIntermediate = precedence!{
            start_template() o:operand() end_template()
                { o }
            --
            s:(literal())
                {  TemplateIntermediate::Literal (s) }
        }

        rule operand() -> TemplateIntermediate =
            separator()* a:attrname() separator()* c:condition()? separator()* o:option()? separator()*
                { TemplateIntermediate::Operand {
                    attribute: a.to_string(),
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

        rule attrname() -> String =
            s:$([ 'a'..='z' | 'A'..='Z']['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' ]*) { s.to_string() }

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
enum TemplateIntermediate {
    // None,
    Literal(String),
    // Join(Self, Self),
    Operand {
        attribute: String,
        condition: Option<TemplateCondition>,
        options: Option<TemplateOption>,
    },
}

#[cfg(test)]
mod tests {
    use super::template;

    #[test]
    fn single_literal() {
        let _ = tracing_subscriber::fmt::try_init();

        let x = template::parse("foo");

        tracing::trace!(?x);
    }

    #[test]
    fn single_operand() {
        let _ = tracing_subscriber::fmt::try_init();

        let x = template::parse("{{ ident }}");

        tracing::trace!(?x);
    }

    #[test]
    fn literal_operand() {
        let _ = tracing_subscriber::fmt::try_init();

        let x = template::parse("some_literal {{ ident }}");

        tracing::trace!(?x);
    }

    #[test]
    fn literal_operand_literal() {
        let _ = tracing_subscriber::fmt::try_init();

        let x = template::parse("some_literal {{ ident }} another_literal");

        tracing::trace!(?x);
    }

    #[test]
    fn operand_literal() {
        let _ = tracing_subscriber::fmt::try_init();

        let x = template::parse("{{ ident }} another_literal");

        tracing::trace!(?x);
    }

    #[test]
    fn literal_operand_literal_operand() {
        let _ = tracing_subscriber::fmt::try_init();

        let x = template::parse("some_literal {{ ident }} another_literal {{ ident }}");

        tracing::trace!(?x);
    }

    #[test]
    fn operand_operand() {
        let _ = tracing_subscriber::fmt::try_init();

        let x = template::parse("{{ ident }}{{ ident }}");

        tracing::trace!(?x);
    }

    #[test]
    fn operand_option_json() {
        let _ = tracing_subscriber::fmt::try_init();

        let x = template::parse("{{ ident | json }}");

        tracing::trace!(?x);
    }
}
