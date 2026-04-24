


peg::parser! {
    grammar template() for str {
        pub rule parse() -> Vec<TemplateIntermediate> =
            s:(element()*) { s }

        rule element() -> TemplateIntermediate = precedence!{
            start_template() separator()+ e:attrname() separator()+ end_template()
                { TemplateIntermediate::Operand (e) }
            --
            s:(literal())
                {  TemplateIntermediate::Literal (s) }
        }

        // rule value() -> TemplateIntermediate =

        rule literal() -> String =
            s:$((!start_template()[_])+)
            { s.to_string() }

        rule attrname() -> String =
            s:$([ 'a'..='z' | 'A'..='Z']['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' ]*) { s.to_string() }

        rule start_template() =
            ['{']['{']

        rule end_template() =
            ['}']['}']

        rule separator() =
            ['\n' | ' ' | '\t' ]



    }
}


#[derive(Debug)]
enum TemplateIntermediate {
    // None,
    Literal(String),
    // Join(Self, Self),
    Operand(String)
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
}


