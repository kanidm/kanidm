


peg::parser! {
    grammar template() for str {
        pub rule parse() -> String = precedence!{
            a:attrname() { a }
        }

        pub(crate) rule attrname() -> String =
            s:$([ 'a'..='z' | 'A'..='Z']['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' ]*) { s.to_string() }
    }
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
}


