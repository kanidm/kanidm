use std::str::FromStr;

pub trait TemplateAttribute: FromStr {}
pub trait TemplateCondition: FromStr + Default {}
pub trait TemplateOption: FromStr + Default {}

peg::parser! {
    grammar template() for str {
        pub rule parse<A: TemplateAttribute, C: TemplateCondition, O: TemplateOption>() -> Vec<TemplateIntermediate<A, C, O>> =
            s:(element()*) { s }

        rule element<A: TemplateAttribute, C: TemplateCondition, O: TemplateOption>() -> TemplateIntermediate<A, C, O> = precedence!{
            start_template() o:operand::<A, C, O>() end_template()
                { o }
            --
            s:(literal())
                {  TemplateIntermediate::Literal (s) }
        }

        rule operand<A: TemplateAttribute, C: TemplateCondition, O: TemplateOption>() -> TemplateIntermediate<A, C, O> =
            separator()* a:attrname::<A>() c:condition::<C>() o:option::<O>()? separator()+
                { TemplateIntermediate::Operand {
                    attribute: a,
                    condition: c,
                    options: o }
                }

        rule condition<C: TemplateCondition>() -> C =
            separator()+ start_condition() separator()+ c:condition_str()
                { c }
            / condition_default()

        rule condition_default<C: TemplateCondition>() -> C =
            { C::default() }

        rule condition_str<C: TemplateCondition>() -> C =
            s:$(['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '(' | ')']+)
                {? C::from_str(s).or(Err("invalid condition")) }

        rule option<O: TemplateOption>() -> O =
            separator()+ start_option() separator()+ os:option_str()
                { os }
            / option_default()

        rule option_default<O: TemplateOption>() -> O =
            { O::default() }

        rule option_str<O: TemplateOption>() -> O =
            s:$(['a'..='z']+)
                {? O::from_str(s).or(Err("invalid option")) }

        rule literal() -> String =
            s:$((!start_template()[_])+)
            { s.to_string() }

        rule attrname<A: TemplateAttribute>() -> A =
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
enum TemplateIntermediate<A, C, O> {
    Literal(String),
    Operand {
        attribute: A,
        condition: C,
        options: Option<O>,
    },
}


impl <A, C, O> for TemplateIntermediate<A, C, O> {
    pub fn render(&self) -> Result<String, ()> {
        
    }
}



#[cfg(test)]
mod tests {
    use super::{
        template, TemplateAttribute, TemplateCondition, TemplateIntermediate, TemplateOption,
    };
    use std::str::FromStr;

    #[derive(Debug, Default)]
    enum TestOption {
        #[default]
        None,
        FormatJson,
    }

    impl FromStr for TestOption {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "json" => Ok(Self::FormatJson),
                _ => Err(()),
            }
        }
    }

    impl TemplateOption for TestOption {}

    #[derive(Debug, Default)]
    enum TestCondition {
        #[default]
        None,
        Abc,
    }

    impl FromStr for TestCondition {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "memberof(abc)" => Ok(Self::Abc),
                _ => Err(()),
            }
        }
    }

    impl TemplateCondition for TestCondition {}

    #[derive(Debug)]
    enum TestAttribute {
        Ident,
    }

    impl FromStr for TestAttribute {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "ident" => Ok(Self::Ident),
                _ => Err(()),
            }
        }
    }

    impl TemplateAttribute for TestAttribute {}

    type TemplateTest = Vec<TemplateIntermediate<TestAttribute, TestCondition, TestOption>>;

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
