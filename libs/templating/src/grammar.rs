use std::str::FromStr;

pub trait TemplateAttribute: FromStr {}

pub trait TemplateCondition: FromStr + Default {
    type Context;

    fn evaluate(&self, ctx: &Self::Context) -> bool;
}

pub trait TemplateRenderer: FromStr + Default {
    type Context;
    type Attribute;
    type Error;

    fn render(
        &self,
        attribute: &Self::Attribute,
        ctx: &Self::Context,
        buffer: &mut String,
    ) -> Result<(), Self::Error>;
}

peg::parser! {
    grammar template() for str {

        pub rule parse<A: TemplateAttribute, C: TemplateCondition, O: TemplateRenderer>() -> Template<A, C, O> =
            s:items() { Template { items: s } }

        rule items<A: TemplateAttribute, C: TemplateCondition, O: TemplateRenderer>() -> Vec<TemplateIntermediate<A, C, O>> =
            s:(element()*) { s }

        rule element<A: TemplateAttribute, C: TemplateCondition, O: TemplateRenderer>() -> TemplateIntermediate<A, C, O> = precedence!{
            start_template() o:operand::<A, C, O>() end_template()
                { o }
            --
            s:(literal())
                {  TemplateIntermediate::Literal (s) }
        }

        rule operand<A: TemplateAttribute, C: TemplateCondition, O: TemplateRenderer>() -> TemplateIntermediate<A, C, O> =
            separator()* a:attrname::<A>() c:condition::<C>() o:renderer::<O>() separator()+
                { TemplateIntermediate::Operand {
                    attribute: a,
                    condition: c,
                    renderer: o }
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

        rule renderer<O: TemplateRenderer>() -> O =
            separator()+ start_renderer() separator()+ os:renderer_str()
                { os }
            / renderer_default()

        rule renderer_default<O: TemplateRenderer>() -> O =
            { O::default() }

        rule renderer_str<O: TemplateRenderer>() -> O =
            s:$(['a'..='z']+)
                {? O::from_str(s).or(Err("invalid renderer")) }

        rule literal() -> String =
            s:$((!start_template()[_])+)
            { s.to_string() }

        rule attrname<A: TemplateAttribute>() -> A =
            s:$([ 'a'..='z' | 'A'..='Z']['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_']*)
                {? A::from_str(s).or(Err("invalid attribute name")) }

        rule start_condition() =
            ['i']['f']

        rule start_renderer() =
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
        renderer: O,
    },
}

#[derive(Debug)]
pub struct Template<A, C, O> {
    items: Vec<TemplateIntermediate<A, C, O>>,
}

impl<A, C, O> Template<A, C, O>
where
    A: TemplateAttribute,
    C: TemplateCondition,
    O: TemplateRenderer<Context = C::Context, Attribute = A>,
{
    pub fn render(&self, ctx: &C::Context) -> Result<String, O::Error> {
        // Make the buffer.
        let mut buffer = String::new();

        for template_item in self.items.iter() {
            match template_item {
                TemplateIntermediate::Literal(data) => buffer.push_str(data.as_str()),
                TemplateIntermediate::Operand {
                    attribute,
                    condition,
                    renderer,
                } if condition.evaluate(ctx) => {
                    renderer.render(attribute, ctx, &mut buffer)?;
                }
                TemplateIntermediate::Operand { .. } => {
                    // trace!("Skipping non-evaled condition");
                }
            }
        }

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        template, Template, TemplateAttribute, TemplateCondition, TemplateIntermediate,
        TemplateRenderer,
    };
    use std::str::FromStr;

    #[derive(Debug, Default)]
    enum TestRenderer {
        #[default]
        None,
        FormatJson,
    }

    impl FromStr for TestRenderer {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "json" => Ok(Self::FormatJson),
                _ => Err(()),
            }
        }
    }

    impl TemplateRenderer for TestRenderer {
        type Context = ();
        type Attribute = TestAttribute;
        type Error = ();

        fn render(
            &self,
            attribute: &Self::Attribute,
            ctx: &Self::Context,
            buffer: &mut String,
        ) -> Result<(), Self::Error> {
            todo!();
        }
    }

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

    impl TemplateCondition for TestCondition {
        type Context = ();

        fn evaluate(&self, _ctx: &Self::Context) -> bool {
            match self {
                Self::None => true,
                Self::Abc => false,
            }
        }
    }

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

    type TemplateTest = Template<TestAttribute, TestCondition, TestRenderer>;

    #[test]
    fn single_literal() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("foo").unwrap();

        tracing::trace!(?x);

        let ctx = ();
        let y = x.render(&ctx);

        tracing::trace!(?y, "rendered");
    }

    #[test]
    fn single_operand() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("{{ ident }}").unwrap();

        tracing::trace!(?x);

        let ctx = ();
        let y = x.render(&ctx);

        tracing::trace!(?y, "rendered");
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
    fn operand_renderer_json() {
        let _ = tracing_subscriber::fmt::try_init();

        let x: TemplateTest = template::parse("{{ ident | json }}").unwrap();

        tracing::trace!(?x);
    }

    #[test]
    fn operand_condition_renderer_json() {
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
