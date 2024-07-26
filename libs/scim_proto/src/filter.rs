#![allow(warnings)]

use serde_json::Value;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrPath {
    // Uri: Option<String>,
    a: String,
    s: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimFilter {
    Or(Box<ScimFilter>, Box<ScimFilter>),
    And(Box<ScimFilter>, Box<ScimFilter>),
    Not(Box<ScimFilter>),

    Present(AttrPath),
    Equal(AttrPath, Value),
    NotEqual(AttrPath, Value),
    Contains(AttrPath, Value),
    StartsWith(AttrPath, Value),
    EndsWith(AttrPath, Value),
    Greater(AttrPath, Value),
    Less(AttrPath, Value),
    GreaterOrEqual(AttrPath, Value),
    LessOrEqual(AttrPath, Value),
}

// separator()* "(" e:term() ")" separator()* { e }

peg::parser! {
    grammar scimfilter() for str {

        pub rule parse() -> ScimFilter = precedence!{
            a:(@) separator()+ "or" separator()+ b:@ {
                ScimFilter::Or(
                    Box::new(a),
                    Box::new(b)
                )
            }
            --
            a:(@) separator()+ "and" separator()+ b:@ {
                ScimFilter::And(
                    Box::new(a),
                    Box::new(b)
                )
            }
            --
            "not" separator()+ "(" e:parse() ")" {
                ScimFilter::Not(Box::new(e))
            }
            --
            // separator()* e:parse() separator()* { e }
            "(" e:parse() ")" { e }
            a:attrexp() { a }
        }

        pub(crate) rule attrexp() -> ScimFilter =
            pres()
            / eq()
            / ne()
            / co()
            / sw()
            / ew()
            / gt()
            / lt()
            / ge()
            / le()

        pub(crate) rule pres() -> ScimFilter =
            a:attrpath() separator()+ "pr" { ScimFilter::Present(a) }

        pub(crate) rule eq() -> ScimFilter =
            a:attrpath() separator()+ "eq" separator()+ v:value() { ScimFilter::Equal(a, v) }

        pub(crate) rule ne() -> ScimFilter =
            a:attrpath() separator()+ "ne" separator()+ v:value() { ScimFilter::NotEqual(a, v) }

        pub(crate) rule co() -> ScimFilter =
            a:attrpath() separator()+ "co" separator()+ v:value() { ScimFilter::Contains(a, v) }

        pub(crate) rule sw() -> ScimFilter =
            a:attrpath() separator()+ "sw" separator()+ v:value() { ScimFilter::StartsWith(a, v) }

        pub(crate) rule ew() -> ScimFilter =
            a:attrpath() separator()+ "ew" separator()+ v:value() { ScimFilter::EndsWith(a, v) }

        pub(crate) rule gt() -> ScimFilter =
            a:attrpath() separator()+ "gt" separator()+ v:value() { ScimFilter::Greater(a, v) }

        pub(crate) rule lt() -> ScimFilter =
            a:attrpath() separator()+ "lt" separator()+ v:value() { ScimFilter::Less(a, v) }

        pub(crate) rule ge() -> ScimFilter =
            a:attrpath() separator()+ "ge" separator()+ v:value() { ScimFilter::GreaterOrEqual(a, v) }

        pub(crate) rule le() -> ScimFilter =
            a:attrpath() separator()+ "le" separator()+ v:value() { ScimFilter::LessOrEqual(a, v) }

        rule separator() =
            ['\n' | ' ' | '\t' ]

        rule operator() =
            ['\n' | ' ' | '\t' | '(' | ')' ]

        rule value() -> Value =
            barevalue()

        rule barevalue() -> Value =
            s:$((!operator()[_])*) {? serde_json::from_str(s).map_err(|_| "invalid json value" ) }

        pub(crate) rule attrpath() -> AttrPath =
            a:attrname() s:subattr()? { AttrPath { a, s } }

        rule subattr() -> String =
            "." s:attrname() { s.to_string() }

        pub(crate) rule attrname() -> String =
            s:$([ 'a'..='z' | 'A'..='Z']['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' ]*) { s.to_string() }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::filter::AttrPath;
    use crate::filter::ScimFilter;
    use serde_json::Value;

    #[test]
    fn test_scimfilter_attrname() {
        assert_eq!(scimfilter::attrname("abcd-_"), Ok("abcd-_".to_string()));
        assert_eq!(scimfilter::attrname("aB-_CD"), Ok("aB-_CD".to_string()));
        assert_eq!(scimfilter::attrname("a1-_23"), Ok("a1-_23".to_string()));
        assert!(scimfilter::attrname("-bcd").is_err());
        assert!(scimfilter::attrname("_bcd").is_err());
        assert!(scimfilter::attrname("0bcd").is_err());
    }

    #[test]
    fn test_scimfilter_attrpath() {
        assert_eq!(
            scimfilter::attrpath("abcd"),
            Ok(AttrPath {
                a: "abcd".to_string(),
                s: None
            })
        );

        assert_eq!(
            scimfilter::attrpath("abcd.abcd"),
            Ok(AttrPath {
                a: "abcd".to_string(),
                s: Some("abcd".to_string())
            })
        );

        assert!(scimfilter::attrname("abcd.0").is_err());
        assert!(scimfilter::attrname("abcd._").is_err());
        assert!(scimfilter::attrname("abcd,0").is_err());
        assert!(scimfilter::attrname(".abcd").is_err());
    }

    #[test]
    fn test_scimfilter_pres() {
        assert!(
            scimfilter::parse("abcd pr")
                == Ok(ScimFilter::Present(AttrPath {
                    a: "abcd".to_string(),
                    s: None
                }))
        );
    }

    #[test]
    fn test_scimfilter_eq() {
        assert!(
            scimfilter::parse("abcd eq \"dcba\"")
                == Ok(ScimFilter::Equal(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_ne() {
        assert!(
            scimfilter::parse("abcd ne \"dcba\"")
                == Ok(ScimFilter::NotEqual(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_co() {
        assert!(
            scimfilter::parse("abcd co \"dcba\"")
                == Ok(ScimFilter::Contains(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_sw() {
        assert!(
            scimfilter::parse("abcd sw \"dcba\"")
                == Ok(ScimFilter::StartsWith(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_ew() {
        assert!(
            scimfilter::parse("abcd ew \"dcba\"")
                == Ok(ScimFilter::EndsWith(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_gt() {
        assert!(
            scimfilter::parse("abcd gt \"dcba\"")
                == Ok(ScimFilter::Greater(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_lt() {
        assert!(
            scimfilter::parse("abcd lt \"dcba\"")
                == Ok(ScimFilter::Less(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_ge() {
        assert!(
            scimfilter::parse("abcd ge \"dcba\"")
                == Ok(ScimFilter::GreaterOrEqual(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_le() {
        assert!(
            scimfilter::parse("abcd le \"dcba\"")
                == Ok(ScimFilter::LessOrEqual(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_group() {
        let f = scimfilter::parse("(abcd eq \"dcba\")");
        eprintln!("{:?}", f);
        assert!(
            f == Ok(ScimFilter::Equal(
                AttrPath {
                    a: "abcd".to_string(),
                    s: None
                },
                Value::String("dcba".to_string())
            ))
        );
    }

    #[test]
    fn test_scimfilter_not() {
        let f = scimfilter::parse("not (abcd eq \"dcba\")");
        eprintln!("{:?}", f);

        assert!(
            f == Ok(ScimFilter::Not(Box::new(ScimFilter::Equal(
                AttrPath {
                    a: "abcd".to_string(),
                    s: None
                },
                Value::String("dcba".to_string())
            ))))
        );
    }

    #[test]
    fn test_scimfilter_and() {
        let f = scimfilter::parse("abcd eq \"dcba\" and bcda ne \"1234\"");
        eprintln!("{:?}", f);

        assert!(
            f == Ok(ScimFilter::And(
                Box::new(ScimFilter::Equal(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                )),
                Box::new(ScimFilter::NotEqual(
                    AttrPath {
                        a: "bcda".to_string(),
                        s: None
                    },
                    Value::String("1234".to_string())
                ))
            ))
        );
    }

    #[test]
    fn test_scimfilter_or() {
        let f = scimfilter::parse("abcd eq \"dcba\" or bcda ne \"1234\"");
        eprintln!("{:?}", f);

        assert!(
            f == Ok(ScimFilter::Or(
                Box::new(ScimFilter::Equal(
                    AttrPath {
                        a: "abcd".to_string(),
                        s: None
                    },
                    Value::String("dcba".to_string())
                )),
                Box::new(ScimFilter::NotEqual(
                    AttrPath {
                        a: "bcda".to_string(),
                        s: None
                    },
                    Value::String("1234".to_string())
                ))
            ))
        );
    }

    #[test]
    fn test_scimfilter_precedence_1() {
        let f = scimfilter::parse("a pr or b pr and c pr or d pr");
        eprintln!("{:?}", f);

        assert!(
            f == Ok(ScimFilter::Or(
                Box::new(ScimFilter::Or(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: "a".to_string(),
                        s: None
                    })),
                    Box::new(ScimFilter::And(
                        Box::new(ScimFilter::Present(AttrPath {
                            a: "b".to_string(),
                            s: None
                        })),
                        Box::new(ScimFilter::Present(AttrPath {
                            a: "c".to_string(),
                            s: None
                        })),
                    )),
                )),
                Box::new(ScimFilter::Present(AttrPath {
                    a: "d".to_string(),
                    s: None
                }))
            ))
        );
    }

    #[test]
    fn test_scimfilter_precedence_2() {
        let f = scimfilter::parse("a pr and b pr or c pr and d pr");
        eprintln!("{:?}", f);

        assert!(
            f == Ok(ScimFilter::Or(
                Box::new(ScimFilter::And(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: "a".to_string(),
                        s: None
                    })),
                    Box::new(ScimFilter::Present(AttrPath {
                        a: "b".to_string(),
                        s: None
                    })),
                )),
                Box::new(ScimFilter::And(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: "c".to_string(),
                        s: None
                    })),
                    Box::new(ScimFilter::Present(AttrPath {
                        a: "d".to_string(),
                        s: None
                    })),
                )),
            ))
        );
    }

    #[test]
    fn test_scimfilter_precedence_3() {
        let f = scimfilter::parse("a pr and (b pr or c pr) and d pr");
        eprintln!("{:?}", f);

        assert!(
            f == Ok(ScimFilter::And(
                Box::new(ScimFilter::And(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: "a".to_string(),
                        s: None
                    })),
                    Box::new(ScimFilter::Or(
                        Box::new(ScimFilter::Present(AttrPath {
                            a: "b".to_string(),
                            s: None
                        })),
                        Box::new(ScimFilter::Present(AttrPath {
                            a: "c".to_string(),
                            s: None
                        })),
                    )),
                )),
                Box::new(ScimFilter::Present(AttrPath {
                    a: "d".to_string(),
                    s: None
                })),
            ))
        );
    }

    #[test]
    fn test_scimfilter_precedence_4() {
        let f = scimfilter::parse("a pr and not (b pr or c pr) and d pr");
        eprintln!("{:?}", f);

        assert!(
            f == Ok(ScimFilter::And(
                Box::new(ScimFilter::And(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: "a".to_string(),
                        s: None
                    })),
                    Box::new(ScimFilter::Not(Box::new(ScimFilter::Or(
                        Box::new(ScimFilter::Present(AttrPath {
                            a: "b".to_string(),
                            s: None
                        })),
                        Box::new(ScimFilter::Present(AttrPath {
                            a: "c".to_string(),
                            s: None
                        })),
                    )))),
                )),
                Box::new(ScimFilter::Present(AttrPath {
                    a: "d".to_string(),
                    s: None
                })),
            ))
        );
    }
}
