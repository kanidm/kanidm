use super::entry::Entry;
use super::error::SchemaError;
use std::collections::HashMap;
// Apparently this is nightly only?
use std::convert::TryFrom;

// representations of schema that confines object types, classes
// and attributes. This ties in deeply with "Entry".
// This only defines the types, and how they are represented. For
// application and validation of the schema, see "Entry".
//
// In the future this will parse/read it's schema from the db
// but we have to bootstrap with some core types.

#[derive(Debug, PartialEq)]
enum Ternary {
    Empty,
    True,
    False,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IndexType {
    EQUALITY,
    PRESENCE,
    SUBSTRING,
}

impl TryFrom<String> for IndexType {
    type Error = ();

    fn try_from(value: String) -> Result<IndexType, Self::Error> {
        if value == "EQUALITY" {
            Ok(IndexType::EQUALITY)
        } else if value == "PRESENCE" {
            Ok(IndexType::PRESENCE)
        } else if value == "SUBSTRING" {
            Ok(IndexType::SUBSTRING)
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyntaxType {
    // We need an insensitive string type too ...
    // We also need to "self host" a syntax type, and index type
    UTF8STRING,
    UTF8STRING_INSENSITIVE,
    BOOLEAN,
    SYNTAX_ID,
    INDEX_ID,
}

impl TryFrom<String> for IndexType {
    type Error = ();

    fn try_from(value: String) -> Result<SyntaxType, Self::Error> {
    }
}

#[derive(Debug, Clone)]
pub struct SchemaAttribute {
    class: Vec<String>,
    name: String,
    // Perhaps later add aliases?
    description: String,
    system: bool,
    secret: bool,
    multivalue: bool,
    index: Vec<IndexType>,
    syntax: SyntaxType,
}

impl SchemaAttribute {
    // Implement Equality, PartialOrd, Normalisation,
    // Validation.
}

#[derive(Debug)]
pub struct SchemaClass {
    class: Vec<String>,
    name: String,
    description: String,
    // This allows modification of system types to be extended in custom ways
    systemmay: Vec<String>,
    may: Vec<String>,
    systemmust: Vec<String>,
    must: Vec<String>,
}

impl SchemaClass {
    // Implement Validation and Normalisation against entries
    pub fn validate_entry(&self, entry: &Entry) -> Result<(), ()> {
        Err(())
    }
}

#[derive(Debug)]
pub struct Schema {
    // We contain sets of classes and attributes.
    classes: HashMap<String, SchemaClass>,
    attributes: HashMap<String, SchemaAttribute>,
}

impl Schema {
    pub fn new() -> Self {
        //
        let mut s = Schema {
            classes: HashMap::new(),
            attributes: HashMap::new(),
        };
        // Bootstrap in definitions of our own schema types
        // First, add all the needed core attributes for schema parsing
        s.attributes.insert(
            String::from("class"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("class"),
                description: String::from("The set of classes defining an object"),
                system: true,
                secret: false,
                multivalue: true,
                index: vec![IndexType::EQUALITY],
                syntax: SyntaxType::UTF8STRING_INSENSITIVE,
            },
        );
        s.attributes.insert(
            String::from("name"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("name"),
                description: String::from("The shortform name of an object"),
                system: true,
                secret: false,
                multivalue: false,
                index: vec![IndexType::EQUALITY],
                syntax: SyntaxType::UTF8STRING_INSENSITIVE,
            },
        );
        s.attributes.insert(
            String::from("description"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("description"),
                description: String::from("A description of an attribute, object or class"),
                system: true,
                secret: false,
                multivalue: false,
                index: vec![],
                syntax: SyntaxType::UTF8STRING,
            },
        );
        s.attributes.insert(
            String::from("system"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("system"),
                description: String::from(
                    "Is this object or attribute provided from the core system?",
                ),
                system: true,
                secret: false,
                multivalue: false,
                index: vec![],
                syntax: SyntaxType::BOOLEAN,
            },
        );
        s.attributes.insert(String::from("secret"), SchemaAttribute {
            class: vec![String::from("attributetype")],
            name: String::from("secret"),
            description: String::from("If true, this value is always hidden internally to the server, even beyond access controls."),
            system: true,
            secret: false,
            multivalue: false,
            index: vec![],
            syntax: SyntaxType::BOOLEAN,
        });
        s.attributes.insert(String::from("multivalue"), SchemaAttribute {
            class: vec![String::from("attributetype")],
            name: String::from("multivalue"),
            description: String::from("If true, this attribute is able to store multiple values rather than just a single value."),
            system: true,
            secret: false,
            multivalue: false,
            index: vec![],
            syntax: SyntaxType::BOOLEAN,
        });
        s.attributes.insert(
            String::from("index"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("index"),
                description: String::from(
                    "Describe the indexes to apply to instances of this attribute.",
                ),
                system: true,
                secret: false,
                multivalue: false,
                index: vec![],
                syntax: SyntaxType::INDEX_ID,
            },
        );
        s.attributes.insert(
            String::from("syntax"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("syntax"),
                description: String::from(
                    "Describe the syntax of this attribute. This affects indexing and sorting.",
                ),
                system: true,
                secret: false,
                multivalue: false,
                index: vec![IndexType::EQUALITY],
                syntax: SyntaxType::SYNTAX_ID,
            },
        );
        s.attributes.insert(
            String::from("systemmay"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("systemmay"),
                description: String::from(
                    "A list of system provided optional attributes this class can store.",
                ),
                system: true,
                secret: false,
                multivalue: true,
                index: vec![],
                syntax: SyntaxType::UTF8STRING_INSENSITIVE,
            },
        );
        s.attributes.insert(
            String::from("may"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("may"),
                description: String::from(
                    "A user modifiable list of optional attributes this class can store.",
                ),
                system: true,
                secret: false,
                multivalue: false,
                index: vec![],
                syntax: SyntaxType::UTF8STRING_INSENSITIVE,
            },
        );
        s.attributes.insert(
            String::from("systemmust"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("systemmust"),
                description: String::from(
                    "A list of system provided required attributes this class must store.",
                ),
                system: true,
                secret: false,
                multivalue: false,
                index: vec![],
                syntax: SyntaxType::UTF8STRING_INSENSITIVE,
            },
        );
        s.attributes.insert(
            String::from("must"),
            SchemaAttribute {
                class: vec![String::from("attributetype")],
                name: String::from("must"),
                description: String::from(
                    "A user modifiable list of required attributes this class must store.",
                ),
                system: true,
                secret: false,
                multivalue: false,
                index: vec![],
                syntax: SyntaxType::UTF8STRING_INSENSITIVE,
            },
        );

        s.classes.insert(
            String::from("attributetype"),
            SchemaClass {
                class: vec![String::from("classtype")],
                name: String::from("attributetype"),
                description: String::from("Definition of a schema attribute"),
                systemmay: vec![String::from("index"), String::from("description")],
                may: vec![],
                systemmust: vec![
                    String::from("class"),
                    String::from("name"),
                    String::from("system"),
                    String::from("secret"),
                    String::from("multivalue"),
                    String::from("syntax"),
                ],
                must: vec![],
            },
        );
        s.classes.insert(
            String::from("classtype"),
            SchemaClass {
                class: vec![String::from("classtype")],
                name: String::from("classtype"),
                description: String::from("Definition of a schema classtype"),
                systemmay: vec![
                    String::from("description"),
                    String::from("systemmay"),
                    String::from("may"),
                    String::from("systemmust"),
                    String::from("must"),
                ],
                may: vec![],
                systemmust: vec![String::from("class"), String::from("name")],
                must: vec![],
            },
        );
        s.classes.insert(
            String::from("extensibleobject"),
            SchemaClass {
                class: vec![String::from("classtype")],
                name: String::from("extensibleobject"),
                description: String::from("A class type that turns off all rules ..."),
                systemmay: vec![],
                may: vec![],
                systemmust: vec![],
                must: vec![],
            },
        );

        s
    }

    pub fn validate(&self) -> Result<(), ()> {
        // FIXME: How can we make this return a proper result?
        //
        // Do we need some functional bullshit?
        // Validate our schema content is sane
        // For now we only have a few basic methods for this, such as
        // checking all our classes must/may are correct.
        for class in self.classes.values() {
            for a in &class.systemmay {
                assert!(self.attributes.contains_key(a));
            }
            for a in &class.may {
                assert!(self.attributes.contains_key(a));
            }
            for a in &class.systemmust {
                assert!(self.attributes.contains_key(a));
            }
            for a in &class.must {
                assert!(self.attributes.contains_key(a));
            }
        }

        Ok(())
    }

    pub fn validate_entry(&self, entry: &Entry) -> Result<(), SchemaError> {
        // First look at the classes on the entry.
        // Now, check they are valid classes
        //
        // FIXME: We could restructure this to be a map that gets Some(class)
        // if found, then do a len/filter/check on the resulting class set?
        let c_valid = entry.classes().fold(Ternary::Empty, |acc, c| {
            if acc == Ternary::False {
                // Begin shortcircuit
                acc
            } else {
                // Test the value (Could be True or Valid on entry.
                // We
                match self.classes.contains_key(c) {
                    true => Ternary::True,
                    false => Ternary::False,
                }
            }
        });

        if c_valid != Ternary::True {
            return Err(SchemaError::INVALID_CLASS);
        };

        let classes: HashMap<String, &SchemaClass> = entry
            .classes()
            .map(|c| (c.clone(), self.classes.get(c).unwrap()))
            .collect();

        let extensible = classes.contains_key("extensibleobject");

        // What this is really doing is taking a set of classes, and building an
        // "overall" class that describes this exact object for checking

        //   for each class
        //      add systemmust/must and systemmay/may to their lists
        //      add anything from must also into may

        // Now from the set of valid classes make a list of must/may
        // FIXME: This is clone on read, which may be really slow. It also may
        // be inefficent on duplicates etc.
        let must: HashMap<String, &SchemaAttribute> = classes
            .iter()
            // Join our class systemmmust + must into one iter
            .flat_map(|(_, cls)| cls.systemmust.iter().chain(cls.must.iter()))
            .map(|s| (s.clone(), self.attributes.get(s).unwrap()))
            .collect();

        let may: HashMap<String, &SchemaAttribute> = classes
            .iter()
            // Join our class systemmmust + must into one iter
            .flat_map(|(_, cls)| {
                cls.systemmust
                    .iter()
                    .chain(cls.must.iter())
                    .chain(cls.systemmay.iter())
                    .chain(cls.may.iter())
            })
            .map(|s| (s.clone(), self.attributes.get(s).unwrap()))
            .collect();

        // FIXME: Error needs to say what is missing
        // We need to return *all* missing attributes.

        // Check that all must are inplace
        //   for each attr in must, check it's present on our ent
        for (attr_name, attr) in must {
            let avas = entry.get_ava(&attr_name);
            if avas.is_none() {
                return Err(SchemaError::MISSING_MUST_ATTRIBUTE);
            }
        }

        // Check that any other attributes are in may
        //   for each attr on the object, check it's in the may+must set
        for (attr_name, avas) in entry.avas() {
            println!("AVAS {:?} : {:?}", attr_name, avas);
            match self.attributes.get(attr_name) {
                Some(a_schema) => {
                    // Now, for each type we do a *full* check of the syntax
                    // and validity of the ava.
                }
                None => {
                    if !extensible {
                        return Err(SchemaError::INVALID_ATTRIBUTE);
                    }
                }
            }
        }

        // Well, we got here, so okay!
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use super::super::entry::Entry;
    use super::super::error::SchemaError;
    use super::{IndexType, Schema, SchemaAttribute, SchemaClass, SyntaxType};

    #[test]
    fn test_schema_index_tryfrom() {
        let r1 = IndexType::try_from(String::from("EQUALITY"));
        assert_eq!(r1, Ok(IndexType::EQUALITY));

        let r2 = IndexType::try_from(String::from("PRESENCE"));
        assert_eq!(r2, Ok(IndexType::PRESENCE));

        let r3 = IndexType::try_from(String::from("SUBSTRING"));
        assert_eq!(r3, Ok(IndexType::SUBSTRING));

        let r4 = IndexType::try_from(String::from("thaoeusaneuh"));
        assert_eq!(r4, Err(()));
    }

    #[test]
    fn test_schema_syntax_tryfrom() {
        
    }

    #[test]
    fn test_schema_attribute_simple() {
        let class_attribute = SchemaAttribute {
            class: vec![String::from("attributetype")],
            name: String::from("class"),
            description: String::from("The set of classes defining an object"),
            system: true,
            secret: false,
            multivalue: true,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::UTF8STRING_INSENSITIVE,
        };
        // Test basic functions of simple attributes
    }

    #[test]
    fn test_schema_classes_simple() {
        // Test basic functions of simple attributes
    }

    #[test]
    fn test_schema_simple() {
        let schema = Schema::new();
        assert!(schema.validate().is_ok());
    }

    #[test]
    fn test_schema_export_validate() {
        // Test exporting schema to entries, then validate them
        // as legitimate entries.
    }

    #[test]
    fn test_schema_entries() {
        // Given an entry, assert it's schema is valid
        // We do
        let schema = Schema::new();
        let mut e_no_class: Entry = Entry::new();
        assert_eq!(
            schema.validate_entry(&e_no_class),
            Err(SchemaError::INVALID_CLASS)
        );

        let mut e_bad_class: Entry = Entry::new();
        e_bad_class
            .add_ava(String::from("class"), String::from("zzzzzz"))
            .unwrap();
        assert_eq!(
            schema.validate_entry(&e_bad_class),
            Err(SchemaError::INVALID_CLASS)
        );

        let mut e_attr_invalid: Entry = Entry::new();
        e_attr_invalid
            .add_ava(String::from("class"), String::from("attributetype"))
            .unwrap();

        assert_eq!(
            schema.validate_entry(&e_attr_invalid),
            Err(SchemaError::MISSING_MUST_ATTRIBUTE)
        );

        let mut e_attr_invalid_may: Entry = Entry::new();
        e_attr_invalid_may
            .add_ava(String::from("class"), String::from("attributetype"))
            .unwrap();
        e_attr_invalid_may
            .add_ava(String::from("name"), String::from("testattr"))
            .unwrap();
        e_attr_invalid_may
            .add_ava(String::from("system"), String::from("false"))
            .unwrap();
        e_attr_invalid_may
            .add_ava(String::from("secret"), String::from("false"))
            .unwrap();
        e_attr_invalid_may
            .add_ava(String::from("multivalue"), String::from("false"))
            .unwrap();
        e_attr_invalid_may
            .add_ava(String::from("syntax"), String::from("UTF8STRING"))
            .unwrap();
        // This is the invalid one
        e_attr_invalid_may
            .add_ava(String::from("zzzz"), String::from("zzzz"))
            .unwrap();

        assert_eq!(
            schema.validate_entry(&e_attr_invalid_may),
            Err(SchemaError::INVALID_ATTRIBUTE)
        );

        let mut e_attr_invalid_syn: Entry = Entry::new();
        e_attr_invalid_syn
            .add_ava(String::from("class"), String::from("attributetype"))
            .unwrap();
        e_attr_invalid_syn
            .add_ava(String::from("name"), String::from("testattr"))
            .unwrap();
        e_attr_invalid_syn
            .add_ava(String::from("system"), String::from("false"))
            .unwrap();
        e_attr_invalid_syn
            .add_ava(String::from("secret"), String::from("false"))
            .unwrap();
        // This is the invalid one
        e_attr_invalid_syn
            .add_ava(String::from("multivalue"), String::from("zzzz"))
            .unwrap();
        e_attr_invalid_syn
            .add_ava(String::from("syntax"), String::from("UTF8STRING"))
            .unwrap();

        assert_eq!(
            schema.validate_entry(&e_attr_invalid_syn),
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        );

        let mut e_ok: Entry = Entry::new();
        e_ok.add_ava(String::from("class"), String::from("attributetype"))
            .unwrap();
        e_ok.add_ava(String::from("name"), String::from("testattr"))
            .unwrap();
        e_ok.add_ava(String::from("system"), String::from("false"))
            .unwrap();
        e_ok.add_ava(String::from("secret"), String::from("false"))
            .unwrap();
        e_ok.add_ava(String::from("multivalue"), String::from("true"))
            .unwrap();
        e_ok.add_ava(String::from("syntax"), String::from("UTF8STRING"))
            .unwrap();

        assert_eq!(schema.validate_entry(&e_ok), Ok(()));
    }

    #[test]
    fn test_schema_extensible() {
        let schema = Schema::new();
        // Just because you are extensible, doesn't mean you can be lazy
        let mut e_extensible_bad: Entry = Entry::new();
        e_extensible_bad
            .add_ava(String::from("class"), String::from("extensibleobject"))
            .unwrap();
        // Secret is a boolean type
        e_extensible_bad
            .add_ava(String::from("secret"), String::from("zzzz"))
            .unwrap();

        assert_eq!(
            schema.validate_entry(&e_extensible_bad),
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        );

        let mut e_extensible: Entry = Entry::new();
        e_extensible
            .add_ava(String::from("class"), String::from("extensibleobject"))
            .unwrap();
        e_extensible
            .add_ava(String::from("zzzz"), String::from("zzzz"))
            .unwrap();

        /* Is okay because extensible! */
        assert_eq!(schema.validate_entry(&e_extensible), Ok(()));
    }

    #[test]
    fn test_schema_custom() {
        // Validate custom schema entries
    }

    #[test]
    fn test_schema_loading() {
        // Validate loading schema from entries
    }
}
