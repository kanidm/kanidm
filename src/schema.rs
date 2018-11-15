use super::entry::Entry;
use super::error::SchemaError;
use super::filter::Filter;
use std::collections::HashMap;
// Apparently this is nightly only?
use std::convert::TryFrom;
use std::str::FromStr;

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

impl TryFrom<&str> for IndexType {
    type Error = ();

    fn try_from(value: &str) -> Result<IndexType, Self::Error> {
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

impl TryFrom<&str> for SyntaxType {
    type Error = ();

    fn try_from(value: &str) -> Result<SyntaxType, Self::Error> {
        if value == "UTF8STRING" {
            Ok(SyntaxType::UTF8STRING)
        } else if value == "UTF8STRING_INSENSITIVE" {
            Ok(SyntaxType::UTF8STRING_INSENSITIVE)
        } else if value == "BOOLEAN" {
            Ok(SyntaxType::BOOLEAN)
        } else if value == "SYNTAX_ID" {
            Ok(SyntaxType::SYNTAX_ID)
        } else if value == "INDEX_ID" {
            Ok(SyntaxType::INDEX_ID)
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchemaAttribute {
    // Is this ... used?
    // class: Vec<String>,
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
    fn validate_bool(&self, v: &String) -> Result<(), SchemaError> {
        bool::from_str(v.as_str())
            .map_err(|_| SchemaError::INVALID_ATTRIBUTE_SYNTAX)
            .map(|_| ())
    }

    fn validate_syntax(&self, v: &String) -> Result<(), SchemaError> {
        SyntaxType::try_from(v.as_str())
            .map_err(|_| SchemaError::INVALID_ATTRIBUTE_SYNTAX)
            .map(|_| ())
    }

    fn validate_index(&self, v: &String) -> Result<(), SchemaError> {
        IndexType::try_from(v.as_str())
            .map_err(|_| SchemaError::INVALID_ATTRIBUTE_SYNTAX)
            .map(|_| ())
    }

    fn validate_utf8string_insensitive(&self, v: &String) -> Result<(), SchemaError> {
        // FIXME: Is there a way to do this that doesn't involve a copy?
        let t = v.to_lowercase();
        if &t == v {
            Ok(())
        } else {
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        }
    }

    pub fn validate_value(&self, v: &String) -> Result<(), SchemaError> {
        match self.syntax {
            SyntaxType::BOOLEAN => self.validate_bool(v),
            SyntaxType::SYNTAX_ID => self.validate_syntax(v),
            SyntaxType::INDEX_ID => self.validate_index(v),
            SyntaxType::UTF8STRING_INSENSITIVE => self.validate_utf8string_insensitive(v),
            _ => Ok(()),
        }
    }

    pub fn validate_ava(&self, ava: &Vec<String>) -> Result<(), SchemaError> {
        // Check multivalue
        if self.multivalue == false && ava.len() > 1 {
            return Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX);
        };
        // If syntax, check the type is correct
        match self.syntax {
            SyntaxType::BOOLEAN => {
                ava.iter().fold(Ok(()), |acc, v| {
                    if acc.is_ok() {
                        self.validate_bool(v)
                    } else {
                        // We got an error before, just skip the rest
                        acc
                    }
                })
            }
            SyntaxType::SYNTAX_ID => {
                ava.iter().fold(Ok(()), |acc, v| {
                    // If acc is err, map will skip it.
                    if acc.is_ok() {
                        self.validate_syntax(v)
                    } else {
                        acc
                    }
                })
            }
            SyntaxType::INDEX_ID => {
                ava.iter().fold(Ok(()), |acc, v| {
                    // If acc is err, map will skip it.
                    if acc.is_ok() {
                        self.validate_index(v)
                    } else {
                        acc
                    }
                })
            }
            SyntaxType::UTF8STRING_INSENSITIVE => {
                ava.iter().fold(Ok(()), |acc, v| {
                    // If acc is err, map will skip it.
                    if acc.is_ok() {
                        self.validate_utf8string_insensitive(v)
                    } else {
                        acc
                    }
                })
            }
            _ => Ok(()),
        }
    }

    pub fn normalise_syntax(&self, v: &String) -> String {
        v.to_uppercase()
    }

    pub fn normalise_index(&self, v: &String) -> String {
        v.to_uppercase()
    }

    pub fn normalise_utf8string_insensitive(&self, v: &String) -> String {
        v.to_lowercase()
    }

    pub fn normalise_value(&self, v: &String) -> String {
        match self.syntax {
            SyntaxType::SYNTAX_ID => self.normalise_syntax(v),
            SyntaxType::INDEX_ID => self.normalise_index(v),
            SyntaxType::UTF8STRING_INSENSITIVE => self.normalise_utf8string_insensitive(v),
            _ => v.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchemaClass {
    // Is this used?
    // class: Vec<String>,
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

#[derive(Debug, Clone)]
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
                // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("attributetype")],
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
            // class: vec![String::from("attributetype")],
            name: String::from("secret"),
            description: String::from("If true, this value is always hidden internally to the server, even beyond access controls."),
            system: true,
            secret: false,
            multivalue: false,
            index: vec![],
            syntax: SyntaxType::BOOLEAN,
        });
        s.attributes.insert(String::from("multivalue"), SchemaAttribute {
            // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("attributetype")],
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
                // class: vec![String::from("classtype")],
                name: String::from("attributetype"),
                description: String::from("Definition of a schema attribute"),
                systemmay: vec![String::from("index")],
                may: vec![],
                systemmust: vec![
                    String::from("class"),
                    String::from("name"),
                    String::from("system"),
                    String::from("secret"),
                    String::from("multivalue"),
                    String::from("syntax"),
                    String::from("description"),
                ],
                must: vec![],
            },
        );
        s.classes.insert(
            String::from("classtype"),
            SchemaClass {
                // class: vec![String::from("classtype")],
                name: String::from("classtype"),
                description: String::from("Definition of a schema classtype"),
                systemmay: vec![
                    String::from("systemmay"),
                    String::from("may"),
                    String::from("systemmust"),
                    String::from("must"),
                ],
                may: vec![],
                systemmust: vec![
                    String::from("class"),
                    String::from("name"),
                    String::from("description"),
                ],
                must: vec![],
            },
        );
        s.classes.insert(
            String::from("extensibleobject"),
            SchemaClass {
                // class: vec![String::from("classtype")],
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

    // This shouldn't fail?
    pub fn bootstrap_core(&mut self) {
        // This will create a set of sane, system core schema that we can use
        // main types are users, groups

        // Create attributes
        // displayname // single
        self.attributes.insert(
            String::from("displayname"),
            SchemaAttribute {
                // class: vec![String::from("attributetype")],
                name: String::from("displayname"),
                description: String::from("The publicly visible display name of this person"),
                system: true,
                secret: false,
                multivalue: false,
                index: vec![IndexType::EQUALITY],
                syntax: SyntaxType::UTF8STRING,
            },
        );
        // name // single
        // mail // multi
        self.attributes.insert(
            String::from("mail"),
            SchemaAttribute {
                // class: vec![String::from("attributetype")],
                name: String::from("mail"),
                description: String::from("mail addresses of the object"),
                system: true,
                secret: false,
                multivalue: true,
                index: vec![IndexType::EQUALITY],
                syntax: SyntaxType::UTF8STRING,
            },
        );
        // memberof // multi
        self.attributes.insert(
            String::from("memberof"),
            SchemaAttribute {
                // class: vec![String::from("attributetype")],
                name: String::from("memberof"),
                description: String::from("reverse group membership of the object"),
                system: true,
                secret: false,
                multivalue: true,
                index: vec![IndexType::EQUALITY],
                syntax: SyntaxType::UTF8STRING_INSENSITIVE,
            },
        );
        // ssh_publickey // multi
        self.attributes.insert(
            String::from("ssh_publickey"),
            SchemaAttribute {
                // class: vec![String::from("attributetype")],
                name: String::from("ssh_publickey"),
                description: String::from("SSH public keys of the object"),
                system: true,
                secret: false,
                multivalue: true,
                index: vec![],
                syntax: SyntaxType::UTF8STRING,
            },
        );
        // password // secret, multi
        self.attributes.insert(
            String::from("password"),
            SchemaAttribute {
                // class: vec![String::from("attributetype")],
                name: String::from("password"),
                description: String::from(
                    "password hash material of the object for authentication",
                ),
                system: true,
                secret: true,
                multivalue: true,
                index: vec![],
                syntax: SyntaxType::UTF8STRING,
            },
        );
        //
        // member
        self.attributes.insert(
            String::from("member"),
            SchemaAttribute {
                // class: vec![String::from("attributetype")],
                name: String::from("member"),
                description: String::from("List of members of the group"),
                system: true,
                secret: false,
                multivalue: true,
                index: vec![IndexType::EQUALITY],
                syntax: SyntaxType::UTF8STRING_INSENSITIVE,
            },
        );

        // Create the classes that use it
        // person
        self.classes.insert(
            String::from("person"),
            SchemaClass {
                name: String::from("person"),
                description: String::from("Object representation of a person"),
                systemmay: vec![
                    String::from("description"),
                    String::from("mail"),
                    String::from("ssh_publickey"),
                    String::from("memberof"),
                    String::from("password"),
                ],
                may: vec![],
                systemmust: vec![
                    String::from("class"),
                    String::from("name"),
                    String::from("displayname"),
                ],
                must: vec![],
            },
        );
        // group
        self.classes.insert(
            String::from("group"),
            SchemaClass {
                name: String::from("group"),
                description: String::from("Object representation of a group"),
                systemmay: vec![String::from("description"), String::from("member")],
                may: vec![],
                systemmust: vec![String::from("class"), String::from("name")],
                must: vec![],
            },
        );
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
            match self.attributes.get(attr_name) {
                Some(a_schema) => {
                    // Now, for each type we do a *full* check of the syntax
                    // and validity of the ava.
                    let r = a_schema.validate_ava(avas);
                    // FIXME: This block could be more functional
                    if r.is_err() {
                        return r;
                    }
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

    pub fn normalise_entry(&mut self, entry: &Entry) -> Entry {
        // We duplicate the entry here, because we can't
        // modify what we got on the protocol level. It also
        // lets us extend and change things.

        let mut entry_new: Entry = Entry::new();
        // Better hope we have the attribute type ...
        let schema_attr_name = self.attributes.get("name").unwrap();
        // For each ava
        for (attr_name, avas) in entry.avas() {
            let attr_name_normal: String = schema_attr_name.normalise_value(attr_name);
            // Get the needed schema type
            let schema_a_r = self.attributes.get(&attr_name_normal);
            // if we can't find schema_a, clone and push
            // else

            let avas_normal: Vec<String> = match schema_a_r {
                Some(schema_a) => {
                    avas.iter()
                        .map(|av| {
                            // normalise those based on schema?
                            schema_a.normalise_value(av)
                        })
                        .collect()
                }
                None => avas.clone(),
            };
            // now push those to the new entry.
            entry_new.add_avas(attr_name_normal, avas_normal);
        }
        // Done!
        entry_new
    }

    // This needs to be recursive?
    pub fn validate_filter(&self, filt: &Filter) -> Result<(), SchemaError> {
        match filt {
            Filter::Eq(attr, value) => match self.attributes.get(attr) {
                Some(schema_a) => schema_a.validate_value(value),
                None => Err(SchemaError::INVALID_ATTRIBUTE),
            },
            Filter::Sub(attr, value) => match self.attributes.get(attr) {
                Some(schema_a) => schema_a.validate_value(value),
                None => Err(SchemaError::INVALID_ATTRIBUTE),
            },
            Filter::Pres(attr) => {
                // This could be better as a contains_key
                // because we never use the value
                match self.attributes.get(attr) {
                    Some(_) => Ok(()),
                    None => Err(SchemaError::INVALID_ATTRIBUTE),
                }
            }
            Filter::Or(filters) => {
                // This should never happen because
                // optimising should remove them as invalid parts?
                if filters.len() == 0 {
                    return Err(SchemaError::EMPTY_FILTER);
                };
                filters.iter().fold(Ok(()), |acc, filt| {
                    if acc.is_ok() {
                        self.validate_filter(filt)
                    } else {
                        acc
                    }
                })
            }
            Filter::And(filters) => {
                // This should never happen because
                // optimising should remove them as invalid parts?
                if filters.len() == 0 {
                    return Err(SchemaError::EMPTY_FILTER);
                };
                filters.iter().fold(Ok(()), |acc, filt| {
                    if acc.is_ok() {
                        self.validate_filter(filt)
                    } else {
                        acc
                    }
                })
            }
            Filter::Not(filters) => {
                // This should never happen because
                // optimising should remove them as invalid parts?
                if filters.len() == 0 {
                    return Err(SchemaError::EMPTY_FILTER);
                };
                filters.iter().fold(Ok(()), |acc, filt| {
                    if acc.is_ok() {
                        self.validate_filter(filt)
                    } else {
                        acc
                    }
                })
            }
        }
    }

    // Normalise *does not* validate.
    // Normalise just fixes some possible common issues, but it
    // can't fix *everything* possibly wrong ...
    pub fn normalise_filter(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::super::entry::Entry;
    use super::super::error::SchemaError;
    use super::super::filter::Filter;
    use super::{IndexType, Schema, SchemaAttribute, SchemaClass, SyntaxType};
    use serde_json;
    use std::convert::TryFrom;

    #[test]
    fn test_schema_index_tryfrom() {
        let r1 = IndexType::try_from("EQUALITY");
        assert_eq!(r1, Ok(IndexType::EQUALITY));

        let r2 = IndexType::try_from("PRESENCE");
        assert_eq!(r2, Ok(IndexType::PRESENCE));

        let r3 = IndexType::try_from("SUBSTRING");
        assert_eq!(r3, Ok(IndexType::SUBSTRING));

        let r4 = IndexType::try_from("thaoeusaneuh");
        assert_eq!(r4, Err(()));
    }

    #[test]
    fn test_schema_syntax_tryfrom() {
        let r1 = SyntaxType::try_from("UTF8STRING");
        assert_eq!(r1, Ok(SyntaxType::UTF8STRING));

        let r2 = SyntaxType::try_from("UTF8STRING_INSENSITIVE");
        assert_eq!(r2, Ok(SyntaxType::UTF8STRING_INSENSITIVE));

        let r3 = SyntaxType::try_from("BOOLEAN");
        assert_eq!(r3, Ok(SyntaxType::BOOLEAN));

        let r4 = SyntaxType::try_from("SYNTAX_ID");
        assert_eq!(r4, Ok(SyntaxType::SYNTAX_ID));

        let r5 = SyntaxType::try_from("INDEX_ID");
        assert_eq!(r5, Ok(SyntaxType::INDEX_ID));

        let r6 = SyntaxType::try_from("zzzzantheou");
        assert_eq!(r6, Err(()));
    }

    #[test]
    fn test_schema_attribute_simple() {
        let class_attribute = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("class"),
            description: String::from("The set of classes defining an object"),
            system: true,
            secret: false,
            multivalue: true,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::UTF8STRING_INSENSITIVE,
        };

        // Test schemaAttribute validation of types.

        // Test single value string
        let single_value_string = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("single_value"),
            description: String::from(""),
            system: true,
            secret: false,
            multivalue: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::UTF8STRING_INSENSITIVE,
        };

        let r1 = single_value_string.validate_ava(&vec![String::from("test")]);
        assert_eq!(r1, Ok(()));

        let r2 =
            single_value_string.validate_ava(&vec![String::from("test1"), String::from("test2")]);
        assert_eq!(r2, Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX));

        // test multivalue string, boolean

        let multi_value_string = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("mv_string"),
            description: String::from(""),
            system: true,
            secret: false,
            multivalue: true,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::UTF8STRING,
        };

        let r5 =
            multi_value_string.validate_ava(&vec![String::from("test1"), String::from("test2")]);
        assert_eq!(r5, Ok(()));

        let multi_value_boolean = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("mv_bool"),
            description: String::from(""),
            system: true,
            secret: false,
            multivalue: true,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::BOOLEAN,
        };

        let r3 =
            multi_value_boolean.validate_ava(&vec![String::from("test1"), String::from("test2")]);
        assert_eq!(r3, Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX));

        let r4 =
            multi_value_boolean.validate_ava(&vec![String::from("true"), String::from("false")]);
        assert_eq!(r4, Ok(()));

        // syntax_id and index_type values
        let single_value_syntax = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("sv_syntax"),
            description: String::from(""),
            system: true,
            secret: false,
            multivalue: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::SYNTAX_ID,
        };

        let r6 = single_value_syntax.validate_ava(&vec![String::from("UTF8STRING")]);
        assert_eq!(r6, Ok(()));

        let r7 = single_value_syntax.validate_ava(&vec![String::from("thaeountaheu")]);
        assert_eq!(r7, Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX));

        let single_value_index = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("sv_index"),
            description: String::from(""),
            system: true,
            secret: false,
            multivalue: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::INDEX_ID,
        };
        //
        let r8 = single_value_index.validate_ava(&vec![String::from("EQUALITY")]);
        assert_eq!(r8, Ok(()));

        let r9 = single_value_index.validate_ava(&vec![String::from("thaeountaheu")]);
        assert_eq!(r9, Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX));
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
        let e_no_class: Entry = serde_json::from_str(
            r#"{
            "attrs": {}
        }"#,
        )
        .unwrap();

        assert_eq!(
            schema.validate_entry(&e_no_class),
            Err(SchemaError::INVALID_CLASS)
        );

        let e_bad_class: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["zzzzzz"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_entry(&e_bad_class),
            Err(SchemaError::INVALID_CLASS)
        );

        let e_attr_invalid: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["attributetype"]
            }
        }"#,
        )
        .unwrap();

        assert_eq!(
            schema.validate_entry(&e_attr_invalid),
            Err(SchemaError::MISSING_MUST_ATTRIBUTE)
        );

        let e_attr_invalid_may: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "system": ["false"],
                "secret": ["false"],
                "multivalue": ["false"],
                "syntax": ["UTF8STRING"],
                "zzzzz": ["zzzz"]
            }
        }"#,
        )
        .unwrap();

        assert_eq!(
            schema.validate_entry(&e_attr_invalid_may),
            Err(SchemaError::INVALID_ATTRIBUTE)
        );

        let e_attr_invalid_syn: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "system": ["false"],
                "secret": ["false"],
                "multivalue": ["zzzzz"],
                "syntax": ["UTF8STRING"]
            }
        }"#,
        )
        .unwrap();

        assert_eq!(
            schema.validate_entry(&e_attr_invalid_syn),
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        );

        let e_ok: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "system": ["false"],
                "secret": ["false"],
                "multivalue": ["true"],
                "syntax": ["UTF8STRING"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_entry(&e_ok), Ok(()));
    }

    #[test]
    fn test_schema_entry_normalise() {
        // Check that entries can be normalised sanely
        let mut schema = Schema::new();
        schema.bootstrap_core();

        // Check syntax to upper
        // check index to upper
        // insense to lower
        // attr name to lower
        let e_test: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["TestPerson"],
                "displayName": ["testperson"],
                "syntax": ["utf8string"],
                "index": ["equality"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_entry(&e_test),
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        );

        let e_expect: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["testperson"],
                "displayname": ["testperson"],
                "syntax": ["UTF8STRING"],
                "index": ["EQUALITY"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_entry(&e_expect), Ok(()));

        let e_normalised = schema.normalise_entry(&e_test);

        assert_eq!(schema.validate_entry(&e_normalised), Ok(()));
        assert_eq!(e_expect, e_normalised);
    }

    #[test]
    fn test_schema_extensible() {
        let schema = Schema::new();
        // Just because you are extensible, doesn't mean you can be lazy

        let e_extensible_bad: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "secret": ["zzzz"]
            }
        }"#,
        )
        .unwrap();

        assert_eq!(
            schema.validate_entry(&e_extensible_bad),
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        );

        let e_extensible: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "secret": ["true"]
            }
        }"#,
        )
        .unwrap();

        /* Is okay because extensible! */
        assert_eq!(schema.validate_entry(&e_extensible), Ok(()));
    }

    #[test]
    fn test_schema_loading() {
        // Validate loading schema from entries
    }

    #[test]
    fn test_schema_bootstrap() {
        let mut schema = Schema::new();
        schema.bootstrap_core();

        // now test some entries
        let e_person: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_entry(&e_person), Ok(()));

        let e_group: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup"],
                "description": ["testperson"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_entry(&e_group), Ok(()));
    }

    #[test]
    fn test_schema_filter_validation() {
        let mut schema = Schema::new();
        // Test mixed case attr name
        let f_mixed: Filter = serde_json::from_str(
            r#"{
            "Eq": [
                "ClAsS", "attributetype"
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_mixed),
            Err(SchemaError::INVALID_ATTRIBUTE)
        );
        // test syntax of bool
        let f_bool: Filter = serde_json::from_str(
            r#"{
            "Eq": [
                "secret", "zzzz"
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_bool),
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        );
        // test insensitise values
        let f_insense: Filter = serde_json::from_str(
            r#"{
            "Eq": [
                "class", "AttributeType"
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_insense),
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        );
        // Test the recursive structures validate
        let f_or_empty: Filter = serde_json::from_str(
            r#"{
            "Or": []
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_or_empty),
            Err(SchemaError::EMPTY_FILTER)
        );
        let f_or: Filter = serde_json::from_str(
            r#"{
            "Or": [
              { "Eq": ["class", "AttributeType"] }
            ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_or),
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        );
        let f_or_mult: Filter = serde_json::from_str(
            r#"{
            "Or": [
              { "Eq": ["class", "attributetype"] },
              { "Eq": ["class", "AttributeType"] }
            ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_or_mult),
            Err(SchemaError::INVALID_ATTRIBUTE_SYNTAX)
        );
        let f_or_ok: Filter = serde_json::from_str(
            r#"{
            "Or": [
              { "Eq": ["class", "attributetype"] },
              { "Eq": ["class", "classtype"] }
            ]
            }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_filter(&f_or_ok), Ok(()));
    }

    #[test]
    fn test_schema_filter_normalisation() {
        // Test mixed case attr name
        // test syntax of bool
        // test normalise of insensitive strings
    }
}
