use std::collections::HashMap;

// representations of schema that confines object types, classes
// and attributes. This ties in deeply with "Entry".
// This only defines the types, and how they are represented. For
// application and validation of the schema, see "Entry".
//
// In the future this will parse/read it's schema from the db
// but we have to bootstrap with some core types.

pub enum IndexType {
    EQUALITY,
    PRESENCE,
    SUBSTRING,
}

pub enum SyntaxType {
    UTF8STRING,
}

pub struct SchemaAttribute {
    name: String,
    description: String,
    system: bool,
    multivalue: bool,
    index: Vec<IndexType>,
    syntax: SyntaxType,
}

pub struct SchemaClass {
    name: String,
    descriptions: String,
    systemmay: Vec<SchemaAttribute>,
    may: Vec<SchemaAttribute>,
    systemmust: Vec<SchemaAttribute>,
    must: Vec<SchemaAttribute>,
}

pub struct Schema {
    // We contain sets of classes and attributes.
    classes: HashMap<String, SchemaClass>,
    attributes: HashMap<String, SchemaAttribute>,
}

impl Schema {
    pub fn new() -> Self {
        //
        // Bootstrap in definitions of our own schema types
        Schema {
            classes: HashMap::new(),
            attributes: HashMap::new(),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::{Schema, SchemaClass, SchemaAttribute};
    use super::super::entry::Entry;

    #[test]
    fn test_schema_attribute_simple() {
        // Test basic functions of simple attributes
    }

    #[test]
    fn test_schema_simple() {
    }
}
