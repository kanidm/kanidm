
// Stores models of various types. Given the design of the DB, this
// is reasonably simple for our backend.

// We have a main id -> entries type, and everything else is a value -> (set id) type or value -> id
// I'll probably make IDL serialisable to cbor or something ...

use diesel;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};


use super::schema::entries;

#[derive(Serialize, Queryable)]
pub struct Entry {
    pub id: i64,
    pub entry: String,
}

#[derive(Insertable)]
#[table_name = "entries"]
pub struct NewEntry<'a> {
    pub id: i64,
    pub entry: &'a str,
}



#[cfg(test)]
mod tests {
    #[test]
    fn test_simple_create() {
        println!("It works!");
    }
}


