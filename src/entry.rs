
use serde_json::{Value, Error};


// make a trait entry for everything to adhere to?
//  * How to get indexs out?
//  * How to track pending diffs?

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {

}

// pub trait Entry {
    //fn to_json_str(&self) -> String;
    // fn to_index_diff -> ???
    // from_json_str() -> Self;
    //
    // Does this match a filter or not?a
    // fn apply_filter -> Result<bool, ()>
// }

//enum Credential {
    //?
//}

#[derive(Serialize, Deserialize, Debug)]
enum Credential {
    Password {
        name: String,
        hash: String,
    },
    TOTPPassword {
        name: String,
        hash: String,
        totp_secret: String,
    },
    SshPublicKey {
        name: String,
        data: String,
    },
}



#[derive(Serialize, Deserialize, Debug)]
struct User {
    username: String,
    // Could this be derived from self? Do we even need schema?
    class: Vec<String>,
    displayname: String,
    legalname: Option<String>,
    email: Vec<String>,
    // uuid?
    // need to support deref later ...
    memberof: Vec<String>,
    sshpublickey: Vec<String>,

    credentials: Vec<Credential>,

}

impl User {
    pub fn new(username: &str, displayname: &str) -> Self {
        // Build a blank value
        User {
            username: String::from(username),
            class: Vec::new(),
            displayname: String::from(displayname),
            legalname: None,
            email: Vec::new(),
            memberof: Vec::new(),
            sshpublickey: Vec::new(),
            credentials: Vec::new(),
        }

    }

    // We need a way to "diff" two User objects
    // as on a modification we want to track the set of changes
    // that is occuring -- needed for indexing to function.

    // Basically we just need to check if it changed, remove
    // the "former" and add the "newer" value.

    // We have to sort vecs ...

    // Is there a way to call this on serialise?
    fn validate() -> Result<(), ()> {
        Err(())
    }
}


#[cfg(test)]
mod tests {
    use super::User;
    use serde_json;

    #[test]
    fn test_user_basic() {
        let u: User = User::new("william", "William Brown");

        println!("u: {:?}", u);

        let d = serde_json::to_string(&u).unwrap();

        println!("d: {}", d.as_str());

        let u2: User = serde_json::from_str(d.as_str()).unwrap();

        println!("u2: {:?}", u2);

    }
}


