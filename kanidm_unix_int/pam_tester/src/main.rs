extern crate pam;
pub fn main() {
        let service = "pam_test_full";
        let user = "testuser";
        let password = "eti8aoshaigeeboh1ohF7rieba0quaThesoivae0";

        let mut auth = pam::Authenticator::with_password(service).unwrap();
        auth.get_handler().set_credentials(user, password);
        let r = auth.authenticate();
        println!("auth -> {:?}", r);
        if r.is_ok() {
            println!("Successfully authenticated!");
            let r = auth.open_session();
            println!("session -> {:?}", r);
            if r.is_ok() {
                println!("Successfully opened session!");
            } else {
                println!("Session failed =/");
            }
        }
        else {
            println!("Authentication failed =/");
        }
}

