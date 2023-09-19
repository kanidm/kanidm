use kanidmd_testkit::{is_free_port, PORT_ALLOC};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn test_mtls_basic_auth() {
    let mut counter = 0;
    let port = loop {
        let possible_port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);
        if is_free_port(possible_port) {
            break possible_port;
        }
        counter += 1;
        #[allow(clippy::panic)]
        if counter >= 5 {
            eprintln!("Unable to allocate port!");
            panic!();
        }
    };

    eprintln!("{:?}", port);

    todo!();
}
