use std::panic;

// Test external behaviorus of the service.

fn run_test<T>(test: T) -> ()
    where T: FnOnce() -> () + panic::UnwindSafe
{
    // setup
    // Create the db: randomise the name of the file. Memory?
    // call out to migrations
    // Do we need any fixtures?

    let result = panic::catch_unwind(||
        test()
    );

    // teardown
    // remove the db file

    assert!(result.is_ok());
}

#[test]
fn test_schema() {
    run_test(|| {
        println!("It works");
    });
}

