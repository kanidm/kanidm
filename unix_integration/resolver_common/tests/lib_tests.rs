use kanidm_unix_resolver::{check_nsswitch_has_kanidm, parse_nsswitch_contents_return_missing};

#[test]
fn parse_nsswitch_contents() {
    let contents = r#"
        passwd: files
        group: files
    "#;
    let missing = parse_nsswitch_contents_return_missing(contents);
    assert_eq!(missing.len(), 2);
    assert!(missing.contains(&"passwd: files".to_string()));
    assert!(missing.contains(&"group: files".to_string()));

    let contents = r#"
    # this is a comment
        passwd: files kanidm
        group: files kanidm
    "#;
    let tempfile = tempfile::NamedTempFile::new().expect("failed to create temp file");
    std::fs::write(tempfile.path(), contents).expect("failed to write to temp file");
    assert!(check_nsswitch_has_kanidm(Some(tempfile.path().into())));
}
