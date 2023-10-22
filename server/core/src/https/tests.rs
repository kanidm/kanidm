#[test]
fn test_javscriptfile() {
    // make sure it outputs what we think it does
    use crate::https::JavaScriptFile;
    let jsf = JavaScriptFile {
        filepath: "wasmloader_admin.js",
        hash: "1234567890".to_string(),
        filetype: Some("module".to_string()),
    };
    assert_eq!(
        jsf.as_tag(),
        r#"<script async src="/pkg/wasmloader_admin.js" integrity="sha384-1234567890" type="module"></script>"#
    );
    let jsf = JavaScriptFile {
        filepath: "wasmloader_admin.js",
        hash: "1234567890".to_string(),
        filetype: None,
    };
    assert_eq!(
        jsf.as_tag(),
        r#"<script async src="/pkg/wasmloader_admin.js" integrity="sha384-1234567890"></script>"#
    );
}
