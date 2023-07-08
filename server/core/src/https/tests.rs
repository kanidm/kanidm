#[test]
fn test_javscriptfile() {
    // make sure it outputs what we think it does
    use crate::https::JavaScriptFile;
    let jsf = JavaScriptFile {
        filepath: "wasmloader.js",
        hash: "1234567890".to_string(),
        filetype: Some("module".to_string()),
    };
    assert_eq!(
        jsf.as_tag(),
        r#"<script src="/pkg/wasmloader.js" crossorigin="anonymous" referrerpolicy="origin" type="module"></script>"#
    );
    let jsf = JavaScriptFile {
        filepath: "wasmloader.js",
        hash: "1234567890".to_string(),
        filetype: None,
    };
    assert_eq!(
        jsf.as_tag(),
        r#"<script src="/pkg/wasmloader.js" crossorigin="anonymous" referrerpolicy="origin"></script>"#
    );
}
