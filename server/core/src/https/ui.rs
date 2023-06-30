use axum::extract::State;
use axum::http::{HeaderValue, Request};
use axum::response::Response;
use hyper::Body;

use super::ServerState;

pub async fn ui_handler(
    State(state): State<ServerState>,
    mut _req: Request<Body>,
) -> Response<String> {
    let (eventid, hvalue) = state.new_eventid();
    let domain_display_name = state.qe_r_ref.get_domain_display_name(eventid).await;

    // this feels icky but I felt that adding a trait on Vec<JavaScriptFile> which generated the string was going a bit far
    let jsfiles: Vec<String> = state
        .js_files
        .clone()
        .into_iter()
        .map(|j| j.as_tag())
        .collect();
    let jstags = jsfiles.join(" ");

    let body = format!(
        r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="theme-color" content="white" />
        <meta name="viewport" content="width=device-width" />
        <title>{}</title>

        <link rel="icon" href="/pkg/img/favicon.png" />
        <link rel="manifest" href="/manifest.webmanifest" />
        <link rel="apple-touch-icon" href="/pkg/img/logo-256.png" />
        <link rel="apple-touch-icon" sizes="180x180" href="/pkg/img/logo-180.png" />
        <link rel="apple-touch-icon" sizes="192x192" href="/pkg/img/logo-192.png" />
        <link rel="apple-touch-icon" sizes="512x512" href="/pkg/img/logo-square.svg" />
        <link rel="stylesheet" href="/pkg/external/bootstrap.min.css" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC"/>
        <link rel="stylesheet" href="/pkg/style.css"/>

        {}

    </head>
    <body class="flex-column d-flex h-100">
        <main class="flex-shrink-0 form-signin">
        <center>
            <img src="/pkg/img/logo-square.svg" alt="Kanidm" class="kanidm_logo"/>
            <h3>Kanidm is loading, please wait... </h3>
        </center>
        </main>
        <footer class="footer mt-auto py-3 bg-light text-end">
            <div class="container">
                <span class="text-muted">Powered by <a href="https://kanidm.com">Kanidm</a></span>
            </div>
        </footer>
    </body>
    </html>"#,
        domain_display_name.as_str(),
        jstags,
    );

    let mut res = Response::new(body);
    let mut headers = res.headers_mut();
    headers.insert(
        "Content-Type",
        HeaderValue::from_str("text/html;charset=utf-8").unwrap(),
    );
    state.header_kopid(&mut headers, hvalue);

    res
}
