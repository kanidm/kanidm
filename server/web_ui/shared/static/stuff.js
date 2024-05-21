window.addEventListener("DOMContentLoaded", (event) => {

    document.body.addEventListener('htmx:configRequest', function (evt) {
        evt.detail.headers['Authorization'] = localStorage.getItem("bearer_token");
    });

    // document.body.addEventListener('htmx:afterResponse', function (evt) {
    //     console.error(evt);
    // })

    document.body.addEventListener('htmx:responseError', function (evt) {
        console.error("response error:", evt);
        // const errorData = JSON.parse(evt.detail.xhr.response) || { "detail": evt.detail.xhr.response };
        // const errorMessage = `Error pulling data: ${errorData.detail}`;
        // let errorDiv = document.getElementById("errors");
        // errorDiv.innerHTML = errorMessage;

        // errorDiv.style.display = "block";
    });

    htmx.logAll();


});
