function setupInteractivePwdModalListeners() {
    console.log("rehooked input listeners")
    const new_pwd = document.getElementById("new-password");
    const new_pwd_check = document.getElementById("new-password-check");
    const pwd_submit = document.getElementById("password-submit");

    function markPwdCheckValid() {
        new_pwd_check.classList.remove("is-invalid");
        new_pwd_check.classList.add("is-valid");
        pwd_submit.disabled = false;
    }

    function markPwdCheckInvalid() {
        new_pwd_check.classList.add("is-invalid");
        new_pwd_check.classList.remove("is-valid");
        pwd_submit.disabled = true;
    }

    new_pwd.addEventListener("input", (_) => {
        if (new_pwd.value === new_pwd_check.value) {
            markPwdCheckValid();
        } else {
            markPwdCheckInvalid();
        }
        new_pwd.classList.remove("is-invalid");
    });

    new_pwd_check.addEventListener("input", (_) => {
        if (new_pwd_check.value === new_pwd.value) {
            markPwdCheckValid();
        } else {
            markPwdCheckInvalid();
        }
    });
}

function submitResponseHandler(event) {
    console.log("Handling potential success response")

    if (event.detail.xhr.status === 200) {
        let modalElement = document.getElementById("staticPassword");
        bootstrap.Modal.getInstance(modalElement).hide();
    }

    setupInteractivePwdModalListeners()
}

function stillSwapFailureResponse(event) {
    console.log("before swap handler")
    if (event.detail.xhr.status === 422) {
        event.detail.shouldSwap = true;
        event.detail.isError = false;
    }
}

window.onload = function () {
    setupInteractivePwdModalListeners();
}
