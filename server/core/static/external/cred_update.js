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
        // Don't mark invalid if user didn't fill in the confirmation box yet
        // Also my password manager (keepassxc with autocomplete)
        //   likes to fire off input events when both inputs were empty.
        if (new_pwd_check.value !== "") {
            if (new_pwd.value === new_pwd_check.value) {
                markPwdCheckValid();
            } else {
                markPwdCheckInvalid();
            }
        }
        new_pwd.classList.remove("is-invalid");
    });

    new_pwd_check.addEventListener("input", (_) => {
        // No point in updating the status if confirmation box is empty
        if (new_pwd_check.value === "") return;
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

function addPasskeyModalEventListeners() {
    setupPasskeyCreateBtn()
    setupSubmitBtnVisibility()
}

function setupPasskeyCreateBtn() {
    console.log("Setting up passkey create btn")
    let begin_passkey_enrollment_btn = document.getElementById("passkey-generate");
    begin_passkey_enrollment_btn?.addEventListener("click", (_event) => {
        let data_elem = document.getElementById('data');
        let credentialRequestOptions = JSON.parse(data_elem.textContent);
        credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(credentialRequestOptions.publicKey.challenge);
        credentialRequestOptions.publicKey.user.id = Base64.toUint8Array(credentialRequestOptions.publicKey.user.id);

        console.log(credentialRequestOptions)
        navigator.credentials
            .create({ publicKey: credentialRequestOptions.publicKey })
            .then((assertion) => {
                console.log(assertion)
                let creationData = {};

                creationData.id = assertion.id;
                creationData.rawId = Base64.fromUint8Array(new Uint8Array(assertion.rawId))
                creationData.response = {};
                creationData.response.attestationObject = Base64.fromUint8Array(new Uint8Array(assertion.response.attestationObject))
                creationData.response.clientDataJSON = Base64.fromUint8Array(new Uint8Array(assertion.response.clientDataJSON))
                creationData.type = assertion.type
                creationData.extensions = assertion.getClientExtensionResults()
                creationData.extensions.uvm = undefined

                // Put the passkey creation data into the form for submission
                document.getElementById("passkey-create-data").value = JSON.stringify(creationData)

                // Make the name input visible and hide the "Begin Passkey Enrollment" button
                document.getElementById("passkey-generate").classList.add("d-none")
                document.getElementById("passkeyNamingForm").classList.remove("d-none")
                document.getElementById("staticPasskeyCreateFooter").classList.remove("d-none")
            });
    });
}

function setupSubmitBtnVisibility() {
    document.getElementById("passkey-label")
        ?.addEventListener("input", updateSubmitButtonVisibility)
}

function updateSubmitButtonVisibility(event) {
    let submitButton = document.getElementById("passkey-submit");
    submitButton.disabled = event.value === "";
}

window.onload = function () {
    setupInteractivePwdModalListeners();
}
