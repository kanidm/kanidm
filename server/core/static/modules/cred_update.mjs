console.debug("credupdate: loaded");

// Makes the password form interactive (e.g. shows when passwords don't match)
function setupInteractivePwdFormListeners() {
    const new_pwd = document.getElementById("new-password");
    const new_pwd_check = document.getElementById("new-password-check");
    const pwd_submit = document.getElementById("password-submit");
    const clientside_feedback = document.getElementById("clientside-feedback");
    const serverside_feedback = document.getElementById("serverside-feedback");
    let pwd_valid = false;
    let pwd_check_valid = false;

    function validatePasswordClientside() {
        let result = window.zxcvbn(
            new_pwd.value,
            ['kanidm'] // context-specific words - TODO: add username, email & org name?
        );
        console.debug("zxcvbn result:", result);
        if (result.feedback.warning) {
            clientside_feedback.innerText = result.feedback.warning;
        } else if (result.feedback.suggestions.length) {
            clientside_feedback.innerText = result.feedback.suggestions.join("\n");
        } else if (result.score < 4){
            clientside_feedback.innerText = `Password is not strong enough`; //? add: (score: ${Math.ceil(result.guesses_log10-1)}/10)`; 
        } else {
            clientside_feedback.innerText = '';
        }
        if (result.score < 4) {
            new_pwd.classList.remove("is-valid");
            new_pwd.classList.add("is-invalid");
            pwd_valid = false;
        } else {
            new_pwd.classList.remove("is-invalid");
            new_pwd.classList.add("is-valid");
            pwd_valid = true;
        }
    }

    /** @return {bool} true if it's valid */
    function validatePwdCheck() {
        // Don't mark invalid if user didn't fill in the confirmation box yet
        // Also KeepassXC with autocomplete likes to fire off input events when
        // both inputs are empty.
        if (new_pwd_check.value === "") {
            // if the field is empty, it's not explicitly invalid, but also not valid
            new_pwd_check.classList.remove("is-invalid");
            new_pwd_check.classList.remove("is-valid");
            pwd_check_valid = false;
        } else if (new_pwd.value !== new_pwd_check.value) {
            new_pwd_check.classList.add("is-invalid");
            new_pwd_check.classList.remove("is-valid");
            pwd_check_valid = false;
        } else {
            new_pwd_check.classList.remove("is-invalid");
            new_pwd_check.classList.add("is-valid");
            pwd_check_valid = true;
        }
    }

    function updateSubmitButtonState() {
        console.log('submit?', pwd_valid, pwd_check_valid)
        pwd_submit.disabled = !(pwd_valid && pwd_check_valid);
    }

    new_pwd.addEventListener("input", () => {
        let disable_submit = false;
        
        // remove feedback from serverside render when user tries new password
        new_pwd.classList.remove("is-invalid");
        serverside_feedback.innerText = '';

        // zxcvbn clientside check (if async load completed, from credential_update_add_password_partial.html)
        if (window.zxcvbn) {
            validatePasswordClientside()
        } else {
            pwd_valid = true;
        }

        validatePwdCheck();
        updateSubmitButtonState();
    });

    new_pwd_check.addEventListener("input", () => {
        // we don't revalidate the password, just check if it's the same
        validatePwdCheck();
        updateSubmitButtonState();
    });
}

window.stillSwapFailureResponse = function (event) {
    if (event.detail.xhr.status === 422 || event.detail.xhr.status === 500) {
        console.debug(`Got HTTP/${event.detail.xhr.status}, still swapping failure response`);
        event.detail.shouldSwap = true;
        event.detail.isError = false;
    }
};

function onPasskeyCreated(assertion) {
    try {
        console.log(assertion);
        let creationData = {};

        creationData.id = assertion.id;
        creationData.rawId = Base64.fromUint8Array(new Uint8Array(assertion.rawId));
        creationData.response = {};
        creationData.response.attestationObject = Base64.fromUint8Array(
            new Uint8Array(assertion.response.attestationObject),
        );
        creationData.response.clientDataJSON = Base64.fromUint8Array(new Uint8Array(assertion.response.clientDataJSON));
        creationData.type = assertion.type;
        creationData.extensions = assertion.getClientExtensionResults();
        creationData.extensions.uvm = undefined;

        // Put the passkey creation data into the form for submission
        document.getElementById("passkey-create-data").value = JSON.stringify(creationData);

        // Make the name input visible and hide the "Begin Passkey Enrollment" button
        document.getElementById("passkeyNamingSafariPre").classList.add("d-none");
        document.getElementById("passkeyNamingForm").classList.remove("d-none");
        document.getElementById("passkeyNamingSubmitBtn").classList.remove("d-none");
    } catch (e) {
        console.log(e);
        if (
            confirm(
                "Failed to encode your new passkey's data for transmission, confirm to reload this page.\nReport this issue if it keeps occurring.",
            )
        ) {
            window.location.reload();
        }
    }
}

function startPasskeyEnrollment() {
    try {
        const data_elem = document.getElementById("data");
        const credentialRequestOptions = JSON.parse(data_elem.textContent);
        credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(
            credentialRequestOptions.publicKey.challenge,
        );
        credentialRequestOptions.publicKey.user.id = Base64.toUint8Array(credentialRequestOptions.publicKey.user.id);

        console.log(credentialRequestOptions);
        navigator.credentials.create({ publicKey: credentialRequestOptions.publicKey }).then(
            (assertion) => {
                onPasskeyCreated(assertion);
            },
            (reason) => {
                alert(`Passkey creation failed ${reason.toString()}`);
                console.log(`Passkey creation failed: ${reason.toString()}`);
            },
        );
    } catch (e) {
        console.log(`Failed to initialize passkey creation: ${e}`);
        if (
            confirm(
                "Failed to initialize passkey creation, confirm to reload this page.\nReport this issue if it keeps occurring.",
            )
        ) {
            window.location.reload();
        }
    }
}

function setupPasskeyNamingSafariButton() {
    document.getElementById("passkeyNamingSafariBtn").addEventListener("click", startPasskeyEnrollment);
}

function setupSubmitBtnVisibility() {
    document.getElementById("passkey-label")?.addEventListener("input", updateSubmitButtonVisibility);
}

function updateSubmitButtonVisibility(event) {
    const submitButton = document.getElementById("passkeyNamingSubmitBtn");
    submitButton.disabled = event.value === "";
}

(function () {
    console.debug("credupdate: init");
    document.body.addEventListener("addPasswordSwapped", () => {
        setupInteractivePwdFormListeners();
    });
    document.body.addEventListener("addPasskeySwapped", () => {
        setupPasskeyNamingSafariButton();
        startPasskeyEnrollment();
        setupSubmitBtnVisibility();
    });
})();
