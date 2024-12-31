/**
 * Initiates the passkey login process by requesting credentials from the user.
 *
 * This function retrieves the credential request options from the DOM, converts
 * necessary fields from Base64 to Uint8Array, and then uses the Web Authentication API
 * to get the user's credentials. Upon successful retrieval, it encodes the assertion
 * response back to Base64 and submits the form with the credential data.
 *
 * @function asskey_login
 * @throws {Error} If the passkey authentication process fails.
 */


function asskey_login() {
    let credentialRequestOptions = JSON.parse(
        document.getElementById("data").textContent,
    );
    credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(
        credentialRequestOptions.publicKey.challenge,
    );
    credentialRequestOptions.publicKey.allowCredentials?.forEach(
        function (listItem) {
            listItem.id = Base64.toUint8Array(listItem.id);
        },
    );

    navigator.credentials.get({ publicKey: credentialRequestOptions.publicKey })
        .then((assertion) => {
            document.getElementById("cred").value = JSON.stringify({
                id: assertion.id,
                rawId: Base64.fromUint8Array(
                    new Uint8Array(assertion.rawId),
                    true,
                ),
                type: assertion.type,
                response: {
                    authenticatorData: Base64.fromUint8Array(
                        new Uint8Array(assertion.response.authenticatorData),
                        true,
                    ),
                    clientDataJSON: Base64.fromUint8Array(
                        new Uint8Array(assertion.response.clientDataJSON),
                        true,
                    ),
                    signature: Base64.fromUint8Array(
                        new Uint8Array(assertion.response.signature),
                        true,
                    ),
                    userHandle: Base64.fromUint8Array(
                        new Uint8Array(assertion.response.userHandle),
                        true,
                    ),
                },
            });
            document.getElementById("cred-form").submit();
        }).catch((error) => {
            console.error(
                `Failed to complete passkey authentication: ${error}`,
            );
            throw error;
        });
}

try {
    const myButton = document.getElementById("start-passkey-button");
    myButton.addEventListener("click", () => {
        asskey_login();
    });
} catch (error) {
    console.error(
        `Failed to add button event listener for passkey authentication: ${error}`,
    );
}

try {
    const myButton = document.getElementById("start-seckey-button");
    myButton.addEventListener("click", () => {
        asskey_login();
    });
} catch (error) {
    console.error(
        `Failed to add button event listener for security key authentication: ${error}`,
    );
}

try {
    addEventListener("load", () => {
        asskey_login();
    addEventListener("load", () => {
        asskey_login();
    });
} catch (error) {
    console.error(
        `Failed to add load-time event listener for passkey authentication: ${error}`,
    );
}
