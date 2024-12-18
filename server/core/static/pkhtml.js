
function asskey_login() {
    let credentialRequestOptions = JSON.parse(document.getElementById('data').textContent);
    credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(credentialRequestOptions.publicKey.challenge);
    credentialRequestOptions.publicKey.allowCredentials?.forEach(function (listItem) {
        listItem.id = Base64.toUint8Array(listItem.id)
    });

    navigator.credentials.get({ publicKey: credentialRequestOptions.publicKey })
    .then((assertion) => {
        document.getElementById("cred").value = JSON.stringify({
            id: assertion.id,
            rawId: Base64.fromUint8Array(new Uint8Array(assertion.rawId), true),
            type: assertion.type,
            response: {
                authenticatorData: Base64.fromUint8Array(new Uint8Array(assertion.response.authenticatorData), true),
                clientDataJSON: Base64.fromUint8Array(new Uint8Array(assertion.response.clientDataJSON), true),
                signature: Base64.fromUint8Array(new Uint8Array(assertion.response.signature), true),
                userHandle: Base64.fromUint8Array(new Uint8Array(assertion.response.userHandle), true)
            },
        });
        document.getElementById("cred-form").submit();
    }).catch((error) => {
        console.error(`Failed to complete passkey authentication: ${error}`);
        throw error;
    });
}

try {
    const myButton = document.getElementById("start-passkey-button");
    myButton.addEventListener("click", () => {
        asskey_login();
    });
} catch (_error) {};

try {
    const myButton = document.getElementById("start-seckey-button");
    myButton.addEventListener("click", () => {
        asskey_login();
    });
} catch (_error) {};

try {
    window.addEventListener("load", (event) => {
        asskey_login()
    });
} catch (_error) {};
