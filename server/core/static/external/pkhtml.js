
function asskey_login() {
    var credentialRequestOptions = JSON.parse(document.getElementById('data').textContent);
        credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(credentialRequestOptions.publicKey.challenge);
        credentialRequestOptions.publicKey.allowCredentials?.forEach(function (listItem) {
            listItem.id = Base64.toUint8Array(listItem.id)
        });

    console.log(credentialRequestOptions);

    navigator.credentials.get({ publicKey: credentialRequestOptions.publicKey })
    .then((assertion) => {
        fetch('http://localhost:8080/login_finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: assertion.id,
                rawId: Base64.fromUint8Array(new Uint8Array(assertion.rawId), true),
                type: assertion.type,
                response: {
                    authenticatorData: Base64.fromUint8Array(new Uint8Array(assertion.response.authenticatorData), true),
                    clientDataJSON: Base64.fromUint8Array(new Uint8Array(assertion.response.clientDataJSON), true),
                    signature: Base64.fromUint8Array(new Uint8Array(assertion.response.signature), true),
                    userHandle: Base64.fromUint8Array(new Uint8Array(assertion.response.userHandle), true)
                },
            }),
        })
    });
}

const myButton = document.getElementById("start-webauthn-button");

myButton.addEventListener("click", () => {
    asskey_login();
});

