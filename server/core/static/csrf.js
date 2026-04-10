const form = document.getElementById("protected_form");

function value_from_hex(value_id) {
    const nonce_hex = document.getElementById(value_id).innerText;
    return Uint8Array.fromHex(nonce_hex);
}

async function protectedSubmitHandler(event) {
    event.preventDefault();

    const related_input_id = document.getElementById("protected_form_related_input_id").innerText;

    document.getElementById("protected_form_submit").disabled = true;

    const nonce = value_from_hex("protected_form_nonce_hex");
    const mask = value_from_hex("protected_form_mask_hex");

    let expected_buffer = new ArrayBuffer(4);
    let expected_view = new DataView(expected_buffer);
    // DataView get/set always writes BigEndian
    expected_view.setUint32(0);
    const expected_u32 = expected_view.getUint32();

    let mask_view = new DataView(mask.buffer);
    const mask_u32 = mask_view.getUint32();

    let key = await window.crypto.subtle.importKey(
        "raw",
        nonce,
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        true,
        ["sign"],
    );

    const email_value = document.getElementById(related_input_id).value;
    const encoder = new TextEncoder();
    const email_bytes = encoder.encode(email_value);

    let timestamp_buffer = new ArrayBuffer(8);
    let timestamp_view = new DataView(timestamp_buffer);
    // DataView get/set always writes BigEndian
    let timestamp = BigInt(Date.now());
    timestamp_view.setBigUint64(0, timestamp);

    const timestamp_u64 = timestamp_view.getBigUint64();
    console.log(timestamp_u64);

    const timestamp_bytes = new Uint8Array(timestamp_buffer);

    var solution = new Uint32Array([0]);

    while (true) {
        // Oh Javascript, how we love theee.
        const buffer = new ArrayBuffer(4);
        new DataView(buffer).setUint32(0, solution[0]);
        // This is what we have to send back.
        const solution_bytes = new Uint8Array(buffer);

        var mergedArray = new Uint8Array(email_bytes.length + solution_bytes.length + timestamp_bytes.length);
        mergedArray.set(email_bytes);
        mergedArray.set(solution_bytes, email_bytes.length);
        mergedArray.set(timestamp_bytes, email_bytes.length + solution_bytes.length);

        let signature = await window.crypto.subtle.sign("HMAC", key, mergedArray);

        let signature_bytes = new Uint8Array(signature);

        let signature_view = new DataView(signature_bytes.buffer);
        const signature_u32 = signature_view.getUint32();

        const signature_u32_masked = signature_u32 & mask_u32;

        const matches = expected_u32 == signature_u32_masked;
        if (matches) {
            break;
        }

        solution[0] += 1;
    }

    // We have to do a dance to get back to BE for xmit.
    const buffer = new ArrayBuffer(4);
    new DataView(buffer).setUint32(0, solution[0]);

    // This is what we have to send back.
    const solution_bytes = new Uint8Array(buffer);
    const solution_hex = solution_bytes.toHex();

    console.log(solution_hex);

    const timestamp_hex = timestamp_bytes.toHex();

    // set that now
    document.getElementById("protected_form_solution_hex").value = solution_hex;
    document.getElementById("protected_form_timestamp_hex").value = timestamp_hex;

    // If the user comes back to the page, we need the button re-enabled for them.
    document.getElementById("protected_form_submit").disabled = false;

    form.submit();
}

form.addEventListener("submit", protectedSubmitHandler);
