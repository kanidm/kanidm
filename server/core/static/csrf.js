const form = document.getElementById("protected_form");

async function protectedSubmitHandler(event) {
    event.preventDefault();

    const related_input_id = form.dataset.relatedInputId;
    const nonce = Uint8Array.fromHex(form.dataset.nonceHex);
    const mask = Uint8Array.fromHex(form.dataset.maskHex);

    document.getElementById("protected_form_submit").disabled = true;

    const expected_buffer = new ArrayBuffer(4);
    const expected_view = new DataView(expected_buffer);
    // DataView get/set always writes BigEndian
    expected_view.setUint32(0);
    const expected_u32 = expected_view.getUint32();

    const mask_view = new DataView(mask.buffer);
    const mask_u32 = mask_view.getUint32();

    const key = await window.crypto.subtle.importKey(
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

    const timestamp_buffer = new ArrayBuffer(8);
    const timestamp_view = new DataView(timestamp_buffer);
    // DataView get/set always writes BigEndian
    const timestamp = BigInt(Date.now());
    timestamp_view.setBigUint64(0, timestamp);

    const timestamp_u64 = timestamp_view.getBigUint64();

    const timestamp_bytes = new Uint8Array(timestamp_buffer);

    var solution = new Uint32Array([0]);

    while (true) {
        // Oh Javascript, how we love theee.
        const buffer = new ArrayBuffer(4);
        new DataView(buffer).setUint32(0, solution[0]);
        // This is what we have to send back.
        const solution_bytes = new Uint8Array(buffer);

        const mergedArray = new Uint8Array(email_bytes.length + solution_bytes.length + timestamp_bytes.length);
        mergedArray.set(email_bytes);
        mergedArray.set(solution_bytes, email_bytes.length);
        mergedArray.set(timestamp_bytes, email_bytes.length + solution_bytes.length);

        const signature = await window.crypto.subtle.sign("HMAC", key, mergedArray);

        const signature_bytes = new Uint8Array(signature);

        const signature_view = new DataView(signature_bytes.buffer);
        const signature_u32 = signature_view.getUint32();

        const signature_u32_masked = signature_u32 & mask_u32;

        if (expected_u32 == signature_u32_masked) {
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

    const timestamp_hex = timestamp_bytes.toHex();

    // set that now
    document.getElementById("protected_form_solution_hex").value = solution_hex;
    document.getElementById("protected_form_timestamp_hex").value = timestamp_hex;

    // If the user comes back to the page, we need the button re-enabled for them.
    document.getElementById("protected_form_submit").disabled = false;

    form.submit();
}

form.addEventListener("submit", protectedSubmitHandler);
