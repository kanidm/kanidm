use std::time::SystemTime;
use once_cell::sync::Lazy;
use openssl::{
    ec::{EcKey},
    memcmp,
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
};
use kanidmd_lib::credential::totp::{Totp, TotpAlgo, TotpDigits};

static BOB_PRIVATE_KEY: &'static [u8] = &[
    45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45,
    45, 45, 45, 10, 77, 73, 71, 72, 65, 103, 69, 65, 77, 66, 77, 71, 66, 121, 113, 71, 83, 77, 52,
    57, 65, 103, 69, 71, 67, 67, 113, 71, 83, 77, 52, 57, 65, 119, 69, 72, 66, 71, 48, 119, 97,
    119, 73, 66, 65, 81, 81, 103, 122, 121, 83, 101, 121, 88, 72, 80, 117, 84, 77, 72, 114, 122,
    120, 82, 10, 122, 43, 66, 57, 49, 117, 49, 71, 53, 89, 76, 87, 119, 83, 73, 85, 51, 51, 69, 77,
    78, 72, 71, 106, 51, 122, 113, 104, 82, 65, 78, 67, 65, 65, 82, 86, 47, 110, 56, 84, 118, 103,
    101, 100, 105, 82, 77, 98, 109, 54, 86, 74, 49, 72, 86, 53, 43, 121, 74, 122, 99, 86, 81, 122,
    10, 90, 76, 107, 84, 74, 105, 65, 72, 69, 73, 102, 115, 120, 80, 67, 74, 86, 69, 55, 100, 109,
    52, 56, 111, 112, 108, 108, 102, 113, 111, 121, 116, 76, 116, 78, 56, 73, 85, 118, 48, 71, 56,
    78, 43, 121, 82, 90, 74, 72, 80, 78, 78, 71, 116, 54, 76, 10, 45, 45, 45, 45, 45, 69, 78, 68,
    32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10,
];
static ALICE_PRIVATE_KEY: &'static [u8] = &[
    45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45,
    45, 45, 45, 10, 77, 73, 71, 72, 65, 103, 69, 65, 77, 66, 77, 71, 66, 121, 113, 71, 83, 77, 52,
    57, 65, 103, 69, 71, 67, 67, 113, 71, 83, 77, 52, 57, 65, 119, 69, 72, 66, 71, 48, 119, 97,
    119, 73, 66, 65, 81, 81, 103, 99, 53, 67, 106, 106, 68, 89, 74, 101, 75, 79, 51, 43, 52, 52,
    115, 10, 102, 82, 122, 97, 79, 52, 52, 53, 53, 116, 86, 81, 116, 105, 75, 114, 47, 107, 70,
    122, 102, 115, 81, 106, 53, 108, 117, 104, 82, 65, 78, 67, 65, 65, 83, 87, 86, 104, 86, 82, 48,
    117, 51, 107, 90, 103, 104, 65, 74, 109, 106, 68, 51, 82, 52, 104, 68, 89, 97, 81, 118, 102,
    75, 121, 10, 113, 87, 100, 49, 50, 66, 99, 57, 67, 48, 74, 108, 122, 99, 66, 73, 75, 86, 81,
    120, 108, 87, 43, 65, 120, 115, 98, 82, 108, 88, 118, 108, 65, 74, 75, 108, 74, 115, 51, 47,
    53, 54, 81, 122, 71, 120, 90, 85, 65, 111, 107, 104, 115, 97, 56, 51, 10, 45, 45, 45, 45, 45,
    69, 78, 68, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10,
];
static BOB: User = User {
    uuid: &[1, 2, 3, 4, 5, 6],
    private_key: Lazy::new(|| EcKey::private_key_from_pem(BOB_PRIVATE_KEY).unwrap()),
};

static ALICE: User = User {
    uuid: &[6, 2, 5, 4, 3, 1],
    private_key: Lazy::new(|| EcKey::private_key_from_pem(ALICE_PRIVATE_KEY).unwrap()),
};

struct User<'a> {
    uuid: &'a [u8],
    private_key: Lazy<EcKey<Private>>,
}


fn derive_shared_key(private: PKey<Private>, public: PKey<Public>) -> Vec<u8> {
    let mut private_key_ctx: PkeyCtx<Private> = PkeyCtx::new(&private).unwrap();
    private_key_ctx
        .derive_init()
        .expect("failed to init key derivation");
    private_key_ctx
        .derive_set_peer(&public)
        .expect("failed to set peer key");
    let keylen = private_key_ctx.derive(None).unwrap();
    let mut tmp_vec = vec![0; keylen];
    let buffer = tmp_vec.as_mut_slice();
    private_key_ctx
        .derive(Some(buffer))
        .expect("failed to derive shared secret");
    return buffer.to_vec();
}

fn alice_server() -> (u32, u32) {
    let alice_private_key = PKey::from_ec_key(ALICE.private_key.clone()).unwrap();
    let bob_private_key = PKey::from_ec_key(BOB.private_key.clone()).unwrap();
    let bob_public_key =
        PKey::public_key_from_pem(bob_private_key.public_key_to_pem().unwrap().as_slice()).unwrap();
    let mut shared_secret_1 = derive_shared_key(alice_private_key, bob_public_key);
    let mut shared_secret_2 = shared_secret_1.clone();
    shared_secret_1.append(ALICE.uuid.to_vec().as_mut());
    shared_secret_2.append(BOB.uuid.to_vec().as_mut());
    let totp_1 = compute_totp(&shared_secret_1);
    let totp_2 = compute_totp(&shared_secret_2);
    (totp_1, totp_2)
}

fn bob_server() -> (u32, u32) {
    let bob_private_key = PKey::from_ec_key(BOB.private_key.clone()).unwrap();
    let alice_private_key = PKey::from_ec_key(ALICE.private_key.clone()).unwrap();
    let alice_public_key =
        PKey::public_key_from_pem(alice_private_key.public_key_to_pem().unwrap().as_slice())
            .unwrap();
    let mut shared_secret_1 = derive_shared_key(bob_private_key, alice_public_key);
    let mut shared_secret_2 = shared_secret_1.clone();

    shared_secret_1.append(ALICE.uuid.to_vec().as_mut());
    shared_secret_2.append(BOB.uuid.to_vec().as_mut());
    let totp_1 = compute_totp(&shared_secret_1);
    let totp_2 = compute_totp(&shared_secret_2);
    (totp_1, totp_2)
}

fn compute_totp(key: &[u8]) -> u32 {
    let totp = Totp::new(key.to_vec(), 30, TotpAlgo::Sha256, TotpDigits::Six);
    let current_time = SystemTime::now();
    totp.do_totp(&current_time).expect("TOTP should be valid")
}
#[test]
fn test_key_derivation() {
    let alice_private_key = PKey::from_ec_key(ALICE.private_key.clone()).unwrap();
    let alice_public_key =
        PKey::public_key_from_pem(alice_private_key.public_key_to_pem().unwrap().as_slice())
            .unwrap();
    let bob_private_key = PKey::from_ec_key(BOB.private_key.clone()).unwrap();
    let bob_public_key =
        PKey::public_key_from_pem(bob_private_key.public_key_to_pem().unwrap().as_slice()).unwrap();
    let alice_shared_secret = derive_shared_key(alice_private_key, bob_public_key);
    let bob_shared_secret = derive_shared_key(bob_private_key, alice_public_key);
    assert!(memcmp::eq(&alice_shared_secret, &bob_shared_secret));
}

#[test]
fn test() {
    let (alice_1, alice_2) = alice_server();
    let (bob_1, bob_2) = bob_server();
    dbg!(alice_1);
    dbg!(alice_2);
    assert_eq!(alice_1, bob_1);
    assert_eq!(alice_2, bob_2)
}
