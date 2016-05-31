extern crate rand;
extern crate crypto;
extern crate hashsign;

#[path = "../src/utils.rs"]
#[macro_use] mod utils;

use crypto::sha2::Sha256;
use hashsign::Key;


#[test]
fn test_sign() {
    let data = rand!(64);

    let sk = Key::default();
    let pk = sk.public();
    let s = sk.sign(&data);

    assert!(pk.verify(&s, &data));
    assert!(!pk.verify(
        &[&[0; 32], &s[32..]].concat(),
        &data
    ));
}

#[test]
fn test_output() {
    let sk = Key::default();
    let sk_data = sk.output();
    assert_eq!(sk, Key::<Sha256>::from(sk_data));

    let pk = sk.public();
    let pk_data = pk.output();
    assert_eq!(pk, Key::<Sha256>::from(pk_data));
}
