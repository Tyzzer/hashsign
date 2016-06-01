extern crate rand;
extern crate crypto;
extern crate hashsign;

#[path = "../src/utils.rs"]
#[macro_use] mod utils;

use hashsign::Key;


#[test]
fn test_lamport_sign() {
    let data = rand!(64);

    let sk = Key::default();
    let pk = sk.public();
    let s = sk.sign(&data).unwrap();

    assert!(pk.verify(&s, &data).unwrap_or(false));
    assert!(!pk.verify(
        &[&[0; 32], &s[32..]].concat(),
        &data
    ).unwrap());
}

#[test]
fn test_lamport_output() {
    let sk = Key::default();
    let sk_data = sk.output().unwrap();
    assert_eq!(sk, Key::from(sk_data).unwrap());

    let pk = sk.public();
    let pk_data = pk.output().unwrap();
    assert_eq!(pk, Key::from(pk_data).unwrap());
}
