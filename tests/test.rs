extern crate hashsign;

use hashsign::{ PrivateKey, PublicKey };

#[test]
fn test_sign() {
    let data = b"Hello world!";

    let sk = PrivateKey::new();
    let pk = sk.public();
    let s = sk.sign(data);

    assert!(pk.verify(&s, data));
    assert!(!pk.verify(&s, b"Hello world."));
    assert!(!pk.verify(
        &[vec![0; 32].as_ref(), &s[32..]].concat(),
        data
    ));
}

#[test]
fn test_output() {
    let sk = PrivateKey::new();
    let sk_data = sk.output();
    assert_eq!(sk, PrivateKey::from(sk_data));

    let pk = sk.public();
    let pk_data = pk.output();
    assert_eq!(pk, PublicKey::from(pk_data));
}
