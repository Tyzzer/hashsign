extern crate crypto;
extern crate hashsign;

use crypto::sha2::Sha256;
use hashsign::Key;


#[test]
fn test_sign() {
    let data = b"Hello world!";

    let sk = Key::default();
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
    let sk = Key::default();
    let sk_data = sk.output();
    assert_eq!(sk.val, Key::from(Sha256::new(), sk_data).val);

    let pk = sk.public();
    let pk_data = pk.output();
    assert_eq!(pk.val, Key::from(Sha256::new(), pk_data).val);
}
