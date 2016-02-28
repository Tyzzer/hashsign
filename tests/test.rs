extern crate hashsign;

use hashsign::PrivateKey;

#[test]
fn test() {
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
