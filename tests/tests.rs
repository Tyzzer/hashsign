extern crate rand;
extern crate crypto;
extern crate hashsign;

#[path = "../src/utils.rs"]
#[macro_use]
mod utils;

use crypto::sha2::Sha256;
use hashsign::{
    HashSign, HashVerify, Key
};


#[test]
fn test_hashsign() {
    let data = rand!(32);

    let mut hashsign = HashSign::<Sha256>::new(4);
    let hashverify = HashVerify::<Sha256>::new(&hashsign.public_export());

    let sign = hashsign.sign(&data).unwrap();

    assert!(hashverify.verify(&sign, &data).unwrap());
}

#[test]
fn test_hashsign_choose() {
    let data = rand!(32);

    let mut hashsign = HashSign::<Sha256>::new(4);
    let hashverify = HashVerify::<Sha256>::new(&hashsign.public_export());

    let (otk, treebin) = hashsign.choose_sign().unwrap();
    let otpk = otk.public().export().unwrap();
    let sign = otk.sign(&data).unwrap();

    assert!(hashverify.choose_verify(&treebin, &otpk).unwrap());

    let pk = Key::<Sha256>::from(&otpk).unwrap();
    assert!(pk.verify(&sign, &data).unwrap());
}
