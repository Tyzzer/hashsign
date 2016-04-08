macro_rules! hash {
    ( $data:expr ) => {{
        let mut out = vec![0; $crate::HASH_LEN];
        let mut hash_obj = Hash::new();
        hash_obj.input($data);
        hash_obj.result(&mut out);
        out
    }};
    ( * $t:expr, $data:expr ) => {
        (1..$t).fold(hash!($data.as_ref()), |sum, _| hash!(&sum))
    }
}

macro_rules! rand {
    ( $len:expr ) => {{
        use $crate::rand::Rng;
        $crate::rand::os::OsRng::new().unwrap()
            .gen_iter().take($len).collect::<Vec<_>>()
    }};
    () => { rand!($crate::HASH_LEN) }
}

pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false };

    let mut d = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }

    // NOTE ((1 & ((d - 1) >> 8)) - 1) != 0
    d == 0
}


#[test]
fn test_macro_test() {
    use crypto::digest::Digest;
    use crypto::sha2::Sha256 as Hash;
    let data = b"Hello world.";

    assert_eq!(
        hash!(&hash!(&hash!(data))),
        hash!(* 3, data)
    );
}

#[test]
fn test_eq() {
    assert!(eq(
        b"Hello world.",
        b"Hello world."
    ));
    assert!(!eq(
        b"Hello world.",
        b"Hello-world!"
    ));
}
