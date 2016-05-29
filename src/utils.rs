macro_rules! hash {
    ( $hasher:expr, $data:expr ) => {{
        let mut hasher = $hasher.clone();
        let mut out = vec![0; hasher.output_bytes()];
        hasher.input($data);
        hasher.result(&mut out);
        out
    }};
    ( $hasher:expr, $t:expr, $data:expr ) => {
        (1..$t).fold(
            hash!($hasher, $data.as_ref()),
            |sum, _| hash!($hasher, &sum)
        )
    };
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
    use crypto::sha2::Sha256;
    use crypto::digest::Digest;

    let data = b"Hello world.";
    let hasher = Sha256::new();

    assert_eq!(
        hash!(hasher, &hash!(hasher, &hash!(hasher, data))),
        hash!(hasher, 3, data)
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
