macro_rules! hash {
    ( $data:expr ) => {{
        let mut out = vec![0; $crate::HASH_LEN];
        let mut hash_obj = Hash::new();
        hash_obj.input($data);
        hash_obj.result(&mut out);
        out
    }};
    ( * $t:expr, $data:expr ) => {
        (0..$t-1).fold(hash!($data.as_ref()), |sum, _| hash!(&sum))
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
