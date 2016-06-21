use crypto::sha2::Sha256;
use crypto::digest::Digest;


macro_rules! hash {
    ( $hasher:expr, $t:expr, $data:expr ) => {
        (0..$t).fold(
            $data.to_vec(),
            |sum, _| $hasher(&sum)
        )
    };
}

macro_rules! rand {
    ( choose $range:expr, $num:expr ) => {{
        use ::rand::{ OsRng, sample };
        sample(&mut OsRng::new().unwrap(), $range, $num)
    }};
    ( choose $range:expr ) => {
        rand!(choose $range, 1).remove(0)
    };
    ( $len:expr ) => {{
        use ::rand::{ Rng, OsRng };
        OsRng::new().unwrap()
            .gen_iter()
            .take($len)
            .collect::<Vec<_>>()
    }};
}


#[inline]
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false };

    let mut d = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }

    // NOTE ((1 & ((d - 1) >> 8)) - 1) != 0
    d == 0
}

pub trait Hash {
    fn hash(data: &[u8]) -> Vec<u8>;
    fn bits() -> usize;
    fn bytes() -> usize;
}

impl Hash for Sha256 {
    fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        let mut output = vec![0; Sha256::new().output_bytes()];
        hasher.input(data);
        hasher.result(&mut output);
        output
    }

    #[inline]
    fn bits() -> usize {
        Sha256::new().output_bits()
    }

    #[inline]
    fn bytes() -> usize {
        Sha256::new().output_bytes()
    }
}


#[test]
fn test_hash_macro() {
    let data = rand!(64);

    assert_eq!(
        data,
        hash!(Sha256::hash, 0, &data)
    );
    assert_eq!(
        Sha256::hash(&data),
        hash!(Sha256::hash, 1, &data)
    );
    assert_eq!(
        Sha256::hash(&Sha256::hash(&Sha256::hash(&data))),
        hash!(Sha256::hash, 3, &data)
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
