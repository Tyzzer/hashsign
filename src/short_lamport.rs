use std::{ fmt, cmp };
use std::marker::PhantomData;
use utils::{ eq, Hash };
use bincode::SizeLimit;
use bincode::serde::{
    serialize, deserialize,
    SerializeError, DeserializeError
};


#[derive(Clone)]
pub struct Key<H: Hash>(pub Vec<(Vec<u8>, Vec<u8>)>, PhantomData<H>);

#[derive(Serialize, Deserialize)]
struct KeyBin(Vec<(Vec<u8>, Vec<u8>)>);

impl<H: Hash> Key<H> {
    /// * s3. For each chunk, generate a pair of secret random 256-bit numbers.
    ///     These 64 numbers are your private key.
    pub fn new() -> Key<H> {
        Key(
            (0..H::bytes())
                .map(|_| (rand!(H::bytes()), rand!(H::bytes())))
                .collect(),
            PhantomData
        )
    }

    pub fn from(v: &[u8]) -> Result<Key<H>, DeserializeError> {
        let KeyBin(key) = deserialize(v)?;
        Ok(Key(key, PhantomData))
    }

    /// * s4. Hash each of these numbers 258 times.
    ///     This final set of 32 pairs of 2 hashes each are your public key.
    ///     (Note: Use a hash chain and this public key becomes just 256 bits)
    pub fn public(&self) -> Key<H> {
        Key(
            self.0.iter()
                .map(|&(ref x, ref y)| (
                    hash!(H::hash, H::bytes() * 8, x),
                    hash!(H::hash, H::bytes() * 8, y)
                ))
                .collect(),
            PhantomData
        )
    }

    /// * s1. Take the SHA-256 hash of the document you want to sign
    /// * s2. Split the 256-bit hash of your document into 32 8-bit chunks
    /// * s5. To create your signature, examine each chunk again.
    ///     Let the value of this chunk be n with the range [0, 255].
    ///     There are 2 256-bit numbers of the private key associated with that chunk.
    ///     Let a equal the first of these numbers hashed n+1 times.
    ///     Let b equal the second of these numbers hashed 256-n times.
    ///     Publish the result (a,b).
    ///     This pair is your signature for this 8-bit chunk.
    /// * s6. Collect up the 32 signatures from each chunk,
    ///     and you have a 32*2*(256/8) = 2kb signature!
    ///     This is 4x smaller than the usual Lamport signature.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SerializeError> {
        let output = H::hash(data).iter()
            .zip(&self.0)
            .map(|(&n, &(ref x, ref y))| (
                hash!(H::hash, n as usize + 1, x),
                hash!(H::hash, (H::bytes() * 8) - (n as usize + 1), y)
            ))
            .collect::<Vec<_>>();
        serialize(&KeyBin(output), SizeLimit::Infinite)
    }

    /// * v1. Take the SHA-256 hash of the document you want to verify
    /// * v2. Split the 256-bit hash of the document into 32 8-bit chunks
    /// * v3. For each chunk, let the chunk's value from the hash be V, the signature pair of numbers be (a, b) and the corresponding public key pair be (Pa, Pb)
    /// * v4. Hash a and count the iterations until it equals Pa or it has been hashed 256 times. If it was hashed 256 times without reaching Pa, the signature is invalid. Save the number of iterations it took to reach Pa from a as i_a.
    /// * v5. Repeat step (4) for b, saving the number of iterations to reach Pb from b as i_b.
    /// * v6. If 256-i_a != i_b-1 or 256-i_a != V, this signature is invalid.
    /// * v7. If there are more chunks, check the next chunk starting with step (3)
    /// * v8. The signature is valid if all chunks are signed correctly.
    pub fn verify(&self, sign: &[u8], data: &[u8]) -> Result<bool, DeserializeError> {
        let KeyBin(sign) = deserialize(sign)?;
        if sign.len() != self.0.len() { return Ok(false) };

        Ok(
            self.0.iter()
                .zip(&sign)
                .zip(H::hash(data))
                .all(|((&(ref x, ref y), &(ref xx, ref yy)), v)|
                    eq(&hash!(H::hash, (H::bytes() * 8) - (v as usize + 1), xx), x)
                        && eq(&hash!(H::hash, v as usize + 1, yy), y)
                )
        )
    }

    pub fn export(&self) -> Result<Vec<u8>, SerializeError> {
        serialize(&KeyBin(self.0.clone()), SizeLimit::Infinite)
    }
}

impl<H: Hash> fmt::Debug for Key<H> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<H: Hash> cmp::PartialEq<Key<H>> for Key<H> {
    fn eq(&self, rhs: &Key<H>) -> bool {
        let (x1, y1): (Vec<_>, Vec<_>) = self.0.iter().cloned().unzip();
        let (x2, y2): (Vec<_>, Vec<_>) = rhs.0.iter().cloned().unzip();
        eq(&x1.concat(), &x2.concat())
            && eq(&y1.concat(), &y2.concat())
    }
}


#[test]
fn test_lamport_sign() {
    use crypto::sha2::Sha256;

    let data = rand!(64);

    let sk = Key::<Sha256>::new();
    let pk = sk.public();
    let s = sk.sign(&data).unwrap();

    assert!(pk.verify(&s, &data).unwrap());
    assert!(!pk.verify(
        &[&[0; 32], &s[32..]].concat(),
        &data
    ).unwrap());
}

#[test]
fn test_lamport_export() {
    use crypto::sha2::Sha256;

    let sk = Key::<Sha256>::new();
    let sk_data = sk.export().unwrap();
    assert_eq!(sk, Key::from(&sk_data).unwrap());

    let pk = sk.public();
    let pk_data = pk.export().unwrap();
    assert_eq!(pk, Key::from(&pk_data).unwrap());
}
