extern crate crypto;
extern crate rand;

#[macro_use] mod utils;

use std::fmt;
pub use crypto::digest::Digest;
pub use crypto::sha2::Sha256;
pub use utils::eq;


#[derive(Clone, Hash)]
pub struct Key<H: Digest+Clone> {
    pub hasher: H,
    pub val: Vec<(Vec<u8>, Vec<u8>)>
}

impl Default for Key<Sha256> {
    /// s3. For each chunk, generate a pair of secret random 256-bit numbers.
    /// These 64 numbers are your private key.
    fn default() -> Key<Sha256> {
        Key::new(Sha256::new())
    }
}

impl<H: Digest+Clone> Key<H> {
    pub fn new(hasher: H) -> Key<H> {
        assert_eq!(hasher.output_bits(), 256);
        let val = (0..hasher.output_bytes())
            .map(|_| (
                rand!(hasher.output_bytes()),
                rand!(hasher.output_bytes()))
            )
            .collect();
        Key {
            hasher: hasher,
            val: val
        }
    }

    pub fn from<V: Into<Vec<u8>>>(hasher: H, v: V) -> Key<H> {
        let v = v.into();
        Key {
            hasher: hasher.clone(),
            val: v.chunks(hasher.output_bytes() * 2)
                .map(|s| s.split_at(hasher.output_bytes()))
                .map(|(x, y)| (x.into(), y.into()))
                .collect()
        }
    }

    /// s4. Hash each of these numbers 258 times.
    /// This final set of 32 pairs of 2 hashes each are your public key.
    /// (Note: Use a hash chain and this public key becomes just 256 bits)
    pub fn public(&self) -> Key<H> {
        Key {
            hasher: self.hasher.clone(),
            val: self.val.iter()
                .map(|&(ref x, ref y)| (
                    hash!(self.hasher, self.hasher.output_bytes() * 8, x),
                    hash!(self.hasher, self.hasher.output_bytes() * 8, y)
                ))
                .collect()
        }
    }

    /// s1. Take the SHA-256 hash of the document you want to sign
    /// s2. Split the 256-bit hash of your document into 32 8-bit chunks
    /// s5. To create your signature, examine each chunk again.
    /// Let the value of this chunk be n with the range [0, 255].
    /// There are 2 256-bit numbers of the private key associated with that chunk.
    /// Let a equal the first of these numbers hashed n+1 times.
    /// Let b equal the second of these numbers hashed 256-n times.
    /// Publish the result (a,b).
    /// This pair is your signature for this 8-bit chunk.
    /// s6. Collect up the 32 signatures from each chunk,
    /// and you have a 32*2*(256/8) = 2kb signature!
    /// This is 4x smaller than the usual Lamport signature.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        hash!(self.hasher, data).iter()
            .zip(self.val.clone())
            .map(|(&n, (x, y))| [
                hash!(self.hasher, n as usize +1, x),
                hash!(self.hasher, (self.hasher.output_bytes() * 8) - (n as usize + 1), y)
            ].concat())
            .collect::<Vec<Vec<u8>>>()
            .concat()
    }

    /// v1. Take the SHA-256 hash of the document you want to verify
    /// v2. Split the 256-bit hash of the document into 32 8-bit chunks
    /// v3. For each chunk, let the chunk's value from the hash be V, the signature pair of numbers be (a, b) and the corresponding public key pair be (Pa, Pb)
    /// v4. Hash a and count the iterations until it equals Pa or it has been hashed 256 times. If it was hashed 256 times without reaching Pa, the signature is invalid. Save the number of iterations it took to reach Pa from a as i_a.
    /// v5. Repeat step (4) for b, saving the number of iterations to reach Pb from b as i_b.
    /// v6. If 256-i_a != i_b-1 or 256-i_a != V, this signature is invalid.
    /// v7. If there are more chunks, check the next chunk starting with step (3)
    /// v8. The signature is valid if all chunks are signed correctly.
    pub fn verify(&self, sign: &[u8], data: &[u8]) -> bool {
        sign.chunks(self.hasher.output_bytes() * 2)
            .map(|s| s.split_at(self.hasher.output_bytes()))
            .zip(self.val.iter())
            .zip(hash!(self.hasher, data))
            .all(|(((x, y), &(ref x_p, ref y_p)), v)| {
                eq(
                    &hash!(self.hasher, (self.hasher.output_bytes() * 8) - (v as usize + 1), x),
                    x_p
                )
                    && eq(&hash!(self.hasher, v as usize + 1, y), y_p)
            })
    }

    pub fn output(&self) -> Vec<u8> {
        self.val.iter()
            .map(|&(ref x, ref y)| [x.to_vec(), y.to_vec()].concat())
            .collect::<Vec<Vec<u8>>>()
            .concat()
    }
}

impl<H: Digest+Clone> fmt::Debug for Key<H> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.val.fmt(f)
    }
}
