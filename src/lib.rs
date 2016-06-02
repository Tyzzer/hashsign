#![feature(question_mark, custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate bincode;
extern crate crypto;
extern crate rand;

#[macro_use] mod utils;
#[path = "short_lamport.rs"] mod lamport;
mod merkle;

use std::marker::PhantomData;
use std::collections::HashMap;
use bincode::SizeLimit;
use bincode::serde::{
    serialize, deserialize,
    SerializeError, DeserializeError
};
use utils::{ eq, Hash };
use merkle::TreeBin;
pub use lamport::Key;
pub use merkle::Tree;


#[derive(Clone, Debug)]
pub struct HashSign<H: Hash+Clone> {
    tree: Tree<H>,
    map: HashMap<Vec<u8>, Key<H>>
}

impl<H: Hash+Clone> HashSign<H> {
    pub fn new(level: u32) -> HashSign<H> {
        let keys = (0..2usize.pow(level))
            .map(|_| Key::new())
            .collect::<Vec<_>>();
        let pkeys = keys.iter()
            .map(|key| key.public().export().unwrap())
            .map(|pk| H::hash(&pk))
            .collect::<Vec<_>>();

        HashSign {
            tree: Tree::build(
                pkeys.iter()
                    .cloned()
                    .map(Tree::Leaf)
                    .collect()
            ),
            map: pkeys.iter()
                .cloned()
                .zip(keys)
                .collect()
        }
    }

    pub fn root_public_export(&self) -> Vec<u8> {
        self.tree.hash()
    }

    pub fn choose_sign(&mut self) -> Result<(Key<H>, Vec<u8>), SignError> {
        if self.map.is_empty() { Err(SignError::Null)? };

        let (tree, pkhash) = self.tree.choose();
        let treebin: TreeBin = tree.into();

        match self.map.remove(&pkhash) {
            Some(key) => Ok((key, serialize(&treebin, SizeLimit::Infinite)?)),
            None => self.choose_sign()
        }
    }
}


#[derive(Clone, Debug)]
pub struct HashVerify<H: Hash> {
    hash: Vec<u8>,
    __: PhantomData<H>
}

impl<H: Hash+Clone> HashVerify<H> {
    pub fn new(hash: &[u8]) -> HashVerify<H> {
        HashVerify {
            hash: hash.into(),
            __: PhantomData
        }
    }

    pub fn choose_verify(&self, tree: &[u8], pk: &[u8]) -> Result<bool, VerifyError> {
        let treebin: TreeBin = deserialize(tree)?;
        let tree: Tree<H> = treebin.into();

        if eq(&self.hash, &tree.hash())
            && tree.vals().map_or(false, |vals| vals.contains(&H::hash(pk)))
        {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}


#[derive(Debug)]
pub enum SignError {
    BinCode(SerializeError),
    Null
}

impl From<SerializeError> for SignError {
    fn from(err: SerializeError) -> SignError {
        SignError::BinCode(err)
    }
}

#[derive(Debug)]
pub enum VerifyError {
    BinCode(DeserializeError),
    Fail
}

impl From<DeserializeError> for VerifyError {
    fn from(err: DeserializeError) -> VerifyError {
        VerifyError::BinCode(err)
    }
}
