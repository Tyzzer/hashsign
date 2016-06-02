#![feature(question_mark, custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate bincode;
extern crate crypto;
extern crate rand;

#[macro_use] mod utils;
#[path = "short_lamport.rs"] mod lamport;
mod merkle;

use std::collections::HashMap;
use utils::Hash;
pub use lamport::Key;
pub use merkle::Tree;


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
                    .map(|pk| Tree::Leaf(pk))
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

    pub fn choose_sign(&mut self) -> Result<(Key<H>, Tree<H>), ()> {
        if self.map.is_empty() { Err(())? };

        let (tree, pkhash) = self.tree.choose();

        match self.map.remove(&pkhash) {
            Some(key) => Ok((key, tree)),
            None => self.choose_sign()
        }
    }
}
