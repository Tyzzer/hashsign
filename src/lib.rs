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
            .collect::<Vec<Key<H>>>();
        let pkeys = keys.iter()
            .map(|key| key.public().output().unwrap())
            .collect::<Vec<Vec<u8>>>();

        let tree = Tree::build(
            pkeys.iter()
                .map(|pk| Tree::leaf(pk))
                .collect()
        ).remove(0);
        let map = pkeys.iter()
            .zip(keys)
            .map(|(pk, k)| (pk.clone(), k))
            .collect::<HashMap<Vec<u8>, Key<H>>>();

        HashSign {
            tree: tree,
            map: map
        }
    }
}
