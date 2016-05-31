#![feature(question_mark, custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate bincode;
extern crate crypto;
extern crate rand;

#[macro_use] mod utils;
#[path = "short_lamport.rs"] pub mod lamport;
pub mod merkle;

//
