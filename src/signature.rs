use crypto::ed25519;
use rand::{thread_rng};
use rand::{CryptoRng, Rng, SeedableRng};

use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;

pub fn reading_circuit() {
    let file = File::open("circuits/AES-non-expanded.txt").unwrap();
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents).unwrap();
    //assert_eq!(contents, "Hello, world!");
    println!("file contents as a string {}", contents);
}

pub fn circuit_signature(){
	let seed: _ = rand::thread_rng().gen::<[u8; 32]>();
	let (sign_key, verify_key) = ed25519::keypair(&seed);

	let file = File::open("circuits/AES-non-expanded.txt").unwrap();
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
	buf_reader.read_to_string(&mut contents).unwrap();
	println!("circuit from file {}", contents);
	let message = contents.into_bytes();
	let sign = ed25519::signature(&message,&sign_key);
	let b: bool = ed25519::verify(&message,&verify_key,&sign);
	println!("Did the verification process work: {}",b );
}

pub fn test_signature(){
	let seed: _ = rand::thread_rng().gen::<[u8; 32]>();
	let (sign_key, verify_key) = ed25519::keypair(&seed);
	let message: _ = rand::thread_rng().gen::<[u8; 32]>();
	let sign = ed25519::signature(&message,&sign_key);
	let b: bool = ed25519::verify(&message,&verify_key,&sign);
	println!("Did the verification process work: {}",b );
}
