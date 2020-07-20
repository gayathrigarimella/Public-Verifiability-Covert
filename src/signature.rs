use crypto::ed25519;
use rand::{thread_rng};
use rand::{CryptoRng, Rng, SeedableRng};

pub fn test_signature(){
	let seed: _ = rand::thread_rng().gen::<[u8; 32]>();
	let (sign_key, verify_key) = ed25519::keypair(&seed);
	let message: _ = rand::thread_rng().gen::<[u8; 32]>();
	let sign = ed25519::signature(&message,&sign_key);
	let b: bool = ed25519::verify(&message,&verify_key,&sign);
	println!("Did the verification process work: {}",b );
}
