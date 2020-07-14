use scuttlebutt::commitment::{Commitment, ShaCommitment};
use scuttlebutt::unix_channel_pair;
use scuttlebutt::channel::AbstractChannel;
use rand::Rng;


pub fn test_commit() {


// define a seed
let seed = [0u8; 32];

// create a commitment object
let mut commit = ShaCommitment::new(seed);

// write input messages
 commit.input(b"hello ");
 commit.input(b"world");

 // finish commitment
 let commitment = commit.finish();
 //println!("seed: {:?}", seed);
 //println!("commitment: {:?}", commitment);

 // check a commitment
 let seed = [0u8; 32];
 let msg = b"hello world";
 let mut commit_ = ShaCommitment::new(seed);
 commit_.input(msg);
 let commitment_ = commit_.finish();

 assert!(ShaCommitment::check(&commitment,&commitment_));

}



pub fn test_sending_commit() {

	let (mut sender, mut receiver) = unix_channel_pair();
        let handle = std::thread::spawn(move || {
            let seed = rand::thread_rng().gen::<[u8; 16]>();
            println!("sending data: {:?}",seed);
            sender.write_bytes(&seed).unwrap();
        });
        
        //let mut commit = ShaCommitment::new(seed);
        let mut data = [0u8;16];
        receiver.read_bytes(&mut data).unwrap();
        println!("received data: {:?}",data);
        handle.join().ok();
}