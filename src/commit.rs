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

pub fn test_sending_bytes() { //using read_bytes();

	let (mut sender, mut receiver) = unix_channel_pair();
        let handle = std::thread::spawn(move || {
            let seed = rand::thread_rng().gen::<[u8; 16]>();
            println!("sending data: {:?}",seed);
            sender.write_bytes(&seed).unwrap();
        });
        
        //let mut commit = ShaCommitment::new(seed);
        let mut data = [0u8;16]; //why is this [0u8;16]?
        receiver.read_bytes(&mut data).unwrap();
        println!("received data: {:?}",data);
        handle.join().ok();
}


pub fn test_sending_commit() {

	let (mut sender, mut receiver) = unix_channel_pair();
        let handle = std::thread::spawn(move || {
            let seed: _ = rand::thread_rng().gen::<[u8; 32]>();
            let mut commit = ShaCommitment::new(seed);
            let input_seed = rand::thread_rng().gen::<[u8; 16]>();
            for i in 0..15 {
                println!("testing {}", input_seed[i]);
                commit.input(&[input_seed[i]]);
            }     
            let commitment = commit.finish();   
            println!("Commitment of 128 bit string: {:?}", commitment);
            sender.write_bytes(&commitment).unwrap();
        });
        
        //let mut commit = ShaCommitment::new(seed);
        let mut rcvd_commitment = [0u8;32]; 
        receiver.read_bytes(&mut rcvd_commitment).unwrap();
        println!("received data: {:?}", rcvd_commitment);
        handle.join().ok();
}

pub fn commit_check_seed() {
    let seed: _ = rand::thread_rng().gen::<[u8; 32]>();
    let mut seed_ = [0u8; 32]; //what is this? 
    seed_.copy_from_slice(&seed);

    // create a commitment object
    let mut commit = ShaCommitment::new(seed);

    let input_seed : _ = rand::thread_rng().gen::<[u8; 16]>(); //128 bits
    // write input messages
    //commit.input(b"hello ");
    //commit.input(b"world");
    for i in 0..15 {
        println!("testing {}", input_seed[i]);
        commit.input(&[input_seed[i]]);
    }

    //commit.input(& [input_seed[0]]);
    //commit.input(& [input_seed[1]]);

    // finish commitment
    let commitment = commit.finish();
    //let hex_commitment = hex::encode(vec!(commitment));

    println!("commitment is {:?}", commitment); //still need the commitment as a hex-string
    // check a commitment
    /*let msg : u8 = 241;
    let mut commit_ = ShaCommitment::new(seed_);
    commit_.input(& [msg]);
    let commitment_ = commit_.finish();
    println!("I am in the commit_check();2");*/
}