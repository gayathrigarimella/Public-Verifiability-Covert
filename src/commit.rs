use scuttlebutt::commitment::{Commitment, ShaCommitment};
use scuttlebutt::{unix_channel_pair, Block, AesRng};
use scuttlebutt::channel::AbstractChannel;
use rand::Rng;

use rand::{CryptoRng, SeedableRng};
use rand::{thread_rng};

use fancy_garbling::{Wire};


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

pub fn test_commit_diff() {


    // define a seed
    let seed = [0u8; 32];
    
    // create a commitment object
    let mut commit = ShaCommitment::new(seed);
    let input_seed = rand::thread_rng().gen::<[u8; 32]>();

    let input_block = rand::random::<Block>();

    //sampling random wire and trying to commit that as a block 
    let mut rng2 = thread_rng(); //
    let input_wire = Wire::rand(&mut rng2, 2); //modulus for wire is u16, not sure what that is yet;
    //usually they choose 2 as the wire modulus?
    
    // write input messages
     commit.input(b"hello ");
     commit.input(b"world");
     commit.input(&input_seed); //Note: 
     commit.input(&input_block.as_ref());
     commit.input(&input_wire.as_block().as_ref()); //wire->block->bytes (u8 stream)
    
     // finish commitment
     let commitment = commit.finish();
     //println!("seed: {:?}", seed);
     println!("commitment: {:?}", commitment);
}
     // check a commitment
     /*let seed = [0u8; 32];
     let msg = b"hello world";
     let mut commit_ = ShaCommitment::new(seed);
     commit_.input(msg);
     let commitment_ = commit_.finish();
    
     assert!(ShaCommitment::check(&commitment,&commitment_));*/
    
pub fn test_sending_bytes() { //using read_bytes();

	let (mut sender, mut receiver) = unix_channel_pair();
        let handle = std::thread::spawn(move || {
            let seed = rand::thread_rng().gen::<[u8; 16]>();
            let seed_block = rand::random::<Block>(); 
            println!("sending data: {:?}",seed);
            println!("sending block: {:?}", seed_block.as_ref());
            sender.write_bytes(&seed).unwrap();
            sender.write_bytes(seed_block.as_ref()).unwrap();
        });
        
        //let mut commit = ShaCommitment::new(seed);
        let mut data = [0u8;32]; //array + rand block
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