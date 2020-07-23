pub mod chou_orlandi;
mod garbler;
mod evaluator;
//mod garble;


//use ocelot::ot::{ChouOrlandiSender as OTSender,ChouOrlandiReceiver as OTReceiver};
use scuttlebutt::{Channel, AesRng, unix_channel_pair, UnixChannel};
use ocelot::ot::{Sender,Receiver};
use scuttlebutt::{Block};
use std:: {
	io::{BufReader, BufWriter},
	os::unix::net::UnixStream
};
use rand::{Rng, SeedableRng};
use rand::{thread_rng};
use fancy_garbling::{circuit::Circuit, FancyInput};
use scuttlebutt::commitment::{Commitment, ShaCommitment};
//use fancy_garbling::circuit;
//use crate::garble::{Garbler as Gb, Evaluator as Ev};

pub use evaluator::Evaluator;
pub use garbler::Garbler;

//use Block::rand_block_vec;
pub type ChouOrlandiSender = chou_orlandi::Sender;
/// Instantiation of the Chou-Orlandi OT receiver.
pub type ChouOrlandiReceiver = chou_orlandi::Receiver;
use ChouOrlandiSender as OTSender;
use ChouOrlandiReceiver as OTReceiver;

fn rand_block_vec(size: usize) -> Vec<Block> {
	(0..size).map(|_| rand::random::<Block>()).collect()
} 

fn rand_bool_vec(size: usize) -> Vec<bool> {
	(0..size).map(|_| rand::random::<bool>()).collect()
} 

pub fn test_ot() {
	let n = 10;
	let m0s = rand_block_vec(n);
        let m1s = rand_block_vec(n);
        let bs = rand_bool_vec(n);
        //let m0s_ = m0s.clone();
        //let m1s_ = m1s.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
             println!("{:?}", ms);
            ot.send(&mut channel, &ms, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let result = ot.receive(&mut channel, &bs, &mut rng).unwrap();
        println!("{:?}", result);
        handle.join().unwrap();
}


pub fn test_seeded_ot() {
	let n = 10;
	let m0s = rand_block_vec(n);
        let m1s = rand_block_vec(n);
        let bs = rand_bool_vec(n);
        //let m0s_ = m0s.clone();
        //let m1s_ = m1s.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            //let mut rng = AesRng::new();
            let mut rng2 = thread_rng(); //
            let random_block: Block = rng2.gen::<Block>();
            let mut rng = AesRng::from_seed(random_block); //seeded rng generation
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
             println!("{:?}", ms);
            ot.send(&mut channel, &ms, &mut rng).unwrap();
        });
        let mut rng = AesRng::new(); //seeded rng generation
        /*let mut rng2 = thread_rng(); //
        let random_block: Block = rng2.gen::<Block>();
        let mut rng = AesRng::from_seed(random_block); */
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let result = ot.receive(&mut channel, &bs, &mut rng).unwrap();
        println!("{:?}", result);
        handle.join().unwrap();
}

pub fn test_aes() {
    let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();

    circ.print_info().unwrap();

    let circ_ = circ.clone();
    let (sender, receiver) = unix_channel_pair();
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let mut gb =
            Garbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(sender, rng).unwrap();
        let xs = gb.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
        let ys = gb.receive_many(&vec![2; 128]).unwrap();
        circ_.eval(&mut gb, &xs, &ys).unwrap();

        let evaluator_encoding = gb.evaluator_wires;
        let garbler_encoding = gb.garbler_wires;

        println!("actual encoding of garbler {:?}", xs[10]);
        println!("test-aes, garbler's input wires {:?}", garbler_encoding[10]);

        println!("actual encoding of garbler {:?}", ys[10]);
        println!("test-aes, garbler's input wires {:?}", evaluator_encoding[10]);
    });
        
        
    let rng = AesRng::new();
    let mut ev =
        Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(receiver, rng).unwrap();
    let xs = ev.receive_many(&vec![2; 128]).unwrap();
    let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
    circ.eval(&mut ev, &xs, &ys).unwrap();
    handle.join().unwrap();
}



pub fn pvc() {
	//	the computational security parameter is
	//	set to 128 for this implementation

	const rep_fact: usize = 4;		//	replicating factor 
	let seed = rand::thread_rng().gen::<[u8; 32]>(); // sha commitment seed

	let (mut sender, mut receiver) = unix_channel_pair();
	let (ot_sender, ot_receiver) = UnixStream::pair().unwrap();
    
    let handle = std::thread::spawn(move || {
		
		
	// Step 1
	let seed_b = rand_block_vec(rep_fact);
	let mut commit = ShaCommitment::new(seed);
	let mut commitments: [[u8; 32]; rep_fact] = [[0; 32]; rep_fact];
	for i in 0..rep_fact {
		let s_b = seed_b[i].as_ref();
		println!("sending seed: {:?}",s_b);
		for j in 0..16 {
			commit.input(&[s_b[j]]);
		}
		commitments[i] = commit.finish();
		commit = ShaCommitment::new(seed);
		sender.write_bytes(&commitments[i]).unwrap();

	}
	sender.flush();
	// Step 2
	let rand_ind = thread_rng().gen_range(0,rep_fact); //this is the choice 'j_hat'
    let mut b : [bool;rep_fact] = [false;rep_fact];
    b[rand_ind] = true;
    let reader = BufReader::new(ot_receiver.try_clone().unwrap());
    let writer = BufWriter::new(ot_receiver.try_clone().unwrap());
    let mut channel = Channel::new(reader, writer);
    for i in 0..rep_fact {
    	let mut rng = AesRng::from_seed(seed_b[i]);
    	let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
    	let result = ot.receive(&mut channel, &[b[i]], &mut rng).unwrap();
    	println!("{:?}", result);
    }
    

	});

	// Step 1
	let mut commitments: [[u8; 32]; rep_fact] = [[0; 32]; rep_fact];
	for i in 0..rep_fact {
		receiver.read_bytes(&mut commitments[i]).unwrap();
		println!("received data: {:?}",commitments[i]);		}
    receiver.flush();
   	// Step 2 
    let mut seed_a = rand_block_vec(rep_fact);
    let mut witness = rand_block_vec(rep_fact);

    let reader = BufReader::new(ot_sender.try_clone().unwrap());
    let writer = BufWriter::new(ot_sender.try_clone().unwrap());
    let mut channel = Channel::new(reader, writer);
    let ot_messages = seed_a
                .into_iter()
                .zip(witness.into_iter())
                .collect::<Vec<(Block, Block)>>();
    println!("Hello: {:?}", ot_messages);
    for i in 0..rep_fact {
    	let seed = rand::random::<Block>();
    	let mut rng = AesRng::from_seed(seed);
    	let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
    	ot.send(&mut channel, &[ot_messages[i]], &mut rng).unwrap();
	}
	//step 3 
	
    handle.join().unwrap();


}			

