use std:: {
	io::{BufReader, BufWriter},
	os::unix::net::UnixStream
};
use scuttlebutt::commitment::{Commitment, ShaCommitment};
use rand::{Rng,thread_rng};
use scuttlebutt::{Block,unix_channel_pair};
use ocelot::ot::{ChouOrlandiSender as OTSender,ChouOrlandiReceiver as OTReceiver};
use ocelot::ot::{Sender,Receiver};
use scuttlebutt::{Channel, AesRng, AbstractChannel};


fn rand_block_vec(size: usize) -> Vec<Block> {
	(0..size).map(|_| rand::random::<Block>()).collect()
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
	let rand_ind = thread_rng().gen_range(0,rep_fact);
    let mut b : [bool;rep_fact] = [false;rep_fact];
    b[rand_ind] = true;
    let mut rng = AesRng::new();
    let reader = BufReader::new(ot_receiver.try_clone().unwrap());
    let writer = BufWriter::new(ot_receiver.try_clone().unwrap());
    let mut channel = Channel::new(reader, writer);
    let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
    let result = ot.receive(&mut channel, &b, &mut rng).unwrap();
    println!("{:?}", result);


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

    let mut rng = AesRng::new();
    let reader = BufReader::new(ot_sender.try_clone().unwrap());
    let writer = BufWriter::new(ot_sender.try_clone().unwrap());
    let mut channel = Channel::new(reader, writer);
    let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
    let ot_messages = seed_a
                .into_iter()
                .zip(witness.into_iter())
                .collect::<Vec<(Block, Block)>>();
    println!("Hello: {:?}", ot_messages);
    ot.send(&mut channel, &ot_messages, &mut rng).unwrap();
    handle.join().unwrap();

}			