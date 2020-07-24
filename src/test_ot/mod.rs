pub mod chou_orlandi;
mod garbler;
mod evaluator;
//mod garble;


//use ocelot::ot::{ChouOrlandiSender as OTSender,ChouOrlandiReceiver as OTReceiver};
use scuttlebutt::channel::AbstractChannel;
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
	//	kappa = 128, lambda = 4

    const lambda: usize = 4;		//	replicating factor 

    let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap(); //we are garbling AES

    //circ.print_info().unwrap(); let circ_ = circ.clone(); 
	
	let (mut receiver, mut sender) = unix_channel_pair();
    let (ot_sender, ot_receiver) = UnixStream::pair().unwrap();
    
    //We sample random inputs for computing the circuit for both parties
    let mut input_rng = thread_rng();
    let mut party_a_input = [0u16; 128];
    let mut party_b_input = [0u16; 128];
    input_rng.fill(&mut party_a_input);
    input_rng.fill(&mut party_b_input);

    let handle = std::thread::spawn(move || {
		
	//party_b: sender thread  
	// Step (a)
    let seed_b = rand_block_vec(lambda); //party_b samples his seeds
    let mut comm_seed_a = rand::thread_rng().gen::<[u8; 32]>(); // sha commitment seed
	let mut commit = ShaCommitment::new(comm_seed_a);
	let mut seed_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda];
	for i in 0..lambda {
		let s_b = seed_b[i].as_ref();
		//println!("sending seed: {:?}",s_b);
		for j in 0..16 {
			commit.input(&[s_b[j]]); //<Block> has size [u8;16]
		}
        seed_commitments[i] = commit.finish();
        comm_seed_a = rand::thread_rng().gen::<[u8; 32]>();
        commit = ShaCommitment::new(comm_seed_a);
        sender.write_bytes(&seed_commitments[i]).unwrap();

    }
    sender.flush();
    
    
    // Step (b) : j_hat, recei
    
	let j_hat = thread_rng().gen_range(0, lambda); //this is the choice 'j_hat'
    let mut b : [bool; lambda] = [false; lambda];
    b[j_hat] = true; //choosing choice bits of OT
    let reader = BufReader::new(ot_receiver.try_clone().unwrap());
    let writer = BufWriter::new(ot_receiver.try_clone().unwrap());
    let mut channel = Channel::new(reader, writer);
    for i in 0..lambda {
    	let mut rng = AesRng::from_seed(seed_b[i]);
    	let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let rcv_seed_a = ot.receive(&mut channel, &[b[i]], &mut rng).unwrap(); //keeping track seed_a from party_b perspective
        //println!("lambda:{}, ot-received: {:?}", j_hat, result);
    }

    //TODO_1: save transcript of the OT in step b as 'trans_j'


    // step (c) : used the seed_b(s) initialize the evaluator
        // the OT is utilizes the same rng (and seed) as the OT in 
        // garbler call to encode_many()

     for i in 0..lambda {
        let rng = AesRng::from_seed(seed_b[i]);
        let mut ev =
        Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(sender.clone(), rng).unwrap();
        let xs = ev.receive_many(&vec![2; 128]).unwrap();
        if i == j_hat {
            let party_b_evalwires = ev.encode_many(&party_b_input, &vec![2; 128]).unwrap();
            // only for j_hat, provide GC input 'y'
        } else {
            let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
            // for all GC's learn the dummy zero wire labels
        }
        sender.flush();
     }

     
     //TODO2: save the transcript hash for the OT called in encode_many()


    // step (d) : collect commit(input_commit, GC, output_wire) for each 'j'
        // collect vector of commitments

        let mut rcv_gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda]; //expecting commitment of seed_b(s)
        for i in 0..lambda {
            sender.clone().read_bytes(&mut rcv_gc_commitments[i]).unwrap();
            //println!("received data: {:?}",commitments[i]);		
        }
        sender.flush();
    



    });




    
    // party_a : receiver thread
	// Step (a)
	let mut commitments: [[u8; 32]; lambda] = [[0; 32]; lambda]; //expecting commitment of seed_b(s)
	for i in 0..lambda {
		receiver.read_bytes(&mut commitments[i]).unwrap();
        //println!("received data: {:?}",commitments[i]);		
    }
    receiver.flush();


       // Step (b) : sampling seed_a(s), sending messages <seed_a, witness>
       
    let seed_a = rand_block_vec(lambda); //sample block-sized <seed_a(s), witness> for OT
    let witness = rand_block_vec(lambda);

    let reader = BufReader::new(ot_sender.try_clone().unwrap());
    let writer = BufWriter::new(ot_sender.try_clone().unwrap());
    let mut channel = Channel::new(reader, writer);
    let ot_messages_b = seed_a.clone() //setting (seed_a, witness) as OT input messages
                .into_iter()
                .zip(witness.into_iter())
                .collect::<Vec<(Block, Block)>>();
    //println!("Hello: {:?}", ot_messages_b);
    for i in 0..lambda {
    	let ot_seed_b = rand::random::<Block>();
    	let mut rng = AesRng::from_seed(ot_seed_b);
    	let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
    	ot.send(&mut channel, &[ot_messages_b[i]], &mut rng).unwrap();
    }
    //TODO_1: save transcript of the OT in step b as 'trans_j'

    receiver.flush();


    // step (c) : used the seed_a(s) to initialize all lambda GC
        // note the OT is seeded by same randomness as the garbler

    
    // step (d) : commit both the garbler's input wires as C1
        // then commit and send c = (GC_j, C1, output_wires)

    
    //initializing array of commitments sent by party_a to party_b 
    let mut gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda];

    let mut comm_seed_d = rand::thread_rng().gen::<[u8; 32]>(); 
    let mut commit = ShaCommitment::new(comm_seed_d); //initializing the commitment for step d 

    for i in 0..lambda {
        let rng = AesRng::from_seed(seed_a[i]);
        let mut gb =
            Garbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(receiver.clone(), rng).unwrap();
        let xs = gb.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
        let ys = gb.receive_many(&vec![2; 128]).unwrap(); // This function calls OT send, OT uses the same rng seeded by 
        //circ.eval(&mut gb, &xs, &ys).unwrap();
        receiver.flush();

        // step (d)
        // commiting the garbler's wire labels for each GC_j
        
        let evaluator_encoding = gb.evaluator_wires;
        for i in 0..evaluator_encoding.len() {
            commit.input(&evaluator_encoding[i].0.as_block().as_ref()); //zero wire
            commit.input(&evaluator_encoding[i].1.as_block().as_ref()); //one wire
        }

        gc_commitments[i] = commit.finish();
        comm_seed_d = rand::thread_rng().gen::<[u8; 32]>();
        commit = ShaCommitment::new(comm_seed_d);
        //step (d) sending the commitments
        receiver.clone().write_bytes(&gc_commitments[i]).unwrap();

    }

    
    
    //TODO2: save the transcript hash for the OT called in receive_many(), is that possible here?
    

    //\handle.join.unwrap();
    

    }			


