pub mod chou_orlandi;
mod garbler;
mod evaluator;
//mod garble;
mod dummy_garbler;

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
use fancy_garbling::{circuit::Circuit, FancyInput, Wire};
use scuttlebutt::commitment::{Commitment, ShaCommitment};
//use fancy_garbling::circuit;
//use crate::garble::{Garbler as Gb, Evaluator as Ev};
use sha2::{Digest,Sha256};
pub use evaluator::Evaluator;
pub use garbler::Garbler;
pub use dummy_garbler::DummyGarbler;
use crypto::ed25519;

use std::fs::File;
use std::io::prelude::*;


//use Block::rand_block_vec;
pub type ChouOrlandiSender = chou_orlandi::Sender;
/// Instantiation of the Chou-Orlandi OT receiver.
pub type ChouOrlandiReceiver = chou_orlandi::Receiver;
use ChouOrlandiSender as OTSender;
use ChouOrlandiReceiver as OTReceiver;
use std::convert::TryInto;

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

        println!("actual encoding of evaluator {:?}", ys[10]);
        println!("test-aes, garbler's input wires {:?}", evaluator_encoding[10]);
    });
        
        
    let rng = AesRng::new();
    let mut ev =
        Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(receiver, rng).unwrap();
    let xs = ev.receive_many(&vec![2; 128]).unwrap();
    let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();

       /* let garbler_encoding = gb.garbler_wires;
        let evaluator_encoding = gb.evaluator_wires;


        println!("actual encoding of garbler {:?}", xs[10]);
        println!("test-aes, garbler's input wires {:?}", garbler_encoding[10]);

        println!("actual encoding of evaluator {:?}", ys[10]);
        println!("test-aes, garbler's input wires {:?}", evaluator_encoding[10]);*/

    println!("ev side: actual encoding of garbler {:?}", xs[10]);
    println!("ev side: actual encoding of evaluator {:?}", ys[10]);
    circ.eval(&mut ev, &xs, &ys).unwrap();
    handle.join().unwrap();
}



pub fn pvc() {
	//	kappa = 128, lambda = 4

    const lambda: usize = 4;		//	replicating factor 

    let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap(); //we are garbling AES

    //circ.print_info().unwrap(); let circ_ = circ.clone(); 
	
    let (mut receiver, mut sender) = unix_channel_pair();
    let (mut commit_receiver, mut commit_sender) = unix_channel_pair();
    let (ot_sender, ot_receiver) = UnixStream::pair().unwrap();
    
    //We sample random inputs for computing the circuit for both parties
    let mut input_rng = thread_rng();
    let mut party_a_input = [0u16; 128];
    let mut party_b_input = [0u16; 128];
    input_rng.fill(&mut party_a_input);
    input_rng.fill(&mut party_b_input);

    let mut comm_seed = rand::thread_rng().gen::<[u8; 32]>(); // sha commitment seed
    let seed: _ = rand::thread_rng().gen::<[u8; 32]>();
    let (private_key, public_key) = ed25519::keypair(&seed);

    let handle = std::thread::spawn(move || {
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
    let mut trans: Vec<Vec<u8>> = vec![Vec::new(); lambda];
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
        trans[i] = ot.transcript.clone();
    }
    //TODO_1: save transcript of the OT in step b as 'trans_j'
    receiver.flush();


    // step (c) : used the seed_a(s) to initialize all lambda GC
        // note the OT is seeded by same randomness as the garbler

    
    // step (d) : commit both the garbler's input wires as C1
        // then commit and send c = (GC_j, C1, output_wires)

    
    //initializing array of commitments sent by party_a to party_b 
    const n1: usize = 128;   //  length of P1 input
    const n3: usize = 128;
    let mut wire_commitments: [[[[u8;32]; 2]; n1]; lambda] = [[[[0;32]; 2]; n1]; lambda];
    let mut gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda];
    let mut gc_hash: [[u8;32]; lambda] = [[0; 32]; lambda];
    let mut commit : ShaCommitment;
    for i in 0..lambda {
        let mut rng = AesRng::from_seed(seed_a[i]);
        let mut gb =
            DummyGarbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(receiver.clone(), rng).unwrap();
        let xs = gb.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
        let ys = gb.receive_many(&vec![2; 128]).unwrap(); // This function calls OT send, OT uses the same rng seeded by 
        circ.eval(&mut gb, &xs, &ys).unwrap();
        gc_hash[i]= gb.gc_hash.finalize().as_slice().try_into().expect("slice with incorrect length");
        let check = gb.ot.transcript;
        //println!("CHECK CHECK {:?}", x);
        receiver.flush();

        // step (d)
        // commiting the garbler's wire labels for each (GC_j, comm(A), Z)
        
        let mut garbler_encoding = gb.garbler_wires;
        println!("evaluator encoding length is {}", garbler_encoding.len());
        for j in 0..garbler_encoding.len() {

            commit = ShaCommitment::new(comm_seed);
            commit.input(&garbler_encoding[j].0.as_block().as_ref()); //zero wire
            wire_commitments[i][j][0] = commit.finish();
            commit = ShaCommitment::new(comm_seed);
            commit.input(&garbler_encoding[j].1.as_block().as_ref()); //one wire
            wire_commitments[i][j][1] = commit.finish();
        }

        //  computing gc_commitments
        commit = ShaCommitment::new(comm_seed);
        commit.input(&gc_hash[i]);
        for j in 0..garbler_encoding.len() {
            commit.input(&wire_commitments[i][j][0]); 
            commit.input(&wire_commitments[i][j][1]); 
        }
        for j in 0..gb.output_wires.len() {
            commit.input(&gb.output_wires[j].0.as_ref());
            commit.input(&gb.output_wires[j].1.as_ref());

        }
        gc_commitments[i] = commit.finish();
        //step (d) sending the commitments
        
       
        commit_receiver.write_bytes(&gc_commitments[i]).unwrap();
        println!("send data: {:?}",gc_commitments[i]);
        
       
    }
    receiver.flush();
    //TODO2: step (c) save the transcript hash for the OT called in receive_many(), is that possible here?
    //TODO3: step (d) need to commit the c_j(s) = (GC_j, commit(garbler inputs), output wires)

    //  Step 5 - comppute signaturez
    let file = File::open("circuits/AES-non-expanded.txt").unwrap();
    let mut buf_reader = BufReader::new(file);
    for i in 0..lambda {
        let mut contents = String::new();
        let mut sign_message: Vec<u8> = Vec::new();
        buf_reader.read_to_string(&mut contents).unwrap();
        sign_message = contents.into_bytes(); 
        //let mut j: &[u8] = i;
        //sign_message.append(&mut j.into());
        println!("Sender has ot transcript {} {:?}",i,trans[i]);
        sign_message.append(&mut trans[i]);
        let mut sign = ed25519::signature(&sign_message,&private_key);
        receiver.write_bytes(&mut sign).unwrap();
    }
    receiver.flush();
	

    });

    //handle.join().unwrap();


    //party_b: sender thread  
    // Step (a)
    let seed_b = rand_block_vec(lambda); //party_b samples his seeds
    let mut commit = ShaCommitment::new(comm_seed);
    let mut seed_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda];
    for i in 0..lambda {
        let s_b = seed_b[i].as_ref();
        //println!("sending seed: {:?}",s_b);
        for j in 0..16 {
            commit.input(&[s_b[j]]); //<Block> has size [u8;16]
        }
        seed_commitments[i] = commit.finish();
        //comm_seed_a = rand::thread_rng().gen::<[u8; 32]>();
        commit = ShaCommitment::new(comm_seed);
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
    let mut rcv_seed_a : Vec<Block> = Vec::new();
    for i in 0..lambda {
        let mut rng = AesRng::from_seed(seed_b[i]);
        let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let temp = ot.receive(&mut channel, &[b[i]], &mut rng).unwrap()[0]; //keeping track seed_a from party_b perspective
        rcv_seed_a.append(&mut vec![temp]);
        //println!("lambda:{}, ot-received: {:?}", j_hat, result);
    }

    //TODO_1: save transcript of the OT in step b as 'trans_j'


    // step (c) : used the seed_b(s) initialize the evaluator
        // the OT is utilizes the same rng (and seed) as the OT in 
        // garbler call to encode_many()

    let mut party_b_evalwires : Vec<Wire> = Vec::new(); //store the evaluator's for final GC computation
     for i in 0..lambda {
        let rng = AesRng::from_seed(seed_b[i]);
        let mut ev =
        Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(sender.clone(), rng).unwrap();
        let xs = ev.receive_many(&vec![2; 128]).unwrap();
        println!("ev side: actual encoding of garbler {:?}", xs[10]);
        if i == j_hat {
            party_b_evalwires = ev.encode_many(&party_b_input, &vec![2; 128]).unwrap();
            println!("ev side: actual encoding of evaluator {:?}", party_b_evalwires[10]);
            //println!("party_b_evalwires: {}", party_b_evalwires[10]);
            // only for j_hat, provide GC input 'y'
        } else {
            let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
            println!("ev side: actual encoding of evaluator {:?}", ys[10]);
            // for all GC's learn the dummy zero wire labels
        }
        
        sender.flush();
     }

        println!("ev side: party_b_eval_wires {}", party_b_evalwires.len());
        println!("ev side: actual encoding of evaluator {:?}", party_b_evalwires[10]);
     
     //TODO2: save the transcript hash for the OT called in encode_many()


    // step (d) : collect commit(input_commit, GC, output_wire) for each 'j'
        // collect vector of commitments

        let mut rcv_gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda]; //expecting commitment of seed_b(s)
        for i in 0..lambda {
            commit_sender.read_bytes(&mut rcv_gc_commitments[i]).unwrap();
            println!("received data: {:?}",rcv_gc_commitments[i]);      
        }
        //sender.flush();

        let mut rcd_signatures: [[u8; 32]; lambda] = [[0; 32]; lambda];
        for i in 0..lambda {
        sender.read_bytes(&mut rcd_signatures[i]).unwrap();
        println!("received signature {:?}", rcd_signatures[i]);
    }

    // Step 6 - simulating P_A from step 3 and 4


    let (mut sim_receiver, mut sim_sender) = unix_channel_pair();
    let (mut sim_commit_receiver, mut sim_commit_sender) = unix_channel_pair();
    let (sim_ot_sender, sim_ot_receiver) = UnixStream::pair().unwrap();

    let handle2 = std::thread::spawn(move || {

        // Simulate Party P_A here
    let circ2 = Circuit::parse("circuits/AES-non-expanded.txt").unwrap(); //we are garbling AES
    let seed_a = rcv_seed_a.clone();
    const n1: usize = 128;   //  length of P1 input
    const n3: usize = 128;
    let mut wire_commitments: [[[[u8;32]; 2]; n1]; lambda] = [[[[0;32]; 2]; n1]; lambda];
    let mut gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda];
    let mut gc_hash: [[u8;32]; lambda] = [[0; 32]; lambda];
    let mut commit : ShaCommitment;
    for i in 0..lambda {
        let mut rng = AesRng::from_seed(seed_a[i]);
        let mut gb =
            DummyGarbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(sim_receiver.clone(), rng).unwrap();
        let xs = gb.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
        let ys = gb.receive_many(&vec![2; 128]).unwrap(); // This function calls OT send, OT uses the same rng seeded by 
        circ2.eval(&mut gb, &xs, &ys).unwrap();
        gc_hash[i]= gb.gc_hash.finalize().as_slice().try_into().expect("slice with incorrect length");
        sim_receiver.flush();

        // step (d)
        // commiting the garbler's wire labels for each (GC_j, comm(A), Z)
        
        let mut garbler_encoding = gb.garbler_wires;
        println!("evaluator encoding length is {}", garbler_encoding.len());
        for j in 0..garbler_encoding.len() {

            commit = ShaCommitment::new(comm_seed);
            commit.input(&garbler_encoding[j].0.as_block().as_ref()); //zero wire
            wire_commitments[i][j][0] = commit.finish();
            commit = ShaCommitment::new(comm_seed);
            commit.input(&garbler_encoding[j].1.as_block().as_ref()); //one wire
            wire_commitments[i][j][1] = commit.finish();
        }

        //  computing gc_commitments
        commit = ShaCommitment::new(comm_seed);
        commit.input(&gc_hash[i]);
        for j in 0..garbler_encoding.len() {
            commit.input(&wire_commitments[i][j][0]); 
            commit.input(&wire_commitments[i][j][1]); 
        }
        for j in 0..gb.output_wires.len() {
            commit.input(&gb.output_wires[j].0.as_ref());
            commit.input(&gb.output_wires[j].1.as_ref());

        }
        gc_commitments[i] = commit.finish();
        //step (d) sending the commitments
        
       
        sim_commit_receiver.write_bytes(&gc_commitments[i]).unwrap();
        println!("send data: {:?}",gc_commitments[i]);
    }
    sim_receiver.flush();

    });

    //  Simulate Party P_B here
    let mut sim_party_b_evalwires : Vec<Wire> = Vec::new(); //store the evaluator's for final GC computation
     for i in 0..lambda {
        let rng = AesRng::from_seed(seed_b[i]);
        let mut ev =
        Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(sim_sender.clone(), rng).unwrap();
        let xs = ev.receive_many(&vec![2; 128]).unwrap();
        println!("ev side: actual encoding of garbler {:?}", xs[10]);
        if i == j_hat {
            sim_party_b_evalwires = ev.encode_many(&party_b_input, &vec![2; 128]).unwrap();
            println!("ev side: actual encoding of evaluator {:?}", party_b_evalwires[10]);
            //println!("party_b_evalwires: {}", party_b_evalwires[10]);
            // only for j_hat, provide GC input 'y'
        } else {
            let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
            println!("ev side: actual encoding of evaluator {:?}", ys[10]);
            // for all GC's learn the dummy zero wire labels
        }
        
        sim_sender.flush();
     }

        println!("ev side: party_b_eval_wires {}", sim_party_b_evalwires.len());
        println!("ev side: actual encoding of evaluator {:?}", sim_party_b_evalwires[10]);
     
     //TODO2: save the transcript hash for the OT called in encode_many()


    // step (d) : collect commit(input_commit, GC, output_wire) for each 'j'
        // collect vector of commitments

        let mut sim_rcv_gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda]; //expecting commitment of seed_b(s)
        for i in 0..lambda {
            sim_commit_sender.read_bytes(&mut sim_rcv_gc_commitments[i]).unwrap();
            println!("compare simulation to original: {:?} {:?}",rcv_gc_commitments[i], sim_rcv_gc_commitments[i]);      
        }




    handle2.join().unwrap();
    handle.join().unwrap();

}			


