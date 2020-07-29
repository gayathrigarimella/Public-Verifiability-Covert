pub mod chou_orlandi;
mod dummy_garbler;
mod evaluator;
mod garbler;

use fancy_garbling::{circuit::Circuit, FancyInput, Wire};
use ocelot::ot::{Receiver, Sender};
use rand::thread_rng;
use rand::{Rng, SeedableRng};
use scuttlebutt::channel::AbstractChannel;
use scuttlebutt::commitment::{Commitment, ShaCommitment};
use scuttlebutt::Block;
use scuttlebutt::{unix_channel_pair, AesRng, Channel, UnixChannel};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};
//use fancy_garbling::circuit;
//use crate::garble::{Garbler as Gb, Evaluator as Ev};
use crypto::ed25519;
pub use dummy_garbler::DummyGarbler;
pub use evaluator::Evaluator;
pub use garbler::Garbler;
use sha2::Digest;
//use std::time::Duration;
//use std::thread;

use std::fs::File;
use std::io::prelude::*;

pub type ChouOrlandiSender = chou_orlandi::Sender;
/// Instantiation of the Chou-Orlandi OT receiver.
pub type ChouOrlandiReceiver = chou_orlandi::Receiver;
use std::convert::TryInto;
use ChouOrlandiReceiver as OTReceiver;
use ChouOrlandiSender as OTSender;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

/*fn rand_bool_vec(size: usize) -> Vec<bool> {
    (0..size).map(|_| rand::random::<bool>()).collect()
} */

fn compare(v1: &[u8], v2: &[u8]) -> bool {
    (v1.len() == v2.len()) && v1.iter().zip(v2).all(|(a, b)| *a == *b)
}

pub fn pvc() {
    //	kappa = 128, lambda = 4
    const n1: usize = 128; //  length of P1 input
    const n3: usize = 128;
    const lambda: usize = 4; //	replicating factor

    let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap(); //we are garbling AES
    let circ_ = circ.clone();
    let circ1 = circ.clone();
    let circ2 = circ.clone();
    //circ.print_info().unwrap(); let circ_ = circ.clone();
    let (mut receiver, mut sender) = unix_channel_pair();
    //let (mut receiver1, mut sender1) = unix_channel_pair();
    let (mut commit_receiver, mut commit_sender) = unix_channel_pair();
    let (ot_sender, ot_receiver) = UnixStream::pair().unwrap();
    //let (mut gc_sender, mut gc_receiver) = unix_channel_pair();
    //We sample random inputs for computing the circuit for both parties
    let mut input_rng = thread_rng();
    let mut party_a_input = [0u16; 128];
    let mut party_b_input = [0u16; 128];
    input_rng.fill(&mut party_a_input);
    input_rng.fill(&mut party_b_input);

    //let mut comm_seed = rand::thread_rng().gen::<[u8; 32]>(); // sha commitment seed
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
        let seed_a2 = seed_a.clone();
        let witness2 = witness.clone();
        let mut trans: Vec<Vec<u8>> = vec![Vec::new(); lambda];
        let mut trans_hash: Vec<Vec<u8>> = vec![Vec::new(); lambda];
        let reader = BufReader::new(ot_sender.try_clone().unwrap());
        let writer = BufWriter::new(ot_sender.try_clone().unwrap());
        let mut channel = Channel::new(reader, writer);
        let ot_messages_b = seed_a
            .clone() //setting (seed_a, witness) as OT input messages
            .into_iter()
            .zip(witness.into_iter())
            .collect::<Vec<(Block, Block)>>();
        //println!("Hello: {:?}", ot_messages_b);
        for i in 0..lambda {
            let ot_seed_b = rand::random::<Block>();
            let mut rng = AesRng::from_seed(ot_seed_b);
            let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
            ot.send(&mut channel, &[ot_messages_b[i]], &mut rng)
                .unwrap();
            trans[i] = ot.transcript.clone();
        }
        //TODO_1: save transcript of the OT in step b as 'trans_j'
        receiver.flush();

        // step (c) : used the seed_a(s) to initialize all lambda GC
        // note the OT is seeded by same randomness as the garbler

        // step (d) : commit both the garbler's input wires as C1
        // then commit and send c = (GC_j, C1, output_wires)

        //initializing array of commitments sent by party_a to party_b
        let mut wire_commitments: [[[[u8; 32]; 2]; n1]; lambda] = [[[[0; 32]; 2]; n1]; lambda];
        let mut gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda];
        let mut gc_hash: [[u8; 32]; lambda] = [[0; 32]; lambda];
        let mut comm_seed_a: [[u8; 32]; lambda] = [[0; 32]; lambda];
        let mut commit: ShaCommitment;
        for i in 0..lambda {
            let mut rng = AesRng::from_seed(seed_a[i]);
            let mut gb = DummyGarbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(
                receiver.clone(),
                rng.clone(),
            )
            .unwrap();
            let xs = gb.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
            let ys = gb.receive_many(&vec![2; 128]).unwrap(); // This function calls OT send, OT uses the same rng seeded by
            circ_.eval(&mut gb, &xs, &ys).unwrap();
            gc_hash[i] = gb
                .gc_hash
                .finalize()
                .as_slice()
                .try_into()
                .expect("slice with incorrect length");
            trans_hash[i] = gb.ot.trans_hash;
            //println!("CHECK CHECK {:?}", x);
            receiver.flush().unwrap();

            // step (d)
            // commiting the garbler's wire labels for each (GC_j, comm(A), Z)

            comm_seed_a[i] = rng.gen::<[u8; 32]>();

            let mut garbler_encoding = gb.garbler_wires;
            println!("evaluator encoding length is {}", garbler_encoding.len());
            for j in 0..garbler_encoding.len() {
                commit = ShaCommitment::new(comm_seed_a[i]);
                commit.input(&garbler_encoding[j].0.as_block().as_ref()); //zero wire
                wire_commitments[i][j][0] = commit.finish();
                commit = ShaCommitment::new(comm_seed_a[i]);
                commit.input(&garbler_encoding[j].1.as_block().as_ref()); //one wire
                wire_commitments[i][j][1] = commit.finish();
            }

            //  computing gc_commitments
            commit = ShaCommitment::new(comm_seed_a[i]);
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
            println!("send data: {:?}", gc_commitments[i]);
        }
        commit_receiver.flush();

        //  Step 5 - compute signatures
        let file = File::open("circuits/AES-non-expanded.txt").unwrap();
        let mut buf_reader = BufReader::new(file);
        for i in 0..lambda {
            let mut contents = String::new();
            let mut sign_message: Vec<u8> = Vec::new();
            buf_reader.read_to_string(&mut contents).unwrap();
            sign_message = contents.into_bytes();
            //let mut j: &[u8] = i;
            //sign_message.append(&mut j.into());
            println!("Sender has ot transcript {} {:?}", i, trans[i]);
            sign_message.append(&mut trans[i]);
            sign_message.append(&mut trans_hash[i].clone());
            let mut sign = ed25519::signature(&sign_message, &private_key);
            //println!("Signature {}",sign.len() );
            receiver.write_bytes(&mut sign).unwrap();
            receiver.flush().unwrap();
        }

        let j_hat = receiver.read_usize().unwrap();
        //println!("after {}",j_hat );
        receiver.flush();

        let mut str_eq_flag: bool = true;
        let mut rcv_seeds: [[u8; 16]; lambda] = [[0; 16]; lambda];
        for i in 0..lambda {
            receiver.read_bytes(&mut rcv_seeds[i]).unwrap();
            if (i != j_hat && !compare(&rcv_seeds[i].clone(), &seed_a2[i].as_ref()))
                || (i == j_hat) && !compare(&rcv_seeds[i].clone(), &witness2[i].as_ref())
            {
                //str_eq_flag = false;
            }
        }
        receiver.flush().unwrap();
        //println!("String flag {}", str_eq_flag);

        // Step 8

        let mut rng = AesRng::from_seed(seed_a2[j_hat]);
        let mut gb =
            Garbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(receiver.clone(), rng).unwrap();
        let xs = gb.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
        let ys = gb.receive_many(&vec![2; 128]).unwrap(); // This function calls OT send, OT uses the same rng seeded by
        circ1.eval(&mut gb, &xs, &ys).unwrap();

        // send wire label commitments and sha seed
        //println!("sent seed {:?}", comm_seed_a[j_hat]);
        receiver.write_bytes(&comm_seed_a[j_hat]);

        for j in 0..n1 {
            receiver.write_bytes(&wire_commitments[j_hat][j][0]);
            receiver.write_bytes(&wire_commitments[j_hat][j][1]);
        }
    });

    //party_b: sender thread
    // Step (a)
    let seed_b = rand_block_vec(lambda); //party_b samples his seeds
    let mut comm_seed_b: [[u8; 32]; lambda] = [[0; 32]; lambda];
    let mut seed_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda];
    for i in 0..lambda {
        comm_seed_b[i] = rand::thread_rng().gen::<[u8; 32]>();
        let mut commit = ShaCommitment::new(comm_seed_b[i]);
        let s_b = seed_b[i].as_ref();
        //println!("sending seed: {:?}",s_b);
        for j in 0..16 {
            commit.input(&[s_b[j]]); //<Block> has size [u8;16]
        }
        seed_commitments[i] = commit.finish();
        sender.write_bytes(&seed_commitments[i]).unwrap();
    }
    sender.flush();
    // Step (b) : j_hat, recei
    let j_hat = thread_rng().gen_range(0, lambda); //this is the choice 'j_hat'
    let mut b: [bool; lambda] = [false; lambda];
    b[j_hat] = true; //choosing choice bits of OT
    let reader = BufReader::new(ot_receiver.try_clone().unwrap());
    let writer = BufWriter::new(ot_receiver.try_clone().unwrap());
    let mut channel = Channel::new(reader, writer);
    let mut rcv_seed_a: Vec<Block> = Vec::new();
    for i in 0..lambda {
        let mut rng = AesRng::from_seed(seed_b[i]);
        let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let temp = ot.receive(&mut channel, &[b[i]], &mut rng).unwrap()[0]; //keeping track seed_a from party_b perspective
        rcv_seed_a.append(&mut vec![temp]);
        //println!("lambda:{}, ot-received: {:?}", j_hat, result);
    }
    let rcv_seed_a2 = rcv_seed_a.clone();

    //TODO_1: save transcript of the OT in step b as 'trans_j'

    let mut trans_hash: Vec<Vec<u8>> = vec![Vec::new(); lambda];

    // step (c) : used the seed_b(s) initialize the evaluator
    // the OT is utilizes the same rng (and seed) as the OT in
    // garbler call to encode_many()

    let mut party_b_evalwires: Vec<Wire> = Vec::new(); //store the evaluator's for final GC computation
    for i in 0..lambda {
        let rng = AesRng::from_seed(seed_b[i]);
        let mut ev =
            Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(sender.clone(), rng)
                .unwrap();
        let xs = ev.receive_many(&vec![2; 128]).unwrap();
        println!("ev side: actual encoding of garbler {:?}", xs[10]);
        if i == j_hat {
            party_b_evalwires = ev.encode_many(&party_b_input, &vec![2; 128]).unwrap();
            println!(
                "ev side: actual encoding of evaluator {:?}",
                party_b_evalwires[10]
            );
        //println!("party_b_evalwires: {}", party_b_evalwires[10]);
        // only for j_hat, provide GC input 'y'
        } else {
            let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
            println!("ev side: actual encoding of evaluator {:?}", ys[10]);
            // for all GC's learn the dummy zero wire labels
        }
        trans_hash[i] = ev.ot.trans_hash;
        sender.flush().unwrap();
    }

    println!("ev side: party_b_eval_wires {}", party_b_evalwires.len());
    println!(
        "ev side: actual encoding of evaluator {:?}",
        party_b_evalwires[10]
    );

    //TODO2: save the transcript hash for the OT called in encode_many()

    // step (d) : collect commit(input_commit, GC, output_wire) for each 'j'
    // collect vector of commitments

    let mut rcv_gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda]; //expecting commitment of seed_b(s)
    for i in 0..lambda {
        commit_sender
            .read_bytes(&mut rcv_gc_commitments[i])
            .unwrap();
        println!("received data: {:?}", rcv_gc_commitments[i]);
    }
    commit_sender.flush().unwrap();

    let mut rcd_signatures: [[u8; 64]; lambda] = [[0; 64]; lambda];
    for i in 0..lambda {
        sender.read_bytes(&mut rcd_signatures[i]).unwrap();
        println!("received signature {}", i);
        sender.flush().unwrap();
    }

    // Step 6 - simulating P_A from step 3 and 4

    let (mut sim_receiver, mut sim_sender) = unix_channel_pair();
    let (mut sim_commit_receiver, mut sim_commit_sender) = unix_channel_pair();
    //let (sim_ot_sender, sim_ot_receiver) = UnixStream::pair().unwrap();
    let mut sim_trans_hash: Vec<Vec<u8>> = vec![Vec::new(); lambda];
    //let mut trans_hash = trans_hash.clone();
    let handle2 = std::thread::spawn(move || {
        // Simulate Party P_A here
        let circ2 = Circuit::parse("circuits/AES-non-expanded.txt").unwrap(); //we are garbling AES
        let seed_a = rcv_seed_a.clone();
        const n1: usize = 128; //  length of P1 input
                               //const n3: usize = 128;
        let mut wire_commitments: [[[[u8; 32]; 2]; n1]; lambda] = [[[[0; 32]; 2]; n1]; lambda];
        let mut gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda];
        let mut gc_hash: [[u8; 32]; lambda] = [[0; 32]; lambda];
        let mut commit: ShaCommitment;
        let mut sim_comm_seed_a: [[u8; 32]; lambda] = [[0; 32]; lambda];

        for i in 0..lambda {
            let mut rng2 = AesRng::from_seed(seed_a[i]);
            let mut gb = DummyGarbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(
                sim_receiver.clone(),
                rng2.clone(),
            )
            .unwrap();
            let xs = gb.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
            let ys = gb.receive_many(&vec![2; 128]).unwrap(); // This function calls OT send, OT uses the same rng seeded by
            circ2.eval(&mut gb, &xs, &ys).unwrap();
            gc_hash[i] = gb
                .gc_hash
                .finalize()
                .as_slice()
                .try_into()
                .expect("slice with incorrect length");

            sim_receiver.flush().unwrap();
            // step (d)
            // commiting the garbler's wire labels for each (GC_j, comm(A), Z)
            sim_comm_seed_a[i] = rng2.gen::<[u8; 32]>();

            let garbler_encoding = gb.garbler_wires;
            println!(
                "sim evaluator encoding length is {}",
                garbler_encoding.len()
            );
            for j in 0..garbler_encoding.len() {
                commit = ShaCommitment::new(sim_comm_seed_a[i]);
                commit.input(&garbler_encoding[j].0.as_block().as_ref()); //zero wire
                wire_commitments[i][j][0] = commit.finish();
                commit = ShaCommitment::new(sim_comm_seed_a[i]);
                commit.input(&garbler_encoding[j].1.as_block().as_ref()); //one wire
                wire_commitments[i][j][1] = commit.finish();
            }

            //  computing gc_commitments
            commit = ShaCommitment::new(sim_comm_seed_a[i]);
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
            println!("sim send data: {:?}", gc_commitments[i]);
        }
        sim_commit_receiver.flush().unwrap();
    });

    //  Simulate Party P_B here
    let mut sim_party_b_evalwires: Vec<Wire> = Vec::new(); //store the evaluator's for final GC computation
    for i in 0..lambda {
        let rng = AesRng::from_seed(seed_b[i]);
        let mut ev =
            Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(sim_sender.clone(), rng)
                .unwrap();
        let xs = ev.receive_many(&vec![2; 128]).unwrap();
        println!("sim ev side: actual encoding of garbler {:?}", xs[10]);
        if i == j_hat {
            sim_party_b_evalwires = ev.encode_many(&party_b_input, &vec![2; 128]).unwrap();
            println!(
                "sim ev side: actual encoding of evaluator {:?}",
                party_b_evalwires[10]
            );
        //println!("party_b_evalwires: {}", party_b_evalwires[10]);
        // only for j_hat, provide GC input 'y'
        } else {
            let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
            println!("sim ev side: actual encoding of evaluator {:?}", ys[10]);
            // for all GC's learn the dummy zero wire labels
        }
        sim_trans_hash[i] = ev.ot.trans_hash.clone();
        sim_sender.flush().unwrap();
    }

    println!(
        "sim ev side: party_b_eval_wires {}",
        sim_party_b_evalwires.len()
    );
    println!(
        "sim ev side: actual encoding of evaluator {:?}",
        sim_party_b_evalwires[10]
    );

    //TODO2: save the transcript hash for the OT called in encode_many()

    // step (d) : collect commit(input_commit, GC, output_wire) for each 'j'
    // collect vector of commitments

    let mut sim_rcv_gc_commitments: [[u8; 32]; lambda] = [[0; 32]; lambda]; //expecting commitment of seed_b(s)
    let mut sim_check: bool = true;
    for i in 0..lambda {
        sim_commit_sender
            .read_bytes(&mut sim_rcv_gc_commitments[i])
            .unwrap();
        if (i != j_hat)
            && (!compare(&rcv_gc_commitments[i], &sim_rcv_gc_commitments[i])
                || !compare(&trans_hash[i], &sim_trans_hash[i]))
        {
            sim_check = false;
        }
    }
    //handle2.join().unwrap();

    if !sim_check {
        println!("Simulation check fails. Output cheating certificate");
    }

    //  Step 7
    sender.write_usize(j_hat).unwrap();
    sender.flush();

    for i in 0..lambda {
        sender.write_bytes(&rcv_seed_a2[i].as_ref()).unwrap();
        //println!("sent: {:?}", rcv_seed_a2[i].as_ref());
    }
    sender.flush();

    // Step 8
    let rng = AesRng::from_seed(seed_b[j_hat]);
    let mut ev =
        Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(sender.clone(), rng).unwrap();
    let xs = ev.receive_many(&vec![2; 128]).unwrap();
    let ys = ev.encode_many(&party_b_input, &vec![2; 128]).unwrap();
    circ2.eval(&mut ev, &xs, &ys).unwrap();
    let mut sha_seed: [u8; 32] = [0; 32];
    sender.read_bytes(&mut sha_seed).unwrap();
    //println!("sha seed received {:?}",sha_seed );
    let mut wire_commitments: [[[u8; 32]; 2]; n1] = [[[0; 32]; 2]; n1];
    for j in 0..n1 {
        sender.read_bytes(&mut wire_commitments[j][0]).unwrap();
        sender.read_bytes(&mut wire_commitments[j][1]).unwrap();
    }

    // check if the commitments are correct
    //let commit_check = true;
    for i in 0..n1 {
        let mut commit = ShaCommitment::new(sha_seed);
        commit.input(&xs[i].as_block().as_ref()); //zero wire
        let commitment1 = commit.finish();

        if !compare(&commitment1, &wire_commitments[i][0])
            && !compare(&commitment1, &wire_commitments[i][1])
        {
            println!("commitment check fails for wires {}", i);
        }
    }

    let mut commit = ShaCommitment::new(sha_seed);
    let mut gc_block_hash = ev.gc_hash.finalize();
    let gc_hash = gc_block_hash.as_slice();
    //println!("gc_hash {:?}",gc_hash );
    commit.input(&gc_hash);
    for j in 0..n1 {
        commit.input(&wire_commitments[j][0]);
        //println!("wire {} 1 {:?}",j,wire_commitments[j][0]);
        commit.input(&wire_commitments[j][1]);
        //println!("wire {} 2 {:?}",j,wire_commitments[j][1]);
    }
    for j in 0..n3 {
        commit.input(&ev.output_wires[j].0.as_ref());
        commit.input(&ev.output_wires[j].1.as_ref());
    }
    let commitment2 = commit.finish();

    if !compare(&commitment2, &rcv_gc_commitments[j_hat]) {
        println!("commitment check fails for c ");
    }

    handle.join().unwrap();
}


#[cfg(test)]
mod tests {
use super::*;
    #[test]
    fn test_aes() {
        pvc();
    }
}
