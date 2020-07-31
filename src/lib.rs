#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(dead_code)]
#![allow(unused_must_use)]
#![allow(unused_variables)]
#![allow(unused_parens)]
#![allow(unused_mut)]

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
use rand::seq::SliceRandom;
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

fn compare(v1: &[u8], v2: &[u8]) -> bool {
    (v1.len() == v2.len()) && v1.iter().zip(v2).all(|(a, b)| *a == *b)
}

pub fn pvc(circuit_file: &'static str, party_a_input : Vec<u16>, party_b_input : Vec<u16>, rep_factor: usize) {
    //  kappa = 128, rep_factor = 4
    let n1: usize = party_a_input.len(); //  length of P1 input
    let n2: usize = party_b_input.len();

    let circ = Circuit::parse(circuit_file).unwrap(); //we are garbling AES
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

    //let mut comm_seed = rand::thread_rng().gen::<[u8; 32]>(); // sha commitment seed
    let seed: _ = rand::thread_rng().gen::<[u8; 32]>();
    let (private_key, public_key) = ed25519::keypair(&seed);

    let handle = std::thread::spawn(move || {
        // party_a : receiver thread
        // Step (a)
        let mut commitments: Vec<[u8; 32]> = vec![[0; 32]; rep_factor]; //expecting commitment of seed_b(s)
        for i in 0..rep_factor {
            receiver.read_bytes(&mut commitments[i]).unwrap();
            //println!("received data: {:?}",commitments[i]);
        }
        receiver.flush();

        // Step (b) : sampling seed_a(s), sending messages <seed_a, witness>

        let seed_a = rand_block_vec(rep_factor); //sample block-sized <seed_a(s), witness> for OT
        let witness = rand_block_vec(rep_factor);
        let seed_a2 = seed_a.clone();
        let witness2 = witness.clone();
        let mut trans: Vec<Vec<u8>> = vec![Vec::new(); rep_factor];
        let mut trans_hash: Vec<Vec<u8>> = vec![Vec::new(); rep_factor];
        let reader = BufReader::new(ot_sender.try_clone().unwrap());
        let writer = BufWriter::new(ot_sender.try_clone().unwrap());
        let mut channel = Channel::new(reader, writer);
        let ot_messages_b = seed_a
            .clone() //setting (seed_a, witness) as OT input messages
            .into_iter()
            .zip(witness.into_iter())
            .collect::<Vec<(Block, Block)>>();
        //println!("Hello: {:?}", ot_messages_b);
        for i in 0..rep_factor {
            let ot_seed_b = rand::random::<Block>();
            let mut rng = AesRng::from_seed(ot_seed_b);
            let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
            ot.send(&mut channel, &[ot_messages_b[i]], &mut rng)
                .unwrap();
            trans[i] = ot.transcript.clone();
        }
        //TODO_1: save transcript of the OT in step b as 'trans_j'
        receiver.flush();

        // step (c) : used the seed_a(s) to initialize all rep_factor GC
        // note the OT is seeded by same randomness as the garbler

        // step (d) : commit both the garbler's input wires as C1
        // then commit and send c = (GC_j, C1, output_wires)

        //initializing array of commitments sent by party_a to party_b
        let mut wire_commitments: Vec<Vec<[[u8; 32]; 2]>> = vec![vec![[[0; 32]; 2]; n1]; rep_factor];
        let mut gc_commitments: Vec<[u8; 32]> = vec![[0; 32]; rep_factor];
        let mut gc_hash: Vec<[u8; 32]> = vec![[0; 32]; rep_factor];
        let mut comm_seed_a: Vec<[u8; 32]> = vec![[0; 32]; rep_factor];
        let mut commit: ShaCommitment;
        for i in 0..rep_factor {
            let mut rng = AesRng::from_seed(seed_a[i]);
            let mut gb = DummyGarbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(
                receiver.clone(),
                rng.clone(),
            )
            .unwrap();
            let xs = gb.encode_many(&party_a_input, &vec![2; n1]).unwrap();
            let ys = gb.receive_many(&vec![2; n2]).unwrap(); // This function calls OT send, OT uses the same rng seeded by
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
        let file = File::open(circuit_file).unwrap();
        let mut buf_reader = BufReader::new(file);
        for i in 0..rep_factor {
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
        let mut rcv_seeds: Vec<[u8; 16]> = vec![[0; 16]; rep_factor];
        for i in 0..rep_factor {
            receiver.read_bytes(&mut rcv_seeds[i]).unwrap();
            if (i != j_hat && !compare(&rcv_seeds[i].clone(), &seed_a2[i].as_ref()))
                || (i == j_hat) && !compare(&rcv_seeds[i].clone(), &witness2[i].as_ref())
            {
                str_eq_flag = false;
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
    let seed_b = rand_block_vec(rep_factor); //party_b samples his seeds
    let mut comm_seed_b: Vec<[u8; 32]> = vec![[0; 32]; rep_factor];
    let mut seed_commitments: Vec<[u8; 32]> = vec![[0; 32]; rep_factor];
    for i in 0..rep_factor {
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
    let j_hat = thread_rng().gen_range(0, rep_factor); //this is the choice 'j_hat'
    let mut b: Vec<bool> = vec![false; rep_factor];
    b[j_hat] = true; //choosing choice bits of OT
    let reader = BufReader::new(ot_receiver.try_clone().unwrap());
    let writer = BufWriter::new(ot_receiver.try_clone().unwrap());
    let mut channel = Channel::new(reader, writer);
    let mut rcv_seed_a: Vec<Block> = Vec::new();
    let mut trans : Vec<Vec<u8>> = vec![Vec::new(); rep_factor];
    for i in 0..rep_factor {
        let mut rng = AesRng::from_seed(seed_b[i]);
        let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let temp = ot.receive(&mut channel, &[b[i]], &mut rng).unwrap()[0]; //keeping track seed_a from party_b perspective
        rcv_seed_a.append(&mut vec![temp]);
        trans[i] = ot.transcript.clone();
        //println!("rep_factor:{}, ot-received: {:?}", j_hat, result);
    }
    let rcv_seed_a2 = rcv_seed_a.clone();


    let mut trans_hash: Vec<Vec<u8>> = vec![Vec::new(); rep_factor];

    // step (c) : used the seed_b(s) initialize the evaluator
    // the OT is utilizes the same rng (and seed) as the OT in
    // garbler call to encode_many()

    let mut party_b_evalwires: Vec<Wire> = Vec::new(); //store the evaluator's for final GC computation
    for i in 0..rep_factor {
        let rng = AesRng::from_seed(seed_b[i]);
        let mut ev =
            Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(sender.clone(), rng)
                .unwrap();
        let xs = ev.receive_many(&vec![2; n1]).unwrap();
        println!("ev side: actual encoding of garbler {:?}", xs[10]);
        if i == j_hat {
            party_b_evalwires = ev.encode_many(&party_b_input, &vec![2; n2]).unwrap();
            println!(
                "ev side: actual encoding of evaluator {:?}",
                party_b_evalwires[10]
            );
        //println!("party_b_evalwires: {}", party_b_evalwires[10]);
        // only for j_hat, provide GC input 'y'
        } else {
            let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; n2]).unwrap();
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

    let mut rcv_gc_commitments: Vec<[u8; 32]> = vec![[0; 32]; rep_factor]; //expecting commitment of seed_b(s)
    for i in 0..rep_factor {
        commit_sender
            .read_bytes(&mut rcv_gc_commitments[i])
            .unwrap();
        println!("received data: {:?}", rcv_gc_commitments[i]);
    }
    commit_sender.flush().unwrap();

    let mut rcd_signatures: Vec<[u8; 64]> = vec![[0; 64]; rep_factor];
    for i in 0..rep_factor {
        sender.read_bytes(&mut rcd_signatures[i]).unwrap();
        println!("received signature {}", i);
        sender.flush().unwrap();
    }

    // Step 6 - simulating P_A from step 3 and 4

    let (mut sim_receiver, mut sim_sender) = unix_channel_pair();
    let (mut sim_commit_receiver, mut sim_commit_sender) = unix_channel_pair();
    //let (sim_ot_sender, sim_ot_receiver) = UnixStream::pair().unwrap();
    let mut sim_trans_hash: Vec<Vec<u8>> = vec![Vec::new(); rep_factor];
    //let mut trans_hash = trans_hash.clone();
    let handle2 = std::thread::spawn(move || {
        // Simulate Party P_A here
        let circ2 = Circuit::parse(circuit_file).unwrap(); //we are garbling AES
        let seed_a = rcv_seed_a.clone();
                               //const n3: usize = 128;
        let mut wire_commitments: Vec<Vec<[[u8; 32]; 2]>> = vec![vec![[[0; 32]; 2]; n1]; rep_factor];
        let mut gc_commitments: Vec<[u8; 32]> = vec![[0; 32]; rep_factor];
        let mut gc_hash: Vec<[u8; 32]> = vec![[0; 32]; rep_factor];
        let mut commit: ShaCommitment;
        let mut sim_comm_seed_a: Vec<[u8; 32]> = vec![[0; 32]; rep_factor];

        for i in 0..rep_factor {
            let mut rng2 = AesRng::from_seed(seed_a[i]);
            let mut gb = DummyGarbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(
                sim_receiver.clone(),
                rng2.clone(),
            )
            .unwrap();
            let xs = gb.encode_many(&vec![0_u16; n1], &vec![2; n1]).unwrap();
            let ys = gb.receive_many(&vec![2; n2]).unwrap(); // This function calls OT send, OT uses the same rng seeded by
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
    for i in 0..rep_factor {
        let rng = AesRng::from_seed(seed_b[i]);
        let mut ev =
            Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(sim_sender.clone(), rng)
                .unwrap();
        let xs = ev.receive_many(&vec![2; n1]).unwrap();
        println!("sim ev side: actual encoding of garbler {:?}", xs[10]);
        if i == j_hat {
            sim_party_b_evalwires = ev.encode_many(&party_b_input, &vec![2; n2]).unwrap();
            println!(
                "sim ev side: actual encoding of evaluator {:?}",
                party_b_evalwires[10]
            );
        //println!("party_b_evalwires: {}", party_b_evalwires[10]);
        // only for j_hat, provide GC input 'y'
        } else {
            let ys = ev.encode_many(&vec![0_u16; n2], &vec![2; n2]).unwrap();
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

    let mut sim_rcv_gc_commitments: Vec<[u8; 32]> = vec![[0; 32]; rep_factor]; //expecting commitment of seed_b(s)
    let mut sim_check: bool = true;
    let mut corrupted_indexes : Vec<usize> = Vec::new();
    sim_commit_sender.flush();
    for i in 0..rep_factor {
        sim_commit_sender
            .read_bytes(&mut sim_rcv_gc_commitments[i])
            .unwrap();
        if (i != j_hat)
            && (!compare(&rcv_gc_commitments[i], &sim_rcv_gc_commitments[i])
                || !compare(&trans_hash[i], &sim_trans_hash[i]))
        {
            sim_check = false;
            corrupted_indexes.push(i);
        }
    }
    sim_commit_sender.flush();
    //handle2.join().unwrap();
    sim_check = false;
    if !sim_check {
        println!("Protocol aborts due to cheating party P_a.");
        let j  = corrupted_indexes.choose(&mut rand::thread_rng());
        println!("Publicly verifiable ceritificate:");
        println!("Corrupted index: {:?}", j);
        //println!("OT transcript trans_{} from step 2: {:?}", j,trans[j]);
        //println!("Transcript H_{} hash from step 3: {:?}", trans_hash[j]);
        //println!("Commitment c_{} from step 4{:?}", j,rcv_gc_commitments[j][0]);
        //println!("Signature sigma_{} from step 5: {:?}", j,rcd_signatures[j][0]);
        //println!("Seed seed_b_{}: {}",j, seed_b[j]);
        //println!("Sha seed {}", comm_seed_b[j] );
    }

    //  Step 7
    sender.write_usize(j_hat).unwrap();
    sender.flush();

    for i in 0..rep_factor {
        sender.write_bytes(&rcv_seed_a2[i].as_ref()).unwrap();
        println!("sent: {:?}", rcv_seed_a2[i].as_ref());
    }
    sender.flush();

    // Step 8
    let rng = AesRng::from_seed(seed_b[j_hat]);
    let mut ev =
        Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(sender.clone(), rng).unwrap();
    let xs = ev.receive_many(&vec![2; n1]).unwrap();
    let ys = ev.encode_many(&party_b_input, &vec![2; n2]).unwrap();
    circ2.eval(&mut ev, &xs, &ys).unwrap();
    let mut sha_seed: [u8; 32] = [0; 32];
    sender.read_bytes(&mut sha_seed).unwrap();
    println!("sha seed received {:?}",sha_seed );
    let mut wire_commitments: Vec<[[u8; 32]; 2]> = vec![[[0; 32]; 2]; n1];
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
    let gc_block_hash = ev.gc_hash.finalize();
    let gc_hash = gc_block_hash.as_slice();
    //println!("gc_hash {:?}",gc_hash );
    commit.input(&gc_hash);
    for j in 0..n1 {
        commit.input(&wire_commitments[j][0]);
        //println!("wire {} 1 {:?}",j,wire_commitments[j][0]);
        commit.input(&wire_commitments[j][1]);
        //println!("wire {} 2 {:?}",j,wire_commitments[j][1]);
    }
    for j in 0..ev.output_wires.len() {
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
        let mut party_a_input = vec![0u16; 128];
        let mut party_b_input = vec![0u16; 128];
        let mut input_rng = thread_rng();
        //input_rng.fill(&mut party_a_input);
        //input_rng.fill(&mut party_b_input);
        pvc("circuits/AES-non-expanded.txt",party_a_input, party_b_input, 4);
    }
}
