use fancy_garbling::{
    circuit::Circuit,
    twopac::semihonest::{Evaluator, Garbler},
    FancyInput,
};

use ocelot::ot::{ChouOrlandiSender,ChouOrlandiReceiver};
use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel, Block};
use rand::{CryptoRng, Rng, SeedableRng};
use rand::{thread_rng};

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
        });
        let rng = AesRng::new();
        let mut ev =
            Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(receiver, rng).unwrap();
        let xs = ev.receive_many(&vec![2; 128]).unwrap();
        let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
        circ.eval(&mut ev, &xs, &ys).unwrap();
        handle.join().unwrap();
    }

pub fn test_seeded_garbling() {
       
    let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();

    circ.print_info().unwrap();

    let circ_ = circ.clone();
    let (sender, receiver) = unix_channel_pair();
    let handle = std::thread::spawn(move || {
        let mut rng2 = thread_rng();
        let random_block: Block = rng2.gen::<Block>();
        let rng = AesRng::from_seed(random_block);
        let mut gb =
            Garbler::<UnixChannel, AesRng, ChouOrlandiSender>::new(sender, rng).unwrap();
        let xs = gb.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
        let ys = gb.receive_many(&vec![2; 128]).unwrap();
        circ_.eval(&mut gb, &xs, &ys).unwrap();
    });
    let rng = AesRng::new();
    let mut ev =
        Evaluator::<UnixChannel, AesRng, ChouOrlandiReceiver>::new(receiver, rng).unwrap();
    let xs = ev.receive_many(&vec![2; 128]).unwrap();
    let ys = ev.encode_many(&vec![0_u16; 128], &vec![2; 128]).unwrap();
    circ.eval(&mut ev, &xs, &ys).unwrap();
    handle.join().unwrap();
}