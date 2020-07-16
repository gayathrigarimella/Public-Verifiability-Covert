
use ocelot::ot::{ChouOrlandiSender as OTSender,ChouOrlandiReceiver as OTReceiver};
use scuttlebutt::{Channel, AesRng, AbstractChannel};
use ocelot::ot::{Sender,Receiver};
use scuttlebutt::{Block};
use std:: {
	io::{BufReader, BufWriter},
	os::unix::net::UnixStream,
	time::SystemTime
};
//use Block::rand_block_vec;

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
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
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