// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Chou-Orlandi oblivious transfer protocol (cf.
//! <https://eprint.iacr.org/2015/267>).
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library and works over blocks rather than arbitrary
//! length messages.
//!
//! This version fixes a bug in the current ePrint write-up
//! (<https://eprint.iacr.org/2015/267/20180529:135402>, Page 4): if the value
//! `x^i` produced by the receiver is not randomized, all the random-OTs
//! produced by the protocol will be the same. We fix this by hashing in `i`
//! during the key derivation phase.

use ocelot::ot::{Receiver as OtReceiver, Sender as OtSender};
use ocelot::Error;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, Malicious, SemiHonest};
use sha2::{Digest,Sha256};
/// Oblivious transfer sender.
pub struct Sender {
    y: Scalar,
    s: RistrettoPoint,
    pub transcript: Vec<u8>,
    pub trans_hash: Vec<u8>
}

impl Sender {

    fn update_transcript(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let message_hash = hasher.finalize();
        self.trans_hash.extend_from_slice(&message_hash);
    }
}


impl OtSender for Sender {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let y = Scalar::random(&mut rng);
        let s = &y * &RISTRETTO_BASEPOINT_TABLE;
        channel.write_pt(&s)?;
        let mut transcript: Vec<u8> = Vec::new();
        let compressed_point = s.compress();
        let message: &[u8] = compressed_point.as_bytes();
        transcript.extend_from_slice(&message);
        let mut trans_hash: Vec<u8> = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        trans_hash.extend_from_slice(&message_hash);
        channel.flush()?;
        Ok(Self { y, s, transcript, trans_hash})
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let ys = self.y * self.s;
        let ks = (0..inputs.len())
            .map(|i| {
                let r = channel.read_pt()?;
                let compressed_point = r.compress();
                let message: &[u8] = compressed_point.as_bytes();
                self.update_transcript(message);
                let yr = self.y * r;
                let k0 = Block::hash_pt(i, &yr);
                let k1 = Block::hash_pt(i, &(yr - ys));
                Ok((k0, k1))
            })
            .collect::<Result<Vec<(Block, Block)>, Error>>()?;
        for (input, k) in inputs.iter().zip(ks.into_iter()) {
            let c0 = k.0 ^ input.0;
            let c1 = k.1 ^ input.1;
            channel.write_block(&c0)?;
            self.update_transcript(c0.as_ref());
            channel.write_block(&c1)?;
            self.update_transcript(c1.as_ref());
            self.transcript.extend_from_slice(c1.as_ref());
        }
        channel.flush()?;
        Ok(())
    }
}


impl std::fmt::Display for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Chou-Orlandi Sender")
    }
}

/// Oblivious transfer receiver.
pub struct Receiver {
    s: RistrettoBasepointTable,
    pub transcript: Vec<u8>,
    pub trans_hash: Vec<u8>
}


impl Receiver {

    fn update_transcript_recv(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let message_hash = hasher.finalize();
        self.trans_hash.extend_from_slice(&message_hash);
    }
}


impl OtReceiver for Receiver {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        let mut transcript: Vec<u8> = Vec::new();
        let mut trans_hash: Vec<u8> = Vec::new();
        let s = channel.read_pt()?;
        let mut transcript: Vec<u8> = Vec::new();
        let compressed_point = s.compress();
        let message: &[u8] = compressed_point.as_bytes();
        transcript.extend_from_slice(&message);
        let mut trans_hash: Vec<u8> = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        trans_hash.extend_from_slice(&message_hash);
        let s = RistrettoBasepointTable::create(&s);
        Ok(Self { s, trans_hash, transcript })
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        mut rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let zero = &Scalar::zero() * &self.s;
        let one = &Scalar::one() * &self.s;
        let ks = inputs
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let x = Scalar::random(&mut rng);
                let c = if *b { one } else { zero };
                let r = c + &x * &RISTRETTO_BASEPOINT_TABLE;
                channel.write_pt(&r)?;
                let compressed_point = r.compress();
                let message: &[u8] = compressed_point.as_bytes();
                self.update_transcript_recv(message);
                Ok(Block::hash_pt(i, &(&x * &self.s)))
            })
            .collect::<Result<Vec<Block>, Error>>()?;
        channel.flush()?;
        inputs
            .iter()
            .zip(ks.into_iter())
            .map(|(b, k)| {
                let c0 = channel.read_block()?;
                self.update_transcript_recv(c0.as_ref());
                let c1 = channel.read_block()?;
                self.update_transcript_recv(c1.as_ref());
                let c = k ^ if *b { c1 } else { c0 };
                Ok(c)
            })
            .collect()
    }
}

impl std::fmt::Display for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Chou-Orlandi Receiver")
    }
}

impl Receiver {

    fn update_transcript(&mut self, message: &mut [u8]) {
        self.transcript.extend_from_slice(&message);
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let message_hash = hasher.finalize();
        self.trans_hash.extend_from_slice(&message_hash);
    }
}

impl SemiHonest for Sender {}
impl Malicious for Sender {}
impl SemiHonest for Receiver {}
impl Malicious for Receiver {}
