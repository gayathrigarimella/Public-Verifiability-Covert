// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.
use fancy_garbling::{
    util::{tweak, tweak2},
};
use fancy_garbling::{errors::TwopacError, Evaluator as Ev, Fancy, FancyInput, FancyReveal, Wire,HasModulus};
pub use fancy_garbling::twopac::semihonest::PartyId;
use ocelot::ot::Receiver as OtReceiver;
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest};
use sha2::{Digest,Sha256};
use fancy_garbling::errors::EvaluatorError;

/// Semi-honest evaluator.
pub struct Evaluator<C, RNG, OT> {
    evaluator: Ev<C>,
    pub ot: OT,
    rng: RNG,
    pub gc_hash: Sha256,
    pub output_colors : Vec<u16>,
    pub output_vec: Vec<u16>,
    current_gate: usize,
}

impl<C, RNG, OT> Evaluator<C, RNG, OT> {}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block> + SemiHonest>
    Evaluator<C, RNG, OT>
{
    /// Make a new `Evaluator`.
    pub fn new(mut channel: C, mut rng: RNG) -> Result<Self, TwopacError> {
        let ot = OT::init(&mut channel, &mut rng)?;
        let evaluator = Ev::new(channel);
        let output_colors: Vec<u16> = Vec::new();
        let output_vec: Vec<u16> = Vec::new();
        let gc_hash = Sha256::new();
        Ok(Self {
            evaluator,
            ot,
            rng,
            gc_hash,
            output_colors,
            output_vec,
            current_gate : 0
        })
    }

    fn run_ot(&mut self, inputs: &[bool]) -> Result<Vec<Block>, TwopacError> {
        self.ot
            .receive(self.evaluator.get_channel(), &inputs, &mut self.rng)
            .map_err(TwopacError::from)
    }
}

impl<C: AbstractChannel, RNG, OT> Evaluator<C, RNG, OT> {
    /// Get a reference to the internal channel.
    pub fn get_channel(&mut self) -> &mut C {
        self.evaluator.get_channel()
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block> + SemiHonest> FancyInput
    for Evaluator<C, RNG, OT>
{
    type Item = Wire;
    type Error = TwopacError;
    type PartyId = PartyId;

    /// Receive a garbler input wire.
    fn receive(&mut self, from: PartyId, modulus: u16) -> Result<Wire, TwopacError> {
        assert!(from == PartyId::Garbler);
        let w = self.evaluator.read_wire(modulus)?;
        Ok(w)
    }

    /// Receive garbler input wires.
    fn receive_many(&mut self, from: PartyId, moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        assert!(from == PartyId::Garbler);
        //moduli.iter().map(|q| {self.garbler_wires.append(*q); self.receive(*q)} ).collect()
        moduli.iter().map(|q| self.receive(from, *q)).collect()
    }

    /// Perform OT and obtain wires for the evaluator's inputs.
    fn encode_many(&mut self, inputs: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        let mut lens = Vec::new();
        let mut bs = Vec::new();
        for (x, q) in inputs.iter().zip(moduli.iter()) {
            let len = f32::from(*q).log(2.0).ceil() as usize;
            for b in (0..len).map(|i| x & (1 << i) != 0) {
                bs.push(b);
            }
            lens.push(len);
        }
        let wires = self.run_ot(&bs)?;
        let mut start = 0;
        Ok(lens
            .into_iter()
            .zip(moduli.iter())
            .map(|(len, q)| {
                let range = start..start + len;
                let chunk = &wires[range];
                start += len;
                combine(chunk, *q)
            })
            .collect::<Vec<Wire>>())
    }
}

fn combine(wires: &[Block], q: u16) -> Wire {
    wires.iter().enumerate().fold(Wire::zero(q), |acc, (i, w)| {
        let w = Wire::from_block(*w, q);
        acc.plus(&w.cmul(1 << i))
    })
}

impl<C: AbstractChannel, RNG, OT> Fancy for Evaluator<C, RNG, OT> {
    type Item = Wire;
    type Error = EvaluatorError;

    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error> {
         let wire: Wire = self.evaluator.read_wire(q).unwrap();
         self.gc_hash.update(&wire.as_block().as_ref());
         Ok(wire)
         //self.evaluator.read_wire(q)
    }

    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.add(&x, &y).map_err(Self::Error::from)
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.sub(&x, &y).map_err(Self::Error::from)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.cmul(&x, c).map_err(Self::Error::from)
    }

    fn mul(&mut self, A: &Wire, B: &Wire) -> Result<Self::Item, Self::Error> {
        if A.modulus() < B.modulus() {
            return self.mul(B, A);
        }
        let q = A.modulus();
        let qb = B.modulus();
        let unequal = q != qb;
        let ngates = q as usize + qb as usize - 2 + unequal as usize;
        let mut gate = Vec::with_capacity(ngates);
        {
            for _ in 0..ngates {
                let block = self.get_channel().read_block()?;
                self.gc_hash.update(block.as_ref());
                gate.push(block);
            }
        }
        let gate_num = self.current_gate;
        self.current_gate += 1;
        let g = tweak2(gate_num as u64, 0);

        // garbler's half gate
        let L = if A.color() == 0 {
            A.hashback(g, q)
        } else {
            let ct_left = gate[A.color() as usize - 1];
            Wire::from_block(ct_left ^ A.hash(g), q)
        };

        // evaluator's half gate
        let R = if B.color() == 0 {
            B.hashback(g, q)
        } else {
            let ct_right = gate[(q + B.color()) as usize - 2];
            Wire::from_block(ct_right ^ B.hash(g), q)
        };

        // hack for unequal mods
        let new_b_color = if unequal {
            let minitable = *gate.last().unwrap();
            let ct = u128::from(minitable) >> (B.color() * 16);
            let pt = u128::from(B.hash(tweak2(gate_num as u64, 1))) ^ ct;
            pt as u16
        } else {
            B.color()
        };

        let res = L.plus_mov(&R.plus_mov(&A.cmul(new_b_color)));
        Ok(res)
    }

    fn proj(&mut self, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Result<Self::Item, Self::Error> {
        let ngates = (x.modulus() - 1) as usize;
        let mut gate = Vec::with_capacity(ngates);
        for _ in 0..ngates {
            let block = self.get_channel().read_block()?;
            self.gc_hash.update(block.as_ref());
            gate.push(block);
        }
        let t = tweak(self.current_gate);
        self.current_gate += 1;
        if x.color() == 0 {
            Ok(x.hashback(t, q))
        } else {
            let ct = gate[x.color() as usize - 1];
            Ok(Wire::from_block(ct ^ x.hash(t), q))
        }
    }

    fn output(&mut self, x: &Wire) -> Result<Option<u16>, Self::Error> {
        let q = x.modulus();
        let c = self.get_channel().read_u16()?;
        self.output_colors.push(c);

        let output = ((q as u32 + x.color() as u32 - c as u32) % q as u32) as u16;
        self.output_vec.push(output);
        Ok(Some(output))
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT> FancyReveal for Evaluator<C, RNG, OT> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.evaluator.reveal(x).map_err(Self::Error::from)
    }
}

impl<C: AbstractChannel, RNG, OT> SemiHonest for Evaluator<C, RNG, OT> {}
