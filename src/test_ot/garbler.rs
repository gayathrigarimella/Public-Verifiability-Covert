// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use fancy_garbling::{errors::TwopacError, Fancy, FancyInput, FancyReveal, Wire, Garbler as Gb, HasModulus};
use ocelot::ot::Sender as OtSender;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest};
//use crate::garble::{Garbler as Gb};
use std::collections::HashMap;

 

/// Semi-honest garbler.
pub struct Garbler<C, RNG, OT> {
    garbler: Gb<C, RNG>,
    channel: C,
    ot: OT,
    rng: RNG,
    pub evaluator_wires : Vec<(Wire, Wire)>,
    pub garbler_wires : Vec<(Wire, Wire)>,
    deltas: HashMap<u16, Wire>
}


impl<C, OT, RNG> std::ops::Deref for Garbler<C, RNG, OT> {
    type Target = Gb<C, RNG>;
    fn deref(&self) -> &Self::Target {
        &self.garbler
    }
}

impl<C, OT, RNG> std::ops::DerefMut for Garbler<C, RNG, OT> {
    fn deref_mut(&mut self) -> &mut Gb<C, RNG> {
        &mut self.garbler
    }
}

impl<
        C: AbstractChannel,
        RNG: CryptoRng + Rng + SeedableRng<Seed = Block>,
        OT: OtSender<Msg = Block> + SemiHonest,
    > Garbler<C, RNG, OT>
{
    /// Make a new `Garbler`.
    pub fn new(mut channel: C, mut rng: RNG) -> Result<Self, TwopacError> {
        let ot = OT::init(&mut channel, &mut rng)?;
        let garbler = Gb::new(channel.clone(), RNG::from_seed(rng.gen()));
        let evaluator_wires: Vec<(Wire, Wire)> = Vec::new();
        let garbler_wires: Vec<(Wire, Wire)> = Vec::new();
        Ok(Garbler {
            garbler,
            channel,
            ot,
            rng,
            evaluator_wires,
            garbler_wires, 
            deltas: HashMap::new()
            
        })
    }

    /// Get a reference to the internal channel.
    pub fn get_channel(&mut self) -> &mut C {
        &mut self.channel
    }

    fn _evaluator_input(&mut self, delta: &Wire, q: u16) -> (Wire, Vec<(Block, Block)>) {
        let len = f32::from(q).log(2.0).ceil() as u16;
        let mut wire = Wire::zero(q);
        let inputs = (0..len)
            .map(|i| {
                let zero = Wire::rand(&mut self.rng, q);
                let one = zero.plus(&delta);
                let mut v = vec![(zero.clone(), one.clone())];
                self.evaluator_wires.append(&mut v);
                wire = wire.plus(&zero.cmul(1 << i));
                (zero.as_block(), one.as_block())
            })
            .collect::<Vec<(Block, Block)>>();
        (wire, inputs)
    }


    fn delta(&mut self, q: u16) -> Wire {
        if let Some(delta) = self.deltas.get(&q) {
            return delta.clone();
        }
        let w = Wire::rand_delta(&mut self.rng, q);
        self.deltas.insert(q, w.clone());
        w
    }

    fn encode_wire(&mut self, val: u16, modulus: u16) -> (Wire, Wire, Wire) {
        let zero = Wire::rand(&mut self.rng, modulus);
        let delta = self.delta(modulus);
        let one = zero.plus(&delta);
        let enc = zero.plus(&delta.cmul(val));
        (zero, enc, one)
    }

}

impl<
        C: AbstractChannel,
        RNG: CryptoRng + Rng + SeedableRng<Seed = Block>,
        OT: OtSender<Msg = Block> + SemiHonest,
    > FancyInput for Garbler<C, RNG, OT>
{
    type Item = Wire;
    type Error = TwopacError;

    fn encode(&mut self, val: u16, modulus: u16) -> Result<Wire, TwopacError> {
        let (mine, theirs) = self.garbler.encode_wire(val, modulus);
        self.garbler.send_wire(&theirs)?;
        self.channel.flush()?;
        Ok(mine)
    }

    fn encode_many(&mut self, vals: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        let ws = vals
            .iter()
            .zip(moduli.iter())
            .map(|(x, q)| {
                let (zero, theirs, one) = self.encode_wire(*x, *q);
                let mut v = vec![(zero.clone(), one.clone())];
                self.garbler_wires.append(&mut v);
                self.garbler.send_wire(&theirs)?;
                Ok(zero)
            })
            .collect();
        self.channel.flush()?;
        ws
    }

    fn receive_many(&mut self, qs: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        let n = qs.len();
        let lens = qs.iter().map(|q| f32::from(*q).log(2.0).ceil() as usize);
        let mut wires = Vec::with_capacity(n);
        let mut inputs = Vec::with_capacity(lens.sum());

        for q in qs.iter() {
            let delta = self.garbler.delta(*q);
            let (wire, input) = self._evaluator_input(&delta, *q);
            wires.push(wire);
            for i in input.into_iter() {
                inputs.push(i);
            }
        }
        self.ot.send(&mut self.channel, &inputs, &mut self.rng)?;
        Ok(wires)
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT> Fancy for Garbler<C, RNG, OT> {
    type Item = Wire;
    type Error = TwopacError;

    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.garbler.constant(x, q).map_err(Self::Error::from)
    }

    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.garbler.add(x, y).map_err(Self::Error::from)
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.garbler.sub(x, y).map_err(Self::Error::from)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Self::Item, Self::Error> {
        self.garbler.cmul(x, c).map_err(Self::Error::from)
    }

    fn mul(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.garbler.mul(x, y).map_err(Self::Error::from)
    }

    fn proj(&mut self, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Result<Self::Item, Self::Error> {
        self.garbler.proj(x, q, tt).map_err(Self::Error::from)
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, Self::Error> {
        self.garbler.output(x).map_err(Self::Error::from)
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT> FancyReveal for Garbler<C, RNG, OT> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.garbler.reveal(x).map_err(Self::Error::from)
    }
}

impl<C, RNG, OT> SemiHonest for Garbler<C, RNG, OT> {}
