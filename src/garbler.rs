// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use fancy_garbling::{errors::TwopacError,errors::GarblerError, Fancy, FancyInput, FancyReveal, Wire, Garbler as Gb, HasModulus};
use ocelot::ot::Sender as OtSender;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest};
//use crate::garble::{Garbler as Gb};
use std::collections::HashMap;
use sha2::{Digest,Sha256};
//use scuttlebutt::{output_tweak, tweak, tweak2, GarblerError};
use fancy_garbling::{
    util::{output_tweak, tweak, tweak2, RngExt},
};

/// Semi-honest garbler.
pub struct Garbler<C, RNG, OT> {
    garbler: Gb<C, RNG>,
    channel: C,
    ot: OT,
    rng: RNG,
    pub evaluator_wires : Vec<(Wire, Wire)>,
    pub garbler_wires : Vec<(Wire, Wire)>,
    current_gate: usize,
    current_output: usize,
    pub gc_hash: Sha256,
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
        let gc_hash = Sha256::new();
        Ok(Garbler {
            garbler,
            channel,
            ot,
            rng,
            evaluator_wires,
            garbler_wires, 
            gc_hash,
            deltas: HashMap::new(),
            current_gate:0,
            current_output: 0
            
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

    /// The current non-free gate index of the garbling computation
    fn current_gate1(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    fn delta(&mut self, q: u16) -> Wire {
        if let Some(delta) = self.deltas.get(&q) {
            return delta.clone();
        }
        let w = Wire::rand_delta(&mut self.rng, q);
        self.deltas.insert(q, w.clone());
        w
    }
/*
    /// The current output index of the garbling computation.
    fn current_output1(&mut self) -> usize {
        let current = self.current_output1;
        self.current_output1 += 1;
        current
    }
*/
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
    type Error = GarblerError;

    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error> {
        let zero = Wire::rand(&mut self.rng, q);
        let wire = zero.plus(&self.delta(q).cmul_eq(x));
        self.gc_hash.update(&wire.as_block().as_ref());
        self.send_wire(&wire)?;
        Ok(zero)
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

    fn mul(&mut self, A: &Wire, B: &Wire) -> Result<Self::Item, Self::Error> {
        if A.modulus() < B.modulus() {
            return self.mul(B, A);
        }

        let q = A.modulus();
        let qb = B.modulus();
        let current = self.current_gate;
        self.current_gate += 1;
        let gate_num = current;

        let D = self.delta(q);
        let Db = self.delta(qb);

        let r;
        let mut gate = vec![Block::default(); q as usize + qb as usize - 2];

        // hack for unequal moduli
        if q != qb {
            // would need to pack minitable into more than one u128 to support qb > 8
            if qb > 8 {
                return Err(GarblerError::AsymmetricHalfGateModuliMax8(qb));
            }

            r = self.rng.gen_u16() % q;
            let t = tweak2(gate_num as u64, 1);

            let mut minitable = vec![u128::default(); qb as usize];
            let mut B_ = B.clone();
            for b in 0..qb {
                if b > 0 {
                    B_.plus_eq(&Db);
                }
                let new_color = ((r + b) % q) as u128;
                let ct = (u128::from(B_.hash(t)) & 0xFFFF) ^ new_color;
                minitable[B_.color() as usize] = ct;
            }

            let mut packed = 0;
            for i in 0..qb as usize {
                packed += minitable[i] << (16 * i);
            }
            gate.push(Block::from(packed));
        } else {
            r = B.color(); // secret value known only to the garbler (ev knows r+b)
        }

        let g = tweak2(gate_num as u64, 0);

        // X = H(A+aD) + arD such that a + A.color == 0
        let alpha = (q - A.color()) % q; // alpha = -A.color
        let X = A
            .plus(&D.cmul(alpha))
            .hashback(g, q)
            .plus_mov(&D.cmul(alpha * r % q));

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (qb - B.color()) % qb;
        let Y = B
            .plus(&Db.cmul(beta))
            .hashback(g, q)
            .plus_mov(&A.cmul((beta + r) % q));

        let mut precomp = Vec::with_capacity(q as usize);

        // precompute a lookup table of X.minus(&D_cmul[(a * r % q)])
        //                            = X.plus(&D_cmul[((q - (a * r % q)) % q)])
        let mut X_ = X.clone();
        precomp.push(X_.as_block());
        for _ in 1..q {
            X_.plus_eq(&D);
            precomp.push(X_.as_block());
        }

        let mut A_ = A.clone();
        for a in 0..q {
            if a > 0 {
                A_.plus_eq(&D);
            }
            // garbler's half-gate: outputs X-arD
            // G = H(A+aD) ^ X+a(-r)D = H(A+aD) ^ X-arD
            if A_.color() != 0 {
                gate[A_.color() as usize - 1] =
                    A_.hash(g) ^ precomp[((q - (a * r % q)) % q) as usize];
            }
        }

        precomp.clear();

        // precompute a lookup table of Y.minus(&A_cmul[((b+r) % q)])
        //                            = Y.plus(&A_cmul[((q - ((b+r) % q)) % q)])
        let mut Y_ = Y.clone();
        precomp.push(Y_.as_block());
        for _ in 1..q {
            Y_.plus_eq(&A);
            precomp.push(Y_.as_block());
        }

        let mut B_ = B.clone();
        for b in 0..qb {
            if b > 0 {
                B_.plus_eq(&Db);
            }
            // evaluator's half-gate: outputs Y-(b+r)D
            // G = H(B+bD) + Y-(b+r)A
            if B_.color() != 0 {
                gate[q as usize - 1 + B_.color() as usize - 1] =
                    B_.hash(g) ^ precomp[((q - ((b + r) % q)) % q) as usize];
            }
        }

        for block in gate.iter() {
            self.channel.write_block(block)?;
            self.gc_hash.update(block.as_ref());
        }
        Ok(X.plus_mov(&Y))
    }

    fn proj(&mut self, A: &Wire, q_out: u16, tt: Option<Vec<u16>>) -> Result<Self::Item, Self::Error> {
        let tt = tt.ok_or(GarblerError::TruthTableRequired)?;

        let q_in = A.modulus();
        let mut gate = vec![Block::default(); q_in as usize - 1];

        let tao = A.color();
        let current = self.current_gate;
        self.current_gate += 1;
        let g = tweak(current);

        let Din = self.delta(q_in);
        let Dout = self.delta(q_out);

        // output zero-wire
        // W_g^0 <- -H(g, W_{a_1}^0 - \tao\Delta_m) - \phi(-\tao)\Delta_n
        let C = A
            .plus(&Din.cmul((q_in - tao) % q_in))
            .hashback(g, q_out)
            .plus_mov(&Dout.cmul((q_out - tt[((q_in - tao) % q_in) as usize]) % q_out));

        // precompute `let C_ = C.plus(&Dout.cmul(tt[x as usize]))`
        let C_precomputed = {
            let mut C_ = C.clone();
            (0..q_out)
                .map(|x| {
                    if x > 0 {
                        C_.plus_eq(&Dout);
                    }
                    C_.as_block()
                })
                .collect::<Vec<Block>>()
        };

        let mut A_ = A.clone();
        for x in 0..q_in {
            if x > 0 {
                A_.plus_eq(&Din); // avoiding expensive cmul for `A_ = A.plus(&Din.cmul(x))`
            }

            let ix = (tao as usize + x as usize) % q_in as usize;
            if ix == 0 {
                continue;
            }

            let ct = A_.hash(g) ^ C_precomputed[tt[x as usize] as usize];
            gate[ix - 1] = ct;
        }

        for block in gate.iter() {
            self.channel.write_block(block)?;
            self.gc_hash.update(block.as_ref());
        }
        Ok(C)
    }

    fn output(&mut self, X: &Self::Item) -> Result<Option<u16>, Self::Error> {
        let q = X.modulus();
        let current = self.current_output;
        self.current_output += 1;
        let i = current;
        let D = self.delta(q);
        for k in 0..q {
            let block = X.plus(&D.cmul(k)).hash(output_tweak(i, k));
            self.channel.write_block(&block)?;
            self.gc_hash.update(block.as_ref());
        }
        Ok(None)
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT> FancyReveal for Garbler<C, RNG, OT> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.garbler.reveal(x).map_err(Self::Error::from)
    }
}

impl<C, RNG, OT> SemiHonest for Garbler<C, RNG, OT> {}
