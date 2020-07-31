# public-verifiablity-covert

This is a Rust-library that implements secure two-party computation with covert security with public verifiability described in [PVC](https://eprint.iacr.org/2018/1108.pdf). Our protocol implementation is built using the Swanky suite of libraries that implement Multiparty computation building blocks in rust [Swanky](https://github.com/GaloisInc/swanky). 
The notion of covert security lies somewhere between semi-honest and malicious-secure and guarantees that cheating behavior is caught with some reasonable probability like 1/2, 1/4. This probability is determined by the 'replicating/deterrence factor' that  parameterized by the protocol. In the event of malicious behavior, the protocol generates a certificate that is publicly verifiable, further deterring cheating. 
Briefly, this protocol uses the cut-and-choose paradigm such that the evaluator checks 'replicating factor - 1' number of garbled circuits(GC) and evaluated one randomly chosen GC. To catch cheating behavior, the garbler generates each GC deterministically from a different uniformly random seed, and the evaluator learns 'replicating factor - 1' of those seeds using a maliciously-secure Oblivious transfer protocol enabling the check. To ensure public verifiability, the garbler signs every message in the OT transcript. Additionally, the evaluator sends a commitment of all his random seeds to the garbler. 

## Code overview
This is a two party protocol with a designated garbler and evaluator. We use the malicious-secure Chou-Orlandi Oblivious instantiation from Swanky's OT library [Ocelot]() and the semi-honest two party secure computation using Garbled circuits from [2PC](). We use the instantiation of commitment scheme in Swanky's [Scuttlebutt]() library. 


Disclaimer: This is research code, please do not use it in production.

## Environment setup: 
### MacOS
- Setup Rust programming language - [installation guide](https://doc.rust-lang.org/book/ch01-01-installation.html)

- Clone this repository
```bash
    git clone https://github.com/gayathrigarimella/public-verifiablity-covert.git
```

- Build the project 
```bash
    cargo build
```

### Ubuntu 
TODO

## Tests: 
We have the following test functions TODO (one test that passes, one that has cheating and the certificate is printed at least)

- Running our test functions
```bash
    cargo test
```

Consider the example below to run your own test for the PVC functionality. Add the circuit description (in the format ..) to the circuits folders. Choose the replicating factor and inputs from both parties ..

```
    pvc(x : [], y .. , lambda) -> (output type){
        spawn two threads {sender}
        {receiver}

    }
```

##

## Contact
Gayathri Garimella <garimelg@oregonstate.edu>
Jaspal Singh Saini <jaspal.singh@iitrpr.ac.in>