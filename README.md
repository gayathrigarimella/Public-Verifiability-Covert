# Public-Verifiability-Covert

This is a Rust-library that implements secure two-party computation with covert security with public verifiability described in the paper [PVC](https://eprint.iacr.org/2018/1108.pdf). Our protocol implementation is built using the Swanky suite of libraries that implement Multiparty computation building blocks in rust [Swanky](https://github.com/GaloisInc/swanky). 
The notion of covert security lies somewhere between semi-honest and malicious-secure and guarantees that cheating behavior is caught with some reasonable probability like 1/2, 1/4. This probability is determined by the 'replicating/deterrence factor' that  parameterized by the protocol. In the event of malicious behavior, the protocol generates a certificate that is publicly verifiable, further deterring cheating. 
Briefly, this protocol uses the cut-and-choose paradigm such that the evaluator checks '(replicating factor - 1)' number of garbled circuits(GC) and evaluated one randomly chosen GC. To catch cheating behavior, the garbler generates each GC deterministically from a different uniformly random seed, and the evaluator learns '(replicating factor - 1)' of those seeds using a maliciously-secure Oblivious transfer protocol enabling the check. To ensure public verifiability, the garbler signs every message in the OT transcript. Additionally, the evaluator sends a commitment of all his random seeds to the garbler. 

## Code overview
This is a two party protocol with a designated garbler and evaluator. We use the malicious-secure Chou-Orlandi Oblivious instantiation from Swanky's OT library [Ocelot](https://github.com/GaloisInc/swanky/tree/master/ocelot) and the semi-honest two party secure computation using Garbled circuits from [2PC](https://github.com/GaloisInc/swanky/tree/master/fancy-garbling/src/twopac). We use the instantiation of commitment scheme in Swanky's [Scuttlebutt](https://github.com/GaloisInc/swanky/tree/master/scuttlebutt/src) library and ECDSA signatures implemented in crypto [PKS](https://docs.rs/rust-crypto/0.2.36/crypto/index.html) and an implementation of  [SHA2](https://docs.rs/sha2/0.9.1/sha2/) hash function.

### Function declaration for the 2 party PVC protocol:  
```bash
pvc(circuit_file: &'static str, 
party_a_input : Vec<u16>, party_b_input : Vec<u16>, 
rep_factor: usize) 
-> std::option::Option<Vec<u16>> {}
```
Input parameters: 
- Circuit_file - file name containing the circuit description. The file must follow the format given here: https://homes.esat.kuleuven.be/~nsmart/MPC/
- party_a_input - Input vector of the garbler
- Party_b_input - Input vector of the evaluator
- Rep_factor - The replicating factor of the PVC protocol. This factor is proportional to the deterrence factor - which determines the probability of catching any cheating. 

Output parameter:
The function outputs ‘None’ if cheating is detected. Else it returns the expected output of evaluating the input circuit on the input vectors. 

The function simulates the execution of the evaluator on the main thread and the garbler on a spawned thread. We establish communication channel between them using unix stream sockets. 

```bash
    let (mut receiver, mut sender) = unix_channel_pair();
```

### Public verifiability
Whenever cheating is detected, the PVC function call prints a publicly verifiable certificate of cheating. Certificate contains the following data items. 

``` bash 
struct certificate {
corrupted index (j): usize, 
OT transcript (trans_j) from step 2: Vec<u8>,
OT transcript hash (H_j) from step 3: Vec<u8>,
Commitment c_j from step 4: [u8; 32],
ECDSA signature \sigma_j from step 5: [u8,64],
seed^b_j : 128 bit Block,
Sha_seed_j : [u8;32],
}
```

Disclaimer: This is research code, please do not use it in production.

## Environment setup: 

### MacOS and Ubuntue
- Setup Rust programming language - [installation guide](https://doc.rust-lang.org/book/ch01-01-installation.html)

- Clone this repository
```bash
    git clone https://github.com/gayathrigarimella/public-verifiablity-covert.git
```

- Build and test
```bash
    cargo build
    cargo test
```

### Tests

-  We run our PVC protocol on AES functionality described by the [circuit](https://github.com/gayathrigarimella/Public-Verifiability-Covert/blob/master/circuits/AES-non-expanded.txt) on uniformly random inputs for the garbler and the evaluator. We have the following test in module lib.rs 
```bash
#[cfg(test)]
mod tests {
use super::*;
    #[test]
    fn test_aes() {
        let mut party_a_input = [0u16; 128];
        let mut party_b_input = [0u16; 128];
        let mut input_rng = thread_rng(); 
        input_rng.fill(&mut party_a_input);
        input_rng.fill(&mut party_b_input);
        pvc("circuits/AES-non-expanded.txt",party_a_input.to_vec(), party_b_input.to_vec(), 4);
    }
}

```

Looking ahead, we would like to re-organize our function into separate modules PVC garbler and PVC evaluator. This would allow us to make the communication channel as a parameter (of the function call) making it amenable to integrate this functionality into larger programs. Additionally, it would allow more rigorous testing of cheating behavior and verification of the certificate. 

## Contact
Gayathri Garimella <garimelg@oregonstate.edu>, 
Jaspal Singh Saini <singjasp@oregonstate.edu>
