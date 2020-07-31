# public-verifiablity-covert

This is a Rust-library that implements secure two-party computation with covert security described in [PVC](https://eprint.iacr.org/2018/1108.pdf). Our protocol implementation is built using the Swanky suite of libraries that implement Multiparty computation building blocks in rust [swanky](https://github.com/GaloisInc/swanky). 
The notion of covert security lies somewhere between semi-honest and malicious-secure and guarantees that cheating behavior is caught with some reasonable probability like 1/2. This probability is determined by the 'lambda' parameter chosen before running the protocol. 
In order to achieve secure two-party computation with covert security, we used the following building blocks 


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

## Tests: 
We have the following test functions 
...

- Running our test functions
```bash
    cargo test
```

Consider the example below to run your own test for the PVC functionality. Add the circuit description in the format to the circuits folders.

```
    pvc(x : [], y .. , lambda) -> (output type){
        spawn two threads {sender}{receiver}

    }
```

## Contacts
Gayathri Garimella <garimelg@oregonstate.edu>
Jaspal Singh Saini <jaspal.singh@iitrpr.ac.in>