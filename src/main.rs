
mod twopac;
mod test_aes;
mod commit;

fn main() {
	//test_aes::test_aes();
    //let mut circ = twopac::circuit("circuits/AES-non-expanded.txt");
    //twopac::run_circuit(&mut circ, vec![0; 128], vec![0; 128]);
    //let mut circ = twopac::circuit("circuits/sha-1.txt");
    //twopac::run_circuit(&mut circ, vec![0; 512], vec![]);
    //let mut circ = twopac::circuit("circuits/sha-256.txt");
    //twopac::run_circuit(&mut circ, vec![0; 512], vec![]);
    commit::test_commit();
    commit::test_sending_commit();
}