//! Spectrum implementation.
extern crate rand;
use crate::crypto::prg::{PRGSeed, PRG};
use bytes::Bytes;
use rand::Rng;
use std::fmt::Debug;
use std::rc::Rc;

/// Distributed Point Function
/// Must generate a set of keys k_1, k_2, ...
/// such that combine(eval(k_1), eval(k_2), ...) = e_i * msg
trait DPF {
    fn new(security_bytes: usize, num_keys: usize, num_points: usize) -> Self;
    fn gen(&self, msg: Bytes, i: usize) -> Vec<DPFKey>;
    fn eval(key: &DPFKey) -> Vec<Bytes>;
    fn combine(parts: Vec<Vec<Bytes>>) -> Vec<Bytes>;
}

/// DPF based on PRG
struct PRGBasedDPF {
    security_bytes: usize,
    num_keys: usize,
    num_points: usize,
}

impl DPF for PRGBasedDPF {
    fn new(security_bytes: usize, num_keys: usize, num_points: usize) -> PRGBasedDPF {
        PRGBasedDPF {
            security_bytes,
            num_keys,
            num_points,
        }
    }

    /// generate new instance of PRG based DPF with two DPF keys
    fn gen(&self, msg: Bytes, i: usize) -> Vec<DPFKey> {
        if self.num_keys != 2 {
            panic!("not implemented!")
        }

        let eval_size = msg.len();

        // make a new PRG going from security -> length of the Bytes
        let prg = Rc::<PRG>::new(PRG::new(self.security_bytes, eval_size));

        let mut seeds_a: Vec<PRGSeed> = Vec::new();
        let mut seeds_b: Vec<PRGSeed> = Vec::new();
        let mut bits_a: Vec<u8> = Vec::new();
        let mut bits_b: Vec<u8> = Vec::new();

        // generate the values distributed to servers A and B
        for j in 0..self.num_points {
            let seed = prg.new_seed();
            let bit = rand::thread_rng().gen_range(0, 2);

            seeds_a.push(seed.clone());
            bits_a.push(bit);

            if j == i {
                let seed_prime = prg.new_seed();
                seeds_b.push(seed_prime);
                bits_b.push(1 - bit);
            } else {
                seeds_b.push(seed.clone());
                bits_b.push(bit);
            }
        }

        let prg_eval_a = prg.eval(&seeds_a[i]);
        let prg_eval_b = prg.eval(&seeds_b[i]);

        // compute G(seed_a) XOR G(seed_b) for the ith seed
        let xor_eval = xor_bytes(&prg_eval_a, &prg_eval_b);

        // compute m XOR G(seed_a) XOR G(seed_b)
        let encoded_msg = xor_bytes(&msg, &xor_eval);

        let mut key_tuple = Vec::<DPFKey>::new();
        key_tuple.push(DPFKey::new(
            prg.clone(),
            encoded_msg.clone(),
            bits_a,
            seeds_a,
        ));
        key_tuple.push(DPFKey::new(prg, encoded_msg, bits_b, seeds_b));

        key_tuple
    }

    /// evaluates the DPF on a given DPFKey and outputs the resulting data
    fn eval(key: &DPFKey) -> Vec<Bytes> {
        // total number of slots
        let n = key.bits.len();

        // vector of slot Bytess
        let mut res: Vec<Bytes> = Vec::<Bytes>::new();

        for i in 0..n {
            let prg_eval_i = key.prg.eval(&key.seeds[i]);

            if key.bits[i] == 1 {
                let slot = xor_bytes(&key.encoded_msg.clone(), &prg_eval_i);
                res.push(slot);
            } else {
                res.push(prg_eval_i);
            }
        }

        res
    }

    /// combines the results produced by running eval on both keys
    fn combine(parts: Vec<Vec<Bytes>>) -> Vec<Bytes> {
        // xor all the parts together
        let mut res = parts[0].clone();
        for part in parts.iter().skip(1) {
            for j in 0..res.len() {
                res[j] = xor_bytes(&res[j], &part[j]);
            }
        }

        res
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct DPFKey {
    prg: Rc<PRG>,
    encoded_msg: Bytes,
    bits: Vec<u8>,
    seeds: Vec<PRGSeed>,
}

impl DPFKey {
    // generates a new DPF key with the necessary parameters needed for evaluation
    pub fn new(prg: Rc<PRG>, encoded_msg: Bytes, bits: Vec<u8>, seeds: Vec<PRGSeed>) -> DPFKey {
        DPFKey {
            prg,
            encoded_msg,
            bits,
            seeds,
        }
    }
}

/// xor bytes in place, a = a ^ b
// TODO: (Performance) xor inplace rather than copying
fn xor_bytes(a: &Bytes, b: &Bytes) -> Bytes {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(&a, &b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const DATA_SIZE: usize = (1 << 10);
    const MAX_NUM_POINTS: usize = 20;
    const SECURITY_BYTES: usize = 16;

    fn num_keys() -> impl Strategy<Value = usize> {
        Just(2)
    }

    fn num_points_and_index() -> impl Strategy<Value = (usize, usize)> {
        (1..MAX_NUM_POINTS).prop_flat_map(|num_points| (Just(num_points), 0..num_points))
    }

    fn data() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), DATA_SIZE)
    }

    proptest! {
        #[test]
        fn test_prg_dpf(
            (num_points, index) in num_points_and_index(),
            num_keys in num_keys(),
            data in data()
        ) {
            let dpf = PRGBasedDPF::new(SECURITY_BYTES, num_keys, num_points);
            let keys = dpf.gen(Bytes::from(data.clone()), index);
            let outputs = keys.iter().map(PRGBasedDPF::eval).collect();
            let actual = PRGBasedDPF::combine(outputs);

            let zeroes = vec![0 as u8; DATA_SIZE];
            let mut expected = vec![zeroes; num_points - 1];
            expected.insert(index, data);
            assert_eq!(actual, expected);
        }
    }
}
