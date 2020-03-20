//! Spectrum implementation.
#![allow(dead_code)]
use crate::crypto::byte_utils::xor_bytes;
use crate::crypto::prg::PRG;
use bytes::Bytes;
use rand::Rng;
use std::fmt::Debug;

/// Distributed Point Function
/// Must generate a set of keys k_1, k_2, ...
/// such that combine(eval(k_1), eval(k_2), ...) = e_i * msg
pub trait DPF {
    type Key;

    fn num_points(&self) -> usize;

    /// Generate `num_keys` DPF keys, the results of which differ only at the given index.
    // TODO(zjn): should be &Bytes
    fn gen(&self, msg: Bytes, idx: usize) -> Vec<Self::Key>;
    fn eval(&self, key: &Self::Key) -> Vec<Bytes>;
    fn combine(&self, parts: Vec<Vec<Bytes>>) -> Vec<Bytes>;
}

/// DPF based on PRG
#[derive(Clone, PartialEq, Debug)]
pub struct PRGBasedDPF<P> {
    prg: P,
    security_bytes: usize,
    num_keys: usize,
    num_points: usize,
}

// DPF key for PRGBasedDPF
#[derive(Clone, PartialEq, Debug)]
pub struct DPFKey<P>
where
    P: PRG,
    P::Seed: Clone + PartialEq + Eq + Debug,
{
    pub encoded_msg: Bytes,
    pub bits: Vec<u8>,
    pub seeds: Vec<<P as PRG>::Seed>,
}

impl<P> DPFKey<P>
where
    P: PRG,
    P::Seed: Clone + PartialEq + Eq + Debug,
{
    // generates a new DPF key with the necessary parameters needed for evaluation
    pub fn new(encoded_msg: Bytes, bits: Vec<u8>, seeds: Vec<P::Seed>) -> DPFKey<P> {
        DPFKey {
            encoded_msg,
            bits,
            seeds,
        }
    }
}

impl<P> PRGBasedDPF<P> {
    pub fn new(
        prg: P,
        security_bytes: usize,
        num_keys: usize,
        num_points: usize,
    ) -> PRGBasedDPF<P> {
        PRGBasedDPF {
            prg,
            security_bytes,
            num_keys,
            num_points,
        }
    }
}

impl<P> DPF for PRGBasedDPF<P>
where
    P: PRG,
    P::Seed: Clone + PartialEq + Eq + Debug,
{
    type Key = DPFKey<P>;

    fn num_points(&self) -> usize {
        self.num_points
    }

    /// generate new instance of PRG based DPF with two DPF keys
    fn gen(&self, msg: Bytes, idx: usize) -> Vec<DPFKey<P>> {
        assert_eq!(self.num_keys, 2, "DPF only implemented for s=2.");

        // make a new PRG going from security -> length of the Bytes
        let mut seeds_a = Vec::new();
        let mut seeds_b = Vec::new();
        let mut bits_a: Vec<u8> = Vec::new();
        let mut bits_b: Vec<u8> = Vec::new();

        // generate the values distributed to servers A and B
        for j in 0..self.num_points {
            let seed = self.prg.new_seed();
            let bit = rand::thread_rng().gen_range(0, 2);

            seeds_a.push(seed.clone());
            bits_a.push(bit);

            if j == idx {
                let seed_prime = self.prg.new_seed();
                seeds_b.push(seed_prime);
                bits_b.push(1 - bit);
            } else {
                seeds_b.push(seed.clone());
                bits_b.push(bit);
            }
        }

        // compute G(seed_a) XOR G(seed_b) for the ith seed
        let xor_eval = xor_bytes(
            &self.prg.eval(&seeds_a[idx], msg.len()),
            &self.prg.eval(&seeds_b[idx], msg.len()),
        );

        // compute m XOR G(seed_a) XOR G(seed_b)
        let encoded_msg = xor_bytes(&msg, &xor_eval);

        vec![
            DPFKey::<P>::new(encoded_msg.clone(), bits_a, seeds_a),
            DPFKey::<P>::new(encoded_msg, bits_b, seeds_b),
        ]
    }

    /// evaluates the DPF on a given DPFKey and outputs the resulting data
    fn eval(&self, key: &DPFKey<P>) -> Vec<Bytes> {
        key.seeds
            .iter()
            .zip(key.bits.iter())
            .map(|(seed, &bits)| {
                let prg_eval_i = self.prg.eval(seed, key.encoded_msg.len());

                if bits == 1 {
                    xor_bytes(&key.encoded_msg.clone(), &prg_eval_i)
                } else {
                    prg_eval_i
                }
            })
            .collect()
    }

    /// combines the results produced by running eval on both keys
    fn combine(&self, parts: Vec<Vec<Bytes>>) -> Vec<Bytes> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::prg::AESPRG;
    use proptest::prelude::*;

    const DATA_SIZE: usize = 1 << 10;
    const MAX_NUM_POINTS: usize = 20;
    const SECURITY_BYTES: usize = 16;

    fn aes_prg_dpfs() -> impl Strategy<Value = PRGBasedDPF<AESPRG>> {
        let prg = AESPRG::new();
        let num_keys = 2; // PRG DPF implementation handles only 2 keys.
        (1..MAX_NUM_POINTS)
            .prop_map(move |num_points| PRGBasedDPF::new(prg, SECURITY_BYTES, num_keys, num_points))
    }

    fn num_points_and_index() -> impl Strategy<Value = (usize, usize)> {
        (1..MAX_NUM_POINTS).prop_flat_map(|num_points| (Just(num_points), 0..num_points))
    }

    fn data() -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), DATA_SIZE).prop_map(Bytes::from)
    }

    fn run_test_dpf<D>(dpf: D, data: Bytes, index: usize)
    where
        D: DPF,
    {
        let dpf_keys = dpf.gen(data.clone(), index);
        let dpf_shares = dpf_keys.iter().map(|k| dpf.eval(k)).collect();
        let dpf_output = dpf.combine(dpf_shares);

        let zeroes = Bytes::from(vec![0 as u8; DATA_SIZE]);
        for (chunk_idx, chunk) in dpf_output.into_iter().enumerate() {
            if chunk_idx == index {
                assert_eq!(chunk, data);
            } else {
                assert_eq!(chunk, zeroes);
            }
        }
    }

    proptest! {
        #[test]
        fn test_prg_dpf(
            dpf in aes_prg_dpfs(),
            index in any::<proptest::sample::Index>(),
            data in data()
        ) {
            let index = index.index(dpf.num_points());
            run_test_dpf(dpf, data, index);
        }
    }
}
