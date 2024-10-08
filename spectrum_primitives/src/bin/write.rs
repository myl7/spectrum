use std::env;
use std::time::Instant;

use prop::strategy::ValueTree;
use prop::test_runner::TestRunner;
use proptest::prelude::*;
use rayon::prelude::*;

use spectrum_primitives::{
    constructions::AesPrg,
    dpf::Dpf,
    vdpf::{two_key_pub::*, Vdpf},
    TwoKeyDpf,
};

#[test]
fn check_bounds() {
    fn check<V: Vdpf>() {}
    check::<Construction<TwoKeyDpf<AesPrg>>>();
}

fn vdpf_with_keys_data() -> impl Strategy<
    Value = (
        Construction<TwoKeyDpf<AesPrg>>,
        Vec<<Construction<TwoKeyDpf<AesPrg>> as Vdpf>::AuthKey>,
        <Construction<TwoKeyDpf<AesPrg>> as Dpf>::Message,
    ),
> {
    any::<Construction<TwoKeyDpf<AesPrg>>>().prop_flat_map(|vdpf| {
        (
            Just(vdpf.clone()),
            Just(vdpf.new_access_keys()),
            <Construction<TwoKeyDpf<AesPrg>> as Dpf>::Message::arbitrary_with(
                vdpf.msg_size().into(),
            ),
        )
    })
}

fn main() {
    let (vdpf, auth_keys, data) = vdpf_with_keys_data()
        .new_tree(&mut TestRunner::deterministic())
        .unwrap()
        .current();
    // let point_idx = idx.index(vdpf.points());
    let point_idx = 100;
    let dpf_keys = vdpf.gen(data, point_idx);
    let dpf_key = &dpf_keys[0];
    let proof_shares = vdpf.gen_proofs(&auth_keys[point_idx], point_idx, &dpf_keys);
    let proof_share = proof_shares[0].clone();
    let old = vec![vdpf.null_message(); vdpf.points()];

    let mb: u32 = env::var("MB").unwrap().parse().unwrap();
    let m = 2usize.pow(mb);
    let thread_num: usize = env::var("THREAD_NUM")
        .unwrap_or("8".to_string())
        .parse()
        .unwrap();

    let write_start = Instant::now();

    let audit_start = Instant::now();
    for _ in 0..m {
        (0..thread_num).into_par_iter().for_each(|_| {
            let audit_token = vdpf.gen_audit(&auth_keys, dpf_key, proof_share);
            vdpf.check_audit(vec![audit_token.clone(), audit_token]);
        });
    }
    println!("audit: {:?}", audit_start.elapsed());

    let dpf_eval_start = Instant::now();
    let mut msgs_list = vec![];
    for _ in 0..m {
        msgs_list = (0..thread_num)
            .into_par_iter()
            .map(|_| vdpf.eval(dpf_key.clone()))
            .collect();
    }
    println!("dpf eval: {:?}", dpf_eval_start.elapsed());

    let mut output = vec![];
    for _ in 0..m {
        let mut msgs_list_clone = msgs_list.clone();
        msgs_list_clone.push(old.clone());
        output = vdpf.combine(msgs_list_clone);
    }

    println!("write: {:?}", write_start.elapsed());
    assert_eq!(output.len(), vdpf.points());
}
