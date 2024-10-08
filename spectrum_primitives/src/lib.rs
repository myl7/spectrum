#![feature(type_ascription)]
#![allow(dead_code)] // for now
#[macro_use]
mod algebra;
#[macro_use]
mod util;
#[macro_use]
mod sharing;
#[macro_use]
mod prg;
#[macro_use]
mod bytes;
#[macro_use]
pub mod dpf;
#[macro_use]
pub mod vdpf;
#[macro_use]
pub mod pir;

pub mod constructions;

pub use algebra::Group;
pub use bytes::Bytes;
pub use dpf::Dpf;
pub use prg::Prg;
pub use vdpf::Vdpf;

pub use constructions::MultiKeyVdpf;
pub use constructions::TwoKeyVdpf;

// These are kind-of leaking. Better to do away with entirely.
pub use constructions::AuthKey;
pub use dpf::multi_key::Key as MultiKeyKey;
pub use dpf::two_key::Key as TwoKeyKey;
pub use dpf::TwoKeyDpf;
pub use prg::ElementVector;
pub use util::Sampleable;
pub use vdpf::multi_key::ProofShare as MultiKeyProof;
pub use vdpf::multi_key::Token as MultiKeyToken;
pub use vdpf::two_key::ProofShare as TwoKeyProof;
pub use vdpf::two_key::Token as TwoKeyToken;
pub use vdpf::two_key_pub::Construction as TwoKeyPubConstruction;
pub use vdpf::two_key_pub::KeyPair as TwoKeyPubAuthKey;
pub use vdpf::two_key_pub::ProofShare as TwoKeyPubProof;
pub use vdpf::two_key_pub::Token as TwoKeyPubToken;

use constructions::AesPrg;
use prg::GroupPrg;

impl TwoKeyVdpf {
    pub fn with_channels_msg_size(channels: usize, msg_size: usize) -> Self {
        TwoKeyVdpf::new(dpf::TwoKeyDpf::new(AesPrg::new(msg_size), channels))
    }
}

pub type TwoKeyPubVdpf = TwoKeyPubConstruction<TwoKeyDpf<AesPrg>>;

impl TwoKeyPubVdpf {
    pub fn with_channels_msg_size(channels: usize, msg_size: usize) -> Self {
        TwoKeyPubVdpf::new(dpf::TwoKeyDpf::new(AesPrg::new(msg_size), channels))
    }
}

impl MultiKeyVdpf {
    pub fn with_channels_parties_msg_size(channels: usize, groups: usize, msg_size: usize) -> Self {
        let prg = GroupPrg::random(msg_size / 32 + 1);
        let dpf = dpf::MultiKeyDpf::new(prg, channels, groups);
        MultiKeyVdpf::new(dpf)
    }
}

#[cfg(feature = "testing")]
pub use constructions::IntsModP;
