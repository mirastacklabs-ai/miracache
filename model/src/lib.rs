//! Stateright model of the miracache correctness protocol (design spec section 8,
//! revision 4; reference: the protocol's TLA+ specification, design spec section 8).
//!
//! See README.md for the spec-step -> model-action table, bounds and variants.

pub mod model;
pub mod runner;
mod symmetry;
pub mod variants;

pub use model::{Action, Bounds, Cfg, Faults, Mira, Rogue, State, Switches};
pub use runner::{check_variant, run_bfs, run_sim, Outcome};
pub use variants::{variant, variants, Variant};
