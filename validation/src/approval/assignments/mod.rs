//! Approval checker assignments module
//!
//! Approval validity checks determine whether Polkadot considers a parachain candidate valid.
//! We distinguish them from backing validity checks that merely determine whether Polakdot
//! should begin processing a parachain candidate.


use std::collections::BTreeMap;

use merlin::Transcript;

use polkadot_primitives::v1::{Id as ParaId, ValidatorId, Hash, Header};


use crate::Error;
pub type AssignmentResult<T> = Result<T,Error>;

pub mod stories;
pub mod criteria;

pub use stories::ApprovalContext;


