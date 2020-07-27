//! Chain stories supporting approval assignment criteria
//!
//! We compute approval checker assignment criteria with VRF outputs,
//! but their correxponding VRF inputs come from information that
//! ideally lives on-chain.  In this submodule, we either retrieve
//! such information provided it exists on-chain, or else revalidate
//! it when it lives off-chain, and then create the "(chain) stories"
//! actually use in validating assignment criteria. 
//! In short, stories isolate our data dependencies upon the relay chain.

use std::sync::Arc;
use std::collections::HashMap;

use babe_primitives::{EquivocationProof, AuthorityId, make_transcript};
use sc_consensus_babe::{Epoch};
// use sc_consensus_slots::{EquivocationProof};
// use sp_consensus_babe::{EquivocationProof};
// https://github.com/paritytech/substrate/pull/6362/files#diff-aee164b6a1b80d52767f208971d01d82R32

use super::{AssignmentResult, ParaId, Hash, Header, Error, ValidatorId};


/// A slot number.
pub type SlotNumber = u64;

/// A epoch number.
pub type EpochNumber = u64;


pub const ANV_SLOTS_PER_BP_SLOTS: u64 = 12; // = 6*2, so every half second

/// Identifies the relay chain block in which we declared these
/// parachain candidates to be availability 
#[derive(Clone,PartialEq,Eq)]
pub struct ApprovalContext {
    /// Relay chain slot number of availability declaration in the relay chain
    pub(crate) slot: SlotNumber,
    /// Epoch in which slot occurs
    pub(crate) epoch: EpochNumber,
    /// Block hash 
    pub(crate) hash: Hash,
    /// Block producer
    pub(crate) authority: ValidatorId,
}

impl ApprovalContext {
    pub fn anv_slot_number(&self) -> SlotNumber {
        self.slot.checked_mul(ANV_SLOTS_PER_BP_SLOTS)
        .expect("Almost 2^60 seconds elapsed?!?")
    }

    pub fn new(checker: ValidatorId) -> AssignmentResult<ApprovalContext> {
        let slot: u64 = unimplemented!();
        let epoch: u64 = unimplemented!();
        let hash: Hash = unimplemented!();
        let authority: ValidatorId = unimplemented!();
        Ok(ApprovalContext { slot, epoch, hash, authority })
    }

    /// Relay chain block production slot
    pub fn slot(&self) -> u64 { self.slot }

    /// Relay chain block production epoch
    pub fn epoch(&self) -> u64 { self.epoch }

    /// Relay chain block hash
    pub fn hash(&self) -> &Hash { &self.hash }

    /// Fetch full epoch data from self.epoch
    pub fn fetch_epoch(&self) -> Epoch {
        unimplemented!()
    }

    /// All parachain/thread ids permitted in the given `epoch` and `slot`.
    ///
    /// We expect results to depend upon the chain state two epochs before
    /// `epoch` and optionally upon `slot`, but more recent dependencies
    /// within the epochs `epoch` or `epoch-1` require analysis.
    pub(super) fn allowed_paraids(&self) -> Arc<[ParaId]> {
        unimplemented!()
    }

    /// Fetch full epoch data from self.epoch
    pub fn fetch_header(&self) -> Header {
        unimplemented!()
    }

    /// Create story for assignment criteria determined by relay chain VRFs.
    ///
    /// We must only revalidate the relay chain VRF, by supplying the proof,
    /// if we have not already done so when importing the block.
    pub fn new_vrf_story(&self, _header: Header, proof: Option<&::schnorrkel::vrf::VRFProof>)
     -> AssignmentResult<RelayVRFStory> 
    {
        let vrf_t = make_transcript(
            &self.fetch_epoch().randomness, 
            self.slot, 
            self.epoch // == self.epoch().epoch_index,
        );

        let authority_id: AuthorityId = unimplemented!();
        use primitives::crypto::Public;
        let publickey = ::schnorrkel::PublicKey::from_bytes(&authority_id.to_raw_vec()) // Vec WTF?!?
            .map_err(|_| Error::BadStory("Relay chain block authorized by improper sr25519 public key")) ?;

        let vrf_preout = unimplemented!();
        let vrf_io = if let Some(pr) = proof {
            unimplemented!(); // TODO: Verify that we imported this block
            publickey.vrf_verify(vrf_t,vrf_preout,pr)
            .map_err(|_| Error::BadStory("Relay chain block VRF failed validation")) ?.0
        } else {
            unimplemented!(); // TODO: Verify that we imported this block
            vrf_preout.attach_input_hash(&publickey,vrf_t)
            .map_err(|_| Error::BadStory("Relay chain block with invalid VRF PreOutput")) ?
        };

        let anv_rc_vrf_source = vrf_io.make_bytes::<[u8; 32]>(b"A&V RC-VRF");
        // above should be based on https://github.com/paritytech/substrate/pull/5788/files

        Ok(RelayVRFStory { anv_rc_vrf_source, })
    }

    /// Initalize empty story for a relay chain block with no equivocations so far.
    ///
    /// We must only revalidate the relay chain VRF, by supplying the proof,
    /// if we have not already done so when importing the block.
    pub fn new_equivocation_story(&self) -> RelayEquivocationStory {
        let header = self.fetch_header();
        RelayEquivocationStory { header, relay_equivocations: Vec::new(), candidate_equivocations: HashMap::new() }
    }
}


/// Approval assignment story comprising a relay chain VRF output
pub struct RelayVRFStory {
    /// Actual final VRF output computed for the 
    pub(super) anv_rc_vrf_source: [u8; 32],
}

/// Approval assignments whose availability declaration is an equivocation
pub struct RelayEquivocationStory {
    /// Relay chain block hash
    pub(super) header: Header,
    /// Relay chain equivocations
    pub(super) relay_equivocations: Vec<Header>, 
    /// Actual final VRF output computed for the 
    pub(super) candidate_equivocations: HashMap<ParaId,Hash>,
}


impl RelayEquivocationStory {
    /*
    /// Add any candidate equivocations found within a relay chain equivocation.
    ///
    /// We define a candidate equivocation in a relay chain block X as
    /// a candidate declared available in X but not declared available
    /// in some relay chain block production equivocation Y of X.  
    ///
    /// We know all `EquivocationProof`s were created by calls to
    /// `sp_consensus_slots::check_equivocation`, so they represent
    /// real relay chainlock production  bequivocations, and need
    /// not be rechecked here.
    pub fn add_equivocation(&mut self, ep: &EquivocationProof<Header>) 
     -> AssignmentResult<()>
    {
        let slot = ep.slot();
        let header = [ep.fst_header(), ep.snd_header()].iter()
            .find(|h| h.hash() == self.header().hash)
            .ok_or(Error::BadStory("Cannot add unrelated equivocation proof.")) ?;
        unimplemented!() // TODO: Iterate over candidate and add to self.candidate_equivocations any that exist under fst_header, but differ or do not exist in snd_header
    }
    */
}

