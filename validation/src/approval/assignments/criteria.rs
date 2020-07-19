//! Approval checker asignment VRF criteria


use merlin::Transcript;
use schnorrkel::{PublicKey, Keypair, vrf};

// pub use sp_consensus_vrf::schnorrkel::{Randomness, VRF_PROOF_LENGTH, VRF_OUTPUT_LENGTH, RANDOMNESS_LENGTH };


use crate::Error;

use super::{
    ApprovalContext, AssignmentResult, Hash, ParaId,
    stories, // RelayVRFStory, RelayEquivocationStory
    ValidatorId,
};



impl ApprovalContext {
    pub fn transcript(&self) -> Transcript {
        let mut t = Transcript::new(b"Approval Assignment Signature");
        t.append_u64(b"rad slot", self.slot);
        t.append_u64(b"rad epoch", self.epoch);
        t.append_message(b"rad block", self.hash.as_ref());
        use primitives::crypto::Public;
        t.append_message(b"rad block", &self.authority.to_raw_vec());  // Vec WTF?!?
        t
    }
}

/// Approval checker assignment criteria
/// 
/// We determine how the relay chain contet, any criteria data, and
/// any relevant stories impact VRF invokation using this trait,
pub trait Criteria : Clone {
    /// Additionl data required for constructing the VRF input
    type Story;

    /// Write the transcript from which build the VRF input.  
    ///
    /// Errors if Any errors indicate 
    fn vrf_input(&self, story: &Self::Story) -> AssignmentResult<Transcript>;

    /// Initialize the transcript for our Schnorr DLEQ proof.
    ///
    /// Any criteria data that requires authentication, currently empty,
    /// but optionally replaces signing this gossip message, saving 64 bytes.
    fn extra(&self, ac: &ApprovalContext) -> Transcript { 
        ac.transcript()
    }
}


/// Initial approval checker assignment based upon checkers' VRF 
/// applied to the relay chain VRF, but then computed modulo the
/// number of parachains.
#[derive(Clone)]
pub struct RelayVRFModulo {
    // Story::anv_rc_vrf_source
}

impl Criteria for RelayVRFModulo {
    type Story = stories::RelayVRFStory;

    /// Panics if the relay chain block has an invalid Ristretto point as VRF pre-output.
    /// If this happenes then polkadot must shut down for repars and fork anyways.
    fn vrf_input(&self, story: &Self::Story) -> AssignmentResult<Transcript> {
        let mut t = Transcript::new(b"Approval Assignment VRF");
        t.append_message(b"RelayVRFModulo", &story.anv_rc_vrf_source );
        Ok(t)
    }
}

// impl RelayVRFInitial { }


/// Approval checker assignment based upon checkers' VRF applied
/// to the relay chain VRF and parachain id, but then outputing a
/// delay.  Applies only if too few check before reaching the delay.
#[derive(Clone)]
pub struct RelayVRFDelay {
    // Story::anv_rc_vrf_source
    pub(crate) paraid: ParaId, 
}

impl Criteria for RelayVRFDelay {
    type Story = stories::RelayVRFStory;

    /// Panics if the relay chain block has an invalid Ristretto point as VRF pre-output.
    /// If this happenes then polkadot must shut down for repars and fork anyways.
    fn vrf_input(&self, story: &Self::Story) -> AssignmentResult<Transcript> {
        let mut t = Transcript::new(b"Approval Assignment VRF");
        t.append_message(b"RelayVRFDelay", &story.anv_rc_vrf_source );
        t.append_u64(b"ParaId", u32::from(self.paraid).into() );
        Ok(t)
    }
}

// impl RelayVRFDelay { }


/// Approval checker assignment based upon parablock hash
/// of a candidate equivocation.
#[derive(Clone)]
pub struct RelayEquivocation {
    // Story::anv_rc_vrf_source
    pub(crate) paraid: ParaId, 
}

impl Criteria for RelayEquivocation {
    type Story = stories::RelayEquivocationStory;

    /// Write the transcript from which build the VRF input for
    /// additional approval checks triggered by relay chain equivocations.
    ///
    /// Errors if paraid does not yet count as a candidate equivocation 
    fn vrf_input(&self, story: &Self::Story) -> AssignmentResult<Transcript> {
        let h = story.candidate_equivocations.get(&self.paraid)
            .ok_or(Error::BadStory("Not a candidate equivocation")) ?;
        let mut t = Transcript::new(b"Approval Assignment VRF");
        t.append_u64(b"ParaId", u32::from(self.paraid).into() );
        t.append_message(b"Candidate Equivocation", h.as_ref() );
        Ok(t)
    }
}




