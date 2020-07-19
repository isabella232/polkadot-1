//! Approval checker asignment VRF criteria

use core::borrow::Borrow;

use merlin::Transcript;
use schnorrkel::{PublicKey, PUBLIC_KEY_LENGTH, Keypair, vrf};

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
    fn extra(&self, context: &ApprovalContext) -> Transcript { 
        context.transcript()
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


/// Internal representation for an assigment with some computable
/// position. We should obtain these first by verifying a signed
/// assignment using `AssignmentSigned::verify`, or simularly using
/// `Criteria::attach` manually, and secondly by evaluating our own
/// criteria.  In the later case, we produce a signed assignment
/// by calling `Assignment::sign`.
pub struct Assignment<C: Criteria, K> {
    /// Assignment criteria specific data
    criteria: C,
    /// Assigned checker's key
    checker: K,
    /// VRFInOut from which we compute the actualy assignment details
    vrf_inout: vrf::VRFInOut,
}

impl<C: Criteria,K> Assignment<C,K> {
    /// Return the checker of type `K`
    pub fn checker(&self) -> &K { &self.checker }
}

impl<C,K> Assignment<C,K> 
where 
    C: Criteria, 
    K: Borrow<Keypair>,  // Replace with another method of location our own signing key
{
    /// Create our own `Assignment` for the given criteria, story,
    /// and our keypair, by constructing its `VRFInOut`.
    ///
    /// We borrow the `Keypair` here for convenience, but `Arc<Keypair>` works.
    // Or else you should add a keypair argument to `sign` too.
    pub fn create(criteria: C, checker: K, story: &C::Story) -> AssignmentResult<Assignment<C,K>> {
        let vrf_inout = checker.borrow().vrf_create_hash(criteria.vrf_input(story) ?);
        Ok(Assignment { criteria, checker, vrf_inout, })
    }

    /// VRF sign our assignment for announcment.
    pub fn sign(&self, context: ApprovalContext) -> AssignmentSigned<C> {
        let checker = self.checker.borrow();
        // Must exactly mirror `schnorrkel::Keypair::vrf_sign_extra`
        // or else rerun one point multiplicaiton in vrf_create_hash
        let t = self.criteria.extra(&context);
        let vrf_proof = checker.dleq_proove(t, &self.vrf_inout, vrf::KUSAMA_VRF).0.to_bytes();
        let vrf_preout = self.vrf_inout.to_output().to_bytes();
        let checker = checker.public.to_bytes();
        let criteria = self.criteria.clone();
        AssignmentSigned { context, criteria, checker, vrf_preout, vrf_proof, }
    }
}

/// Announcable VRF signed assignment
pub struct AssignmentSigned<C: Criteria> {
    context: ApprovalContext,
    criteria: C,
    checker: [u8; PUBLIC_KEY_LENGTH], 
    vrf_preout: [u8; vrf::VRF_OUTPUT_LENGTH],
    vrf_proof: [u8; vrf::VRF_PROOF_LENGTH],
}

impl<C: Criteria> AssignmentSigned<C> {
    /// Get publickey identifying checker
    pub fn checker(&self) -> AssignmentResult<PublicKey> {
        PublicKey::from_bytes(&self.checker)
        .map_err(|_| Error::BadAssignmnet("Bad VRF signature (bad publickey)"))
    }

    /// Verify a signed assignment
    pub fn verify(&self, story: &C::Story)
     -> AssignmentResult<(&ApprovalContext,Assignment<C,PublicKey>)> 
    {
        let AssignmentSigned { context, criteria, checker, vrf_preout, vrf_proof, } = self;
        let checker = self.checker() ?;
        let vrf_inout = vrf::VRFOutput::from_bytes(vrf_preout)
            .expect("length enforced statically")
            .attach_input_hash(&checker, self.criteria.vrf_input(story) ?)
            .map_err(|_| Error::BadAssignmnet("Bad VRF signature (bad pre-output)")) ?;
        let vrf_proof = vrf::VRFProof::from_bytes(vrf_proof)
            .map_err(|_| Error::BadAssignmnet("Bad VRF signature (bad proof)")) ?;
        let t = criteria.extra(&context);
        let _ = checker.dleq_verify(t, &vrf_inout, &vrf_proof, vrf::KUSAMA_VRF)
            .map_err(|_| Error::BadAssignmnet("Bad VRF signature (invalid)")) ?;
        Ok((context, Assignment { criteria: criteria.clone(), checker, vrf_inout, }))
    }
}



