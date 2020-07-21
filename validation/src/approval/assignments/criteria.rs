//! Approval checker asignment VRF criteria
//!
//! We manage the actual VRF computations for approval checker
//! assignments inside this module, so most schnorrkell logic gets
//! isolated here.
//!
//! TODO: We should expand RelayVRFModulo to do rejection sampling
//! using `vrf::vrf_merge`, which requires `Vec<..>`s for
//! `AssignmentSigned::vrf_preout` and `Assignment::vrf_inout`.

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


/*
pub(super) struct Position {
    delay_tranche: u16,
    paraid: ParaId,
}
*/


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
pub trait Criteria : Clone + 'static {
    /// Additionl data required for constructing the VRF input
    type Story;

    /// Write the transcript from which build the VRF input.  
    ///
    /// Errors if Any errors indicate 
    fn vrf_input(&self, story: &Self::Story, sample: u16) -> AssignmentResult<Transcript>;

    /// Initialize the transcript for our Schnorr DLEQ proof.
    ///
    /// Any criteria data that requires authentication, which should make
    /// signing gossip messages unecessary, saving 64 bytes, etc.
    fn extra(&self, context: &ApprovalContext) -> Transcript { 
        context.transcript()
    }

    // fn position(&self, vrf_inout: &vrf::VRFInOut) -> Position;
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
    fn vrf_input(&self, story: &Self::Story, sample: u16) -> AssignmentResult<Transcript> {
        if sample > 0 { return Err(Error::BadAssignment("RelayVRFModulo does not yet support additional samples")); }
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
    fn vrf_input(&self, story: &Self::Story, sample: u16) -> AssignmentResult<Transcript> {
        if sample > 0 {
            // TODO: Is this really a BadAssignment or a BadStory or something else?
            return Err(Error::BadAssignment("RelayVRFDelay cannot ever support additional samples")); 
        }
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
    fn vrf_input(&self, story: &Self::Story, sample: u16) -> AssignmentResult<Transcript> {
        if sample > 0 {
            // TODO: Is this really a BadAssignment or a BadStory or something else?
            return Err(Error::BadAssignment("RelayVRFDelay cannot ever support additional samples")); 
        }
        let h = story.candidate_equivocations.get(&self.paraid)
            .ok_or(Error::BadStory("Not a candidate equivocation")) ?;
        let mut t = Transcript::new(b"Approval Assignment VRF");
        t.append_u64(b"ParaId", u32::from(self.paraid).into() );
        t.append_message(b"Candidate Equivocation", h.as_ref() );
        Ok(t)
    }
}


/// Internal representation for a assigment with some computable
/// delay. 
/// We should obtain these first by verifying a signed
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

impl<C,K> Assignment<C,K> where C: Criteria {
    /// Identify the checker as a `&K` 
    pub fn checker(&self) -> &K { &self.checker }
}

impl<C> Assignment<C,()> where C: Criteria {
    /// Create our own `Assignment` for the given criteria, story,
    /// and our keypair, by constructing its `VRFInOut`.
    pub fn create(criteria: C, story: &C::Story, checker: &Keypair) -> AssignmentResult<Assignment<C,()>> {
        let vrf_inout = checker.borrow().vrf_create_hash(criteria.vrf_input(story,0) ?);
        Ok(Assignment { criteria, checker: (), vrf_inout, })
    }

    /// VRF sign our assignment for announcment.
    ///
    /// We could take `K: Borrow<Keypair>` above in `create`, saving us
    /// the `checker` argument here, and making `K=Arc<Keypair>` work,
    /// except `Assignment`s always occur with so much repetition that
    /// passing the `Keypair` again makes more sense.
    pub fn sign(&self, context: ApprovalContext, checker: &Keypair) -> AssignmentSigned<C> {
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
        .map_err(|_| Error::BadAssignment("Bad VRF signature (bad publickey)"))
    }

    /// Verify a signed assignment
    pub fn verify(&self, story: &C::Story)
     -> AssignmentResult<(&ApprovalContext,Assignment<C,PublicKey>)> 
    {
        let AssignmentSigned { context, criteria, checker, vrf_preout, vrf_proof, } = self;
        let checker = self.checker() ?;
        let vrf_inout = vrf::VRFOutput::from_bytes(vrf_preout)
            .expect("length enforced statically")
            .attach_input_hash(&checker, self.criteria.vrf_input(story,0) ?)
            .map_err(|_| Error::BadAssignment("Bad VRF signature (bad pre-output)")) ?;
        let vrf_proof = vrf::VRFProof::from_bytes(vrf_proof)
            .map_err(|_| Error::BadAssignment("Bad VRF signature (bad proof)")) ?;
        let t = criteria.extra(&context);
        let _ = checker.dleq_verify(t, &vrf_inout, &vrf_proof, vrf::KUSAMA_VRF)
            .map_err(|_| Error::BadAssignment("Bad VRF signature (invalid)")) ?;
        Ok((context, Assignment { criteria: criteria.clone(), checker, vrf_inout, }))
    }
}


/// We require `Assignment<C,K>` methods generic over `C`
/// that position this assignment inside the assignment tracker
pub(super) trait Position {
    /// Assignment's  our `ParaId` from allowed `ParaId` returnned by
    /// `stories::allowed_paraids`.
    fn paraid(&self, context: &ApprovalContext) -> AssignmentResult<ParaId>;

    /// Always assign `RelayVRFModulo` the zeroth delay tranche
    fn delay_tranche(&self) -> super::DelayTranche { 0 }
}

impl<K> Position for Assignment<RelayVRFModulo,K> {
    /// Assign our `ParaId` from allowed `ParaId` returnned by
    /// `stories::allowed_paraids`.
    fn paraid(&self, context: &ApprovalContext) -> AssignmentResult<ParaId> {
        // TODO: Optimize accessing this from `ApprovalContext`
        let paraids = context.allowed_paraids();
        // We use u64 here to give a reasonable distribution modulo the number of parachains
        let mut parachain = u64::from_le_bytes(self.vrf_inout.make_bytes::<[u8; 8]>(b"parachain"));
        parachain %= paraids.len() as u64;  // assumes usize < u64
        Ok(paraids[parachain as usize])
    }

    /// Always assign `RelayVRFModulo` the zeroth delay tranche
    fn delay_tranche(&self) -> super::DelayTranche { 0 }
}

/// Approval checker assignment criteria that fully utilizes delays.
///
/// We require this helper trait to help unify the handling of  
/// `RelayVRFDelay` and `RelayEquivocation`.
pub trait DelayCriteria : Criteria {
    /// All delay based assignment criteria contain an explicit paraid
    fn paraid(&self) -> ParaId;
}
impl DelayCriteria for RelayVRFDelay {
    fn paraid(&self) -> ParaId { self.paraid }
}
impl DelayCriteria for RelayEquivocation {
    fn paraid(&self) -> ParaId { self.paraid }
}

impl<C,K> Position for Assignment<C,K> where C: DelayCriteria {
    /// Assign our `ParaId` from the one explicitly stored, but error 
    /// if disallowed by `stories::allowed_paraids`.
    fn paraid(&self, context: &ApprovalContext) -> AssignmentResult<ParaId> {
        use core::ops::Deref;
        let paraid = self.criteria.paraid();
        context.allowed_paraids().deref()
        .binary_search(&paraid)
        .map(|_| paraid)
        .map_err(|_| Error::BadAssignment("RelayEquivocation has bad ParaId"))
    }

    /// Assign our delay using our VRF output
    fn delay_tranche(&self) -> super::DelayTranche {
        let max_tranches: u32 = unimplemented!();
        // We use u64 here to give a reasonable distribution modulo the number of tranches
        let mut tranche = u64::from_le_bytes(self.vrf_inout.make_bytes::<[u8; 8]>(b"tranche"));
        tranche %= max_tranches as u64;
        tranche as u32
    }
}




