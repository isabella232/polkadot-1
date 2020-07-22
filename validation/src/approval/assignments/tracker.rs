//! Approval assignment tracker
//!
//! We mostly plumb information from stories into criteria method
//! invokations in this module, which 
//!

use std::collections::{BTreeMap,HashSet};

use crate::Error;

use super::{
    ApprovalContext, AssignmentResult, Hash, ParaId,
    DelayTranche, stories,
    criteria::{self, Assignment, AssignmentSigned, Criteria, Position},
    ValidatorId,
};



/// Assignments list sorted by their delay tranche
///
// #[derive(..)]
struct AssignmentsByDelay<C: Criteria>(BTreeMap<DelayTranche,Vec< Assignment<C> >>);

impl<C: Criteria> Default for AssignmentsByDelay<C> {
    fn default() -> Self { AssignmentsByDelay(Default::default()) }
}

impl<C> AssignmentsByDelay<C> 
where C: Criteria, Assignment<C>: Position,
{    
    fn bucket_mut(&mut self, delay_tranche: DelayTranche)
     -> Option<&mut Vec< Assignment<C> >> 
    {
        self.0.get_mut(&delay_tranche)
    }
    
    /// Add new `Assignment` avoiding inserting any duplicates.
    ///
    /// Assumes there is only one valid delay value determined by
    /// some VRF output.
    fn insert(&mut self, a: Assignment<C>) -> AssignmentResult<()> {
        let mut v = self.0.entry(a.delay_tranche()).or_insert(Vec::new());
        // We could improve performance here with `HashMap<ValidatorId,..>`
        // but these buckets should stay small-ish due to using VRFs.
        if v.iter().any( |a0| a0.checker() == a.checker() ) { 
            return Err(Error::BadAssignment("Attempted insertion of duplicate ")); 
        }
        v.push(a);
        Ok(())
    }

    /// Iterate immutably over checkers.
    fn range<T, R>(&self, r: R) -> impl Iterator<Item=&Assignment<C>>
    where
        // I'd expect DelayTranche: Borrow<T> implies T = DelayTranche by whatever.
        DelayTranche: ::std::borrow::Borrow<T>, 
        R: ::std::ops::RangeBounds<T>,
        T: Ord + ?Sized, 
    {
        self.0.range(r).map( |(_,v)| v.iter() ).flatten()
    }
}


/// Approvals target levels
///
/// We instantiuate this with `Default` currently, but we'll want the
/// relay VRF target number to be configurable by the chain eventually.
pub struct ApprovalsTargets {
    /// Approvals required for criteria based upon relay chain VRF output,
    /// never too larger, never too small.
    pub relay_vrf_checkers: u16,
    /// Approvals required for criteria based upon relay chain equivocations,
    /// initially zero but increased if we discover equivocations.
    pub relay_equivocation_checkers: u16,
}

impl Default for ApprovalsTargets {
    fn default() -> Self {
        ApprovalsTargets {
            relay_vrf_checkers: 20,  // We've no analysis backing this choice yet.
            relay_equivocation_checkers: 0,
        }
    }
}


#[derive(Default)]
/// All assignments tracked for one specfic parachain cadidate.
///
/// TODO: Add some bitfield that detects multiple insertions by the same validtor.
pub struct CandidateTracker {
    targets: ApprovalsTargets,
    /// Approval statments
    approved: HashSet<ValidatorId>,
    /// Assignments of modulo type based on the relay chain VRF
    ///
    /// We only use `delay_tranche = 0` for `RelayVRFModulo`
    /// but it's easier to reuse all this other code than
    /// impement anything different.
    relay_vrf_modulo:   AssignmentsByDelay<criteria::RelayVRFModulo>,
    /// Assignments of delay type based on the relay chain VRF
    relay_vrf_delay:    AssignmentsByDelay<criteria::RelayVRFDelay>,
    /// Assignments of delay type based on candidate equivocations
    relay_equivocation: AssignmentsByDelay<criteria::RelayEquivocation>,
}

impl CandidateTracker {
    fn access_criteria_mut<C>(&mut self) -> &mut AssignmentsByDelay<C>
    where C: Criteria, Assignment<C>: Position,
    {
        use core::any::Any;
        (&mut self.relay_vrf_modulo as &mut dyn Any).downcast_mut::<AssignmentsByDelay<C>>()
        .or( (&mut self.relay_vrf_delay as &mut dyn Any).downcast_mut::<AssignmentsByDelay<C>>() )
        .or( (&mut self.relay_equivocation as &mut dyn Any).downcast_mut::<AssignmentsByDelay<C>>() )
        .expect("Oops, we've some foreign type satisfying Criteria!")
    }

    /// Read current approvals checkers target levels
    pub fn targets(&self) -> &ApprovalsTargets { &self.targets }

    /// Mark validator as approving this candiddate
    ///
    /// We returns true if this freshly marks a new validator
    /// as approving the candidate, and false if we already knew this
    /// validator approved the andidate.  We do not consider duplicate
    /// calls an error, but they might indicate a problem elsewhere
    /// in the gossip system.
    ///
    /// We accept and correctly process premature approve calls, but
    /// our current scheme makes counting approvals slightly slower.
    /// We can optimize performance later with slightly more complex code.
    pub fn approve(&mut self, checker: ValidatorId) -> bool {
        self.approved.insert(checker)
    }

    pub fn is_approved(&self) -> bool {
        unimplemented!()
    }
}

pub struct Tracker {
    context: ApprovalContext,
    relay_vrf_story: stories::RelayVRFStory,
    relay_equivocation_story: stories::RelayEquivocationStory,
    candidates: BTreeMap<ParaId,CandidateTracker>
}

impl Tracker {
    pub fn new(context: ApprovalContext, target: u16) -> AssignmentResult<Tracker> {
        // TODO: Improve `stories::*::new()` methods
        let header = unimplemented!();
        let relay_vrf_story = context.new_vrf_story(header,unimplemented!()) ?;
        let relay_equivocation_story = unimplemented!(); // stories::RelayEquivocationStory::new(header);
        let candidates = BTreeMap::default();
        // TODO: Add parachain candidates 
        Ok(Tracker { context, relay_vrf_story, relay_equivocation_story, candidates, })
    }

    fn access_story<C>(&self) -> &C::Story
    where C: Criteria, Assignment<C>: Position,
    {
        use core::any::Any;
        (&self.relay_vrf_story as &dyn Any).downcast_ref::<C::Story>()
        .or( (&self.relay_equivocation_story as &dyn Any).downcast_ref::<C::Story>() )
        .expect("Oops, we've some foreign type as Criteria::Story!")
    }

    /// Insert an assignment after verifying its signature 
    pub(super) fn verify_and_insert<C>(&mut self, story: &C::Story, a: &AssignmentSigned<C>)
     -> AssignmentResult<()> 
    where C: Criteria, Assignment<C>: Position,
    {
        let (context,a) = a.verify(self.access_story::<C>()) ?;
        if *context != self.context { 
            return Err(Error::BadAssignment("Incorrect ApprovalContext"));
        }
        let paraid = a.paraid(context) ?;
        self.candidates.entry(paraid)
        .or_insert(CandidateTracker::default())
        .access_criteria_mut::<C>()
        .insert(a)
    }

    /// Read individual candidate's tracker
    ///
    /// Useful for `is_approved` and `targets` methods of `CandidateTracker`.
    pub fn candidate(&self, paraid: &ParaId) -> AssignmentResult<&CandidateTracker>
    {
        self.candidates.get(paraid).ok_or(Error::BadAssignment("Invalid ParaId"))
    }

    /// Access individual candidate's tracker mutably
    ///
    /// Useful for `approve` method of `CandidateTracker`.
    pub fn candidate_mut(&mut self, paraid: &ParaId) -> AssignmentResult<&mut CandidateTracker>
    {
        self.candidates.get_mut(paraid).ok_or(Error::BadAssignment("Invalid ParaId"))
    }

    /// Ask if all candidates are approved
    pub fn is_approved(&self) -> bool {
        self.candidates.iter().all(|(_paraid,c)| c.is_approved())
    }
}

