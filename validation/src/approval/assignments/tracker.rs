//! Approval assignment tracker
//!
//! We mostly plumb information from stories into criteria method
//! invokations in this module, which 
//!

use core::{ cmp::max, convert::TryFrom, ops, };
use std::collections::{BTreeMap, HashSet, HashMap, hash_map::Entry};

use crate::Error;

use super::{
    ApprovalContext, AssignmentResult, Hash, ParaId,
    DelayTranche, stories,
    criteria::{self, Assignment, AssignmentSigned, Criteria, Position},
    ValidatorId,
};


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


/// Verified assignments sorted by their delay tranche
///
// #[derive(..)]
pub(super) struct AssignmentsByDelay<C: Criteria, K = criteria::AssignmentSignature>
    (BTreeMap<DelayTranche,Vec< Assignment<C,K> >>);

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
    fn insert(&mut self, a: Assignment<C>, context: &ApprovalContext) -> AssignmentResult<DelayTranche> {
        let delay_tranche = a.delay_tranche(context);
        let mut v = self.0.entry(delay_tranche).or_insert(Vec::new());
        // We could improve performance here with `HashMap<ValidatorId,..>`
        // but these buckets should stay small-ish due to using VRFs.
        if v.iter().any( |a0| a0.checker() == a.checker() ) { 
            return Err(Error::BadAssignment("Attempted insertion of duplicate ")); 
        }
        // debug_assert!( !v.iter().any( |a0| a0.checker() == a.checker() ) );
        v.push(a);
        Ok(delay_tranche)
    }

    /// Iterate immutably over checkers.
    fn range<R>(&self, r: R) -> impl Iterator<Item=&Assignment<C>>
    where R: ::std::ops::RangeBounds<DelayTranche>,
    {
        self.0.range(r).map( |(_,v)| v.iter() ).flatten()
    }
}


/// Current status of a checker with an assignemnt to this candidate.
///
/// We cannot store an `approved` state inside `AssignmentsByDelay`
/// because we maybe recieve approval messages before the assignment
/// message.  We thus need some extra checker tracking data structure,
/// but more options exist:
///
/// We could track an `Option<DelayTranche>` here, with `Some` for
/// assigned checkers, and `None` for approving, but unasigned,
/// but this complicates the code more than expected.
struct CheckerStatus {
    /// Is this assignment approved?
    approved: bool,
    /// Is this my own assignment?
    mine: bool,
    // /// Improve lookup times, `None` if approved without existing assignment.
    // delay_tranche: Option<DelayTranche>,
}

#[derive(Default)]
/// All assignments tracked for one specfic parachain cadidate.
///
/// TODO: Add some bitfield that detects multiple insertions by the same validtor.
pub struct CandidateTracker {
    targets: ApprovalsTargets,
    /// Approval statments
    checkers: HashMap<ValidatorId,CheckerStatus>,
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
        (&mut self.relay_vrf_modulo as &mut dyn Any)
        .downcast_mut::<AssignmentsByDelay<C>>()
        .or( (&mut self.relay_vrf_delay as &mut dyn Any)
             .downcast_mut::<AssignmentsByDelay<C>>() )
        .or( (&mut self.relay_equivocation as &mut dyn Any)
             .downcast_mut::<AssignmentsByDelay<C>>() )
        .expect("Oops, we've some foreign type satisfying Criteria!")
    }

    /// Read current approvals checkers target levels
    pub fn targets(&self) -> &ApprovalsTargets { &self.targets }

    // /// Write current approvals checkers target levels
    // pub fn targets_mut(&self) -> &mut ApprovalsTargets { &mut self.targets }

    /// Return whether the given validator approved this candiddate,
    /// or `None` if we've no assignment form them.
    pub fn is_approved_by_checker(&self, checker: &ValidatorId) -> Option<bool> {
        self.checkers.get(checker).map(|status| status.approved)
    }

    /// Mark validator as approving this candiddate
    ///
    /// We cannot expose approving my own candidates from the `Tracker`
    /// because they require additional work.
    pub(super) fn approve(&mut self, checker: ValidatorId, mine: bool) -> AssignmentResult<()> {
        match self.checkers.entry(checker) {
            Entry::Occupied(mut e) => { 
                let e = e.get_mut();
                if e.mine != mine {
                    return Err(Error::BadAssignment("Attempted to approve my own assignment from Tracker or visa versa!"));
                }
                e.approved = true;
            },
            Entry::Vacant(mut e) => { e.insert(CheckerStatus { approved: true, mine: false, }); },
        }
        Ok(())
    }

    /// Mark another validator as approving this candiddate
    ///
    /// We accept and correctly process premature approve calls, but
    /// our current scheme makes counting approvals slightly slower.
    /// We can optimize performance later with slightly more complex code.
    pub fn approve_others(&mut self, checker: ValidatorId) -> AssignmentResult<()> {
        self.approve(checker, false)
    }

    fn count_approved_helper(&self,iter: impl Iterator<Item=ValidatorId>) -> usize 
    {
        let mut cm = HashSet::new();
        for checker in iter {
            if Some(true) == self.is_approved_by_checker(&checker) {  cm.insert(checker);  }
        }
        cm.len()
    }

    fn approval_by_relay_vrf<R>(&self, r: R) -> usize
    where R: ::std::ops::RangeBounds<DelayTranche> + Clone
    {
        let x = self.relay_vrf_modulo.range(r.clone())  // Always delay_tranche=0
            .map( |a| a.checker().clone() );
        let y = self.relay_vrf_delay.range(r)  // Always delay_tranche=0
            .map( |a| a.checker().clone() );
        self.count_approved_helper( x.chain(y) )
    }

    fn approval_by_relay_equivocation<R>(&self, r: R) -> usize
    where R: ::std::ops::RangeBounds<DelayTranche>
    {
        self.count_approved_helper( self.relay_equivocation.range(r).map( |a| a.checker().clone() ) )
    }

    pub fn is_approved_before(&self, delay: DelayTranche) -> bool {
        self.approval_by_relay_vrf(0..delay)
         < self.targets.relay_vrf_checkers as usize
        &&
        self.approval_by_relay_equivocation(0..delay)
         < self.targets.relay_equivocation_checkers as usize
    }
}



/// Tracks approval checkers assignments
///
/// Inner type and builder for `Watcher` and `Announcer`, which
/// provide critical methods unavailable on `Tracker` alone.
pub struct Tracker {
    context: ApprovalContext,
    current_slot: u64,
    relay_vrf_story: stories::RelayVRFStory,
    relay_equivocation_story: stories::RelayEquivocationStory,
    candidates: BTreeMap<ParaId,CandidateTracker>
}

impl Tracker {
    pub fn new(context: ApprovalContext, target: u16) -> AssignmentResult<Tracker> {
        let current_slot = context.anv_slot_number();
        // TODO: Improve `stories::*::new()` methods
        let header = unimplemented!();
        let relay_vrf_story = context.new_vrf_story(header,unimplemented!()) ?;
        let relay_equivocation_story = unimplemented!(); // stories::RelayEquivocationStory::new(header);
        let candidates = BTreeMap::default();
        // TODO: Add parachain candidates 
        Ok(Tracker { context, current_slot, relay_vrf_story, relay_equivocation_story, candidates, })
    }

    fn access_story<C>(&self) -> &C::Story
    where C: Criteria, Assignment<C>: Position,
    {
        use core::any::Any;
        (&self.relay_vrf_story as &dyn Any).downcast_ref::<C::Story>()
        .or( (&self.relay_equivocation_story as &dyn Any).downcast_ref::<C::Story>() )
        .expect("Oops, we've some foreign type as Criteria::Story!")
    }

    /// Insert assignment verified elsewhere
    pub(super) fn insert<C>(&mut self, a: Assignment<C>, mine: bool) -> AssignmentResult<()> 
    where C: Criteria, Assignment<C>: Position,
    {
        let checker = a.checker().clone();
        let paraid = a.paraid(&self.context)
            .ok_or(Error::BadAssignment("Insert attempted on missing ParaId.")) ?;
        let candidate = self.candidates.entry(paraid).or_insert(CandidateTracker::default());
        if let Some(cs) = candidate.checkers.get(&checker) { if cs.mine != mine {
            return Err(Error::BadAssignment("Attempted to verify my own assignment!"));
        } }
        candidate.access_criteria_mut::<C>().insert(a,&self.context) ?;
        candidate.checkers.entry(checker).or_insert(CheckerStatus { approved: false, mine, });
        Ok(())        
    }

    /// Insert an assignment after verifying its signature 
    pub(super) fn verify_and_insert<C>(&mut self, a: &AssignmentSigned<C>)
     -> AssignmentResult<()> 
    where C: Criteria, Assignment<C>: Position,
    {
        let (context,a) = a.verify(self.access_story::<C>()) ?;
        if *context != self.context { 
            return Err(Error::BadAssignment("Incorrect ApprovalContext"));
        }
        self.insert(a,false)
    }

    /// Read individual candidate's tracker
    ///
    /// Useful for `targets` and maybe `is_approved_before` methods of `CandidateTracker`.
    pub fn candidate(&self, paraid: &ParaId) -> AssignmentResult<&CandidateTracker>
    {
        self.candidates.get(paraid).ok_or(Error::BadAssignment("Invalid ParaId"))
    }

    /// Access individual candidate's tracker mutably
    ///
    /// Useful for `approve` method of `CandidateTracker`.
    pub fn candidate_mut(&mut self, paraid: &ParaId) -> AssignmentResult<&mut CandidateTracker> {
        self.candidates.get_mut(paraid).ok_or(Error::BadAssignment("Invalid ParaId"))
    }

    pub fn current_anv_slot(&self) -> u64 { self.current_slot }

    pub fn delay(&self) -> DelayTranche {
        let delay_bound: u32 = unimplemented!(); // TODO: num_validators? smaller?
        let slot = self.current_slot.checked_sub( self.context.anv_slot_number() )
            .expect("current_slot initialized to context.slot, qed");
        u32::try_from( max(slot, delay_bound as u64) ).expect("just checked this, qed")
    }

    /// Ask if all candidates are approved
    pub fn is_approved(&self) -> bool {
        let slot = self.delay();
        self.candidates.iter().all(|(_paraid,c)| c.is_approved_before(slot))
    }

    /// Initalize tracking others assignments and approvals
    /// without creating assignments ourself.
    pub fn into_watcher(self) -> Watcher {
        Watcher { tracker: self } 
    }
}


/// Tracks only others assignments and approvals
pub struct Watcher {
    tracker: Tracker,
}

impl ops::Deref for Watcher {
    type Target = Tracker;
    fn deref(&self) -> &Tracker { &self.tracker }
}
impl ops::DerefMut for Watcher {
    fn deref_mut(&mut self) -> &mut Tracker { &mut self.tracker }
}

impl Watcher {
    /// 
    pub fn increase_anv_slot(&mut self, slot: u64) {
        self.tracker.current_slot = max(self.tracker.current_slot, slot);
    }
}
