//! Approval assignment tracker
//!
//! We mostly plumb information from stories into criteria method
//! invokations in this module, which 
//!

use core::{ cmp::{max,min}, convert::TryFrom, ops, };
use std::collections::{BTreeMap, HashMap, hash_map::Entry};

use crate::Error;

use super::{
    ApprovalContext, ApprovalTargets, AssigneeStatus, AssignmentResult,
    Hash, ParaId, DelayTranche,
    stories,
    criteria::{self, Assignment, AssignmentSigned, Criteria, Position},
    ValidatorId,
};


/// Verified assignments sorted by their delay tranche
///
// #[derive(..)]
pub(super) struct AssignmentsByDelay<C: Criteria, K = criteria::AssignmentSignature>
    (BTreeMap<DelayTranche,Vec< Assignment<C,K> >>);

impl<C: Criteria> Default for AssignmentsByDelay<C> {
    fn default() -> Self { AssignmentsByDelay(Default::default()) }
}
impl<C: Criteria> Default for AssignmentsByDelay<C,()> {
    fn default() -> Self { AssignmentsByDelay(Default::default()) }
}

impl<C,K> AssignmentsByDelay<C,K> 
where C: Criteria, Assignment<C,K>: Position,
{
    /// Add new `Assignment` avoiding inserting any duplicates.
    ///
    /// Assumes there is only one valid delay value determined by
    /// some VRF output.
    pub(super) fn insert_assignment_unchecked(&mut self, a: Assignment<C,K>, context: &ApprovalContext) -> DelayTranche {
        let delay_tranche = a.delay_tranche(context);
        let mut v = self.0.entry(delay_tranche).or_insert(Vec::new());
        v.push(a);
        delay_tranche
    }

    /// Iterate immutably over all assignments within the given tranche assignment range.
    fn range<R>(&self, r: R) -> impl Iterator<Item=&Assignment<C,K>>
    where R: ::std::ops::RangeBounds<DelayTranche>,
    {
        self.0.range(r).map( |(_,v)| v.iter() ).flatten()
    }
}

impl<C> AssignmentsByDelay<C> 
where C: Criteria, Assignment<C>: Position,
{
    /// Iterate over all checkers, and their actual recieved times,
    /// in the given tranche assignment, always earlier than the
    /// recieved time.
    fn iter_checker_n_recieved(&self, tranche: DelayTranche)
     -> impl Iterator<Item=(ValidatorId,DelayTranche)> + '_
    {
        // We use `btree_map::Range` as a hack to handle `tranche` being invalid well.
        self.range(tranche..tranche+1).map( |a| a.checker_n_recieved() )
    }

    /// Add new `Assignment` avoiding inserting any duplicates.
    ///
    /// Assumes there is only one valid delay value determined by
    /// some VRF output.
    pub(super) fn insert_assignment_checked(&mut self, a: Assignment<C>, context: &ApprovalContext) -> AssignmentResult<DelayTranche> {
        let delay_tranche = a.delay_tranche(context);
        let mut v = self.0.entry(delay_tranche).or_insert(Vec::new());
        // We could improve performance here with `HashMap<ValidatorId,..>`
        // but these buckets should stay small-ish due to using VRFs.
        if v.iter().any( |a0| a0.checker() == a.checker() ) { 
            return Err(Error::BadAssignment("Attempted inserting duplicate assignment!")); 
        }
        // debug_assert!( !v.iter().any( |a0| a0.checker() == a.checker() ) );
        v.push(a);
        Ok(delay_tranche)
    }
}

impl<C> AssignmentsByDelay<C,()> 
where C: Criteria, Assignment<C,()>: Position,
{
    /// Remove entire tranche from pending announcements
    ///
    /// TODO: Should this contain max paramateter and randomly advance
    /// any excessive annoucements?  Should the announcer do this
    /// internally?  Or should all scheduling decissions be made in
    /// advnace?
    pub(super) fn pull_tranche(&mut self, delay_tranche: DelayTranche)
     -> Option<Vec< Assignment<C,()> >> 
    {
        self.0.remove(&delay_tranche)
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

/// All assignments tracked for one specfic parachain cadidate.
///
/// TODO: Add some bitfield that detects multiple insertions by the same validtor.
#[derive(Default)]
pub struct CandidateTracker {
    targets: ApprovalTargets,
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
    pub fn targets(&self) -> &ApprovalTargets { &self.targets }

    // /// Write current approvals checkers target levels
    // pub fn targets_mut(&self) -> &mut ApprovalTargets { &mut self.targets }

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
            Entry::Vacant(mut e) => {
                e.insert(CheckerStatus { approved: true, mine: false, }); 
            },
        }
        Ok(())
    }

    /// Mark another validator as approving this candiddate
    ///
    /// We accept and correctly process premature approve calls, but
    /// our current scheme makes counting approvals slightly slower.
    /// We can optimize performance later with slightly more complex code.
    ///
    /// TODO: We should rejects approving your own assignments, except
    /// we've a bug that invoking this on yourself before the assignment
    /// exists creates an assignemnt with `mine = true`.
    pub fn approve_others(&mut self, checker: ValidatorId) -> AssignmentResult<()> {
        self.approve(checker, false)
    }

    /// Returns the approved and absent counts for all validtors
    /// given by the iterator.  Ignores unassigned validators, which
    /// makes results meaningless if you want them counted, but
    /// this behavior makes sense assuming checkers contains every
    /// validator discussed elsewhere, including ourselves.
    fn assignee_counter<I>(&self, iter: I, noshow_tranche: DelayTranche) -> Counter
    where I: Iterator<Item=(ValidatorId,DelayTranche)>
    {
        let mut cm: HashMap<ValidatorId,DelayTranche> = HashMap::new(); // Deduplicate iter
        let mut assigned: u32 = 0;
        for (checker,recieved) in iter {
            if let Some(b) = self.is_approved_by_checker(&checker) {
                assigned += 1;  // Panics if more than u32::MAX = 4 billion validators.
                if !b {
                    cm.entry(checker)
                        .and_modify(|r| { *r = min(*r,recieved) })
                        .or_insert(recieved);
                }
            } // TODO:  Internal error log?
        }
        let mut waiting = cm.len() as u32;
        let noshows = cm.values().cloned().filter(|r: &u32| *r < noshow_tranche).count() as u32;
        let approved = assigned - waiting;
        waiting -= noshows;
        debug_assert!( assigned == approved + waiting + noshows );
        Counter { approved, waiting, noshows, assigned }
    }

    /// Returns the approved and absent counts of validtors assigned
    /// by either `RelayVRFStory` or `RelayWquivocationStory`, and
    /// within the given range.
    fn count_assignees_in_tranche<S: 'static>(
        &self, 
        tranche: DelayTranche, 
        noshow_tranche: DelayTranche
    ) -> Counter
    {
        use core::any::TypeId;
        let s = TypeId::of::<S>();
        if s == TypeId::of::<stories::RelayVRFStory>() {
            let x = self.relay_vrf_modulo.iter_checker_n_recieved(tranche);
            let y = self.relay_vrf_delay.iter_checker_n_recieved(tranche);
            self.assignee_counter( x.chain(y), noshow_tranche )
        } else if s == TypeId::of::<stories::RelayEquivocationStory>() {
            let z = self.relay_equivocation.iter_checker_n_recieved(tranche);
            self.assignee_counter(z, noshow_tranche)
        } else { panic!("Oops, we've some foreign type for Criteria::Story!") }
    }

    /// Recompute our current approval progress number
    pub fn assignee_tracker<S: 'static>(&self, now: DelayTranche)
     -> impl Iterator<Item=AssigneeStatus> + '_
    {
        let mut done = false;
        // We account for no shows in multiple tranches by increasing the no show timeout
        let mut c = AssigneeStatus {
            tranche:  0,
            target:   self.targets.target::<S>(),
            approved: 0, 
            waiting:  0, 
            noshows:  0,
            debt:     0,
            assigned: 0
        };
        let mut noshow_timeout = self.targets.noshow_timeout;

        // We fuse using `done` but we neglect `impl FusedIterator`
        // because this version reads nicely like the while loop and
        // we invoke it only twice per second or so anyways.
        ::core::iter::from_fn( move || {
            // We do not count tranches for which we should not yet have
            // recieved any assignments, even though we do store early
            // announcements.
            if done || c.tranche + noshow_timeout > now + self.targets.noshow_timeout {
                return None;
            }
            // === while c.tranche + noshow_timeout <= now + self.targets.noshow_timeout

            let d = self.count_assignees_in_tranche::<S>(c.tranche, noshow_timeout);
            c.assigned += d.assigned;
            c.waiting  += d.waiting;
            c.noshows  += d.noshows;
            c.debt     += d.noshows;
            c.approved += d.approved;
            c.tranche += 1;

            // Consider later tranches if not enough assignees yet
            if c.assigned <= c.target {
                return Some(c.clone()); 
                // === continue;
            }
            // Ignore later tranches if we've enough assignees and no no shows
            if c.debt == 0 {
                done = true;
                return Some(c.clone());
                // === break;
            }
            // We replace no shows by increasing our target when
            // reaching our initial or any subseuent target.
            // We ask for two new checkers per no show here,
            // acording to the analysis (TODO: Alistair)
            c.target = c.assigned; // + c.debt;
            c.debt = 0;
            // We view tranches as later for being counted no show
            // since they announced much latter.
            noshow_timeout += self.targets.noshow_timeout;

            return Some(c.clone()); 
            // === continue;
            } ) // .fuse() // rustc could maybe optimize this away
        // c
    }

    pub fn approval_status<S: 'static>(&self, now: DelayTranche) -> AssigneeStatus {
        self.assignee_tracker::<S>(now)
        .last().expect("Our closure returns None only with tranche > 0, qed")
    }

    pub fn is_approved_before(&self, now: DelayTranche) -> bool {
        self.approval_status::<stories::RelayVRFStory>(now).is_approved()
        && self.approval_status::<stories::RelayEquivocationStory>(now).is_approved()
    }
}

struct Counter {
    /// Approval votes thus far
    approved: u32,
    /// Awaiting approval votes
    waiting: u32,
    /// We've waoted too long for these, so they require relacement
    noshows: u32, 
    /// Total validtors assigned, so approved wiaitng, or noshow
    assigned: u32
}


/// Tracks approval checkers assignments
///
/// Inner type and builder for `Watcher` and `Announcer`, which
/// provide critical methods unavailable on `Tracker` alone.
pub struct Tracker {
    context: ApprovalContext,
    pub(super) current_slot: u64,
    pub(super) relay_vrf_story: stories::RelayVRFStory,
    relay_equivocation_story: stories::RelayEquivocationStory,
    candidates: BTreeMap<ParaId,CandidateTracker>
}

impl Tracker {
    /// Create a tracker to build a `Watcher` or `Announcer`
    pub fn new(context: ApprovalContext, target: u16) -> AssignmentResult<Tracker> {
        let current_slot = context.anv_slot_number();
        // TODO: Improve `stories::*::new()` methods
        let relay_vrf_story = context.new_vrf_story() ?;
        let relay_equivocation_story = context.new_equivocation_story(); 
        let candidates = BTreeMap::new();
        // TODO: Add parachain candidates here maybe ??
        Ok(Tracker { context, current_slot, relay_vrf_story, relay_equivocation_story, candidates, })
    }

    /// Initialize tracking a candidate.
    ///
    /// Invoke this for all desired candidates before invoking
    /// the `into_watcher` or `into_announcer` builders, normally.
    /// Add all candidates from `CandidateEvents`.
    ///
    /// Returns `false` if this invokation reinitalized an
    /// existing candidate, maybe harmless maybe not.
    pub fn initalize_candidate(&mut self, paraid: ParaId) -> bool {
        let candidate = CandidateTracker {
            // TODO: We'll want more nuanced control over initial targets levels.
            targets:   ApprovalTargets::default(),
            checkers:  HashMap::new(),
            relay_vrf_modulo:   AssignmentsByDelay::default(),
            relay_vrf_delay:    AssignmentsByDelay::default(),
            relay_equivocation: AssignmentsByDelay::default(),
        };
        self.candidates.insert(paraid,candidate).is_none() 
    }

    pub fn context(&self) -> &ApprovalContext { &self.context }

    pub(super) fn access_story<C>(&self) -> &C::Story
    where C: Criteria, Assignment<C>: Position,
    {
        use core::any::Any;
        (&self.relay_vrf_story as &dyn Any).downcast_ref::<C::Story>()
        .or( (&self.relay_equivocation_story as &dyn Any).downcast_ref::<C::Story>() )
        .expect("Oops, we've some foreign type as Criteria::Story!")
    }

    /// Read individual candidate's tracker
    ///
    /// Useful for `targets` and maybe `is_approved_before` methods of `CandidateTracker`.
    pub fn candidate(&self, paraid: &ParaId) -> AssignmentResult<&CandidateTracker>
    {
        self.candidates.get(paraid)
            .ok_or(Error::BadAssignment("Absent ParaId"))
    }

    /// Access individual candidate's tracker mutably
    ///
    /// Useful for `approve` method of `CandidateTracker`.
    pub fn candidate_mut(&mut self, paraid: &ParaId) -> AssignmentResult<&mut CandidateTracker> {
        self.candidates.get_mut(paraid)
            .ok_or(Error::BadAssignment("Absent ParaId"))
    }

    /// Insert assignment verified elsewhere
    pub(super) fn insert_assignment<C>(&mut self, a: Assignment<C>, mine: bool) -> AssignmentResult<()> 
    where C: Criteria, Assignment<C>: Position,
    {
        let checker = a.checker().clone();
        let paraid = a.paraid(&self.context)
            .ok_or(Error::BadAssignment("Insert attempted on missing ParaId.")) ?;
        // let candidate = self.candidate_mut(&paraid);
        let candidate = self.candidates.get_mut(&paraid)
            .ok_or(Error::BadAssignment("Absent ParaId")) ?;
        // We must handle some duplicate assignments because checkers
        // could be assigned under both RelayVRF* and RelayEquivocation
        if let Some(cs) = candidate.checkers.get_mut(&checker) { 
            if cs.mine != mine {
                return Err(Error::BadAssignment("Attempted inserting assignment with disagreement over it being mine!"));
            }
        }
        candidate.access_criteria_mut::<C>().insert_assignment_checked(a,&self.context) ?;
        candidate.checkers.entry(checker).or_insert(CheckerStatus { approved: false, mine, });
        Ok(())        
    }

    /// Verify an assignments signature without inserting
    pub(super) fn verify_only<C>(&self, a: &AssignmentSigned<C>)
     -> AssignmentResult<Assignment<C>> 
    where C: Criteria, Assignment<C>: Position,
    {
        let (context,a) = a.verify(self.access_story::<C>(), self.current_delay_tranche()) ?;
        if *context != self.context { 
            return Err(Error::BadAssignment("Incorrect ApprovalContext"));
        }
        Ok(a)
    }

    /// Insert an assignment after verifying its signature 
    pub(super) fn verify_and_insert<C>(
        &mut self, 
        a: &AssignmentSigned<C>, 
        myself: Option<ValidatorId>)
     -> AssignmentResult<()> 
    where C: Criteria, Assignment<C>: Position,
    {
        if myself.as_ref() == Some(a.checker()) {
            return Err(Error::BadAssignment("Attempted verification of my own "));
        }
        let a = self.verify_only(a) ?;
        self.insert_assignment(a,false)
    }

    pub fn current_anv_slot(&self) -> u64 { self.current_slot }

    pub fn delay_tranche(&self, slot: u64) -> Option<DelayTranche> {
        let slot = slot.checked_sub( self.context.anv_slot_number() ) ?;
        u32::try_from( max(slot, self.context.num_delay_tranches() as u64 - 1) ).ok()
    }

    pub fn current_delay_tranche(&self) -> DelayTranche {
        self.delay_tranche( self.current_slot )
        .expect("We initialise current_slot to context.anv_slot_number and then always increased it afterwards, qed")
    }

    /*
    pub fn current_noshow_delay_tranche(&self) -> DelayTranche {
        self.current_delay_tranche()
            .saturating_sub( stories::NOSHOW_DELAY_TRANCHES )
    }
    */

    /// Ask if all candidates are approved
    pub fn is_approved(&self) -> bool {
        let now = self.current_delay_tranche();
        self.candidates.iter().all( |(_paraid,c)| c.is_approved_before(now) )
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
    /// Advances the AnV slot aka time to the specified value. 
    pub fn advance_anv_slot(&mut self, slot: u64) {
        self.tracker.current_slot = max(self.tracker.current_slot, slot);
    }

    /// Insert an assignment notice after verifying its signature 
    pub fn import_others(&mut self, a: &[u8]) -> AssignmentResult<()> {
        unimplemented!();  // deserialize
    }

}
