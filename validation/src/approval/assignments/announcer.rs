//! Announcer for our own approval checking assignments
//!
//! 

use core::{ ops };
use std::collections::{BTreeMap, HashSet, HashMap};

use schnorrkel::{Keypair};

use super::{
    ApprovalContext, AssigneeStatus, AssignmentResult, Hash, ParaId,
    DelayTranche, 
    stories,
    criteria::{self, Assignment, AssignmentSigned, Criteria, DelayCriteria, Position},
    tracker::{self, AssignmentsByDelay, Tracker},
    ValidatorId,
};


impl Tracker {
    /// Initialize tracking of both our own and others assignments and approvals
    pub fn into_announcer(self, myself: Keypair) -> AssignmentResult<Announcer> {
        let mut tracker = self;
        let mut announced_relay_vrf_modulo = AssignmentsSigned::default();
        for sample in 0..tracker.context().num_samples() {
            let a = Assignment::create(
                criteria::RelayVRFModulo { sample }, 
                &tracker.relay_vrf_story, // tracker.access_story::<criteria::RelayVRFModulo>()
                &myself,
            ).expect("RelayVRFModulo cannot error here");
            let context = tracker.context().clone();
            // We sample incorrect `ParaId`s here sometimes so just skip them.
            if let Some(paraid) = a.paraid(&context) {
                // Add eah paraid only once.
                if announced_relay_vrf_modulo.0.contains_key(&paraid) { continue; }
                let recieved = 0; // TODO: Allow for late announcement
                let a = a.sign(&context, &myself, recieved);
                let a_signed = a.to_signed(context);
                tracker.insert_assignment(a,true) ?;
                announced_relay_vrf_modulo.0.insert(paraid,a_signed);
            }
        }
        let mut selfy = Announcer { 
            tracker,  myself,
            announced_relay_vrf_modulo,
            announced_relay_vrf_delay:     AssignmentsSigned::default(),
            announced_relay_equivocation:  AssignmentsSigned::default(),
            pending_relay_vrf_delay:       AssignmentsByDelay::default(),
            pending_relay_equivocation:   AssignmentsByDelay::default(),
        };
        for paraid in selfy.tracker.context().paraids_by_core().clone().iter().filter_map(Option::as_ref) {
            selfy.create_pending(criteria::RelayVRFDelay { paraid: *paraid })
                .expect("Assignment::create cannot fail for RelayVRFDelay, only RelayEquivocation, qed");
        }
        Ok(selfy)
    }
}


pub struct AssignmentsSigned<C: Criteria>(BTreeMap<ParaId, AssignmentSigned<C> >);

impl<C: Criteria> Default for AssignmentsSigned<C> {
    fn default() -> Self { AssignmentsSigned(Default::default()) }
}

// TODO: Access/output/serializtion methods, 
// impl<C: Criteria> AssignmentsSigned<C> { }


/// Track both our own and others assignments and approvals
pub struct Announcer {
    /// Inheret the `Tracker` that built us
    tracker: Tracker,
    /// We require secret key access to invoke creation and signing of VRFs
    ///
    /// TODO: Actually substrate manages this another way, so change this part.
    myself: Keypair,
    // /// Unannounced potential assignments with delay determined by relay chain VRF
    // /// TODO: We'll need this once we add functionality to delay work
    // pending_relay_vrf_modulo: AssignmentsByDelay<criteria::RelayVRFDelay,()>,
    /// Unannounced potential assignments with delay determined by relay chain VRF
    pending_relay_vrf_delay: AssignmentsByDelay<criteria::RelayVRFDelay,()>,
    /// Unannounced potential assignments with delay determined by candidate equivocation
    pending_relay_equivocation: AssignmentsByDelay<criteria::RelayEquivocation,()>,
    /// Already announced assignments with determined by relay chain VRF 
    announced_relay_vrf_modulo: AssignmentsSigned<criteria::RelayVRFModulo>,
    /// Already announced assignments with delay determined by relay chain VRF
    announced_relay_vrf_delay: AssignmentsSigned<criteria::RelayVRFDelay>,
    /// Already announced assignments with delay determined by candidate equivocation
    announced_relay_equivocation: AssignmentsSigned<criteria::RelayEquivocation>,
}

impl ops::Deref for Announcer {
    type Target = Tracker;
    fn deref(&self) -> &Tracker { &self.tracker }
}
impl ops::DerefMut for Announcer {
    fn deref_mut(&mut self) -> &mut Tracker { &mut self.tracker }
}

impl Announcer {
    fn access_pending_mut<C>(&mut self) -> &mut AssignmentsByDelay<C,()>
    where C: DelayCriteria, Assignment<C>: Position,
    {
        use core::any::Any;
        (&mut self.pending_relay_vrf_delay as &mut dyn Any)
            .downcast_mut::<AssignmentsByDelay<C,()>>()
        .or( (&mut self.pending_relay_equivocation as &mut dyn Any)
            .downcast_mut::<AssignmentsByDelay<C,()>>() )
        .expect("Oops, we've some foreign type or RelayVRFDelay as DelayCriteria!")
    }

    fn create_pending<C>(&mut self, criteria: C) -> AssignmentResult<()>
    where C: DelayCriteria, Assignment<C>: Position,
    {
        let context = self.tracker.context().clone();
        // We skip absent `ParaId`s when creating any pending assignemnts without error, but..
        if context.core_by_paraid( criteria.paraid() ).is_none() { return Ok(()); }
        let a = Assignment::create(criteria, self.tracker.access_story::<C>(), &self.myself) ?;
        self.access_pending_mut::<C>().insert_assignment_unchecked(a, &context);
        Ok(())
    }

    fn id(&self) -> ValidatorId {
        criteria::validator_id_from_key(&self.myself.public)
    }

    /// Access outgoing announcement set immutably
    pub(super) fn access_announced<C>(&mut self) -> &AssignmentsSigned<C>
    where C: DelayCriteria, Assignment<C>: Position,
    {
        use core::any::Any;
        (&self.announced_relay_vrf_modulo as &dyn Any).downcast_ref::<AssignmentsSigned<C>>()
        .or( (&self.announced_relay_vrf_delay as &dyn Any).downcast_ref::<AssignmentsSigned<C>>() )
        .or( (&self.announced_relay_equivocation as &dyn Any).downcast_ref::<AssignmentsSigned<C>>() )
        .expect("Oops, we've some foreign type as Criteria!")
    }

    /// Access outgoing announcements set mutably 
    pub(super) fn access_announced_mut<C>(&mut self) -> &mut AssignmentsSigned<C>
    where C: DelayCriteria, Assignment<C>: Position,
    {
        use core::any::Any;
        (&mut self.announced_relay_vrf_modulo as &mut dyn Any)
            .downcast_mut::<AssignmentsSigned<C>>()
        .or( (&mut self.announced_relay_vrf_delay as &mut dyn Any)
            .downcast_mut::<AssignmentsSigned<C>>() )
        .or( (&mut self.announced_relay_equivocation as &mut dyn Any)
            .downcast_mut::<AssignmentsSigned<C>>() )
        .expect("Oops, we've some foreign type as Criteria!")
    }

    /// Announce any unannounced assignments from the given tranche
    /// as filtered by the provided closure.
    ///
    /// TODO: It'll be more efficent to operate on ranges here
    fn announce_pending_with<'a,C,F>(&'a mut self, tranche: DelayTranche, f: F)
    where C: DelayCriteria, Assignment<C>: Position,
          F: 'a + FnMut(&Assignment<C,()>) -> bool,
    {
        let mut vs: Vec<Assignment<C,()>> = self.access_pending_mut::<C>()
            .drain_filter(tranche..tranche+1,f).collect();
        for a in vs {
            let context = self.tracker.context().clone();
            let recieved = self.tracker.current_delay_tranche();
            let paraid = a.paraid(&context)
                .expect("Announcing assignment for `ParaId` not assigned to any core.");
            let a = a.sign(&context, &self.myself, recieved);
            let a_signed = a.to_signed(context);
            // Importantly `insert_assignment` computes delay tranche
            // from the assignment which determines priority.  We may
            // have extra delay in `a.vrf_signature.recieved` which
            // only determines when it becomes a no show.
            self.tracker.insert_assignment(a,true)
            .expect("First, we insert only for paraids assigned to cores here because this assignment gets fixed by the relay chain block.  Second, we restrict each criteria to doing only one assignment per paraid, so we cannot find any duplicates.  Also, we've already removed the pending assignment above, making `candidate.checkers` empty.");
            self.access_announced_mut::<C>().0.insert(paraid,a_signed);
        }
    }

    /// Announce any unannounced assignments from the given tranche
    /// as filtered by the provided closure.
    /// 
    fn announce_pending_from_assignees<C>(
        &mut self, 
        tranche: DelayTranche,
        context: &ApprovalContext,
        assignees: &mut HashMap<ParaId,AssigneeStatus>
    )
    where C: DelayCriteria, Assignment<C>: Position,
    {
        self.announce_pending_with::<criteria::RelayVRFDelay,_>(tranche,
            |a| if let Some(paraid) = a.paraid(context) {
                let b = assignees.get(&paraid)
                // We admit a.delay_tranche() < tranche here because
                // `self.pending_*` could represent posponed work.
                .filter( |c| a.delay_tranche(context) <= c.tranche().unwrap() )
                .is_some();
                if b { assignees.remove(&paraid); }
                b
            } else { false }
        )
    }

    /// Advances the AnV slot aka time to the specified value,
    /// enquing any pending announcements too.
    pub fn advance_anv_slot(&mut self, new_slot: u64) {
        // We allow rerunning this with the current slot rightn ow, but..
        if new_slot < self.tracker.current_slot { return; }

        let new_delay_tranche = self.delay_tranche(new_slot)
            .expect("new_slot > current_slot > context.anv_slot_number");
        let now = self.current_delay_tranche();
        // let myself = self.id();

        // We first reconstruct the current assignee status for any unapproved
        // sessions, including all current announcements.
        let mut relay_vrf_assignees = HashMap::new();
        let mut relay_equivocation_assignees = HashMap::new();
        for (paraid,candidate) in self.tracker.candidates() {
            // We cannot skip previously approved checks here because 
            // we could announce ourself as RelayEquivocation checkers
            // even after fulfilling a RelayVRF assignment.  Yet, we'd
            // love something like this, maybe two announced flags.
            // if candidate.is_approved_by_checker(&myself) { continue; }

            let c = candidate.assignee_status::<stories::RelayVRFStory>(now);
            if ! c.is_approved() { relay_vrf_assignees.insert(*paraid,c); }
            let c = candidate.assignee_status::<stories::RelayEquivocationStory>(now);
            if ! c.is_approved() { relay_equivocation_assignees.insert(*paraid,c); }
        }

        let context = self.tracker.context().clone();
        for tranche in 0..now {
            // self.announce_pending_from_assignees::<criteria::RelayVRFModulo>
            //     (tranche, &context, &mut relay_vrf_assignees);
            self.announce_pending_from_assignees::<criteria::RelayVRFDelay>
                (tranche, &context, &mut relay_vrf_assignees);
            self.announce_pending_from_assignees::<criteria::RelayEquivocation>
                (tranche, &context, &mut relay_equivocation_assignees);
            // We avoid recomputing assignee statuses inside this loop
            // becuase we never check any given candidate more than once
        }
    }

    /// Mark myself as approving this candiddate
    pub fn approve_mine(&mut self, paraid: &ParaId) -> AssignmentResult<()> {
        let myself = self.id();
        self.tracker.candidate_mut(paraid)?.approve(myself, true) ?;
        // TODO: We could restrict this to the current paraid of course.
        self.advance_anv_slot(self.tracker.current_slot);
        Ok(())
    }

}

