//! SBO reservations: which connection holds a control object, under which
//! control number, and until when.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::model::{AddCause, ObjectReference};

use super::ConnId;

/// How long an SBO reservation is held without an operate.
pub const SELECT_TIMEOUT: Duration = Duration::from_secs(30);

/// An active SBO reservation of a control object.
#[derive(Debug, Clone)]
struct Selection {
    conn: ConnId,
    expiry: Instant,
    /// The control number the select carried.
    ///
    /// `None` for the SBO read form, which has no parameters to carry one; the
    /// SBOw form always does.
    ctl_num: Option<u8>,
}

/// The table of live reservations.
#[derive(Debug, Default)]
pub struct Selections {
    active: HashMap<ObjectReference, Selection>,
}

impl Selections {
    /// Reserves a control object for a connection, recording the control
    /// number an operate will have to repeat.
    ///
    /// Returns false when another client holds a live reservation, which is
    /// the whole point of select-before-operate.
    pub fn reserve(
        &mut self,
        reference: &ObjectReference,
        conn: ConnId,
        ctl_num: Option<u8>,
        now: Instant,
    ) -> bool {
        if let Some(sel) = self.active.get(reference) {
            if sel.conn != conn && now < sel.expiry {
                return false;
            }
        }
        self.active.insert(
            reference.clone(),
            Selection {
                conn,
                expiry: now + SELECT_TIMEOUT,
                ctl_num,
            },
        );
        true
    }

    /// Validates an operate against the reservation held for `reference`.
    ///
    /// IEC 61850-7-2 has one control sequence carry one control number: the
    /// operate must come from the connection that selected the object and must
    /// repeat the select's number, or it belongs to some other sequence and
    /// the server must not execute it.
    pub fn check_operate(
        &self,
        reference: &ObjectReference,
        conn: ConnId,
        ctl_num: u8,
        now: Instant,
    ) -> AddCause {
        let Some(sel) = self.active.get(reference) else {
            return AddCause::OBJECT_NOT_SELECTED;
        };
        if sel.conn != conn || now >= sel.expiry {
            return AddCause::OBJECT_NOT_SELECTED;
        }
        match sel.ctl_num {
            Some(n) if n != ctl_num => AddCause::INCONSISTENT_PARAMETERS,
            _ => AddCause::NONE,
        }
    }

    /// Validates a cancel the same way, except that cancelling when nothing is
    /// reserved is allowed: a direct control has no reservation to name, and
    /// there is nothing to protect.
    pub fn check_cancel(
        &self,
        reference: &ObjectReference,
        conn: ConnId,
        ctl_num: u8,
        now: Instant,
    ) -> AddCause {
        let Some(sel) = self.active.get(reference) else {
            return AddCause::NONE;
        };
        if now >= sel.expiry {
            return AddCause::NONE;
        }
        if sel.conn != conn {
            // Another client holds it; its sequence is not this one's to end.
            return AddCause::OBJECT_NOT_SELECTED;
        }
        match sel.ctl_num {
            Some(n) if n != ctl_num => AddCause::INCONSISTENT_PARAMETERS,
            _ => AddCause::NONE,
        }
    }

    /// Releases any reservation of `reference`, after an operate or cancel.
    pub fn clear(&mut self, reference: &ObjectReference) {
        self.active.remove(reference);
    }

    /// Drops every reservation held by a closing connection.
    pub fn release_conn(&mut self, conn: ConnId) {
        self.active.retain(|_, sel| sel.conn != conn);
    }

    /// Returns how many reservations are held, for diagnostics.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.active.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ConnId = ConnId(1);
    const B: ConnId = ConnId(2);

    fn reference() -> ObjectReference {
        ObjectReference::new("ied1LD0/GGIO1.SPCSO1")
    }

    #[test]
    fn a_reservation_excludes_another_client_until_it_expires() {
        let mut s = Selections::default();
        let now = Instant::now();
        let r = reference();

        assert!(s.reserve(&r, A, Some(1), now));
        assert!(!s.reserve(&r, B, Some(1), now), "B must not steal A's select");
        // A may re-select its own reservation, which is how a retry works.
        assert!(s.reserve(&r, A, Some(2), now));

        // Once it has expired, anyone may take it.
        let later = now + SELECT_TIMEOUT + Duration::from_secs(1);
        assert!(s.reserve(&r, B, Some(1), later));
    }

    /// An operate from a connection that did not select the object is the
    /// case select-before-operate exists to prevent.
    #[test]
    fn an_operate_from_the_wrong_connection_is_refused() {
        let mut s = Selections::default();
        let now = Instant::now();
        let r = reference();
        s.reserve(&r, A, Some(5), now);

        assert_eq!(s.check_operate(&r, A, 5, now), AddCause::NONE);
        assert_eq!(
            s.check_operate(&r, B, 5, now),
            AddCause::OBJECT_NOT_SELECTED
        );
    }

    /// One control sequence carries one control number; an operate quoting a
    /// different one belongs to another sequence.
    #[test]
    fn an_operate_with_the_wrong_control_number_is_refused() {
        let mut s = Selections::default();
        let now = Instant::now();
        let r = reference();
        s.reserve(&r, A, Some(5), now);

        assert_eq!(
            s.check_operate(&r, A, 6, now),
            AddCause::INCONSISTENT_PARAMETERS
        );
        assert_eq!(s.check_operate(&r, A, 5, now), AddCause::NONE);
    }

    /// The normal-security SBO read carries no control number, so the operate
    /// that follows is checked on the reservation alone.
    #[test]
    fn a_select_without_a_control_number_accepts_any_operate_number() {
        let mut s = Selections::default();
        let now = Instant::now();
        let r = reference();
        s.reserve(&r, A, None, now);

        assert_eq!(s.check_operate(&r, A, 0, now), AddCause::NONE);
        assert_eq!(s.check_operate(&r, A, 42, now), AddCause::NONE);
        assert_eq!(
            s.check_operate(&r, B, 42, now),
            AddCause::OBJECT_NOT_SELECTED
        );
    }

    #[test]
    fn an_operate_after_the_reservation_expires_is_refused() {
        let mut s = Selections::default();
        let now = Instant::now();
        let r = reference();
        s.reserve(&r, A, Some(1), now);

        let later = now + SELECT_TIMEOUT + Duration::from_millis(1);
        assert_eq!(
            s.check_operate(&r, A, 1, later),
            AddCause::OBJECT_NOT_SELECTED
        );
    }

    #[test]
    fn an_operate_with_no_reservation_at_all_is_refused() {
        let s = Selections::default();
        assert_eq!(
            s.check_operate(&reference(), A, 1, Instant::now()),
            AddCause::OBJECT_NOT_SELECTED
        );
    }

    /// A direct control has no reservation to name, so cancelling one is not
    /// an error.
    #[test]
    fn cancelling_an_unreserved_object_is_allowed() {
        let s = Selections::default();
        assert_eq!(
            s.check_cancel(&reference(), A, 1, Instant::now()),
            AddCause::NONE
        );
    }

    #[test]
    fn cancelling_another_clients_selection_is_refused() {
        let mut s = Selections::default();
        let now = Instant::now();
        let r = reference();
        s.reserve(&r, A, Some(3), now);

        assert_eq!(
            s.check_cancel(&r, B, 3, now),
            AddCause::OBJECT_NOT_SELECTED
        );
        assert_eq!(
            s.check_cancel(&r, A, 9, now),
            AddCause::INCONSISTENT_PARAMETERS
        );
        assert_eq!(s.check_cancel(&r, A, 3, now), AddCause::NONE);
    }

    #[test]
    fn clearing_and_disconnecting_release_reservations() {
        let mut s = Selections::default();
        let now = Instant::now();
        let r1 = ObjectReference::new("LD/GGIO1.SPCSO1");
        let r2 = ObjectReference::new("LD/GGIO1.SPCSO2");
        s.reserve(&r1, A, Some(1), now);
        s.reserve(&r2, B, Some(1), now);
        assert_eq!(s.len(), 2);

        s.clear(&r1);
        assert_eq!(s.len(), 1);

        // A dropped connection must not leave an object locked forever.
        s.release_conn(B);
        assert!(s.is_empty());
    }
}
