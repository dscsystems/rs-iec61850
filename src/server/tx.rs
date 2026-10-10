use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use crate::mms::{TimeQuality, Value};
use crate::model::{Fc, Model, ObjectReference, Quality, TrgOps};

/// The leaves an update wrote and the trigger reasons each write raised.
///
/// A leaf is keyed by reference and functional constraint: the same reference
/// can exist under several constraints, and a change under CF is no change to
/// a dataset member under ST.
pub(crate) type ChangeSet = BTreeMap<(ObjectReference, Fc), TrgOps>;

/// Notes a write of `new` over `old` to a leaf with trigger options `trg`.
///
/// It raises the attribute's dchg or qchg when the value changed and its dupd
/// whenever it was written (IEC 61850-7-2); an attribute without trigger
/// options, a timestamp for one, raises nothing.
pub(crate) fn record(
    changes: &mut ChangeSet,
    reference: ObjectReference,
    fc: Fc,
    trg: TrgOps,
    old: Option<&Value>,
    new: &Value,
) {
    let mut r = trg.0 & TrgOps::DATA_UPDATE.0;
    if old != Some(new) {
        r |= trg.0 & (TrgOps::DATA_CHANGE.0 | TrgOps::QUALITY_CHANGE.0);
    }
    changes.entry((reference, fc)).or_insert(TrgOps(0)).0 |= r;
}

/// The quality of the server's clock, stamped on every time the server
/// produces.
///
/// It holds the quality plus one, so that zero means "not set" and every
/// quality octet, 0 included, can be stored.
#[derive(Debug, Default)]
pub(crate) struct Clock(AtomicU32);

impl Clock {
    pub(crate) fn set(&self, q: TimeQuality) {
        self.0.store(u32::from(q.0) + 1, Ordering::Relaxed);
    }

    /// The quality the server stamps its times with: what was set, else
    /// [`TimeQuality::DEFAULT`].
    pub(crate) fn quality(&self) -> TimeQuality {
        match self.0.load(Ordering::Relaxed) {
            0 => TimeQuality::DEFAULT,
            v => TimeQuality((v - 1) as u8),
        }
    }

    /// The current time as a `UtcTime` carrying the server's clock quality.
    pub(crate) fn now(&self) -> Value {
        Value::utc_time(SystemTime::now(), self.quality())
    }
}

/// An in-progress atomic model update.
///
/// Its methods mutate leaf data attribute values; they take effect together
/// when the update returns, and drive any reports whose dataset includes the
/// changed attributes.
#[derive(Debug)]
pub struct Tx<'a> {
    pub(crate) model: &'a mut Model,
    pub(crate) changed: ChangeSet,
    pub(crate) clock: Arc<Clock>,
}

impl<'a> Tx<'a> {
    #[cfg(test)]
    pub(crate) fn new(model: &'a mut Model) -> Tx<'a> {
        Tx::with_clock(model, Arc::new(Clock::default()))
    }

    pub(crate) fn with_clock(model: &'a mut Model, clock: Arc<Clock>) -> Tx<'a> {
        Tx {
            model,
            changed: ChangeSet::new(),
            clock,
        }
    }

    /// Returns the current time as a `UtcTime` value carrying the server's
    /// clock quality ([`Server::set_time_quality`](super::Server::set_time_quality)),
    /// for a caller that sets a timestamp through [`set`](Tx::set).
    pub fn now(&self) -> Value {
        self.clock.now()
    }

    /// Returns the current value of the leaf attribute at `reference`.
    ///
    /// Use this rather than [`Server::read`](super::Server::read) inside an
    /// update: the server's read takes the model lock, which the update
    /// already holds.
    pub fn get(&self, reference: impl Into<ObjectReference>, fc: Fc) -> Option<&Value> {
        self.model
            .attribute(&reference.into(), fc)
            .and_then(|da| da.value.as_ref())
    }

    /// Assigns a value to the leaf attribute at `reference`.
    ///
    /// Returns whether the attribute existed and was a leaf. Structured
    /// attributes are written through their members, so a write to one is
    /// refused rather than silently dropping the parts that did not match.
    pub fn set(
        &mut self,
        reference: impl Into<ObjectReference>,
        fc: Fc,
        v: Value,
    ) -> bool {
        let reference = reference.into();
        let Some(da) = self.model.attribute_mut(&reference, fc) else {
            tracing::warn!(%reference, %fc, "server: update to an unknown attribute");
            return false;
        };
        if !da.children.is_empty() {
            tracing::warn!(%reference, %fc, "server: update to a structured attribute");
            return false;
        }
        let old = da.value.replace(v);
        let trg = da.trg_ops;
        let new = da.value.as_ref().expect("just set");
        record(&mut self.changed, reference, fc, trg, old.as_ref(), new);
        true
    }

    /// Flips a boolean leaf attribute and returns the new value.
    pub fn toggle(&mut self, reference: impl Into<ObjectReference>, fc: Fc) -> bool {
        let reference = reference.into();
        let on = !self.get(reference.clone(), fc).is_some_and(Value::as_bool);
        self.set(reference, fc, Value::boolean(on));
        on
    }

    /// Sets a float measurand, under `MX` by convention.
    pub fn set_float32(&mut self, reference: impl Into<ObjectReference>, v: f32) -> bool {
        self.set(reference, Fc::Mx, Value::float32(v))
    }

    /// Sets a boolean status value, under `ST` by convention.
    pub fn set_bool(&mut self, reference: impl Into<ObjectReference>, v: bool) -> bool {
        self.set(reference, Fc::St, Value::boolean(v))
    }

    /// Sets an integer value under the given constraint.
    pub fn set_int32(
        &mut self,
        reference: impl Into<ObjectReference>,
        fc: Fc,
        v: i32,
    ) -> bool {
        self.set(reference, fc, Value::int32(v))
    }

    /// Sets a quality attribute, under `MX` or `ST`.
    pub fn set_quality(
        &mut self,
        reference: impl Into<ObjectReference>,
        fc: Fc,
        q: Quality,
    ) -> bool {
        self.set(reference, fc, q.value())
    }

    /// Sets a `UtcTime` attribute to the current time, stamped with the
    /// server's clock quality.
    pub fn set_timestamp_now(
        &mut self,
        reference: impl Into<ObjectReference>,
        fc: Fc,
    ) -> bool {
        let now = self.clock.now();
        self.set(reference, fc, now)
    }

    /// Sets a `UtcTime` attribute to an explicit time, stamped with the
    /// server's clock quality.
    pub fn set_timestamp(
        &mut self,
        reference: impl Into<ObjectReference>,
        fc: Fc,
        t: SystemTime,
    ) -> bool {
        let q = self.clock.quality();
        self.set(reference, fc, Value::utc_time(t, q))
    }

    /// Returns the references this transaction has written so far.
    pub fn changed(&self) -> std::collections::BTreeSet<ObjectReference> {
        self.changed.keys().map(|(r, _)| r.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scl;

    fn model() -> Model {
        scl::load_model(
            concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/simpleIO_direct_control.cid"),
            &scl::BuildOptions::new(),
        )
        .expect("the reference CID loads")
    }

    /// The first logical device of the reference model, for building
    /// references without hard-coding the IED name.
    fn ld_name(m: &Model) -> String {
        m.devices[0].name.clone()
    }

    #[test]
    fn setting_a_leaf_records_it_as_changed() {
        let mut m = model();
        let ld = ld_name(&m);
        let mut tx = Tx::new(&mut m);
        let r = format!("{ld}/GGIO1.AnIn1.mag.f");

        assert!(tx.set_float32(r.clone(), 230.4));
        assert_eq!(tx.get(r.clone(), Fc::Mx).unwrap().as_f32(), 230.4);
        assert!(tx.changed().contains(&ObjectReference::new(r)));
    }

    #[test]
    fn an_unknown_reference_changes_nothing() {
        let mut m = model();
        let ld = ld_name(&m);
        let mut tx = Tx::new(&mut m);
        assert!(!tx.set_float32(format!("{ld}/GGIO1.Nope.mag.f"), 1.0));
        assert!(!tx.set_bool("nodevice/GGIO1.Ind1.stVal", true));
        assert!(tx.changed().is_empty());
    }

    /// A structured attribute is written through its members; accepting the
    /// parent would drop whatever did not match its shape.
    #[test]
    fn a_structured_attribute_is_not_directly_settable() {
        let mut m = model();
        let ld = ld_name(&m);
        let mut tx = Tx::new(&mut m);
        assert!(
            !tx.set(format!("{ld}/GGIO1.AnIn1.mag"), Fc::Mx, Value::float32(1.0)),
            "mag is a structure"
        );
        assert!(tx.changed().is_empty());
    }

    #[test]
    fn toggle_flips_a_boolean_and_reports_the_new_value() {
        let mut m = model();
        let ld = ld_name(&m);
        let mut tx = Tx::new(&mut m);
        let r = format!("{ld}/GGIO1.Ind1.stVal");

        let first = tx.toggle(r.clone(), Fc::St);
        assert_eq!(tx.get(r.clone(), Fc::St).unwrap().as_bool(), first);
        let second = tx.toggle(r.clone(), Fc::St);
        assert_eq!(second, !first);
        assert_eq!(tx.get(r, Fc::St).unwrap().as_bool(), second);
    }

    #[test]
    fn quality_and_timestamp_helpers_write_the_right_shapes() {
        let mut m = model();
        let ld = ld_name(&m);
        let mut tx = Tx::new(&mut m);

        let q_ref = format!("{ld}/GGIO1.AnIn1.q");
        assert!(tx.set_quality(
            q_ref.clone(),
            Fc::Mx,
            Quality::GOOD | Quality::OLD_DATA
        ));
        let v = tx.get(q_ref, Fc::Mx).unwrap();
        assert_eq!(v.bit_len(), 13);
        assert!(Quality::from_value(v).is(Quality::OLD_DATA));

        let t_ref = format!("{ld}/GGIO1.AnIn1.t");
        assert!(tx.set_timestamp_now(t_ref.clone(), Fc::Mx));
        let v = tx.get(t_ref, Fc::Mx).unwrap();
        assert_eq!(v.type_of(), crate::mms::Type::UtcTime);
        assert!(v.time().is_some());
    }

    #[test]
    fn several_changes_accumulate_into_one_change_set() {
        let mut m = model();
        let ld = ld_name(&m);
        let mut tx = Tx::new(&mut m);
        tx.set_float32(format!("{ld}/GGIO1.AnIn1.mag.f"), 1.0);
        tx.set_float32(format!("{ld}/GGIO1.AnIn2.mag.f"), 2.0);
        tx.set_bool(format!("{ld}/GGIO1.Ind1.stVal"), true);
        assert_eq!(tx.changed().len(), 3);

        // Writing the same reference twice records it once.
        tx.set_float32(format!("{ld}/GGIO1.AnIn1.mag.f"), 3.0);
        assert_eq!(tx.changed().len(), 3);
    }
}
