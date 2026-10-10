//! Sampled-value control blocks (IEC 61850-7-2 clause 16, mapped by
//! IEC 61850-8-1/9-2).
//!
//! They are live: a client enables an MSVCB or a USVCB with `SvEna` and
//! reserves a USVCB with `Resv`. The IEC 61850-9-2 mapping makes only those two
//! writable, as libiec61850 does; the rest of a block is its configuration. A
//! reserved USVCB belongs to the association that reserved it, and every other
//! one is refused with temporarily-unavailable until it is released, by
//! writing `Resv` false or by the association ending, which also disables the
//! block, since the stream was that client's.
//!
//! The server does not publish the samples itself: which values are sampled,
//! at what rate and from which clock is the application's. It hears of every
//! change through [`Server::on_sv_control`](super::Server::on_sv_control) and
//! runs a publisher, for instance [`crate::sv::LePublisher::from_model`],
//! while the block is enabled.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::mms::{DataAccessError, Type, Value};
use crate::model::{Fc, Model, SvControl};

use super::ConnId;

/// A change of a sampled-value control block made by a client or by the end
/// of its association.
#[derive(Debug, Clone)]
pub struct SvControlEvent {
    /// The logical device (MMS domain) of the block.
    pub device: String,
    /// The logical node holding the block.
    pub node: String,
    /// The block's configuration.
    pub block: SvControl,
    /// Set for a USVCB (FC US).
    pub unicast: bool,
    /// `SvEna` after the change.
    pub enabled: bool,
    /// `Resv` after the change; always false for an MSVCB.
    pub reserved: bool,
    /// The association that holds the reservation, `None` when none does. A
    /// unicast stream goes to the block's `DstAddress`; an application that
    /// addresses the reserving client instead finds it here.
    pub conn: Option<ConnId>,
}

/// Receives sampled-value control block changes.
pub type SvControlHandler = std::sync::Arc<dyn Fn(&SvControlEvent) + Send + Sync>;

/// The runtime state of one block.
#[derive(Debug)]
struct SvcbState {
    device: String,
    node: String,
    block: SvControl,
    unicast: bool,
    owner: Option<ConnId>,
}

/// The server's sampled-value control blocks, by `domain\0LN$MS$name` (or
/// `US`).
#[derive(Debug, Default)]
pub(crate) struct SvcbRegistry {
    blocks: Mutex<BTreeMap<String, SvcbState>>,
}

fn key_of(domain: &str, base: &str) -> String {
    format!("{domain}\u{0}{base}")
}

impl SvcbRegistry {
    /// Indexes the blocks the control-block materialisation put in the model.
    pub(crate) fn build(m: &Model) -> SvcbRegistry {
        let mut blocks = BTreeMap::new();
        for ld in &m.devices {
            for ln in &ld.nodes {
                for sc in &ln.sv_controls {
                    let Some(o) = ln
                        .objects
                        .iter()
                        .find(|o| o.name == sc.name && (o.cdc == "MSVCB" || o.cdc == "USVCB"))
                    else {
                        continue;
                    };
                    let unicast = o.cdc == "USVCB";
                    let fc = if unicast { "US" } else { "MS" };
                    blocks.insert(
                        key_of(&ld.name, &format!("{}${fc}${}", ln.name, sc.name)),
                        SvcbState {
                            device: ld.name.clone(),
                            node: ln.name.clone(),
                            block: sc.clone(),
                            unicast,
                            owner: None,
                        },
                    );
                }
            }
        }
        SvcbRegistry {
            blocks: Mutex::new(blocks),
        }
    }

    /// Reports whether `item` (`LN$MS$name[$attr]` or `LN$US$...`) addresses a
    /// sampled-value control block, returning its key and the attribute.
    pub(crate) fn key(&self, domain: &str, item: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = item.split('$').collect();
        if parts.len() < 3 || (parts[1] != "MS" && parts[1] != "US") {
            return None;
        }
        let key = key_of(domain, &parts[..3].join("$"));
        if !self.blocks.lock().unwrap().contains_key(&key) {
            return None;
        }
        Some((key, parts.get(3).copied().unwrap_or("").to_string()))
    }

    /// Decides whether `conn` may write `attr` of a block. Called with the
    /// model write lock held.
    pub(crate) fn check_write(
        &self,
        model: &Model,
        key: &str,
        attr: &str,
        v: &Value,
        conn: ConnId,
    ) -> Result<(), DataAccessError> {
        let blocks = self.blocks.lock().unwrap();
        let st = blocks.get(key).ok_or(DataAccessError::ObjectNonExistent)?;
        if st.owner.is_some_and(|o| o != conn) {
            return Err(DataAccessError::TemporarilyUnavailable);
        }
        if attr == "SvEna" || (attr == "Resv" && st.unicast) {
            if v.type_of() != Type::Boolean {
                return Err(DataAccessError::TypeInconsistent);
            }
            return Ok(());
        }
        if flag(model, st, "SvEna") {
            return Err(DataAccessError::TemporarilyUnavailable);
        }
        Err(DataAccessError::ObjectAccessDenied)
    }

    /// The value of `attr` before a write, to tell a change from a rewrite.
    pub(crate) fn before(&self, model: &Model, key: &str, attr: &str) -> bool {
        let blocks = self.blocks.lock().unwrap();
        blocks.get(key).is_some_and(|st| flag(model, st, attr))
    }

    /// Applies a stored write and returns the event to report, if the block's
    /// state changed. Called with the model write lock held.
    pub(crate) fn on_write(
        &self,
        model: &Model,
        key: &str,
        attr: &str,
        old: bool,
        conn: ConnId,
    ) -> Option<SvControlEvent> {
        let mut blocks = self.blocks.lock().unwrap();
        let st = blocks.get_mut(key)?;
        let now = match attr {
            "SvEna" => flag(model, st, "SvEna"),
            "Resv" => {
                let now = flag(model, st, "Resv");
                st.owner = now.then_some(conn);
                now
            }
            _ => return None,
        };
        (now != old).then(|| event(model, st))
    }

    /// Frees the USVCBs `conn` reserved and disables them, as its association
    /// has ended, returning the changes. Called with the model write lock
    /// held.
    pub(crate) fn release_conn(&self, model: &mut Model, conn: ConnId) -> Vec<SvControlEvent> {
        let mut out = Vec::new();
        let mut blocks = self.blocks.lock().unwrap();
        for st in blocks.values_mut() {
            if st.owner != Some(conn) {
                continue;
            }
            st.owner = None;
            set_flag(model, st, "Resv", false);
            set_flag(model, st, "SvEna", false);
            out.push(event(model, st));
        }
        out
    }
}

fn fc_of(st: &SvcbState) -> Fc {
    if st.unicast {
        Fc::Us
    } else {
        Fc::Ms
    }
}

fn flag(model: &Model, st: &SvcbState, name: &str) -> bool {
    model
        .device(&st.device)
        .and_then(|ld| ld.node(&st.node))
        .and_then(|ln| ln.object(&st.block.name))
        .and_then(|o| o.attributes.iter().find(|a| a.name == name && a.fc == fc_of(st)))
        .and_then(|a| a.value.as_ref())
        .is_some_and(|v| v.as_bool())
}

fn set_flag(model: &mut Model, st: &SvcbState, name: &str, on: bool) {
    let fc = fc_of(st);
    if let Some(a) = model
        .device_mut(&st.device)
        .and_then(|ld| ld.node_mut(&st.node))
        .and_then(|ln| ln.object_mut(&st.block.name))
        .and_then(|o| o.attributes.iter_mut().find(|a| a.name == name && a.fc == fc))
    {
        a.value = Some(Value::boolean(on));
    }
}

fn event(model: &Model, st: &SvcbState) -> SvControlEvent {
    SvControlEvent {
        device: st.device.clone(),
        node: st.node.clone(),
        block: st.block.clone(),
        unicast: st.unicast,
        enabled: flag(model, st, "SvEna"),
        reserved: st.unicast && flag(model, st, "Resv"),
        conn: st.owner,
    }
}
