//! Dispatches MMS confirmed requests against the model.

use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use crate::asn1::{
    self, bool_elem, cons, context_constructed, context_primitive, prim, uint_elem, Decoder,
    Element, TAG_GRAPHIC_STRING, TAG_SEQUENCE, TAG_VISIBLE_STRING,
};
use crate::mms::{self, data_element, DataAccessError, Value};
use crate::model::{self, AddCause, CtlModel, Fcda, ObjectReference};

use super::control::{self, Phase};
use super::select::SELECT_TIMEOUT;
use super::rcb;
use super::reporting;
use super::server::Inner;
use super::tx::{self, ChangeSet};
use super::{access, ConnId};

/// MMS confirmed service CHOICE tag numbers.
const SVC_GET_NAME_LIST: u32 = 1;
const SVC_IDENTIFY: u32 = 2;
const SVC_READ: u32 = 4;
const SVC_WRITE: u32 = 5;
const SVC_GET_VARIABLE_ACCESS: u32 = 6;
const SVC_DEFINE_NAMED_VAR_LIST: u32 = 11;
const SVC_GET_NAMED_VAR_LIST_ATTR: u32 = 12;
const SVC_DELETE_NAMED_VAR_LIST: u32 = 13;
const SVC_FILE_OPEN: u32 = 72;
const SVC_FILE_READ: u32 = 73;
const SVC_FILE_CLOSE: u32 = 74;
const SVC_FILE_DELETE: u32 = 76;
const SVC_FILE_DIRECTORY: u32 = 77;

/// The octets a paged response spends around its entries: the confirmed
/// response's tag, length and invokeID, the service and list tags and lengths,
/// and moreFollows.
const PAGE_ENVELOPE: usize = 32;

/// Takes as many of `elements` as fit in a response of `max_pdu` octets (zero
/// for no limit), reporting whether any were left over.
///
/// A page always carries at least one element, or a client could never make
/// progress.
fn fill_page(elements: impl IntoIterator<Item = Element>, max_pdu: usize) -> (Vec<Element>, bool) {
    let budget = max_pdu.saturating_sub(PAGE_ENVELOPE);
    let (mut page, mut used) = (Vec::new(), 0);
    for el in elements {
        if max_pdu > 0 && !page.is_empty() && used + el.size() > budget {
            return (page, true);
        }
        used += el.size();
        page.push(el);
    }
    (page, false)
}

/// Serves one association's requests against the shared server state.
pub struct Handler {
    pub inner: Arc<Inner>,
    pub conn: ConnId,
    /// What the write request in progress changed in the process image,
    /// reported once its writes are all applied.
    pub(crate) changes: Mutex<ChangeSet>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler").field("conn", &self.conn).finish()
    }
}

impl mms::Handler for Handler {
    async fn handle(
        &self,
        req: mms::Request,
        conn: &mms::ServerConn,
    ) -> mms::Result<Element> {
        tracing::debug!(
            service = req.service,
            bytes = req.content.len(),
            "server: request"
        );
        match req.service {
            SVC_IDENTIFY => Ok(self.identity()),
            SVC_GET_NAME_LIST => self.get_name_list(&req.content, conn.max_pdu),
            SVC_READ => self.read(&req.content),
            SVC_WRITE => self.write(&req.content),
            SVC_GET_VARIABLE_ACCESS => self.get_variable_access(&req.content),
            SVC_GET_NAMED_VAR_LIST_ATTR => self.get_nvl_attrs(&req.content),
            SVC_DEFINE_NAMED_VAR_LIST => self.define_nvl(&req.content),
            SVC_DELETE_NAMED_VAR_LIST => self.delete_nvl(&req.content),
            SVC_FILE_OPEN | SVC_FILE_READ | SVC_FILE_CLOSE | SVC_FILE_DELETE
            | SVC_FILE_DIRECTORY => self.file_service(req.service, &req.content, conn.max_pdu),
            _ => Err(mms::Error::Service(mms::ServiceError {
                class: mms::ErrorClass(1),
                code: 1, // unrecognized-service
                rejected: true,
                detail: String::new(),
            })),
        }
    }
}

impl Handler {
    fn identity(&self) -> Element {
        let id = &self.inner.identity;
        cons(
            context_constructed(SVC_IDENTIFY),
            [
                prim(context_primitive(0), id.vendor.as_bytes().to_vec()),
                prim(context_primitive(1), id.model.as_bytes().to_vec()),
                prim(context_primitive(2), id.revision.as_bytes().to_vec()),
            ],
        )
    }

    /// Answers GetNameList one page at a time: as many names as fit in the
    /// association's maximum PDU, with moreFollows telling the client to
    /// continue after the last one.
    fn get_name_list(&self, content: &[u8], max_pdu: usize) -> mms::Result<Element> {
        let mut dec = Decoder::new(content);
        // objectClass [0] { basicObjectClass [0] INTEGER }
        let class_content = dec.expect(context_constructed(0))?;
        let class_bytes = Decoder::new(class_content).expect(context_primitive(0))?;
        let class = asn1::decode_int(class_bytes)?;

        // objectScope [1] CHOICE { vmdSpecific [0] NULL,
        //                          domainSpecific [1] Identifier }
        let mut domain = String::new();
        if let Some(scope) = dec.optional(context_constructed(1))? {
            let mut sd = Decoder::new(scope);
            if let Some(d) = sd.optional(context_primitive(1))? {
                domain = String::from_utf8_lossy(d).into_owned();
            }
        }
        let after = match dec.optional(context_primitive(2))? {
            Some(a) => String::from_utf8_lossy(a).into_owned(),
            None => String::new(),
        };

        let mut names = {
            let model = self.inner.model.read().unwrap();
            enumerate(&model, class, &domain)
        };

        // Apply the continuation point.
        if !after.is_empty() {
            if let Some(i) = names.iter().position(|n| *n == after) {
                names.drain(..=i);
            }
        }
        let (page, more) = fill_page(
            names
                .into_iter()
                .map(|n| prim(TAG_VISIBLE_STRING, n.into_bytes())),
            max_pdu,
        );
        let list = cons(context_constructed(0), page);
        Ok(cons(
            context_constructed(SVC_GET_NAME_LIST),
            [list, bool_elem(context_primitive(1), more)],
        ))
    }

    fn read(&self, content: &[u8]) -> mms::Result<Element> {
        let mut dec = Decoder::new(content);
        // An optional specificationWithResult [0] BOOLEAN precedes the access
        // specification; some clients set it when reading datasets.
        dec.optional(context_primitive(0))?;
        let vas_content = dec.expect(context_constructed(1))?;
        let mut vd = Decoder::new(vas_content);

        let mut results: Vec<Element> = Vec::new();
        if let Some(list_content) = vd.optional(context_constructed(0))? {
            // listOfVariable
            let mut ld = Decoder::new(list_content);
            let mut targets: Vec<Option<(String, String)>> = Vec::new();
            while ld.more() {
                let entry = ld.expect(TAG_SEQUENCE)?;
                targets.push(parse_var_spec(entry).ok());
            }
            for t in targets {
                results.push(match t {
                    Some((domain, item)) => self.read_one(&domain, &item),
                    None => access_failure(DataAccessError::ObjectNonExistent),
                });
            }
        } else if let Some(name_content) = vd.optional(context_constructed(1))? {
            // variableListName: a dataset read.
            let (domain, list) = parse_object_name(name_content)?;
            let members = {
                let model = self.inner.model.read().unwrap();
                reporting::dataset_members(&model, &domain, &list)
            };
            for m in members {
                results.push(self.read_one(&m.domain, &m.item));
            }
        } else {
            return Err(mms::Error::protocol("unsupported read access specification"));
        }
        Ok(cons(
            context_constructed(SVC_READ),
            [cons(context_constructed(1), results)],
        ))
    }

    fn read_one(&self, domain: &str, item: &str) -> Element {
        // Reading an SBO attribute performs the select of a normal-security
        // control: the reservation is taken here, and the object reference
        // comes back on success.
        if let Some((base, Phase::Sbo)) = control::split_control(item) {
            let reference = control::control_ref(domain, &base);
            let (declared, sbo_timeout) = {
                let model = self.inner.model.read().unwrap();
                (
                    control::declared_ctl_model(&model, &reference),
                    control::cf_millis(&model, &reference, "sboTimeout"),
                )
            };
            // Only an SBO-with-normal-security object is selected by reading
            // SBO; an empty name tells the client the select failed.
            if declared.is_some_and(|cm| cm != CtlModel::SboNormal) {
                return data_element(&Value::visible_string(""))
                    .unwrap_or_else(|| access_failure(DataAccessError::ObjectNonExistent));
            }
            let timeout = if sbo_timeout.is_zero() {
                SELECT_TIMEOUT
            } else {
                sbo_timeout
            };
            let taken = self.inner.selections.lock().unwrap().reserve(
                &reference,
                self.conn,
                None,
                timeout,
                Instant::now(),
            );
            let name = if taken { reference.to_string() } else { String::new() };
            return data_element(&Value::visible_string(name))
                .unwrap_or_else(|| access_failure(DataAccessError::ObjectNonExistent));
        }

        let model = self.inner.model.read().unwrap();
        let Some(ld) = model.device(domain) else {
            return access_failure(DataAccessError::ObjectNonExistent);
        };
        let Some(ln) = item.split('$').next().and_then(|n| ld.node(n)) else {
            return access_failure(DataAccessError::ObjectNonExistent);
        };
        match access::resolve_read(ln, item) {
            Some(v) => data_element(&v)
                .unwrap_or_else(|| access_failure(DataAccessError::ObjectNonExistent)),
            None => access_failure(DataAccessError::ObjectNonExistent),
        }
    }

    fn write(&self, content: &[u8]) -> mms::Result<Element> {
        let mut dec = Decoder::new(content);
        // WriteRequest: the access specification (an untagged CHOICE, so the
        // listOfVariable [0] tag shows through), then listOfData [0].
        let list_content = dec.expect(context_constructed(0))?;
        let data_content = dec.expect(context_constructed(0))?;

        let mut targets: Vec<Option<(String, String)>> = Vec::new();
        let mut ld = Decoder::new(list_content);
        while ld.more() {
            let entry = ld.expect(TAG_SEQUENCE)?;
            targets.push(parse_var_spec(entry).ok());
        }

        let mut values: Vec<Value> = Vec::new();
        let mut dd = Decoder::new(data_content);
        while dd.more() {
            values.push(mms::decode_data(&mut dd)?);
        }

        let mut results: Vec<Element> = Vec::with_capacity(values.len());
        for (i, v) in values.iter().enumerate() {
            let Some(Some((domain, item))) = targets.get(i).cloned() else {
                results.push(write_failure(DataAccessError::ObjectNonExistent));
                continue;
            };
            match self.write_one(&domain, &item, v) {
                Ok(()) => results.push(prim(context_primitive(1), Vec::new())), // success [1] NULL
                Err(code) => results.push(write_failure(code)),
            }
        }

        // Written data and operated controls report like any other change,
        // once the request is applied. The reports are held until the write's
        // response is out.
        let changes = std::mem::take(&mut *self.changes.lock().unwrap());
        if !changes.is_empty() {
            let mut model = self.inner.model.write().unwrap();
            let conns = self.inner.conns.lock().unwrap();
            self.inner.reports.on_update(&mut model, &conns, &changes);
        }
        Ok(cons(context_constructed(SVC_WRITE), results))
    }

    /// Applies one write, including the control, report and setting-group side
    /// effects it may carry.
    fn write_one(
        &self,
        domain: &str,
        item: &str,
        v: &Value,
    ) -> std::result::Result<(), DataAccessError> {
        // Control writes are not ordinary attribute writes: they run a state
        // machine and never land in the model directly.
        if control::split_control(item).is_some() {
            return self.control_write(domain, item, v);
        }

        let mut model = self.inner.model.write().unwrap();
        let Some(ld) = model.device_mut(domain) else {
            return Err(DataAccessError::ObjectNonExistent);
        };
        let Some(ln) = item.split('$').next().and_then(|n| ld.node_mut(n)) else {
            return Err(DataAccessError::ObjectNonExistent);
        };
        let Some(da) = access::resolve_write(ln, item) else {
            return Err(DataAccessError::ObjectAccessUnsupported);
        };

        // Report and setting group control block attributes have their own
        // rules; everything else is governed by the functional-constraint
        // write policy.
        let sgcb = super::settinggroup::is_sgcb_write(item)
            .filter(|_| self.inner.setting_groups.contains_key(domain));
        let control_block = rcb::rcb_key(domain, item).is_some() || sgcb.is_some();
        if !control_block {
            self.write_permitted(domain, da.fc)?;
        }
        if !value_fits(da, v) {
            return Err(DataAccessError::TypeInconsistent);
        }
        // A control block's own rules run before anything is stored: a refused
        // write must leave the block as it was.
        if let Some(attr) = sgcb {
            self.inner.setting_groups[domain].check_write(attr, v)?;
        }
        let rcb_attr = rcb::rcb_key(domain, item).map(|(_, attr)| attr);

        // The access hook sees the attribute and the proposed value, and its
        // refusal is what the client is told.
        let hook = self.inner.write_handler.read().unwrap().clone();
        if let Some(h) = hook {
            h(da, v)?;
        }
        let (fc, trg) = (da.fc, da.trg_ops);
        // A report control block's rules need the model as a whole, so the
        // attribute is looked up again once they have run.
        if let Some(attr) = &rcb_attr {
            self.inner
                .reports
                .check_rcb_write(&model, domain, item, attr, v, self.conn)?;
        }
        let da = model
            .device_mut(domain)
            .and_then(|ld| item.split('$').next().and_then(|n| ld.node_mut(n)))
            .and_then(|ln| access::resolve_write(ln, item))
            .ok_or(DataAccessError::ObjectAccessUnsupported)?;
        let old = da.value.replace(v.clone());
        if !control_block {
            let (reference, _) = model::from_mms(domain, item);
            tx::record(
                &mut self.changes.lock().unwrap(),
                reference,
                fc,
                trg,
                old.as_ref(),
                v,
            );
        }

        // Report control block side effects: reservation, enabling, general
        // interrogation, resync, purge and a dataset change.
        if let Some(attr) = rcb_attr {
            let conns = self.inner.conns.lock().unwrap();
            self.inner.reports.on_rcb_write(
                &mut model,
                &conns,
                domain,
                item,
                &attr,
                v,
                self.conn,
            );
        }
        // Setting group control block side effects.
        if let Some(attr) = super::settinggroup::is_sgcb_write(item) {
            if let Some(mgr) = self.inner.setting_groups.get(domain) {
                mgr.on_sgcb_write(&mut model, attr, v);
            }
        }
        Ok(())
    }

    /// Applies the functional-constraint write policy (IEC 61850-7-2): only
    /// the constraints the server made writable are, and an SE setting only
    /// while a setting group is being edited.
    fn write_permitted(
        &self,
        domain: &str,
        fc: model::Fc,
    ) -> std::result::Result<(), DataAccessError> {
        if !self.inner.writable.contains(&fc) {
            return Err(DataAccessError::ObjectAccessDenied);
        }
        if fc == model::Fc::Se {
            let editing = self
                .inner
                .setting_groups
                .get(domain)
                .is_some_and(|m| m.editing() >= 1);
            if !editing {
                return Err(DataAccessError::TemporarilyUnavailable);
            }
        }
        Ok(())
    }

    /// Handles a write to a control attribute.
    ///
    /// A refused command is answered negatively and, ahead of that answer,
    /// with a LastApplError report naming the cause (IEC 61850-8-1).
    fn control_write(
        &self,
        domain: &str,
        item: &str,
        v: &Value,
    ) -> std::result::Result<(), DataAccessError> {
        let Some((base, phase)) = control::split_control(item) else {
            return Err(DataAccessError::ObjectAccessUnsupported);
        };
        let phase_name = match phase {
            Phase::Oper => "Oper",
            Phase::Sbow => "SBOw",
            Phase::Cancel => "Cancel",
            // SBO is the select of normal security, and it is a read.
            Phase::Sbo => return Err(DataAccessError::ObjectAccessDenied),
        };
        // The control structure is written whole; its members are not
        // separately writable.
        if !item.ends_with(&format!("${phase_name}")) || v.type_of() != mms::Type::Structure {
            return Err(DataAccessError::TypeInconsistent);
        }
        let reference = control::control_ref(domain, &base);
        let ctl_item = format!("{base}${phase_name}");
        let sc = self.inner.conns.lock().unwrap().get(&self.conn).cloned();
        let mut ctx =
            control::decode_oper(reference.clone(), v, self.conn, sc.as_ref().and_then(|c| c.peer));
        ctx.select = phase == Phase::Sbow;
        let refuse = |ctx: &control::ControlCtx, cause: AddCause| {
            if let Some(sc) = &sc {
                let report = control::last_appl_error_report(domain, &ctl_item, ctx, cause);
                if sc.send_unconfirmed_first(report).is_err() {
                    tracing::debug!(item = %ctl_item, "server: LastApplError send failed");
                }
            }
            Err(DataAccessError::ObjectAccessDenied)
        };
        let now = Instant::now();

        let (declared, sbo_timeout, oper_timeout) = {
            let model = self.inner.model.read().unwrap();
            (
                control::declared_ctl_model(&model, &reference),
                control::cf_millis(&model, &reference, "sboTimeout"),
                control::cf_millis(&model, &reference, "operTimeout"),
            )
        };
        let ctl_model = declared.unwrap_or(CtlModel::DirectNormal);
        match declared {
            // A status-only object offers no control service.
            Some(CtlModel::StatusOnly) => return refuse(&ctx, AddCause::NOT_SUPPORTED),
            // Select-with-value belongs to SBO with enhanced security only.
            Some(cm) if phase == Phase::Sbow && cm != CtlModel::SboEnhanced => {
                return refuse(&ctx, AddCause::NOT_SUPPORTED)
            }
            _ => {}
        }

        if phase == Phase::Cancel {
            let cause = self.inner.selections.lock().unwrap().check_cancel(
                &reference,
                self.conn,
                ctx.ctl_num,
                now,
            );
            if cause != AddCause::NONE {
                return refuse(&ctx, cause);
            }
            self.inner.selections.lock().unwrap().clear(&reference);
            return Ok(());
        }

        // An SBO operate must belong to a live selection: made by this
        // connection, and carrying that select's control number.
        if phase == Phase::Oper && ctl_model.has_select() {
            let cause = self.inner.selections.lock().unwrap().check_operate(
                &reference,
                self.conn,
                ctx.ctl_num,
                now,
            );
            if cause != AddCause::NONE {
                return refuse(&ctx, cause);
            }
        }

        // An enhanced-security operate is concluded by a CommandTermination,
        // which the handler may take over (defer_termination).
        if phase == Phase::Oper && declared.is_some_and(|cm| cm.is_enhanced()) {
            if let Some(sc) = &sc {
                ctx.term = Some(control::Termination::new(
                    Arc::clone(sc),
                    domain,
                    &ctl_item,
                    &ctx,
                    v,
                ));
            }
        }

        let handler = self.inner.controls.read().unwrap().get(&reference).cloned();
        let cause = match handler {
            Some(h) => h(&ctx),
            None => AddCause::NONE,
        };
        if cause != AddCause::NONE {
            if let Some(term) = &ctx.term {
                term.discard();
            }
            return refuse(&ctx, cause);
        }

        if ctx.select {
            // SBOw reserves the object under the control number the operate
            // will have to repeat. A reservation another client holds is not
            // ours to take.
            let timeout = if sbo_timeout.is_zero() {
                SELECT_TIMEOUT
            } else {
                sbo_timeout
            };
            let taken = self.inner.selections.lock().unwrap().reserve(
                &reference,
                self.conn,
                Some(ctx.ctl_num),
                timeout,
                now,
            );
            if !taken {
                return refuse(&ctx, AddCause::OBJECT_ALREADY_SELECTED);
            }
            return Ok(());
        }

        // The operate is accepted: reflect it into the process image.
        {
            let mut model = self.inner.model.write().unwrap();
            control::apply_control(
                &mut model,
                &reference,
                &ctx.value,
                &mut self.changes.lock().unwrap(),
            );
        }
        self.inner.selections.lock().unwrap().clear(&reference);

        if let Some(term) = &ctx.term {
            if term.is_deferred() {
                term.supervise(oper_timeout);
            } else {
                // Sent now, it is held until the operate's response is out.
                term.finish(AddCause::NONE);
            }
        }
        Ok(())
    }

    fn get_variable_access(&self, content: &[u8]) -> mms::Result<Element> {
        let mut dec = Decoder::new(content);
        let name_content = dec.expect(context_constructed(0))?; // name [0]
        let (domain, item) = parse_object_name(name_content)?;

        let model = self.inner.model.read().unwrap();
        let ld = model
            .device(&domain)
            .ok_or(DataAccessError::ObjectNonExistent)?;
        let ln = item
            .split('$')
            .next()
            .and_then(|n| ld.node(n))
            .ok_or(DataAccessError::ObjectNonExistent)?;
        let ts = access::type_spec_for(ln, &item).ok_or(DataAccessError::ObjectNonExistent)?;
        let ber = ts.ber().ok_or(DataAccessError::TypeUnsupported)?;

        // The type specification goes at [2], not [1]: [1] is the optional
        // address, and a client reading it there finds the wrong element.
        Ok(cons(
            context_constructed(SVC_GET_VARIABLE_ACCESS),
            [
                bool_elem(context_primitive(0), false), // mmsDeletable
                cons(context_constructed(2), [ber]),
            ],
        ))
    }

    fn get_nvl_attrs(&self, content: &[u8]) -> mms::Result<Element> {
        let (domain, list) = parse_object_name(content)?;
        let members = {
            let model = self.inner.model.read().unwrap();
            reporting::dataset_members(&model, &domain, &list)
        };
        if members.is_empty() && !self.dataset_exists(&domain, &list) {
            return Err(DataAccessError::ObjectNonExistent.into());
        }
        let var_list = cons(
            context_constructed(1),
            members.iter().map(|m| {
                cons(
                    TAG_SEQUENCE,
                    [cons(
                        context_constructed(0), // variableSpecification name [0]
                        [domain_specific_name(&m.domain, &m.item)],
                    )],
                )
            }),
        );
        Ok(cons(
            context_constructed(SVC_GET_NAMED_VAR_LIST_ATTR),
            [bool_elem(context_primitive(0), false), var_list],
        ))
    }

    fn dataset_exists(&self, domain: &str, list: &str) -> bool {
        let Some((ln_name, ds_name)) = list.split_once('$') else {
            return false;
        };
        let model = self.inner.model.read().unwrap();
        model
            .device(domain)
            .and_then(|ld| ld.node(ln_name))
            .and_then(|ln| ln.data_set(ds_name))
            .is_some()
    }

    /// Creates a dynamic named variable list from the request's members.
    fn define_nvl(&self, content: &[u8]) -> mms::Result<Element> {
        let mut dec = Decoder::new(content);
        let (domain, list) = parse_object_name_elem(&mut dec)?;
        let Some((ln_name, ds_name)) = list.split_once('$') else {
            return Err(DataAccessError::ObjectValueInvalid.into());
        };
        // listOfVariable is [0] in ISO 9506-2. Earlier versions of this crate
        // sent [1], the tag of the attributes response, so that is accepted
        // too rather than refusing them.
        let list_content = match dec.optional(context_constructed(0))? {
            Some(c) => c,
            None => dec.expect(context_constructed(1))?,
        };

        let mut entries: Vec<Fcda> = Vec::new();
        let mut ld = Decoder::new(list_content);
        while ld.more() {
            let entry = ld.expect(TAG_SEQUENCE)?;
            let spec = Decoder::new(entry).expect(context_constructed(0))?;
            let (md, mi) = parse_object_name(spec)?;
            let (reference, fc) = model::from_mms(&md, &mi);
            entries.push(Fcda { reference, fc });
        }

        let mut m = self.inner.model.write().unwrap();
        let ln = m
            .device_mut(&domain)
            .and_then(|ld| ld.node_mut(ln_name))
            .ok_or(DataAccessError::ObjectNonExistent)?;
        if ln.data_set(ds_name).is_some() {
            return Err(DataAccessError::ObjectValueInvalid.into());
        }
        ln.data_sets.push(model::DataSet {
            name: ds_name.to_string(),
            entries,
        });
        // DefineNamedVariableList-Response ::= NULL.
        Ok(prim(
            context_primitive(SVC_DEFINE_NAMED_VAR_LIST),
            Vec::new(),
        ))
    }

    /// Removes dynamic named variable lists.
    fn delete_nvl(&self, content: &[u8]) -> mms::Result<Element> {
        let mut dec = Decoder::new(content);
        // scopeOfDelete [0] INTEGER DEFAULT specific.
        dec.optional(context_primitive(0))?;
        let (mut matched, mut deleted) = (0u64, 0u64);
        if let Some(list_content) = dec.optional(context_constructed(1))? {
            let mut nd = Decoder::new(list_content);
            let mut m = self.inner.model.write().unwrap();
            while nd.more() {
                let Ok((domain, list)) = parse_object_name_elem(&mut nd) else {
                    break;
                };
                matched += 1;
                if delete_dataset(&mut m, &domain, &list) {
                    deleted += 1;
                }
            }
        }
        Ok(cons(
            context_constructed(SVC_DELETE_NAMED_VAR_LIST),
            [
                uint_elem(context_primitive(0), matched),
                uint_elem(context_primitive(1), deleted),
            ],
        ))
    }

    fn file_service(&self, service: u32, content: &[u8], max_pdu: usize) -> mms::Result<Element> {
        let Some(files) = &self.inner.files else {
            return Err(DataAccessError::ObjectAccessUnsupported.into());
        };
        match service {
            SVC_FILE_OPEN => {
                let mut dec = Decoder::new(content);
                let name_seq = dec.expect(context_constructed(0))?;
                let name = Decoder::new(name_seq)
                    .expect(TAG_GRAPHIC_STRING)
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .unwrap_or_default();
                let (id, size, modified) = files.open(&name).map_err(|e| {
                    // Tell a directory apart from a missing file: a client
                    // that picked a directory out of a listing needs to know
                    // which mistake it made.
                    match e.kind() {
                        std::io::ErrorKind::InvalidInput => {
                            DataAccessError::ObjectAccessUnsupported
                        }
                        std::io::ErrorKind::PermissionDenied => {
                            DataAccessError::ObjectAccessDenied
                        }
                        _ => DataAccessError::ObjectNonExistent,
                    }
                })?;
                let mut attrs = cons(
                    context_constructed(1),
                    [uint_elem(context_primitive(0), u64::from(size))],
                );
                if let Some(t) = modified {
                    attrs.push(prim(
                        context_primitive(1),
                        super::file::generalized_time(t).into_bytes(),
                    ));
                }
                Ok(cons(
                    context_constructed(SVC_FILE_OPEN),
                    [asn1::int_elem(context_primitive(0), i64::from(id)), attrs],
                ))
            }
            SVC_FILE_READ => {
                let id = asn1::decode_int(content).unwrap_or(0) as i32;
                // A chunk fills what the association's PDU leaves after the
                // response's own framing.
                let limit = if max_pdu == 0 {
                    super::file::FILE_CHUNK_SIZE
                } else {
                    max_pdu.saturating_sub(PAGE_ENVELOPE).max(1)
                };
                let (chunk, more) = files
                    .read(id, limit)
                    .ok_or(DataAccessError::ObjectNonExistent)?;
                Ok(cons(
                    context_constructed(SVC_FILE_READ),
                    [
                        prim(context_primitive(0), chunk),
                        bool_elem(context_primitive(1), more),
                    ],
                ))
            }
            SVC_FILE_CLOSE => {
                let id = asn1::decode_int(content).unwrap_or(0) as i32;
                files.close(id);
                Ok(prim(context_primitive(SVC_FILE_CLOSE), Vec::new()))
            }
            SVC_FILE_DELETE => {
                let mut dec = Decoder::new(content);
                let name_seq = dec.expect(context_constructed(0))?;
                let name = Decoder::new(name_seq)
                    .expect(TAG_GRAPHIC_STRING)
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .unwrap_or_default();
                files
                    .delete(&name)
                    .map_err(|_| DataAccessError::ObjectNonExistent)?;
                Ok(prim(context_primitive(SVC_FILE_DELETE), Vec::new()))
            }
            SVC_FILE_DIRECTORY => {
                let mut dec = Decoder::new(content);
                let dir = match dec.optional(context_constructed(0))? {
                    Some(c) => Decoder::new(c)
                        .expect(TAG_GRAPHIC_STRING)
                        .map(|n| String::from_utf8_lossy(n).into_owned())
                        .unwrap_or_default(),
                    None => String::new(),
                };
                let after = match dec.optional(context_constructed(1))? {
                    Some(c) => Decoder::new(c)
                        .expect(TAG_GRAPHIC_STRING)
                        .map(|n| String::from_utf8_lossy(n).into_owned())
                        .unwrap_or_default(),
                    None => String::new(),
                };
                let mut entries = files
                    .list(&dir)
                    .map_err(|_| DataAccessError::ObjectNonExistent)?;
                if !after.is_empty() {
                    if let Some(i) = entries.iter().position(|e| e.name == after) {
                        entries.drain(..=i);
                    }
                }
                let (page, more) = fill_page(
                    entries.into_iter().map(|e| {
                        let mut attrs = cons(
                            context_constructed(1),
                            [uint_elem(context_primitive(0), u64::from(e.size))],
                        );
                        if let Some(t) = e.modified {
                            attrs.push(prim(
                                context_primitive(1),
                                super::file::generalized_time(t).into_bytes(),
                            ));
                        }
                        cons(
                            TAG_SEQUENCE,
                            [
                                cons(
                                    context_constructed(0),
                                    [prim(TAG_GRAPHIC_STRING, e.name.into_bytes())],
                                ),
                                attrs,
                            ],
                        )
                    }),
                    max_pdu,
                );
                Ok(cons(
                    context_constructed(SVC_FILE_DIRECTORY),
                    [
                        cons(context_constructed(0), [cons(TAG_SEQUENCE, page)]),
                        bool_elem(context_primitive(1), more),
                    ],
                ))
            }
            _ => Err(DataAccessError::ObjectAccessUnsupported.into()),
        }
    }
}

/// Enumerates the names of one MMS object class.
fn enumerate(model: &model::Model, class: i64, domain: &str) -> Vec<String> {
    match class {
        // domain
        9 => model.devices.iter().map(|ld| ld.name.clone()).collect(),
        // named variable
        0 => model
            .device(domain)
            .map(access::names_for_domain)
            .unwrap_or_default(),
        // named variable list (dataset)
        2 => model
            .device(domain)
            .map(|ld| {
                ld.nodes
                    .iter()
                    .flat_map(|ln| {
                        ln.data_sets
                            .iter()
                            .map(move |ds| format!("{}${}", ln.name, ds.name))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn delete_dataset(model: &mut model::Model, domain: &str, list: &str) -> bool {
    let Some((ln_name, ds_name)) = list.split_once('$') else {
        return false;
    };
    let Some(ln) = model
        .device_mut(domain)
        .and_then(|ld| ld.node_mut(ln_name))
    else {
        return false;
    };
    let before = ln.data_sets.len();
    ln.data_sets.retain(|ds| ds.name != ds_name);
    ln.data_sets.len() != before
}

/// Extracts a domain and item from a `ListOfVariable` entry.
fn parse_var_spec(entry: &[u8]) -> mms::Result<(String, String)> {
    let mut dec = Decoder::new(entry);
    let spec_content = dec.expect(context_constructed(0))?; // name [0]
    parse_object_name(spec_content)
}

/// Decodes an ObjectName element's content into a domain and item.
pub(crate) fn parse_object_name(content: &[u8]) -> mms::Result<(String, String)> {
    parse_object_name_elem(&mut Decoder::new(content))
}

/// Reads one ObjectName from a decoder.
///
/// It is a CHOICE, so it appears directly as its alternative: domain-specific
/// `[1]` or vmd-specific `[0]`.
pub(crate) fn parse_object_name_elem(dec: &mut Decoder<'_>) -> mms::Result<(String, String)> {
    let (tag, c) = dec.read_tlv()?;
    if tag == context_constructed(1) {
        let mut dd = Decoder::new(c);
        let domain = dd.expect(TAG_VISIBLE_STRING)?;
        let item = dd.expect(TAG_VISIBLE_STRING)?;
        Ok((
            String::from_utf8_lossy(domain).into_owned(),
            String::from_utf8_lossy(item).into_owned(),
        ))
    } else if tag == context_primitive(0) {
        Ok((String::new(), String::from_utf8_lossy(c).into_owned()))
    } else {
        Err(mms::Error::protocol(format!(
            "unsupported ObjectName tag {tag}"
        )))
    }
}

fn domain_specific_name(domain: &str, item: &str) -> Element {
    cons(
        context_constructed(1),
        [
            prim(TAG_VISIBLE_STRING, domain.as_bytes().to_vec()),
            prim(TAG_VISIBLE_STRING, item.as_bytes().to_vec()),
        ],
    )
}

/// An AccessResult failure `[0]`, as it appears in a read response.
fn access_failure(code: DataAccessError) -> Element {
    uint_elem(context_primitive(0), u64::from(code.code()))
}

/// A write result failure `[0]`.
fn write_failure(code: DataAccessError) -> Element {
    uint_elem(context_primitive(0), u64::from(code.code()))
}

/// Reports whether `v` may replace `da`'s value: the same MMS type, the same
/// width for a bit string, and within range for a sized integer.
///
/// Storing anything else would corrupt every later read and report of the
/// attribute, so it is refused as type-inconsistent.
pub(crate) fn value_fits(da: &model::DataAttribute, v: &Value) -> bool {
    let want = match &da.value {
        Some(cur) => cur.type_of(),
        None => match da.kind {
            Some(k) => k,
            None => return true,
        },
    };
    if want == mms::Type::None {
        return true;
    }
    if v.type_of() != want {
        return false;
    }
    match want {
        mms::Type::BitString => da.value.as_ref().is_none_or(|cur| v.bit_len() == cur.bit_len()),
        mms::Type::Integer => {
            int_range(&da.btype).is_none_or(|(lo, hi)| (lo..=hi).contains(&v.as_i64()))
        }
        mms::Type::Unsigned => int_range(&da.btype)
            .is_none_or(|(_, hi)| i128::from(v.as_u64()) <= i128::from(hi)),
        _ => true,
    }
}

/// The value range of a sized SCL integer `bType`.
fn int_range(btype: &str) -> Option<(i64, i64)> {
    Some(match btype {
        "INT8" => (i64::from(i8::MIN), i64::from(i8::MAX)),
        "INT16" => (i64::from(i16::MIN), i64::from(i16::MAX)),
        "INT32" => (i64::from(i32::MIN), i64::from(i32::MAX)),
        "INT8U" => (0, i64::from(u8::MAX)),
        "INT16U" => (0, i64::from(u16::MAX)),
        "INT32U" => (0, i64::from(u32::MAX)),
        _ => return None,
    })
}

/// Keeps the control model import used, since it is only referenced through a
/// method call above.
const _: fn(CtlModel) -> bool = CtlModel::has_select;
/// Ditto for the weak reference the report engine takes.
const _: fn(&Arc<Inner>) -> Weak<Inner> = Arc::downgrade;
const _: fn(&ObjectReference) -> &str = ObjectReference::as_str;

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(btype: &str, v: Value) -> model::DataAttribute {
        model::DataAttribute {
            name: "setVal".into(),
            fc: model::Fc::Sp,
            kind: Some(v.type_of()),
            btype: btype.into(),
            value: Some(v),
            ..Default::default()
        }
    }

    /// A sized integer is refused outside its range, and a value of another
    /// type or width never fits.
    #[test]
    fn a_value_fits_only_its_type_width_and_range() {
        let u8_attr = leaf("INT8U", Value::uint8(0));
        assert!(!value_fits(&u8_attr, &Value::uint32(300)), "300 into INT8U");
        assert!(value_fits(&u8_attr, &Value::uint32(200)), "200 into INT8U");

        let i16_attr = leaf("INT16", Value::int16(0));
        assert!(!value_fits(&i16_attr, &Value::int32(-40_000)));
        assert!(value_fits(&i16_attr, &Value::int32(-32_768)));

        let f = leaf("FLOAT32", Value::float32(0.0));
        assert!(!value_fits(&f, &Value::visible_string("1.0")), "another type");

        let q = leaf("Quality", Value::bit_string(13));
        assert!(!value_fits(&q, &Value::bit_string(8)), "another width");
        assert!(value_fits(&q, &Value::bit_string(13)));
    }

    #[test]
    fn object_names_decode_in_both_scopes() {
        let el = domain_specific_name("ied1LD0", "GGIO1$MX$AnIn1").encode();
        assert_eq!(
            parse_object_name(&el).unwrap(),
            ("ied1LD0".to_string(), "GGIO1$MX$AnIn1".to_string())
        );

        let el = prim(context_primitive(0), b"SomeGlobal".to_vec()).encode();
        assert_eq!(
            parse_object_name(&el).unwrap(),
            (String::new(), "SomeGlobal".to_string())
        );

        let el = prim(context_primitive(7), vec![]).encode();
        assert!(parse_object_name(&el).is_err());
    }

    #[test]
    fn access_failures_encode_as_the_failure_alternative() {
        let el = access_failure(DataAccessError::ObjectNonExistent).encode();
        // [0] primitive, carrying the code.
        assert_eq!(el[0], 0x80);
        assert_eq!(el[2], 10);
    }
}
