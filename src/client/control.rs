use std::sync::Mutex;
use std::time::SystemTime;

use crate::mms::{TimeQuality, Type, TypeSpec, Value};
use crate::model::{AddCause, CtlModel, Fc, ObjectReference, OrCat};

use super::{Client, Error, Result};

/// Which step of a control sequence failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Select,
    Operate,
    Cancel,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Stage::Select => "select",
            Stage::Operate => "operate",
            Stage::Cancel => "cancel",
        })
    }
}

/// Carries the additional cause of a failed control.
#[derive(Debug, thiserror::Error)]
pub struct ControlError {
    pub stage: Stage,
    pub add_cause: AddCause,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The additional cause is the device's own diagnosis and says far more
        // than the MMS error, so it wins when the device supplied one.
        if self.add_cause != AddCause::NONE && self.add_cause != AddCause::UNKNOWN {
            return write!(
                f,
                "client: control {} failed: {}",
                self.stage, self.add_cause
            );
        }
        match &self.source {
            Some(e) => write!(f, "client: control {} failed: {e}", self.stage),
            None => write!(f, "client: control {} failed", self.stage),
        }
    }
}

impl ControlError {
    fn new(stage: Stage, add_cause: AddCause) -> ControlError {
        ControlError {
            stage,
            add_cause,
            source: None,
        }
    }

    fn with_source(
        stage: Stage,
        add_cause: AddCause,
        e: impl std::error::Error + Send + Sync + 'static,
    ) -> ControlError {
        ControlError {
            stage,
            add_cause,
            source: Some(Box::new(e)),
        }
    }
}

/// Configures a control operation.
#[derive(Debug, Clone)]
pub struct ControlOptions {
    pub or_cat: OrCat,
    pub or_ident: Vec<u8>,
    pub test: bool,
    pub interlock_check: bool,
    pub synchro_check: bool,
    /// Overrides the control model instead of using the one read from
    /// `ctlModel`.
    pub model: Option<CtlModel>,
}

impl Default for ControlOptions {
    fn default() -> ControlOptions {
        ControlOptions {
            or_cat: OrCat::StationControl,
            or_ident: Vec::new(),
            test: false,
            interlock_check: false,
            synchro_check: false,
            model: None,
        }
    }
}

impl ControlOptions {
    pub fn new() -> ControlOptions {
        ControlOptions::default()
    }

    /// Sets the originator category and identifier.
    #[must_use]
    pub fn with_originator(mut self, cat: OrCat, ident: impl AsRef<str>) -> ControlOptions {
        self.or_cat = cat;
        self.or_ident = ident.as_ref().as_bytes().to_vec();
        self
    }

    /// Marks the command as a test.
    #[must_use]
    pub fn with_test(mut self, test: bool) -> ControlOptions {
        self.test = test;
        self
    }

    /// Requests the interlock check.
    #[must_use]
    pub fn with_interlock_check(mut self, on: bool) -> ControlOptions {
        self.interlock_check = on;
        self
    }

    /// Requests the synchronisation check.
    #[must_use]
    pub fn with_synchro_check(mut self, on: bool) -> ControlOptions {
        self.synchro_check = on;
        self
    }

    /// Overrides the control model instead of reading `ctlModel`.
    #[must_use]
    pub fn with_model(mut self, m: CtlModel) -> ControlOptions {
        self.model = Some(m);
        self
    }
}

/// Tracks the control number of the sequence in progress.
#[derive(Debug, Default)]
struct Sequence {
    ctl_num: u8,
    /// A sequence is open, so the control number must be reused.
    in_sequence: bool,
    ctl_val_spec: Option<TypeSpec>,
}

/// A handle to a controllable data object (an SPC, DPC, INC, APC and so on).
///
/// Its control model is read from the server unless set explicitly with
/// [`ControlOptions::with_model`].
///
/// A handle runs one control sequence at a time; driving the same handle from
/// several tasks concurrently interleaves their sequences and makes them share
/// a control number.
#[derive(Debug)]
pub struct ControlObject<'a> {
    client: &'a Client,
    reference: ObjectReference,
    model: CtlModel,
    domain: String,
    /// `LN$CO$DO`.
    object: String,
    sequence: Mutex<Sequence>,
}

impl Client {
    /// Returns a control handle for the object at `reference`, reading its
    /// `ctlModel` from the server.
    ///
    /// A device that does not expose `ctlModel` is assumed to be
    /// direct-with-normal-security, which is what a status-only object would
    /// reject anyway.
    pub async fn control_for(
        &self,
        reference: impl Into<ObjectReference>,
    ) -> Result<ControlObject<'_>> {
        let reference = reference.into();
        let path = reference.path();
        if path.len() < 2 {
            return Err(Error::client(format!(
                "control reference {reference:?} must be LD/LN.DO"
            )));
        }
        let object = format!("{}$CO${}", path[0], path[1..].join("$"));
        // ctlModel lives under CF, not CO.
        let model = match self.read(reference.child("ctlModel"), Fc::Cf).await {
            Ok(v) => CtlModel::from_code(v.as_i64() as u8),
            Err(_) => CtlModel::DirectNormal,
        };
        Ok(ControlObject {
            client: self,
            domain: reference.ld().to_string(),
            reference,
            model,
            object,
            sequence: Mutex::new(Sequence::default()),
        })
    }
}

impl ControlObject<'_> {
    /// Returns the control model in effect.
    pub fn model(&self) -> CtlModel {
        self.model
    }

    /// Returns the reference of the controlled object.
    pub fn reference(&self) -> &ObjectReference {
        &self.reference
    }

    /// Returns the control number of the current or most recent sequence.
    ///
    /// It is the `ctlNum` carried by that sequence's select and operate, which
    /// is what identifies the matching CommandTermination.
    pub fn ctl_num(&self) -> u8 {
        self.sequence.lock().unwrap().ctl_num
    }

    /// Performs a complete control operation appropriate to the model: for SBO
    /// models it selects first.
    ///
    /// `value` is the `ctlVal`: a boolean for SPC and DPC, a numeric for INC,
    /// and an `AnalogueValue` structure for APC.
    pub async fn operate(&self, value: Value, opts: &ControlOptions) -> Result<()> {
        let model = opts.model.unwrap_or(self.model);
        if model.has_select() {
            self.do_select(value.clone(), opts, model).await?;
        }
        self.do_operate(value, opts).await
    }

    /// Performs the select step for SBO-with-normal-security controls.
    ///
    /// The read carries no control number, but it still opens the sequence
    /// whose number the following operate must use.
    pub async fn select(&self) -> Result<()> {
        self.begin_sequence();
        let item = format!("{}$SBO", self.object);
        let vals = match self.client.mms().read(&self.domain, &[&item]).await {
            Ok(v) => v,
            Err(e) => {
                self.end_sequence();
                return Err(ControlError::with_source(Stage::Select, AddCause::UNKNOWN, e).into());
            }
        };
        // Success returns a non-empty object name; an empty one is a refusal.
        if vals.first().map(Value::text).unwrap_or_default().is_empty() {
            self.end_sequence();
            return Err(ControlError::new(Stage::Select, AddCause::SELECT_FAILED).into());
        }
        Ok(())
    }

    /// Performs the select step for SBO-with-enhanced-security.
    pub async fn select_with_value(&self, value: Value, opts: &ControlOptions) -> Result<()> {
        let model = opts.model.unwrap_or(self.model);
        self.do_select(value, opts, model).await
    }

    async fn do_select(
        &self,
        value: Value,
        opts: &ControlOptions,
        model: CtlModel,
    ) -> Result<()> {
        if model == CtlModel::SboNormal {
            return self.select().await;
        }
        // SBOw: write the operate structure. This opens the sequence, and the
        // operate that follows repeats its control number.
        let oper = self.build_oper(value, opts, self.begin_sequence());
        let item = format!("{}$SBOw", self.object);
        let results = match self.client.mms().write(&self.domain, &[&item], &[oper]).await {
            Ok(r) => r,
            Err(e) => {
                self.end_sequence();
                return Err(ControlError::with_source(Stage::Select, AddCause::UNKNOWN, e).into());
            }
        };
        if let Some(Err(code)) = results.into_iter().next() {
            self.end_sequence();
            let cause = self.last_appl_error().await;
            return Err(ControlError::with_source(Stage::Select, cause, code).into());
        }
        Ok(())
    }

    async fn do_operate(&self, value: Value, opts: &ControlOptions) -> Result<()> {
        // Reuses the select's control number when a sequence is open; the
        // sequence ends here either way, since a retry is a new sequence.
        let oper = self.build_oper(value, opts, self.begin_sequence());
        let item = format!("{}$Oper", self.object);
        let result = self.client.mms().write(&self.domain, &[&item], &[oper]).await;
        self.end_sequence();

        let results = result.map_err(|e| {
            ControlError::with_source(Stage::Operate, AddCause::UNKNOWN, e)
        })?;
        if let Some(Err(code)) = results.into_iter().next() {
            let cause = self.last_appl_error().await;
            return Err(ControlError::with_source(Stage::Operate, cause, code).into());
        }
        // Enhanced models confirm asynchronously with a CommandTermination;
        // the positive write already says the operate was accepted, and
        // awaiting the termination is left to the caller through the
        // information-report stream.
        Ok(())
    }

    /// Aborts a selection or operation.
    ///
    /// It carries the control number of the sequence being cancelled, which is
    /// how the server identifies it.
    pub async fn cancel(&self, opts: &ControlOptions) -> Result<()> {
        let oper = self.build_oper(Value::boolean(false), opts, self.begin_sequence());
        let item = format!("{}$Cancel", self.object);
        let result = self.client.mms().write(&self.domain, &[&item], &[oper]).await;
        self.end_sequence();

        let results = result
            .map_err(|e| ControlError::with_source(Stage::Cancel, AddCause::UNKNOWN, e))?;
        if let Some(Err(code)) = results.into_iter().next() {
            return Err(ControlError::with_source(Stage::Cancel, AddCause::UNKNOWN, code).into());
        }
        Ok(())
    }

    /// Returns the type specification of the object's control value, read from
    /// the type of its `Oper` structure.
    ///
    /// It is what a caller needs to build a `ctlVal` the server will accept: an
    /// SPC takes a boolean, a DPC a two-bit bit string, an INC an integer, and
    /// an APC the `AnalogueValue` structure, whose components say whether the
    /// server expects an integer (`i`) or a float (`f`).
    ///
    /// Sizes follow the [`TypeSpec`] convention: a bit-string or string width
    /// is negative when the server declares it as a maximum rather than a fixed
    /// length, so compare on its magnitude.
    ///
    /// The type of a control object is static, so the answer is cached and
    /// later calls cost no round trip.
    pub async fn ctl_val_spec(&self) -> Result<TypeSpec> {
        if let Some(cached) = self.sequence.lock().unwrap().ctl_val_spec.clone() {
            return Ok(cached);
        }
        // Oper carries ctlVal under every control model. SBOw is the fallback
        // for SBO objects whose Oper the server will not describe.
        let mut items = vec![format!("{}$Oper", self.object)];
        if self.model.has_select() {
            items.push(format!("{}$SBOw", self.object));
        }
        let mut last: Option<Error> = None;
        for item in &items {
            let ts = match self
                .client
                .mms()
                .get_variable_access_attributes(&self.domain, item)
                .await
            {
                Ok(ts) => ts,
                Err(e) => {
                    last = Some(e.into());
                    continue;
                }
            };
            let Some(spec) = component_spec(&ts, "ctlVal") else {
                last = Some(Error::client(format!(
                    "{}: {item} has no ctlVal component",
                    self.reference
                )));
                continue;
            };
            self.sequence.lock().unwrap().ctl_val_spec = Some(spec.clone());
            return Ok(spec);
        }
        Err(last.unwrap_or_else(|| {
            Error::client(format!("control value type of {}", self.reference))
        }))
    }

    /// Returns the MMS type of the object's control value.
    ///
    /// It is [`Type::Structure`] for an APC, whose value is an
    /// `AnalogueValue`; use [`ctl_val_spec`](ControlObject::ctl_val_spec) to
    /// see inside it.
    pub async fn ctl_val_type(&self) -> Result<Option<Type>> {
        Ok(self.ctl_val_spec().await?.kind)
    }

    /// Returns the control number to use for the next request.
    ///
    /// A control sequence (select, operate, cancel) carries one control number
    /// throughout: IEC 61850-7-2 has the client increment `ctlNum` once per new
    /// sequence, and a server that compares the operate's number against the
    /// selected one rejects the operate as inconsistent-parameters otherwise.
    /// The number is therefore allocated by the first request of a sequence and
    /// reused until the sequence ends. It wraps at 255 by design.
    fn begin_sequence(&self) -> u8 {
        let mut seq = self.sequence.lock().unwrap();
        if !seq.in_sequence {
            seq.ctl_num = seq.ctl_num.wrapping_add(1);
            seq.in_sequence = true;
        }
        seq.ctl_num
    }

    /// Closes the current sequence, so the next one takes a fresh number.
    fn end_sequence(&self) {
        self.sequence.lock().unwrap().in_sequence = false;
    }

    /// Constructs the operate structure:
    /// `{ ctlVal, origin{orCat, orIdent}, ctlNum, T, Test, Check }`.
    fn build_oper(&self, value: Value, opts: &ControlOptions, ctl_num: u8) -> Value {
        let origin = Value::structure(vec![
            Value::int8(opts.or_cat.code() as i8),
            Value::octet_string(opts.or_ident.clone()),
        ]);
        let mut check = Value::bit_string(2);
        check.set_bit(0, opts.interlock_check);
        check.set_bit(1, opts.synchro_check);

        Value::structure(vec![
            value,
            origin,
            Value::uint8(ctl_num),
            Value::utc_time(SystemTime::now(), TimeQuality::accuracy(10)),
            Value::boolean(opts.test),
            check,
        ])
    }

    /// Reads `LastApplError` to recover the additional cause of a rejected
    /// control, best effort.
    async fn last_appl_error(&self) -> AddCause {
        let vals = self
            .client
            .mms()
            .read(&self.domain, &["LLN0$ST$LastApplError$AddCause"])
            .await;
        match vals.ok().and_then(|v| v.into_iter().next()) {
            Some(v) if v.as_access_error().is_none() => AddCause(v.as_i64() as u8),
            _ => AddCause::UNKNOWN,
        }
    }
}

/// Returns the type of a named member of a structure type.
fn component_spec(ts: &TypeSpec, name: &str) -> Option<TypeSpec> {
    if ts.kind != Some(Type::Structure) {
        return None;
    }
    ts.components
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.spec.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::Component;

    #[test]
    fn control_errors_prefer_the_devices_own_diagnosis() {
        let e = ControlError::new(Stage::Operate, AddCause::BLOCKED_BY_INTERLOCKING);
        assert_eq!(
            e.to_string(),
            "client: control operate failed: blocked-by-interlocking"
        );

        // With no diagnosis, the underlying error is what there is to say.
        let e = ControlError::with_source(
            Stage::Select,
            AddCause::UNKNOWN,
            crate::mms::DataAccessError::ObjectAccessDenied,
        );
        assert!(e.to_string().contains("select"));
        assert!(e.to_string().contains("object-access-denied"));
    }

    #[test]
    fn stages_render_their_names() {
        assert_eq!(Stage::Select.to_string(), "select");
        assert_eq!(Stage::Operate.to_string(), "operate");
        assert_eq!(Stage::Cancel.to_string(), "cancel");
    }

    #[test]
    fn the_control_value_type_is_found_inside_the_operate_structure() {
        let oper = TypeSpec::structure(vec![
            Component {
                name: "ctlVal".into(),
                spec: TypeSpec::scalar(Type::Boolean),
            },
            Component {
                name: "origin".into(),
                spec: TypeSpec::structure(vec![]),
            },
            Component {
                name: "ctlNum".into(),
                spec: TypeSpec::sized(Type::Unsigned, 8),
            },
        ]);
        assert_eq!(
            component_spec(&oper, "ctlVal").unwrap().kind,
            Some(Type::Boolean)
        );
        assert!(component_spec(&oper, "nope").is_none());
        // A scalar has no components to look inside.
        assert!(component_spec(&TypeSpec::scalar(Type::Boolean), "ctlVal").is_none());
    }

    #[test]
    fn options_default_to_station_control_with_no_checks() {
        let o = ControlOptions::new();
        assert_eq!(o.or_cat, OrCat::StationControl);
        assert!(!o.test && !o.interlock_check && !o.synchro_check);
        assert!(o.model.is_none());

        let o = ControlOptions::new()
            .with_originator(OrCat::RemoteControl, "scada-1")
            .with_interlock_check(true)
            .with_test(true);
        assert_eq!(o.or_cat, OrCat::RemoteControl);
        assert_eq!(o.or_ident, b"scada-1");
        assert!(o.interlock_check && o.test);
        assert!(!o.synchro_check);
    }
}
